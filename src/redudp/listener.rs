use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

#[cfg(target_os = "linux")]
use tokio::io::unix::AsyncFd;

use crate::config::types::RedudpConfig;
use crate::redudp::session::run_session_worker;

#[derive(Default)]
pub struct BoundSocketCache {
    sockets: Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>,
}

impl BoundSocketCache {
    pub async fn get_or_bind(&self, src_addr: SocketAddr) -> io::Result<Arc<UdpSocket>> {
        let mut lock = self.sockets.lock().await;
        if let Some(sock) = lock.get(&src_addr) {
            return Ok(sock.clone());
        }

        let domain = match src_addr {
            SocketAddr::V4(_) => socket2::Domain::IPV4,
            SocketAddr::V6(_) => socket2::Domain::IPV6,
        };

        let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        socket.set_reuse_address(true)?;

        #[cfg(target_os = "linux")]
        {
            let on: libc::c_int = 1;
            unsafe {
                let _ = libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_IP,
                    libc::IP_TRANSPARENT,
                    &on as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&on) as libc::socklen_t,
                );
            }
        }

        socket.set_nonblocking(true)?;
        socket.bind(&src_addr.into())?;

        let std_sock: std::net::UdpSocket = socket.into();
        let tokio_sock = Arc::new(UdpSocket::from_std(std_sock)?);
        lock.insert(src_addr, tokio_sock.clone());
        Ok(tokio_sock)
    }
}

pub struct RedudpListener {
    config: RedudpConfig,
}

impl RedudpListener {
    pub fn new(config: RedudpConfig) -> Self {
        Self { config }
    }

    pub async fn run(self: Arc<Self>) -> io::Result<()> {
        let bind_addr = SocketAddr::new(self.config.local_ip, self.config.local_port);
        let is_tproxy = self.config.is_tproxy();

        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;

        socket.set_reuse_address(true)?;
        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        socket.set_reuse_port(true)?;
        socket.set_nonblocking(true)?;

        if is_tproxy {
            #[cfg(target_os = "linux")]
            {
                let on: libc::c_int = 1;
                unsafe {
                    let _ = libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::SOL_IP,
                        libc::IP_TRANSPARENT,
                        &on as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&on) as libc::socklen_t,
                    );
                    let _ = libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::SOL_IP,
                        libc::IP_RECVORIGDSTADDR,
                        &on as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&on) as libc::socklen_t,
                    );
                }
            }
        }

        socket.bind(&bind_addr.into())?;
        let std_socket: std::net::UdpSocket = socket.into();

        log::info!(
            "redudp listening on {} [mode: {}] -> proxy {}:{}",
            bind_addr,
            if is_tproxy { "TPROXY" } else { "REDIRECT" },
            self.config.ip,
            self.config.port
        );

        let (reply_tx, mut reply_rx) = mpsc::channel::<(SocketAddr, SocketAddr, Vec<u8>)>(1024);

        let socket_cache = Arc::new(BoundSocketCache::default());
        let socket_cache_clone = socket_cache.clone();
        let fallback_socket = Arc::new(UdpSocket::from_std(std_socket.try_clone()?)?);
        let fallback_send = fallback_socket.clone();
        let config_clone = self.config.clone();

        // Outbound reply forwarder task
        tokio::spawn(async move {
            while let Some((client_addr, dest_addr, payload)) = reply_rx.recv().await {
                if config_clone.is_tproxy() {
                    match socket_cache_clone.get_or_bind(dest_addr).await {
                        Ok(sock) => {
                            if let Err(e) = sock.send_to(&payload, client_addr).await {
                                log::debug!("TPROXY cached socket send error: {}, falling back", e);
                                let _ = fallback_send.send_to(&payload, client_addr).await;
                            }
                        }
                        Err(e) => {
                            log::debug!("TPROXY bind to {} failed: {}, falling back", dest_addr, e);
                            let _ = fallback_send.send_to(&payload, client_addr).await;
                        }
                    }
                } else {
                    let _ = fallback_send.send_to(&payload, client_addr).await;
                }
            }
        });

        // Active sessions table
        type SessionEntry = (mpsc::Sender<Vec<u8>>, Instant);
        let sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), SessionEntry>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let sessions_cleaner = sessions.clone();
        let timeout_secs = self.config.udp_timeout;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let mut lock = sessions_cleaner.lock().await;
                let now = Instant::now();
                lock.retain(|_, (tx, last_active)| {
                    !tx.is_closed() && now.duration_since(*last_active).as_secs() < timeout_secs
                });
            }
        });

        #[cfg(target_os = "linux")]
        let async_listener = AsyncFd::new(std_socket)?;
        #[cfg(not(target_os = "linux"))]
        let listener_sock = fallback_socket;

        let mut buf = vec![0u8; 65535];

        loop {
            #[cfg(target_os = "linux")]
            let (len, client_addr, orig_dst) = {
                let mut guard = async_listener.readable().await?;
                match guard.try_io(|inner| recv_udp_pkt_tproxy(inner.get_ref().as_raw_fd(), &mut buf)) {
                    Ok(Ok(res)) => res,
                    Ok(Err(e)) => {
                        log::warn!("UDP recvmsg error: {}", e);
                        continue;
                    }
                    Err(_would_block) => continue,
                }
            };

            #[cfg(not(target_os = "linux"))]
            let (len, client_addr, orig_dst): (usize, SocketAddr, Option<SocketAddr>) = {
                match listener_sock.recv_from(&mut buf).await {
                    Ok((n, addr)) => (n, addr, None),
                    Err(e) => {
                        log::warn!("UDP recv_from error: {}", e);
                        continue;
                    }
                }
            };

            let packet_data = buf[..len].to_vec();

            // Determine target destination address
            let dest_addr = if is_tproxy {
                orig_dst.unwrap_or_else(|| {
                    SocketAddr::new(
                        self.config
                            .dest_ip
                            .unwrap_or(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                        self.config.dest_port.unwrap_or(53),
                    )
                })
            } else {
                SocketAddr::new(
                    self.config
                        .dest_ip
                        .unwrap_or(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                    self.config.dest_port.unwrap_or(53),
                )
            };

            let key = (client_addr, dest_addr);
            let mut lock = sessions.lock().await;

            if let Some((tx, last_active)) = lock.get_mut(&key) {
                *last_active = Instant::now();
                let _ = tx.send(packet_data).await;
            } else {
                let (tx, rx) = mpsc::channel(self.config.max_pktqueue.max(16));
                let _ = tx.send(packet_data).await;
                lock.insert(key, (tx, Instant::now()));

                let cfg = self.config.clone();
                let reply_tx_clone = reply_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        run_session_worker(cfg, client_addr, dest_addr, rx, reply_tx_clone).await
                    {
                        log::debug!("redudp session {} -> {} ended: {}", client_addr, dest_addr, e);
                    }
                });
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn recv_udp_pkt_tproxy(
    fd: std::os::unix::io::RawFd,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
    let mut client_addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut control_buf = [0u8; 1024];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };

    msg.msg_name = &mut client_addr as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of_val(&client_addr) as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control_buf.len() as _;

    let res = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if res < 0 {
        return Err(io::Error::last_os_error());
    }

    let client_sockaddr = unsafe {
        if client_addr.ss_family as libc::c_int == libc::AF_INET {
            let sin: &libc::sockaddr_in = std::mem::transmute(&client_addr);
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            SocketAddr::V4(std::net::SocketAddrV4::new(ip, port))
        } else if client_addr.ss_family as libc::c_int == libc::AF_INET6 {
            let sin6: &libc::sockaddr_in6 = std::mem::transmute(&client_addr);
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, sin6.sin6_flowinfo, sin6.sin6_scope_id))
        } else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Unknown address family"));
        }
    };

    let mut dest_sockaddr = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_IP && (*cmsg).cmsg_type == libc::IP_ORIGDSTADDR {
                let sin: *const libc::sockaddr_in = libc::CMSG_DATA(cmsg) as *const _;
                let ip = Ipv4Addr::from(u32::from_be((*sin).sin_addr.s_addr));
                let port = u16::from_be((*sin).sin_port);
                dest_sockaddr = Some(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)));
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Ok((res as usize, client_sockaddr, dest_sockaddr))
}
