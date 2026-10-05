use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

use crate::config::types::RedudpConfig;
use crate::redudp::session::run_session_worker;

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
        let udp_socket = Arc::new(UdpSocket::from_std(std_socket)?);

        log::info!(
            "redudp listening on {} [mode: {}] -> proxy {}:{}",
            bind_addr,
            if is_tproxy { "TPROXY" } else { "REDIRECT" },
            self.config.ip,
            self.config.port
        );

        let (reply_tx, mut reply_rx) = mpsc::channel::<(SocketAddr, SocketAddr, Vec<u8>)>(1024);

        // Outbound replies to client task
        let send_socket = udp_socket.clone();
        let config_clone = self.config.clone();
        tokio::spawn(async move {
            while let Some((client_addr, dest_addr, payload)) = reply_rx.recv().await {
                if config_clone.is_tproxy() {
                    #[cfg(target_os = "linux")]
                    {
                        // Send from spoofed dest_addr using IP_TRANSPARENT socket
                        let send_res = send_tproxy_reply(dest_addr, client_addr, &payload);
                        if let Err(e) = send_res {
                            log::debug!(
                                "TPROXY send reply failed (falling back to listener): {}",
                                e
                            );
                            let _ = send_socket.send_to(&payload, client_addr).await;
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        let _ = send_socket.send_to(&payload, client_addr).await;
                    }
                } else {
                    let _ = send_socket.send_to(&payload, client_addr).await;
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

        let mut buf = vec![0u8; 65535];

        loop {
            let (len, client_addr) = match udp_socket.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(e) => {
                    log::warn!("UDP listener recv_from error: {}", e);
                    continue;
                }
            };

            let packet_data = buf[..len].to_vec();

            // Determine target destination address
            let dest_addr = if is_tproxy {
                #[cfg(target_os = "linux")]
                {
                    // In TPROXY, try getting IP_ORIGDSTADDR or default to static/loopback
                    get_orig_dst_addr(udp_socket.as_raw_fd()).unwrap_or_else(|| {
                        SocketAddr::new(
                            self.config
                                .dest_ip
                                .unwrap_or(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                            self.config.dest_port.unwrap_or(53),
                        )
                    })
                }
                #[cfg(not(target_os = "linux"))]
                {
                    SocketAddr::new(
                        self.config
                            .dest_ip
                            .unwrap_or(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                        self.config.dest_port.unwrap_or(53),
                    )
                }
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
                        log::debug!(
                            "redudp session {} -> {} ended: {}",
                            client_addr,
                            dest_addr,
                            e
                        );
                    }
                });
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn get_orig_dst_addr(fd: std::os::unix::io::RawFd) -> Option<SocketAddr> {
    unsafe {
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        let ret = libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );

        if ret == 0 {
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            Some(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
        } else {
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn send_tproxy_reply(src_addr: SocketAddr, dst_addr: SocketAddr, payload: &[u8]) -> io::Result<()> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    socket.set_reuse_address(true)?;
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

    socket.bind(&src_addr.into())?;
    socket.send_to(payload, &dst_addr.into())?;
    Ok(())
}
