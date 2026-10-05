use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::config::types::{BaseConfig, ProxyType, RedsocksConfig};
use crate::proxy::http_connect::HttpConnectResult;
use crate::proxy::*;
use crate::redirector::Redirector;
use crate::redsocks::pump::run_duplex_pump;
use crate::stats::StatsTracker;

pub struct RedsocksInstance {
    config: RedsocksConfig,
    base_config: BaseConfig,
    redirector: Arc<Redirector>,
    stats: Arc<StatsTracker>,
}

impl RedsocksInstance {
    pub fn new(
        config: RedsocksConfig,
        base_config: BaseConfig,
        redirector: Arc<Redirector>,
        stats: Arc<StatsTracker>,
    ) -> Self {
        Self {
            config,
            base_config,
            redirector,
            stats,
        }
    }

    pub async fn run(self: Arc<Self>) -> io::Result<()> {
        let bind_addr = SocketAddr::new(self.config.local_ip, self.config.local_port);

        // Configure socket with socket2 for listenq and reuse options
        let domain = match bind_addr {
            SocketAddr::V4(_) => socket2::Domain::IPV4,
            SocketAddr::V6(_) => socket2::Domain::IPV6,
        };

        let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None)?;
        socket.set_reuse_address(true)?;
        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        socket.set_reuse_port(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&bind_addr.into())?;
        socket.listen(self.config.listenq as i32)?;

        let std_listener: std::net::TcpListener = socket.into();
        let listener = TcpListener::from_std(std_listener)?;

        log::info!(
            "redsocks [{:?}] listening on {} -> proxy {}:{}",
            self.config.proxy_type,
            bind_addr,
            self.config.ip,
            self.config.port
        );

        let idle_timeout = if self.base_config.connpres_idle_timeout > 0 {
            Some(Duration::from_secs(self.base_config.connpres_idle_timeout))
        } else {
            None
        };

        loop {
            // Check connection limit
            let max_conn = self.base_config.redsocks_conn_max as usize;
            if max_conn > 0 && self.stats.active_count() >= max_conn {
                log::warn!(
                    "Connection limit hit ({}/{}), throttling accept",
                    self.stats.active_count(),
                    max_conn
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            let (client_stream, client_addr) = match listener.accept().await {
                Ok(res) => res,
                Err(e) => {
                    log::warn!("accept error: {}", e);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };

            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) = this
                    .handle_client(client_stream, client_addr, idle_timeout)
                    .await
                {
                    log::debug!("Client {} error: {}", client_addr, e);
                }
            });
        }
    }

    async fn handle_client(
        &self,
        mut client_stream: TcpStream,
        client_addr: SocketAddr,
        idle_timeout: Option<Duration>,
    ) -> io::Result<()> {
        let dest_addr = self.redirector.get_dest_addr(&client_stream)?;

        // Apply TCP Keepalive
        apply_tcp_keepalive(&client_stream, &self.base_config)?;

        let proxy_type_str = format!("{:?}", self.config.proxy_type);
        let client_id = self
            .stats
            .register_client(client_addr, dest_addr, &proxy_type_str);

        if self.base_config.log_info {
            log::info!(
                "accepted connection from {} -> target {} (via {:?} proxy {}:{})",
                client_addr,
                dest_addr,
                self.config.proxy_type,
                self.config.ip,
                self.config.port
            );
        }

        let res = match self.config.proxy_type {
            ProxyType::Socks4 => {
                let mut proxy_stream =
                    TcpStream::connect((self.config.ip.as_str(), self.config.port)).await?;
                apply_tcp_keepalive(&proxy_stream, &self.base_config)?;
                socks4_connect(&mut proxy_stream, dest_addr, self.config.login.as_deref()).await?;
                run_duplex_pump(
                    client_stream,
                    proxy_stream,
                    self.stats.clone(),
                    client_id,
                    idle_timeout,
                )
                .await
            }
            ProxyType::Socks5 => {
                let mut proxy_stream =
                    TcpStream::connect((self.config.ip.as_str(), self.config.port)).await?;
                apply_tcp_keepalive(&proxy_stream, &self.base_config)?;
                socks5_connect(
                    &mut proxy_stream,
                    dest_addr,
                    self.config.login.as_deref(),
                    self.config.password.as_deref(),
                )
                .await?;
                run_duplex_pump(
                    client_stream,
                    proxy_stream,
                    self.stats.clone(),
                    client_id,
                    idle_timeout,
                )
                .await
            }
            ProxyType::HttpConnect => {
                let (proxy_stream, connect_res) = http_connect(
                    &self.config.ip,
                    self.config.port,
                    dest_addr,
                    client_addr,
                    self.config.login.as_deref(),
                    self.config.password.as_deref(),
                    self.config.disclose_src,
                    self.config.on_proxy_fail,
                )
                .await?;

                apply_tcp_keepalive(&proxy_stream, &self.base_config)?;

                match connect_res {
                    HttpConnectResult::Success => {
                        run_duplex_pump(
                            client_stream,
                            proxy_stream,
                            self.stats.clone(),
                            client_id,
                            idle_timeout,
                        )
                        .await
                    }
                    HttpConnectResult::ForwardError(err_bytes) => {
                        let _ = client_stream.write_all(&err_bytes).await;
                        let _ = client_stream.flush().await;
                        Ok(())
                    }
                }
            }
            ProxyType::HttpRelay => {
                let mut proxy_stream =
                    TcpStream::connect((self.config.ip.as_str(), self.config.port)).await?;
                apply_tcp_keepalive(&proxy_stream, &self.base_config)?;
                http_relay_handshake(&mut client_stream, dest_addr, &mut proxy_stream).await?;
                run_duplex_pump(
                    client_stream,
                    proxy_stream,
                    self.stats.clone(),
                    client_id,
                    idle_timeout,
                )
                .await
            }
        };

        self.stats.unregister_client(client_id);

        if self.base_config.log_info {
            log::info!(
                "closed connection from {} -> target {}",
                client_addr,
                dest_addr
            );
        }

        res
    }
}

pub fn apply_tcp_keepalive(stream: &TcpStream, base: &BaseConfig) -> io::Result<()> {
    let fd = stream.as_raw_fd();
    unsafe {
        let on: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of_val(&on) as libc::socklen_t,
        );

        #[cfg(target_os = "linux")]
        {
            if base.tcp_keepalive_time > 0 {
                let time = base.tcp_keepalive_time as libc::c_int;
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_KEEPIDLE,
                    &time as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&time) as libc::socklen_t,
                );
            }
            if base.tcp_keepalive_intvl > 0 {
                let intvl = base.tcp_keepalive_intvl as libc::c_int;
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_KEEPINTVL,
                    &intvl as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&intvl) as libc::socklen_t,
                );
            }
            if base.tcp_keepalive_probes > 0 {
                let probes = base.tcp_keepalive_probes as libc::c_int;
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_KEEPCNT,
                    &probes as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&probes) as libc::socklen_t,
                );
            }
        }
    }
    Ok(())
}
