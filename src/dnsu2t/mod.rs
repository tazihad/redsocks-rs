use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};

use crate::config::types::Dnsu2tConfig;
use crate::dnstc::DNS_QR;

pub struct Dnsu2tServer {
    config: Dnsu2tConfig,
}

impl Dnsu2tServer {
    pub fn new(config: Dnsu2tConfig) -> Self {
        Self { config }
    }

    pub async fn run(self: Arc<Self>) -> io::Result<()> {
        let bind_addr = SocketAddr::new(self.config.local_ip, self.config.local_port);
        let udp_socket = Arc::new(UdpSocket::bind(bind_addr).await?);

        log::info!(
            "dnsu2t listening on {} -> TCP resolver {}:{}",
            bind_addr,
            self.config.remote_ip,
            self.config.remote_port
        );

        let (tcp_send_tx, tcp_send_rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(1024);
        let tcp_send_rx = Arc::new(Mutex::new(tcp_send_rx));
        let inflight: Arc<Mutex<HashMap<u16, (SocketAddr, Instant)>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Background worker managing persistent TCP connection
        let inflight_for_worker = inflight.clone();
        let udp_socket_for_replies = udp_socket.clone();
        let config_clone = self.config.clone();

        tokio::spawn(async move {
            loop {
                log::debug!(
                    "dnsu2t connecting to upstream DNS TCP {}:{}",
                    config_clone.remote_ip,
                    config_clone.remote_port
                );

                match TcpStream::connect((
                    config_clone.remote_ip.as_str(),
                    config_clone.remote_port,
                ))
                .await
                {
                    Ok(tcp_stream) => {
                        let (mut tcp_r, mut tcp_w) = tcp_stream.into_split();

                        let inflight_send = inflight_for_worker.clone();
                        let timeout_secs = config_clone.remote_timeout;
                        let inflight_max = config_clone.inflight_max;
                        let rx_mutex = tcp_send_rx.clone();

                        let send_task = async move {
                            let mut rx = rx_mutex.lock().await;
                            while let Some((client_addr, query)) = rx.recv().await {
                                if query.len() < 12 {
                                    continue;
                                }
                                let id = u16::from_be_bytes([query[0], query[1]]);

                                let mut lock = inflight_send.lock().await;
                                // Check max inflight
                                if lock.len() >= inflight_max {
                                    let now = Instant::now();
                                    lock.retain(|_, (_, ts)| {
                                        now.duration_since(*ts).as_secs() < timeout_secs
                                    });
                                    if lock.len() >= inflight_max {
                                        log::warn!("dnsu2t inflight limit reached, dropping query");
                                        continue;
                                    }
                                }

                                lock.insert(id, (client_addr, Instant::now()));
                                drop(lock);

                                // Send 2-byte length prefix + query
                                let len_prefix = (query.len() as u16).to_be_bytes();
                                if let Err(e) = tcp_w.write_all(&len_prefix).await {
                                    log::warn!("dnsu2t TCP write len error: {}", e);
                                    break;
                                }
                                if let Err(e) = tcp_w.write_all(&query).await {
                                    log::warn!("dnsu2t TCP write query error: {}", e);
                                    break;
                                }
                                let _ = tcp_w.flush().await;
                            }
                        };

                        let inflight_recv = inflight_for_worker.clone();
                        let udp_socket_recv = udp_socket_for_replies.clone();

                        let recv_task = async move {
                            let mut len_buf = [0u8; 2];
                            loop {
                                if let Err(e) = tcp_r.read_exact(&mut len_buf).await {
                                    log::debug!("dnsu2t TCP upstream disconnected: {}", e);
                                    break;
                                }
                                let msg_len = u16::from_be_bytes(len_buf) as usize;
                                let mut msg = vec![0u8; msg_len];
                                if let Err(e) = tcp_r.read_exact(&mut msg).await {
                                    log::warn!("dnsu2t TCP read payload error: {}", e);
                                    break;
                                }

                                if msg.len() >= 12 {
                                    let id = u16::from_be_bytes([msg[0], msg[1]]);
                                    let mut lock = inflight_recv.lock().await;
                                    if let Some((client_addr, _)) = lock.remove(&id) {
                                        let _ = udp_socket_recv.send_to(&msg, client_addr).await;
                                    }
                                }
                            }
                        };

                        tokio::select! {
                            _ = send_task => {},
                            _ = recv_task => {},
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to connect to upstream DNS TCP server: {}", e);
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
            }
        });

        // UDP listener loop
        let mut buf = vec![0u8; 65535];
        loop {
            let (len, client_addr) = match udp_socket.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(e) => {
                    log::warn!("dnsu2t UDP recv error: {}", e);
                    continue;
                }
            };

            if len <= 12 {
                continue;
            }

            // Ensure it's a query (QR == 0)
            if (buf[2] & DNS_QR) != 0 {
                continue;
            }

            let query = buf[..len].to_vec();
            let _ = tcp_send_tx.send((client_addr, query)).await;
        }
    }
}
