use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::config::types::RedudpConfig;
use crate::proxy::socks5::*;

pub struct Socks5UdpPacket {
    pub payload: Vec<u8>,
}

pub struct RedudpSession {
    pub client_addr: SocketAddr,
    pub dest_addr: SocketAddr,
    pub last_activity: Instant,
    pub tx_packet: mpsc::Sender<Vec<u8>>,
}

pub async fn run_session_worker(
    config: RedudpConfig,
    client_addr: SocketAddr,
    dest_addr: SocketAddr,
    mut rx_packet: mpsc::Receiver<Vec<u8>>,
    outbound_reply_tx: mpsc::Sender<(SocketAddr, SocketAddr, Vec<u8>)>,
) -> io::Result<()> {
    // 1. Establish TCP connection to SOCKS5 server for UDP ASSOCIATE
    let mut tcp_stream = TcpStream::connect((config.ip.as_str(), config.port)).await?;
    let proxy_ip = tcp_stream.peer_addr()?.ip();

    let relay_addr = socks5_udp_associate(
        &mut tcp_stream,
        proxy_ip,
        config.login.as_deref(),
        config.password.as_deref(),
    )
    .await?;

    log::debug!(
        "UDP ASSOCIATE succeeded for client {} -> target {}. SOCKS5 relay at {}",
        client_addr,
        dest_addr,
        relay_addr
    );

    // 2. Bind UDP socket to communicate with SOCKS5 relay
    let udp_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    udp_socket.connect(relay_addr).await?;

    let timeout_duration = std::time::Duration::from_secs(config.udp_timeout);
    let mut tcp_buf = [0u8; 1];

    // Outbound loop: client packets -> SOCKS5 UDP relay
    let udp_send = udp_socket.clone();
    let dest_for_header = dest_addr;

    let send_task = async move {
        while let Some(packet) = rx_packet.recv().await {
            let mut framed = Vec::with_capacity(10 + packet.len());
            framed.push(0); // RSV
            framed.push(0); // RSV
            framed.push(0); // FRAG = 0

            match dest_for_header.ip() {
                IpAddr::V4(v4) => {
                    framed.push(SOCKS5_ATYP_IPV4);
                    framed.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    framed.push(SOCKS5_ATYP_IPV6);
                    framed.extend_from_slice(&v6.octets());
                }
            }
            framed.extend_from_slice(&dest_for_header.port().to_be_bytes());
            framed.extend_from_slice(&packet);

            if let Err(e) = udp_send.send(&framed).await {
                log::warn!("Failed to send UDP packet to SOCKS5 relay: {}", e);
                break;
            }
        }
    };

    // Inbound loop: SOCKS5 UDP relay packets -> strip header -> forward back to client
    let udp_recv = udp_socket.clone();
    let reply_tx = outbound_reply_tx.clone();

    let recv_task = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let n = match udp_recv.recv(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    log::warn!("UDP recv error from SOCKS5 relay: {}", e);
                    break;
                }
            };

            if n < 10 {
                continue;
            }

            // Check header: RSV(2) + FRAG(1) + ATYP(1)
            let frag = buf[2];
            if frag != 0 {
                // Fragmented UDP packets not supported
                continue;
            }

            let atyp = buf[3];
            let payload_offset = match atyp {
                SOCKS5_ATYP_IPV4 => 4 + 4 + 2,
                SOCKS5_ATYP_IPV6 => 4 + 16 + 2,
                SOCKS5_ATYP_DOMAIN => {
                    let dlen = buf[4] as usize;
                    4 + 1 + dlen + 2
                }
                _ => continue,
            };

            if n <= payload_offset {
                continue;
            }

            let payload = buf[payload_offset..n].to_vec();
            // Send back to client: reply from dest_addr to client_addr
            let _ = reply_tx.send((client_addr, dest_addr, payload)).await;
        }
    };

    // Keepalive / termination check: if TCP control connection closes or timeout
    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
        res = tcp_stream.read(&mut tcp_buf) => {
            log::debug!("SOCKS5 TCP control connection for {} terminated: {:?}", client_addr, res);
        }
        _ = tokio::time::sleep(timeout_duration) => {
            log::debug!("UDP session for {} idle timed out", client_addr);
        }
    }

    Ok(())
}

pub fn make_socks5_preamble(dest: SocketAddr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10);
    buf.push(0); // RSV
    buf.push(0); // RSV
    buf.push(0); // FRAG
    match dest.ip() {
        IpAddr::V4(v4) => {
            buf.push(SOCKS5_ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(SOCKS5_ATYP_IPV6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&dest.port().to_be_bytes());
    buf
}
