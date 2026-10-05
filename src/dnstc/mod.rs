use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::config::types::DnstcConfig;

pub const DNS_QR: u8 = 0x80;
pub const DNS_TC: u8 = 0x02;
pub const DNS_Z: u8 = 0x70;

pub struct DnstcServer {
    config: DnstcConfig,
}

impl DnstcServer {
    pub fn new(config: DnstcConfig) -> Self {
        Self { config }
    }

    pub async fn run(self: Arc<Self>) -> io::Result<()> {
        let bind_addr = SocketAddr::new(self.config.local_ip, self.config.local_port);
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);

        log::info!("dnstc listening on {}", bind_addr);

        let mut buf = vec![0u8; 65535];
        loop {
            let (len, client_addr) = match socket.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(e) => {
                    log::warn!("dnstc recv error: {}", e);
                    continue;
                }
            };

            if let Some(reply_len) = process_dns_query(&mut buf[..len]) {
                if let Err(e) = socket.send_to(&buf[..reply_len], client_addr).await {
                    log::warn!("dnstc sendto {} error: {}", client_addr, e);
                } else {
                    log::debug!("dnstc sent truncated DNS reply to {}", client_addr);
                }
            }
        }
    }
}

pub fn process_dns_query(packet: &mut [u8]) -> Option<usize> {
    if packet.len() <= 12 {
        return None;
    }

    let qr_byte = packet[2];
    let z_byte = packet[3];
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    let nscount = u16::from_be_bytes([packet[8], packet[9]]);

    // Verify it is a valid query: QR == 0, Z == 0, qdcount > 0, ancount == 0, nscount == 0
    if (qr_byte & DNS_QR) == 0
        && (z_byte & DNS_Z) == 0
        && qdcount > 0
        && ancount == 0
        && nscount == 0
    {
        packet[2] |= DNS_QR | DNS_TC;
        Some(packet.len())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_dns_query() {
        // Construct a sample DNS query: ID=0x1234, QR=0, QDCOUNT=1
        let mut query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // QR=0, RD=1, RA=0, Z=0, RCODE=0
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00, 0x01, // QTYPE=A, QCLASS=IN
        ];

        let len = process_dns_query(&mut query).expect("should process query");
        assert_eq!(len, query.len());

        // Byte 2 must have QR (0x80) and TC (0x02) bits set
        assert_ne!(query[2] & DNS_QR, 0);
        assert_ne!(query[2] & DNS_TC, 0);
    }
}
