use std::io;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn socks4_connect(
    stream: &mut TcpStream,
    dest_addr: SocketAddr,
    username: Option<&str>,
) -> io::Result<()> {
    let dest_ip = match dest_addr.ip() {
        IpAddr::V4(ipv4) => ipv4,
        IpAddr::V6(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS4 does not support IPv6 destinations",
            ));
        }
    };

    let user = username.unwrap_or("");
    let mut req = Vec::with_capacity(9 + user.len());
    req.push(4); // SOCKS version 4
    req.push(1); // Command 1: CONNECT
    req.extend_from_slice(&dest_addr.port().to_be_bytes());
    req.extend_from_slice(&dest_ip.octets());
    req.extend_from_slice(user.as_bytes());
    req.push(0); // NUL terminator for user ID

    stream.write_all(&req).await?;
    stream.flush().await?;

    let mut reply = [0u8; 8];
    stream.read_exact(&mut reply).await?;

    if reply[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid SOCKS4 reply version: {}", reply[0]),
        ));
    }

    match reply[1] {
        90 => Ok(()), // Granted
        91 => Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "SOCKS4 server rejected or failed connection",
        )),
        92 => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS4 server rejected: client not running identd",
        )),
        93 => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS4 server rejected: identd user ID mismatch",
        )),
        other => Err(io::Error::other(format!(
            "SOCKS4 server returned unknown status code {}",
            other
        ))),
    }
}
