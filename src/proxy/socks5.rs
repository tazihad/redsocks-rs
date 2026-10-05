use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const SOCKS5_VER: u8 = 5;
pub const SOCKS5_CMD_CONNECT: u8 = 1;
pub const SOCKS5_CMD_BIND: u8 = 2;
pub const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 3;

pub const SOCKS5_AUTH_NONE: u8 = 0;
pub const SOCKS5_AUTH_PASSWORD: u8 = 2;
pub const SOCKS5_AUTH_NO_ACCEPTABLE: u8 = 0xFF;

pub const SOCKS5_ATYP_IPV4: u8 = 1;
pub const SOCKS5_ATYP_DOMAIN: u8 = 3;
pub const SOCKS5_ATYP_IPV6: u8 = 4;

pub async fn socks5_handshake(
    stream: &mut TcpStream,
    login: Option<&str>,
    password: Option<&str>,
) -> io::Result<()> {
    // 1. Send supported authentication methods
    let has_auth = login.is_some() && password.is_some();
    if has_auth {
        stream
            .write_all(&[SOCKS5_VER, 2, SOCKS5_AUTH_NONE, SOCKS5_AUTH_PASSWORD])
            .await?;
    } else {
        stream.write_all(&[SOCKS5_VER, 1, SOCKS5_AUTH_NONE]).await?;
    }
    stream.flush().await?;

    // 2. Read selected method
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != SOCKS5_VER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid SOCKS5 version: {}", resp[0]),
        ));
    }

    match resp[1] {
        SOCKS5_AUTH_NONE => Ok(()),
        SOCKS5_AUTH_PASSWORD => {
            let u = login.unwrap_or("");
            let p = password.unwrap_or("");
            if u.len() > 255 || p.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Username or password exceeds 255 bytes",
                ));
            }

            let mut req = Vec::with_capacity(3 + u.len() + p.len());
            req.push(1); // sub-negotiation version 1
            req.push(u.len() as u8);
            req.extend_from_slice(u.as_bytes());
            req.push(p.len() as u8);
            req.extend_from_slice(p.as_bytes());

            stream.write_all(&req).await?;
            stream.flush().await?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;
            if auth_resp[0] != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid SOCKS5 password auth version: {}", auth_resp[0]),
                ));
            }
            if auth_resp[1] != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("SOCKS5 authentication failed, error code: {}", auth_resp[1]),
                ));
            }
            Ok(())
        }
        SOCKS5_AUTH_NO_ACCEPTABLE => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 server: no acceptable authentication methods",
        )),
        other => Err(io::Error::other(format!(
            "SOCKS5 server requested unknown auth method: {}",
            other
        ))),
    }
}

pub async fn socks5_connect(
    stream: &mut TcpStream,
    dest_addr: SocketAddr,
    login: Option<&str>,
    password: Option<&str>,
) -> io::Result<()> {
    socks5_handshake(stream, login, password).await?;
    send_socks5_command(stream, SOCKS5_CMD_CONNECT, dest_addr).await?;
    let _ = read_socks5_reply(stream).await?;
    Ok(())
}

pub async fn socks5_udp_associate(
    stream: &mut TcpStream,
    proxy_ip: IpAddr,
    login: Option<&str>,
    password: Option<&str>,
) -> io::Result<SocketAddr> {
    socks5_handshake(stream, login, password).await?;

    // Send UDP ASSOCIATE with 0.0.0.0:0
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
    send_socks5_command(stream, SOCKS5_CMD_UDP_ASSOCIATE, bind_addr).await?;

    let relay_addr = read_socks5_reply(stream).await?;
    // RFC 1928: If chosen BND.ADDR is 0.0.0.0, use the proxy server's IP
    let final_addr = match relay_addr.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => SocketAddr::new(proxy_ip, relay_addr.port()),
        IpAddr::V6(v6) if v6.is_unspecified() => SocketAddr::new(proxy_ip, relay_addr.port()),
        _ => relay_addr,
    };
    Ok(final_addr)
}

async fn send_socks5_command(stream: &mut TcpStream, cmd: u8, dest: SocketAddr) -> io::Result<()> {
    let mut req = Vec::with_capacity(22);
    req.push(SOCKS5_VER);
    req.push(cmd);
    req.push(0); // Reserved

    match dest.ip() {
        IpAddr::V4(v4) => {
            req.push(SOCKS5_ATYP_IPV4);
            req.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            req.push(SOCKS5_ATYP_IPV6);
            req.extend_from_slice(&v6.octets());
        }
    }
    req.extend_from_slice(&dest.port().to_be_bytes());

    stream.write_all(&req).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_socks5_reply(stream: &mut TcpStream) -> io::Result<SocketAddr> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    if header[0] != SOCKS5_VER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid SOCKS5 reply version: {}", header[0]),
        ));
    }

    if header[1] != 0 {
        let msg = match header[1] {
            1 => "general SOCKS server failure",
            2 => "connection not allowed by ruleset",
            3 => "Network unreachable",
            4 => "Host unreachable",
            5 => "Connection refused",
            6 => "TTL expired",
            7 => "Command not supported",
            8 => "Address type not supported",
            _ => "unknown SOCKS5 error",
        };
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 error {}: {}", header[1], msg),
        ));
    }

    let atyp = header[3];
    let ip = match atyp {
        SOCKS5_ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;
            IpAddr::V4(Ipv4Addr::from(buf))
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain_buf = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain_buf).await?;
            // If domain is returned, default to loopback or parse as IP
            if let Ok(s) = std::str::from_utf8(&domain_buf) {
                if let Ok(ip) = s.parse::<IpAddr>() {
                    ip
                } else {
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
                }
            } else {
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
            }
        }
        SOCKS5_ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf).await?;
            IpAddr::V6(Ipv6Addr::from(buf))
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported SOCKS5 address type: {}", other),
            ));
        }
    };

    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok(SocketAddr::new(ip, port))
}
