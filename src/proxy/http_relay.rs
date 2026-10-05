use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn http_relay_handshake(
    client_stream: &mut TcpStream,
    dest_addr: SocketAddr,
    proxy_stream: &mut TcpStream,
) -> io::Result<()> {
    // Read complete HTTP request headers from client up to \r\n\r\n
    let mut header_buf = Vec::with_capacity(2048);
    let mut byte = [0u8; 1];

    while header_buf.len() < 16384 {
        client_stream.read_exact(&mut byte).await?;
        header_buf.push(byte[0]);
        if header_buf.ends_with(b"\r\n\r\n") || header_buf.ends_with(b"\n\n") {
            break;
        }
    }

    let header_str = String::from_utf8_lossy(&header_buf);
    let mut lines = header_str.split("\r\n");

    let first_line = lines.next().unwrap_or("GET / HTTP/1.1");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");
    let version = parts.next().unwrap_or("HTTP/1.1");

    // Look for Host header
    let mut host_header: Option<String> = None;
    let mut other_headers = Vec::new();

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                host_header = Some(v.trim().to_string());
            } else {
                other_headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
    }

    // Determine host and port for absolute URI
    let host = host_header.unwrap_or_else(|| {
        if dest_addr.port() == 80 {
            format!("{}", dest_addr.ip())
        } else {
            format!("{}:{}", dest_addr.ip(), dest_addr.port())
        }
    });

    let new_request_line = if path.starts_with('/') {
        format!("{} http://{}{} {}\r\n", method, host, path, version)
    } else {
        format!("{} {}\r\n", first_line, version)
    };

    let mut out = Vec::new();
    out.extend_from_slice(new_request_line.as_bytes());
    out.extend_from_slice(format!("Host: {}\r\n", host).as_bytes());

    for (k, v) in other_headers {
        out.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
    }
    out.extend_from_slice(b"\r\n");

    proxy_stream.write_all(&out).await?;
    proxy_stream.flush().await?;

    Ok(())
}
