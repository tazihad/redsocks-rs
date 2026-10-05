use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn http_relay_handshake(
    client_stream: &mut TcpStream,
    dest_addr: SocketAddr,
    proxy_stream: &mut TcpStream,
) -> io::Result<()> {
    // Read initial HTTP request line from client
    let mut line_buf = Vec::new();
    let mut byte = [0u8; 1];

    while line_buf.len() < 4096 {
        client_stream.read_exact(&mut byte).await?;
        line_buf.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }

    let line_str = String::from_utf8_lossy(&line_buf);
    let trimmed = line_str.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed.split_whitespace();

    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");
    let version = parts.next().unwrap_or("HTTP/1.1");

    // Rewrite request line: if path is relative, rewrite to absolute http://dest:port/path
    let rewritten_line = if path.starts_with('/') {
        format!(
            "{} http://{}{}{} {}\r\n",
            method,
            dest_addr.ip(),
            if dest_addr.port() != 80 {
                format!(":{}", dest_addr.port())
            } else {
                "".to_string()
            },
            path,
            version
        )
    } else {
        format!("{}\r\n", trimmed)
    };

    proxy_stream.write_all(rewritten_line.as_bytes()).await?;
    proxy_stream.flush().await?;

    Ok(())
}
