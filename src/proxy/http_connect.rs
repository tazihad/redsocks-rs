use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::types::{DiscloseSrc, OnProxyFail};
use crate::proxy::http_auth::{basic_auth_header, DigestChallenge};

#[derive(Debug)]
pub enum HttpConnectResult {
    Success,
    ForwardError(Vec<u8>),
}

#[allow(clippy::too_many_arguments)]
pub async fn http_connect(
    proxy_addr: &str,
    proxy_port: u16,
    dest_addr: SocketAddr,
    client_addr: SocketAddr,
    login: Option<&str>,
    password: Option<&str>,
    disclose_src: DiscloseSrc,
    on_proxy_fail: OnProxyFail,
) -> io::Result<(TcpStream, HttpConnectResult)> {
    let mut stream = TcpStream::connect((proxy_addr, proxy_port)).await?;
    let mut auth_header: Option<String> = None;
    let mut nc_count = 1;

    // First attempt
    if let (Some(u), Some(p)) = (login, password) {
        // Pre-emptively send Basic auth if configured
        auth_header = Some(basic_auth_header(u, p));
    }

    let dest_str = dest_addr.to_string();
    let req = build_connect_request(&dest_str, client_addr, auth_header.as_deref(), disclose_src);
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let (status_code, headers, raw_header_bytes) = read_http_response(&mut stream).await?;

    if (200..=299).contains(&status_code) {
        return Ok((stream, HttpConnectResult::Success));
    }

    if let (407, Some(u), Some(p)) = (status_code, login, password) {
        // Check Proxy-Authenticate header
        let mut digest_challenge = None;
        let mut has_basic = false;

        for (k, v) in &headers {
            if k.eq_ignore_ascii_case("proxy-authenticate") {
                if v.to_ascii_lowercase().starts_with("digest") {
                    digest_challenge = DigestChallenge::parse(v);
                } else if v.to_ascii_lowercase().starts_with("basic") {
                    has_basic = true;
                }
            }
        }

        let new_auth_header = if let Some(challenge) = digest_challenge {
            nc_count += 1;
            Some(challenge.response_header(u, p, "CONNECT", &dest_str, nc_count))
        } else if has_basic {
            Some(basic_auth_header(u, p))
        } else {
            None
        };

        if let Some(auth) = new_auth_header {
            // Reconnect and retry with negotiated challenge
            drop(stream);
            let mut stream = TcpStream::connect((proxy_addr, proxy_port)).await?;
            let req = build_connect_request(&dest_str, client_addr, Some(&auth), disclose_src);
            stream.write_all(req.as_bytes()).await?;
            stream.flush().await?;

            let (status_code2, _headers2, raw_header_bytes2) =
                read_http_response(&mut stream).await?;
            if (200..=299).contains(&status_code2) {
                return Ok((stream, HttpConnectResult::Success));
            }

            if on_proxy_fail == OnProxyFail::ForwardHttpErr {
                return Ok((stream, HttpConnectResult::ForwardError(raw_header_bytes2)));
            }

            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("HTTP Proxy auth failed with status {}", status_code2),
            ));
        }
    }

    if on_proxy_fail == OnProxyFail::ForwardHttpErr {
        return Ok((stream, HttpConnectResult::ForwardError(raw_header_bytes)));
    }

    Err(io::Error::new(
        io::ErrorKind::ConnectionRefused,
        format!("HTTP Proxy rejected CONNECT with status {}", status_code),
    ))
}

fn build_connect_request(
    dest: &str,
    client_addr: SocketAddr,
    auth_header: Option<&str>,
    disclose_src: DiscloseSrc,
) -> String {
    let mut req = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", dest, dest);

    if let Some(auth) = auth_header {
        req.push_str(&format!("Proxy-Authorization: {}\r\n", auth));
    }

    match disclose_src {
        DiscloseSrc::None => {}
        DiscloseSrc::XForwardedFor => {
            req.push_str(&format!("X-Forwarded-For: {}\r\n", client_addr.ip()));
        }
        DiscloseSrc::ForwardedIp => {
            req.push_str(&format!("Forwarded: for={}\r\n", client_addr.ip()));
        }
        DiscloseSrc::ForwardedIpPort => {
            req.push_str(&format!(
                "Forwarded: for=\"{}:{}\"\r\n",
                client_addr.ip(),
                client_addr.port()
            ));
        }
    }

    req.push_str("\r\n");
    req
}

async fn read_http_response(
    stream: &mut TcpStream,
) -> io::Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];

    // Read until \r\n\r\n
    loop {
        stream.read_exact(&mut byte).await?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") || buf.ends_with(b"\n\n") {
            break;
        }
        if buf.len() > 16384 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP headers too large",
            ));
        }
    }

    let header_str = String::from_utf8_lossy(&buf);
    let mut lines = header_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");

    // HTTP/1.1 200 OK
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let status_code: u16 = parts
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid HTTP status line: '{}'", status_line),
            )
        })?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    Ok((status_code, headers, buf))
}
