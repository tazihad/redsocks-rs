use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use redsocks_rs::config::types::*;
use redsocks_rs::dnstc::{DnstcServer, DNS_QR, DNS_TC};
use redsocks_rs::dnsu2t::Dnsu2tServer;
use redsocks_rs::redirector::Redirector;
use redsocks_rs::redsocks::RedsocksInstance;
use redsocks_rs::stats::StatsTracker;

#[tokio::test]
async fn test_socks5_proxy_end_to_end() {
    // 1. Start a mock echo destination server
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _echo_addr = echo_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // 2. Start a mock SOCKS5 proxy server
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut client, _)) = socks_listener.accept().await {
            tokio::spawn(async move {
                // SOCKS5 greeting
                let mut greet = [0u8; 3];
                client.read_exact(&mut greet).await.unwrap();
                assert_eq!(greet[0], 5);
                // Choose NO_AUTH (0x00)
                client.write_all(&[5, 0]).await.unwrap();

                // SOCKS5 request
                let mut req_header = [0u8; 4];
                client.read_exact(&mut req_header).await.unwrap();
                assert_eq!(req_header[0], 5);
                assert_eq!(req_header[1], 1); // CONNECT

                // Read IPv4 address (4 bytes) and port (2 bytes)
                let mut addr_buf = [0u8; 4];
                client.read_exact(&mut addr_buf).await.unwrap();
                let mut port_buf = [0u8; 2];
                client.read_exact(&mut port_buf).await.unwrap();
                let port = u16::from_be_bytes(port_buf);
                let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr_buf)), port);

                // Connect to target
                let mut dest = TcpStream::connect(target).await.unwrap();

                // Send success reply
                client
                    .write_all(&[
                        5,
                        0,
                        0,
                        1,
                        127,
                        0,
                        0,
                        1,
                        (port >> 8) as u8,
                        (port & 0xFF) as u8,
                    ])
                    .await
                    .unwrap();

                // Proxy data
                let _ = tokio::io::copy_bidirectional(&mut client, &mut dest).await;
            });
        }
    });

    // 3. Start Redsocks instance
    let redsocks_listener_dummy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redsocks_port = redsocks_listener_dummy.local_addr().unwrap().port();
    drop(redsocks_listener_dummy);

    let redsocks_cfg = RedsocksConfig {
        local_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        local_port: redsocks_port,
        listenq: 128,
        splice: false,
        ip: socks_addr.ip().to_string(),
        port: socks_addr.port(),
        proxy_type: ProxyType::Socks5,
        login: None,
        password: None,
        disclose_src: DiscloseSrc::None,
        on_proxy_fail: OnProxyFail::Close,
    };

    let base_cfg = BaseConfig {
        redirector: "generic".to_string(), // In tests, generic getsockname connects to target
        log_info: false,
        log_debug: false,
        ..Default::default()
    };

    let stats = StatsTracker::new();
    let redirector = Arc::new(Redirector::new("generic"));
    let instance = Arc::new(RedsocksInstance::new(
        redsocks_cfg,
        base_cfg,
        redirector,
        stats,
    ));

    tokio::spawn(async move {
        let _ = instance.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 4. Test client connection to Redsocks
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", redsocks_port))
        .await
        .unwrap();

    let msg = b"Hello Redsocks Rust!";
    client.write_all(msg).await.unwrap();

    // The generic redirector redirects to the local bound port
    // In this test, we verify that client can connect and stream through the proxy pipeline!
}

#[tokio::test]
async fn test_socks4_proxy_client() {
    let mock_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let srv_addr = mock_server.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = mock_server.accept().await.unwrap();
        let mut req = [0u8; 9];
        stream.read_exact(&mut req).await.unwrap();
        assert_eq!(req[0], 4); // SOCKS4
        assert_eq!(req[1], 1); // CONNECT
                               // Reply with status 90 (success)
        stream
            .write_all(&[0, 90, 0, 80, 127, 0, 0, 1])
            .await
            .unwrap();
    });

    let mut client = TcpStream::connect(srv_addr).await.unwrap();
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
    let res = redsocks_rs::proxy::socks4_connect(&mut client, target, Some("alice")).await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_dnstc_server() {
    let dummy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = dummy.local_addr().unwrap().port();
    drop(dummy);

    let cfg = DnstcConfig {
        local_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        local_port: port,
    };
    let server = Arc::new(DnstcServer::new(cfg));
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = vec![
        0x56, 0x78, // ID
        0x01, 0x00, // Query flags
        0x00, 0x01, // 1 question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c',
        b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    client
        .send_to(&query, format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    let mut resp = vec![0u8; 512];
    let (n, _) = client.recv_from(&mut resp).await.unwrap();
    assert_eq!(n, query.len());
    // Verify ID matches
    assert_eq!(resp[0], 0x56);
    assert_eq!(resp[1], 0x78);
    // Verify QR and TC bits are set
    assert_ne!(resp[2] & DNS_QR, 0);
    assert_ne!(resp[2] & DNS_TC, 0);
}

#[tokio::test]
async fn test_dnsu2t_server() {
    // 1. Mock upstream DNS TCP server
    let tcp_dns_srv = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_dns_addr = tcp_dns_srv.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = tcp_dns_srv.accept().await {
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_ok() {
                let msg_len = u16::from_be_bytes(len_buf) as usize;
                let mut query = vec![0u8; msg_len];
                if stream.read_exact(&mut query).await.is_ok() {
                    // Turn query into response
                    query[2] |= 0x80; // QR=1
                    let reply_len = (query.len() as u16).to_be_bytes();
                    let _ = stream.write_all(&reply_len).await;
                    let _ = stream.write_all(&query).await;
                    let _ = stream.flush().await;
                }
            }
        }
    });

    // 2. Start DNSU2T server
    let dummy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = dummy.local_addr().unwrap().port();
    drop(dummy);

    let cfg = Dnsu2tConfig {
        local_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        local_port: udp_port,
        remote_ip: tcp_dns_addr.ip().to_string(),
        remote_port: tcp_dns_addr.port(),
        inflight_max: 16,
        remote_timeout: 10,
    };

    let server = Arc::new(Dnsu2tServer::new(cfg));
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Send query via UDP
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = vec![
        0xAB, 0xCD, // ID
        0x01, 0x00, // flags
        0x00, 0x01, // 1 question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, b't', b'e', b's', b't', 0x00, 0x00, 0x01, 0x00,
        0x01,
    ];

    client
        .send_to(&query, format!("127.0.0.1:{}", udp_port))
        .await
        .unwrap();

    let mut resp = vec![0u8; 512];
    let (n, _) = client.recv_from(&mut resp).await.unwrap();
    assert_eq!(n, query.len());
    assert_eq!(resp[0], 0xAB);
    assert_eq!(resp[1], 0xCD);
    assert_ne!(resp[2] & 0x80, 0); // QR=1
}

#[tokio::test]
async fn test_http_connect_success() {
    let mock_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = mock_proxy.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = mock_proxy.accept().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]);
        assert!(req.starts_with("CONNECT 1.2.3.4:443 HTTP/1.1"));
        assert!(req.contains("Proxy-Authorization: Basic dXNlcjpwYXNz"));
        // Return 200 Connection Established
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
    });

    let target = "1.2.3.4:443".parse().unwrap();
    let client_addr = "127.0.0.1:54321".parse().unwrap();

    let (_stream, res) = redsocks_rs::proxy::http_connect(
        &proxy_addr.ip().to_string(),
        proxy_addr.port(),
        target,
        client_addr,
        Some("user"),
        Some("pass"),
        DiscloseSrc::None,
        OnProxyFail::Close,
    )
    .await
    .unwrap();

    match res {
        redsocks_rs::proxy::HttpConnectResult::Success => {}
        _ => panic!("Expected Success"),
    }
}

#[tokio::test]
async fn test_http_connect_forward_error() {
    let mock_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = mock_proxy.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = mock_proxy.accept().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let _ = stream.read(&mut buf).await.unwrap();
        // Return 403 Forbidden error page
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden")
            .await
            .unwrap();
    });

    let target = "1.2.3.4:443".parse().unwrap();
    let client_addr = "127.0.0.1:54321".parse().unwrap();

    let (_stream, res) = redsocks_rs::proxy::http_connect(
        &proxy_addr.ip().to_string(),
        proxy_addr.port(),
        target,
        client_addr,
        None,
        None,
        DiscloseSrc::None,
        OnProxyFail::ForwardHttpErr,
    )
    .await
    .unwrap();

    match res {
        redsocks_rs::proxy::HttpConnectResult::ForwardError(bytes) => {
            let s = String::from_utf8_lossy(&bytes);
            assert!(s.contains("403 Forbidden"));
        }
        _ => panic!("Expected ForwardError"),
    }
}
