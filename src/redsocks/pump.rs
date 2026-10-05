use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::stats::StatsTracker;

pub async fn run_duplex_pump(
    mut client_stream: TcpStream,
    mut proxy_stream: TcpStream,
    stats: Arc<StatsTracker>,
    client_id: usize,
    idle_timeout: Option<Duration>,
) -> io::Result<()> {
    let (mut client_r, mut client_w) = client_stream.split();
    let (mut proxy_r, mut proxy_w) = proxy_stream.split();

    let stats_up = stats.clone();
    let stats_down = stats.clone();

    let client_to_proxy = async move {
        let mut buf = vec![0u8; 16384];
        let mut total = 0u64;

        loop {
            let read_future = client_r.read(&mut buf);
            let n = if let Some(timeout) = idle_timeout {
                match tokio::time::timeout(timeout, read_future).await {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "Idle timeout expired",
                        ));
                    }
                }
            } else {
                read_future.await?
            };

            if n == 0 {
                proxy_w.shutdown().await?;
                break;
            }

            proxy_w.write_all(&buf[..n]).await?;
            proxy_w.flush().await?;
            total += n as u64;
            stats_up.update_activity(client_id, n as u64, 0);
        }

        Ok::<u64, io::Error>(total)
    };

    let proxy_to_client = async move {
        let mut buf = vec![0u8; 16384];
        let mut total = 0u64;

        loop {
            let read_future = proxy_r.read(&mut buf);
            let n = if let Some(timeout) = idle_timeout {
                match tokio::time::timeout(timeout, read_future).await {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "Idle timeout expired",
                        ));
                    }
                }
            } else {
                read_future.await?
            };

            if n == 0 {
                client_w.shutdown().await?;
                break;
            }

            client_w.write_all(&buf[..n]).await?;
            client_w.flush().await?;
            total += n as u64;
            stats_down.update_activity(client_id, 0, n as u64);
        }

        Ok::<u64, io::Error>(total)
    };

    tokio::select! {
        res1 = client_to_proxy => res1?,
        res2 = proxy_to_client => res2?,
    };

    Ok(())
}
