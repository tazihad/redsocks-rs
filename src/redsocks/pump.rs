use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::stats::StatsTracker;

#[cfg(target_os = "linux")]
use std::os::unix::io::{AsRawFd, RawFd};

pub async fn run_pump(
    client_stream: TcpStream,
    proxy_stream: TcpStream,
    stats: Arc<StatsTracker>,
    client_id: usize,
    idle_timeout: Option<Duration>,
    use_splice: bool,
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    if use_splice {
        match run_splice_pump(&client_stream, &proxy_stream, stats.clone(), client_id, idle_timeout).await {
            Ok(()) => return Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) || e.raw_os_error() == Some(libc::ENOSYS) => {
                log::debug!("Splice not supported on this fd/kernel, falling back to duplex pump");
            }
            Err(e) => return Err(e),
        }
    }

    // Default or fallback
    let _ = use_splice;
    run_duplex_pump(client_stream, proxy_stream, stats, client_id, idle_timeout).await
}

#[cfg(target_os = "linux")]
struct Pipe {
    read_fd: RawFd,
    write_fd: RawFd,
}

#[cfg(target_os = "linux")]
impl Pipe {
    fn new() -> io::Result<Self> {
        let mut fds = [0; 2];
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        // Try increasing pipe capacity to 64KB
        unsafe {
            libc::fcntl(fds[0], libc::F_SETPIPE_SZ, 65536);
        }
        Ok(Self {
            read_fd: fds[0],
            write_fd: fds[1],
        })
    }
}

#[cfg(target_os = "linux")]
impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.read_fd);
            libc::close(self.write_fd);
        }
    }
}

#[cfg(target_os = "linux")]
pub async fn run_splice_pump(
    client_stream: &TcpStream,
    proxy_stream: &TcpStream,
    stats: Arc<StatsTracker>,
    client_id: usize,
    idle_timeout: Option<Duration>,
) -> io::Result<()> {
    let pipe_cp = Pipe::new()?;
    let pipe_pc = Pipe::new()?;

    let stats_up = stats.clone();
    let stats_down = stats.clone();

    let client_to_proxy = async {
        let mut pipe_bytes = 0usize;
        loop {
            if pipe_bytes < 65536 {
                let readable_future = client_stream.readable();
                if let Some(timeout) = idle_timeout {
                    tokio::time::timeout(timeout, readable_future).await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Idle timeout"))??;
                } else {
                    readable_future.await?;
                }

                let res = client_stream.try_io(tokio::io::Interest::READABLE, || {
                    let ret = unsafe {
                        libc::splice(
                            client_stream.as_raw_fd(),
                            std::ptr::null_mut(),
                            pipe_cp.write_fd,
                            std::ptr::null_mut(),
                            65536 - pipe_bytes,
                            libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE,
                        )
                    };
                    if ret < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(ret)
                    }
                });

                match res {
                    Ok(n) if n > 0 => {
                        pipe_bytes += n as usize;
                        stats_up.update_activity(client_id, n as u64, 0);
                    }
                    Ok(0) => {
                        // EOF from client, drain pipe to proxy
                        while pipe_bytes > 0 {
                            proxy_stream.writable().await?;
                            let written = proxy_stream.try_io(tokio::io::Interest::WRITABLE, || {
                                let ret = unsafe {
                                    libc::splice(
                                        pipe_cp.read_fd,
                                        std::ptr::null_mut(),
                                        proxy_stream.as_raw_fd(),
                                        std::ptr::null_mut(),
                                        pipe_bytes,
                                        libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE,
                                    )
                                };
                                if ret < 0 {
                                    Err(io::Error::last_os_error())
                                } else {
                                    Ok(ret)
                                }
                            });
                            if let Ok(w) = written {
                                pipe_bytes -= w as usize;
                            }
                        }
                        unsafe {
                            libc::shutdown(proxy_stream.as_raw_fd(), libc::SHUT_WR);
                        }
                        break;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                    _ => {}
                }
            }

            if pipe_bytes > 0 {
                proxy_stream.writable().await?;
                let written = proxy_stream.try_io(tokio::io::Interest::WRITABLE, || {
                    let ret = unsafe {
                        libc::splice(
                            pipe_cp.read_fd,
                            std::ptr::null_mut(),
                            proxy_stream.as_raw_fd(),
                            std::ptr::null_mut(),
                            pipe_bytes,
                            libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE,
                        )
                    };
                    if ret < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(ret)
                    }
                });
                if let Ok(w) = written {
                    pipe_bytes -= w as usize;
                }
            }
        }
        Ok::<(), io::Error>(())
    };

    let proxy_to_client = async {
        let mut pipe_bytes = 0usize;
        loop {
            if pipe_bytes < 65536 {
                let readable_future = proxy_stream.readable();
                if let Some(timeout) = idle_timeout {
                    tokio::time::timeout(timeout, readable_future).await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Idle timeout"))??;
                } else {
                    readable_future.await?;
                }

                let res = proxy_stream.try_io(tokio::io::Interest::READABLE, || {
                    let ret = unsafe {
                        libc::splice(
                            proxy_stream.as_raw_fd(),
                            std::ptr::null_mut(),
                            pipe_pc.write_fd,
                            std::ptr::null_mut(),
                            65536 - pipe_bytes,
                            libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE,
                        )
                    };
                    if ret < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(ret)
                    }
                });

                match res {
                    Ok(n) if n > 0 => {
                        pipe_bytes += n as usize;
                        stats_down.update_activity(client_id, 0, n as u64);
                    }
                    Ok(0) => {
                        while pipe_bytes > 0 {
                            client_stream.writable().await?;
                            let written = client_stream.try_io(tokio::io::Interest::WRITABLE, || {
                                let ret = unsafe {
                                    libc::splice(
                                        pipe_pc.read_fd,
                                        std::ptr::null_mut(),
                                        client_stream.as_raw_fd(),
                                        std::ptr::null_mut(),
                                        pipe_bytes,
                                        libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE,
                                    )
                                };
                                if ret < 0 {
                                    Err(io::Error::last_os_error())
                                } else {
                                    Ok(ret)
                                }
                            });
                            if let Ok(w) = written {
                                pipe_bytes -= w as usize;
                            }
                        }
                        unsafe {
                            libc::shutdown(client_stream.as_raw_fd(), libc::SHUT_WR);
                        }
                        break;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                    _ => {}
                }
            }

            if pipe_bytes > 0 {
                client_stream.writable().await?;
                let written = client_stream.try_io(tokio::io::Interest::WRITABLE, || {
                    let ret = unsafe {
                        libc::splice(
                            pipe_pc.read_fd,
                            std::ptr::null_mut(),
                            client_stream.as_raw_fd(),
                            std::ptr::null_mut(),
                            pipe_bytes,
                            libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE,
                        )
                    };
                    if ret < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(ret)
                    }
                });
                if let Ok(w) = written {
                    pipe_bytes -= w as usize;
                }
            }
        }
        Ok::<(), io::Error>(())
    };

    tokio::select! {
        res1 = client_to_proxy => res1?,
        res2 = proxy_to_client => res2?,
    };

    Ok(())
}

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
