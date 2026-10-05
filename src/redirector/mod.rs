use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectorType {
    Iptables,
    Generic,
    Pf,
    Ipf,
}

impl std::str::FromStr for RedirectorType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "iptables" => Ok(RedirectorType::Iptables),
            "generic" => Ok(RedirectorType::Generic),
            "pf" => Ok(RedirectorType::Pf),
            "ipf" => Ok(RedirectorType::Ipf),
            _ => Ok(RedirectorType::Generic),
        }
    }
}

pub struct Redirector {
    kind: RedirectorType,
}

impl Redirector {
    pub fn new(name: &str) -> Self {
        let kind = name.parse().unwrap_or(RedirectorType::Generic);
        Self { kind }
    }

    pub fn get_dest_addr(&self, stream: &TcpStream) -> io::Result<SocketAddr> {
        match self.kind {
            RedirectorType::Iptables => {
                #[cfg(target_os = "linux")]
                {
                    get_original_dst_linux(stream)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    stream.local_addr()
                }
            }
            RedirectorType::Generic | RedirectorType::Pf | RedirectorType::Ipf => {
                stream.local_addr()
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn get_original_dst_linux(stream: &TcpStream) -> io::Result<SocketAddr> {
    let fd = stream.as_raw_fd();

    // First try IPv4 SO_ORIGINAL_DST
    unsafe {
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        let ret = libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );

        if ret == 0 {
            let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            return Ok(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)));
        }

        // Next try IPv6 IP6T_SO_ORIGINAL_DST
        let mut addr6: libc::sockaddr_in6 = std::mem::zeroed();
        let mut len6 = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

        const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;
        let ret6 = libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            IP6T_SO_ORIGINAL_DST,
            &mut addr6 as *mut _ as *mut libc::c_void,
            &mut len6,
        );

        if ret6 == 0 {
            let ip = std::net::Ipv6Addr::from(addr6.sin6_addr.s6_addr);
            let port = u16::from_be(addr6.sin6_port);
            return Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip,
                port,
                addr6.sin6_flowinfo,
                addr6.sin6_scope_id,
            )));
        }

        // If getsockopt fails (e.g. running in testing without iptables REDIRECT rules),
        // fallback to getsockname to be robust
        stream.local_addr()
    }
}
