use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyType {
    Socks4,
    #[default]
    Socks5,
    HttpConnect,
    HttpRelay,
}

impl std::str::FromStr for ProxyType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "socks4" => Ok(ProxyType::Socks4),
            "socks5" => Ok(ProxyType::Socks5),
            "http-connect" | "http_connect" => Ok(ProxyType::HttpConnect),
            "http-relay" | "http_relay" => Ok(ProxyType::HttpRelay),
            _ => Err(format!("Unknown proxy type: '{}'", s)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiscloseSrc {
    #[default]
    None,
    XForwardedFor,
    ForwardedIp,
    ForwardedIpPort,
}

impl std::str::FromStr for DiscloseSrc {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "false" | "none" | "off" | "0" => Ok(DiscloseSrc::None),
            "x-forwarded-for" | "x_forwarded_for" => Ok(DiscloseSrc::XForwardedFor),
            "forwarded_ip" | "forwarded-ip" => Ok(DiscloseSrc::ForwardedIp),
            "forwarded_ipport" | "forwarded-ipport" => Ok(DiscloseSrc::ForwardedIpPort),
            _ => Err(format!("Unknown disclose_src option: '{}'", s)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnProxyFail {
    #[default]
    Close,
    ForwardHttpErr,
}

impl std::str::FromStr for OnProxyFail {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "close" => Ok(OnProxyFail::Close),
            "forward_http_err" | "forward-http-err" => Ok(OnProxyFail::ForwardHttpErr),
            _ => Err(format!("Unknown on_proxy_fail option: '{}'", s)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseConfig {
    pub log_debug: bool,
    pub log_info: bool,
    pub log: String,
    pub daemon: bool,
    pub user: Option<String>,
    pub group: Option<String>,
    pub chroot: Option<String>,
    pub redirector: String,
    pub tcp_keepalive_time: u32,
    pub tcp_keepalive_probes: u32,
    pub tcp_keepalive_intvl: u32,
    pub rlimit_nofile: u64,
    pub redsocks_conn_max: u32,
    pub connpres_idle_timeout: u64,
    pub max_accept_backoff: u64,
}

impl Default for BaseConfig {
    fn default() -> Self {
        Self {
            log_debug: false,
            log_info: true,
            log: "stderr".to_string(),
            daemon: false,
            user: None,
            group: None,
            chroot: None,
            redirector: "iptables".to_string(),
            tcp_keepalive_time: 0,
            tcp_keepalive_probes: 0,
            tcp_keepalive_intvl: 0,
            rlimit_nofile: 0,
            redsocks_conn_max: 0,
            connpres_idle_timeout: 7440,
            max_accept_backoff: 60000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedsocksConfig {
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub listenq: u32,
    pub splice: bool,
    pub ip: String,
    pub port: u16,
    pub proxy_type: ProxyType,
    pub login: Option<String>,
    pub password: Option<String>,
    pub disclose_src: DiscloseSrc,
    pub on_proxy_fail: OnProxyFail,
}

impl Default for RedsocksConfig {
    fn default() -> Self {
        Self {
            local_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            local_port: 12345,
            listenq: 128,
            splice: true,
            ip: "127.0.0.1".to_string(),
            port: 1080,
            proxy_type: ProxyType::Socks5,
            login: None,
            password: None,
            disclose_src: DiscloseSrc::None,
            on_proxy_fail: OnProxyFail::Close,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedudpConfig {
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub ip: String,
    pub port: u16,
    pub login: Option<String>,
    pub password: Option<String>,
    pub dest_ip: Option<IpAddr>,
    pub dest_port: Option<u16>,
    pub udp_timeout: u64,
    pub udp_timeout_stream: u64,
    pub max_pktqueue: usize,
}

impl Default for RedudpConfig {
    fn default() -> Self {
        Self {
            local_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            local_port: 10053,
            ip: "127.0.0.1".to_string(),
            port: 1080,
            login: None,
            password: None,
            dest_ip: None,
            dest_port: None,
            udp_timeout: 30,
            udp_timeout_stream: 180,
            max_pktqueue: 5,
        }
    }
}

impl RedudpConfig {
    pub fn is_tproxy(&self) -> bool {
        self.dest_ip.is_none() || self.dest_port.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnstcConfig {
    pub local_ip: IpAddr,
    pub local_port: u16,
}

impl Default for DnstcConfig {
    fn default() -> Self {
        Self {
            local_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            local_port: 5300,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dnsu2tConfig {
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub inflight_max: usize,
    pub remote_timeout: u64,
}

impl Default for Dnsu2tConfig {
    fn default() -> Self {
        Self {
            local_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            local_port: 5313,
            remote_ip: "8.8.8.8".to_string(),
            remote_port: 53,
            inflight_max: 16,
            remote_timeout: 30,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppConfig {
    pub base: BaseConfig,
    pub redsocks: Vec<RedsocksConfig>,
    pub redudp: Vec<RedudpConfig>,
    pub dnstc: Vec<DnstcConfig>,
    pub dnsu2t: Vec<Dnsu2tConfig>,
}
