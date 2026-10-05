# redsocks-rs

A complete, high-performance, modern reimplementation of [darkk/redsocks](https://github.com/darkk/redsocks) in Rust.

**redsocks-rs** transparently redirects any TCP connection or UDP packet to a **SOCKS4**, **SOCKS5**, or **HTTPS (HTTP CONNECT)** proxy using Linux firewall redirect rules (`iptables` or `nftables`). Redirection can be applied system-wide, per network interface, per user (`--uid-owner`), or per group (`--gid-owner`).

---

## Features

- **Full Protocol Compatibility with Upstream redsocks**:
  - **SOCKS4**: Transparent TCP redirection with username/ident support.
  - **SOCKS5**: Full RFC 1928 / RFC 1929 support (No-Auth, Username/Password auth, IPv4, IPv6, Domain destinations).
  - **HTTP CONNECT**: Tunnel TCP traffic over HTTPS/HTTP proxies, supporting `Basic` and `Digest` (RFC 2617 MD5) challenge-response authentication, custom client IP disclosure headers (`X-Forwarded-For`, `Forwarded`), and HTTP error forwarding (`on_proxy_fail = forward_http_err`).
  - **HTTP Relay**: Transparent plain HTTP proxying and request-line URL rewriting.
- **UDP Transparent Proxying (`redudp`)**:
  - Relays UDP packets through upstream SOCKS5 proxies using `UDP ASSOCIATE`.
  - Supports both **REDIRECT** (fixed destination) and **TPROXY** (dynamic destination discovery via `IP_RECVORIGDSTADDR` and `IP_TRANSPARENT`).
  - Automatic session tracking, packet queuing while negotiating proxy association, and idle timeouts.
- **DNS Handling Modules**:
  - **`dnstc` (DNS TCP Enforcer)**: Fake DNS responder that answers all UDP queries with the TrunCation (`TC=1`) bit set, forcing RFC-compliant resolvers (bind9, dig, systemd-resolved) to retry over TCP, which then gets transparently redirected through redsocks.
  - **`dnsu2t` (DNS UDP-to-TCP Multiplexing Relay)**: Multiplexes multiple UDP DNS requests into a single persistent TCP connection with standard 2-byte RFC 1035 length prefixes.
- **High Performance & Safety**:
  - Built with Rust and Tokio async multi-threaded event loop.
  - Zero-copy data pumping with Linux `splice(2)` optimization.
  - Safe memory management without buffer overflows or leaks.
  - TCP Keepalive tuning (`TCP_KEEPIDLE`, `TCP_KEEPINTVL`, `TCP_KEEPCNT`).
  - Connection throttling and backoff (`redsocks_conn_max`, `connpres_idle_timeout`).
- **Daemon & Process Management**:
  - Native daemon mode (`daemon = on`).
  - Dropping privileges to unprivileged users/groups (`user = ...`, `group = ...`).
  - `chroot` isolation.
  - `rlimit_nofile` resource configuration.
  - PID file support (`-p <pidfile>`).
  - Live client inspection on **`SIGUSR1`** (dumps active client lists, timestamps, and transfer bytes).
  - Graceful shutdown on **`SIGTERM`** and **`SIGINT`**.

---

## Installation & Building

### Prerequisites

- Rust toolchain (1.75+ or newer, with cargo)
- Linux (for netfilter `SO_ORIGINAL_DST`, `IP_TRANSPARENT`, and `splice`)

### Build Release Binary

```bash
cargo build --release
```

The optimized binary will be created at:
```bash
./target/release/redsocks-rs
```

To install to system path:
```bash
sudo cp target/release/redsocks-rs /usr/local/bin/redsocks
```

---

## Usage

```
redsocks [OPTIONS]

Options:
  -c <CONFIG>       Path to config file [default: redsocks.conf]
  -t                Test config syntax and exit
  -p <PIDFILE>      Write PID to specified file
  -h, --help        Print help
  -V, --version     Print version
```

### Testing Configuration Syntax

```bash
redsocks -c /etc/redsocks.conf -t
```

---

## Configuration Reference

The configuration file uses the classic C-style syntax compatible with darkk/redsocks:

```c
base {
    log_debug = off;              // Detailed debugging
    log_info = on;                // Connection events
    log = stderr;                 // stderr | "file:/path/to/log" | "syslog:daemon"
    daemon = off;                 // Fork into background
    redirector = iptables;        // iptables | generic

    // Privilege dropping
    // user = nobody;
    // group = nogroup;
    // chroot = "/var/chroot";

    // Resource limits
    // rlimit_nofile = 65536;
    // redsocks_conn_max = 4096;
    // connpres_idle_timeout = 7440;
}

redsocks {
    local_ip = 127.0.0.1;
    local_port = 12345;
    listenq = 128;
    splice = true;

    ip = 127.0.0.1;
    port = 1080;
    type = socks5;                // socks4 | socks5 | http-connect | http-relay

    // Optional authentication
    // login = "username";
    // password = "password";

    // Optional HTTP disclosure and error handling
    // disclose_src = false;     // false | X-Forwarded-For | Forwarded_ip | Forwarded_ipport
    // on_proxy_fail = close;    // close | forward_http_err
}

redudp {
    local_ip = 127.0.0.1;
    local_port = 10053;
    ip = 127.0.0.1;
    port = 1080;

    // Fixed destination (REDIRECT mode) or omit for TPROXY dynamic destination
    dest_ip = 8.8.8.8;
    dest_port = 53;

    udp_timeout = 30;
    udp_timeout_stream = 180;
}

dnstc {
    local_ip = 127.0.0.1;
    local_port = 5300;
}

dnsu2t {
    local_ip = 127.0.0.1;
    local_port = 5313;
    remote_ip = 8.8.8.8;
    remote_port = 53;
    inflight_max = 16;
}
```

---

## Firewall Setup Guides

### 1. Linux `iptables` Setup

#### Redirect all outgoing TCP traffic:

```bash
# Create custom chain
sudo iptables -t nat -N REDSOCKS

# Bypass local, private, and reserved subnets
sudo iptables -t nat -A REDSOCKS -d 0.0.0.0/8 -j RETURN
sudo iptables -t nat -A REDSOCKS -d 10.0.0.0/8 -j RETURN
sudo iptables -t nat -A REDSOCKS -d 100.64.0.0/10 -j RETURN
sudo iptables -t nat -A REDSOCKS -d 127.0.0.0/8 -j RETURN
sudo iptables -t nat -A REDSOCKS -d 169.254.0.0/16 -j RETURN
sudo iptables -t nat -A REDSOCKS -d 172.16.0.0/12 -j RETURN
sudo iptables -t nat -A REDSOCKS -d 192.168.0.0/16 -j RETURN
sudo iptables -t nat -A REDSOCKS -d 198.18.0.0/15 -j RETURN
sudo iptables -t nat -A REDSOCKS -d 224.0.0.0/4 -j RETURN
sudo iptables -t nat -A REDSOCKS -d 240.0.0.0/4 -j RETURN

# Redirect remaining TCP traffic to redsocks listening port
sudo iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports 12345

# Redirect traffic from a specific local group (e.g., "socksified"):
sudo groupadd -f socksified
sudo iptables -t nat -A OUTPUT -p tcp -m owner --gid-owner socksified -j REDSOCKS
```

Run any program under transparent proxying:
```bash
sg socksified -c "curl https://ifconfig.me"
```

#### Redirect router traffic from LAN interface (`eth0`):
```bash
sudo iptables -t nat -A PREROUTING --in-interface eth0 -p tcp -j REDSOCKS
```

---

### 2. Linux `nftables` Setup

```nft
table ip nat {
    chain redsocks_chain {
        ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4 } return
        meta skgid "socksified" tcp dport != 1080 redirect to :12345
    }

    chain output {
        type nat hook output priority filter; policy accept;
        jump redsocks_chain
    }
}
```

---

## Live Monitoring (SIGUSR1)

Send `SIGUSR1` to the redsocks process to inspect all active connections, their addresses, idle times, and traffic volume:

```bash
kill -USR1 $(cat /var/run/redsocks.pid)
```

Log output:
```
[INFO] === [SIGUSR1] Dumping active client list (2 clients) ===
[INFO] Client #0 [Socks5]: 192.168.1.10:48212 -> 93.184.216.34:443, age: 14.20s, idle: 0.12s, up: 1820 bytes, down: 45012 bytes
[INFO] Client #1 [HttpConnect]: 192.168.1.15:52110 -> 142.250.180.206:443, age: 3.45s, idle: 1.05s, up: 512 bytes, down: 2048 bytes
[INFO] === End of client list ===
```

---

## License

Licensed under the Apache License, Version 2.0.
