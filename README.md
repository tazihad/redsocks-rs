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

## Prerequisites

### 1. System Requirements & Kernel Modules
- **Linux Kernel**: 3.2+ (tested up to 6.x) with Netfilter support:
  - `iptable_nat` / `nf_nat` (for TCP `REDIRECT` and `SO_ORIGINAL_DST`)
  - `xt_TPROXY` and `nf_defrag_ipv4` (optional, for UDP `redudp` dynamic TPROXY mode)
  - `xt_owner` (for user/group-based redirection `--uid-owner` / `--gid-owner`)
  - Linux `splice(2)` support (standard on modern Linux kernels)

### 2. Package Dependencies
Install `iptables`, `iproute2`, and `curl` on your system:

- **Debian / Ubuntu / Raspberry Pi OS**:
  ```bash
  sudo apt update && sudo apt install -y iptables iproute2 curl
  ```
- **Arch Linux / Manjaro**:
  ```bash
  sudo pacman -Sy iptables iproute2 curl
  ```
- **Fedora / RHEL / Rocky / AlmaLinux**:
  ```bash
  sudo dnf install -y iptables iproute curl
  ```
- **Alpine Linux**:
  ```bash
  apk add iptables iproute2 curl
  ```

*(If compiling from source, a Rust toolchain `1.75+` is also required: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)*

---

## Installation & File Placement

### File Hierarchy Standard (Where to Put Files)

When installing `redsocks-rs` onto a Linux system, place the files in standard locations as follows:

| Source File | Destination Path | Permissions | Purpose |
| :--- | :--- | :--- | :--- |
| **`redsocks`** (executable) | `/usr/local/bin/redsocks` | `0755` (`rwxr-xr-x`, root:root) | Main compiled redirector daemon |
| **`redsocks-rs`** (symlink) | `/usr/local/bin/redsocks-rs` | `0777` (symlink) | Optional convenience alias pointing to `redsocks` |
| **`redsocks.conf.example`** | `/etc/redsocks.conf` | `0644` (`rw-r--r--`, root:root) | Primary service configuration file |
| **`redsocks.service`** | `/etc/systemd/system/redsocks.service` | `0644` (`rw-r--r--`, root:root) | Systemd unit file for daemon supervision |

---

### Option A: Install Pre-Built Binary (Recommended)

Download and extract the latest pre-compiled release from GitHub:

```bash
# 1. Download and extract the latest release tarball
VERSION="0.1.0"
curl -fsSL -O "https://github.com/tazihad/redsocks-rs/releases/download/v${VERSION}/redsocks-rs-v${VERSION}-linux-x86_64.tar.gz"
tar -xzf "redsocks-rs-v${VERSION}-linux-x86_64.tar.gz"
cd "redsocks-rs-v${VERSION}-linux-x86_64"

# 2. Install executable binary & symlink
sudo install -m 0755 redsocks /usr/local/bin/redsocks
sudo ln -sf /usr/local/bin/redsocks /usr/local/bin/redsocks-rs

# 3. Install configuration file
sudo install -m 0644 redsocks.conf.example /etc/redsocks.conf

# 4. Install systemd service
sudo install -m 0644 redsocks.service /etc/systemd/system/redsocks.service
```

---

### Option B: Build & Install from Source

```bash
# 1. Clone repository
git clone https://github.com/tazihad/redsocks-rs.git
cd redsocks-rs

# 2. Compile optimized release binary
cargo build --release

# 3. Install executable binary & symlink
sudo install -m 0755 target/release/redsocks /usr/local/bin/redsocks
sudo ln -sf /usr/local/bin/redsocks /usr/local/bin/redsocks-rs

# 4. Install configuration file
sudo install -m 0644 redsocks.conf.example /etc/redsocks.conf

# 5. Install systemd service
sudo install -m 0644 redsocks.service /etc/systemd/system/redsocks.service
```

---

### Managing the Service (Systemd)

After placing the files, configure and start the daemon with systemd:

```bash
# 1. Edit configuration with your proxy server details (IP, port, type, etc.)
sudo nano /etc/redsocks.conf

# 2. Test configuration syntax
redsocks -c /etc/redsocks.conf -t

# 3. Reload systemd daemon to pick up the new unit file
sudo systemctl daemon-reload

# 4. Enable service to start on system boot and start it now
sudo systemctl enable --now redsocks

# 5. Check service status
sudo systemctl status redsocks

# 6. View live logs
journalctl -u redsocks -f
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

### Understanding How `redsocks` and `iptables` Work Together

1. **Interception**: An application makes an outbound TCP connection to a remote IP and port.
2. **Redirection**: Linux `iptables` intercepts the `SYN` packet in the `OUTPUT` chain (or `PREROUTING` on a router) and executes `REDIRECT --to-ports 12345`.
3. **Destination Recovery**: `redsocks` accepts the redirected connection on `127.0.0.1:12345` and calls the Linux kernel socket option `getsockopt(..., SO_ORIGINAL_DST, ...)` to find the real destination address the application intended to reach.
4. **Proxy Handshake & Relay**: `redsocks` connects to the upstream proxy (SOCKS5/HTTP) and instructs it to connect to the original destination, then relays data between the client and proxy using zero-copy `splice(2)`.

> [!IMPORTANT]
> **CRITICAL: Preventing Infinite Redirection Loops**
> When `redsocks` connects to the upstream proxy, its own connection is also outbound TCP! If `iptables` redirects `redsocks`'s connection back into `redsocks`, an infinite loop occurs and crashes the network.
>
> You **must** bypass proxy traffic using either of these two methods:
> 1. **Bypass Proxy IP**: Add `-d <PROXY_IP> -j RETURN` to your rules.
> 2. **Bypass by User/Group**: Run `redsocks` under a dedicated user (e.g. `redsocks` or `nobody`) and add `-m owner --uid-owner redsocks -j RETURN` to `OUTPUT`.

---

### 1. Linux `iptables` Setup

#### Scenario A: Per-Group Transparent Proxying (Recommended for Desktops)
Only applications run within a specific group (e.g., `socksified`) are redirected through the proxy. All other system applications connect normally.

```bash
# 1. Create a dedicated group for socksified applications
sudo groupadd -f socksified
sudo usermod -aG socksified "$USER"   # log out and back in for group change to take effect

# 2. Create custom REDSOCKS iptables chain
sudo iptables -t nat -N REDSOCKS

# 3. Bypass reserved, private, and local subnets
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

# 4. (Loop prevention) Bypass upstream proxy server IP (replace with your proxy IP)
# sudo iptables -t nat -A REDSOCKS -d <YOUR_PROXY_SERVER_IP> -j RETURN

# 5. Redirect remaining TCP packets to redsocks local port
sudo iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports 12345

# 6. Apply REDSOCKS chain only to traffic owned by the 'socksified' group
sudo iptables -t nat -A OUTPUT -p tcp -m owner --gid-owner socksified -j REDSOCKS
```

**Testing per-group transparent redirection**:
```bash
# Check current public IP directly
curl https://ifconfig.me

# Run curl transparently through redsocks via the proxy
sg socksified -c "curl https://ifconfig.me"
```

---

#### Scenario B: System-Wide Redirection (All Local Machine TCP Traffic)
Redirects all outgoing TCP connections from the local machine through the proxy, while exempting `redsocks` itself to prevent loops.

```bash
# 1. Create REDSOCKS chain
sudo iptables -t nat -N REDSOCKS

# 2. Bypass private & local networks
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

# 3. Bypass upstream proxy server IP
# sudo iptables -t nat -A REDSOCKS -d <YOUR_PROXY_SERVER_IP> -j RETURN

# 4. Redirect TCP to redsocks port
sudo iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports 12345

# 5. Loop prevention: bypass traffic generated by redsocks (run redsocks as 'nobody' or 'redsocks' user)
sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner nobody -j RETURN

# 6. Send all other outbound TCP traffic to REDSOCKS
sudo iptables -t nat -A OUTPUT -p tcp -j REDSOCKS
```

---

#### Scenario C: Router / Gateway Redirection (Transparent LAN Proxy)
If running `redsocks-rs` on a Linux router or gateway machine to transparently proxy client devices connected on a LAN interface (e.g., `eth1` or `br0`):

```bash
# Direct incoming LAN client traffic to REDSOCKS chain
sudo iptables -t nat -A PREROUTING --in-interface eth1 -p tcp -j REDSOCKS
```

---

#### How to Teardown / Reset `iptables` Rules

To revert all `redsocks` iptables rules back to normal:

```bash
# Flush custom REDSOCKS chain and remove references from OUTPUT / PREROUTING
sudo iptables -t nat -D OUTPUT -p tcp -m owner --gid-owner socksified -j REDSOCKS 2>/dev/null || true
sudo iptables -t nat -D OUTPUT -p tcp -m owner --uid-owner nobody -j RETURN 2>/dev/null || true
sudo iptables -t nat -D OUTPUT -p tcp -j REDSOCKS 2>/dev/null || true
sudo iptables -t nat -D PREROUTING --in-interface eth1 -p tcp -j REDSOCKS 2>/dev/null || true
sudo iptables -t nat -F REDSOCKS 2>/dev/null || true
sudo iptables -t nat -X REDSOCKS 2>/dev/null || true
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
