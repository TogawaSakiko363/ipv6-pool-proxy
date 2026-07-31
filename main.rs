use arc_swap::ArcSwap;
use std::env;
use std::fs;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Semaphore;
use tokio::time::timeout;

// musl's default allocator serializes hard under many concurrent threads;
// mimalloc removes that bottleneck. Biggest single win on this ARM/musl build.
#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// --- High-concurrency tunables ---
// Keep per-connection footprint small and apply timeouts everywhere so a slow
// or hung peer can never permanently consume a socket.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const SNI_READ_TIMEOUT: Duration = Duration::from_secs(15);
const UPSTREAM_DNS_TIMEOUT: Duration = Duration::from_secs(5);
const COPY_BUF_SIZE: usize = 16 * 1024;         // fallback path only (non-Linux)
// Concurrency caps are the primary OOM guard: every accepted connection costs
// fds + buffers (splice adds a kernel pipe per direction), so an unbounded
// accept storm on a small box means the kernel OOM-kills us. These are
// defaults; override with --max-conns / --max-dns to fit the host's RAM.
// 32k conns * ~2 splice pipes stays well under a few GB.
const DEFAULT_MAX_CONNS: usize = 32_768;        // in-flight TCP handlers (SOCKS5 + SNI)
const DEFAULT_MAX_DNS: usize = 16_384;          // in-flight UDP DNS workers
const ACCEPT_BACKOFF_MAX_MS: u64 = 1000;
// TLS record payload max is 16384; ClientHello sits in one record.
const MAX_CLIENT_HELLO_LEN: usize = 16 * 1024 + 5;

#[derive(Debug)]
struct Config {
    dns_listens: Vec<SocketAddr>,
    proxy_listens: Vec<SocketAddr>,
    auth: Option<Auth>,
    prefix: Ipv6Prefix,
    ipv4_pass_through: bool,
    // Paths kept so SIGHUP can re-read the files; both are optional because
    // domain rules only apply to dns mode and whitelist is opt-in.
    domain_config_path: Option<PathBuf>,
    whitelist_path: Option<PathBuf>,
    // Admission-control caps; sized to host RAM to bound worst-case memory.
    max_conns: usize,
    max_dns: usize,
    // File-backed state that can change at runtime via SIGHUP. Hot-path code
    // does config.hot.load() once per task; reload is lock-free via ArcSwap.
    hot: ArcSwap<HotConfig>,
}

#[derive(Debug, Default)]
struct HotConfig {
    domain_rules: DomainRules,
    whitelist: Option<IpWhitelist>,
}

impl Config {
    fn allows(&self, ip: IpAddr) -> bool {
        self.hot
            .load()
            .whitelist
            .as_ref()
            .map_or(true, |wl| wl.allows(ip))
    }

    fn matches_domain(&self, domain: &str) -> bool {
        self.hot.load().domain_rules.is_match(domain)
    }

    fn matches_normalized(&self, qname: &str) -> bool {
        self.hot.load().domain_rules.is_normalized_match(qname)
    }
}

#[derive(Clone, Debug, Default)]
struct DomainRules {
    exact: Vec<String>,
    suffix: Vec<String>,
    keyword: Vec<String>,
    tld: Vec<String>,
}

#[derive(Clone, Debug)]
struct Auth {
    username: Vec<u8>,
    password: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct Ipv6Prefix {
    network: u128,
    prefix_len: u8,
}

#[derive(Debug)]
enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl DomainRules {
    fn load(path: PathBuf) -> std::io::Result<Self> {
        let content = fs::read_to_string(&path).map_err(|err| {
            Error::new(
                err.kind(),
                format!("failed to read domain config {}: {err}", path.display()),
            )
        })?;
        Self::parse(&content)
    }

    fn parse(content: &str) -> std::io::Result<Self> {
        let mut rules = Self::default();
        for (index, raw_line) in content.lines().enumerate() {
            let line = raw_line.split_once('#').map_or(raw_line, |(value, _)| value).trim();
            if line.is_empty() {
                continue;
            }

            let (kind, value) = line
                .split_once(':')
                .map_or(("exact", line), |(kind, value)| (kind.trim(), value.trim()));
            let value = normalize_domain_rule(value);
            if value.is_empty() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("empty domain rule at line {}", index + 1),
                ));
            }

            match kind.to_ascii_lowercase().as_str() {
                "exact" => rules.exact.push(value),
                "suffix" => rules.suffix.push(value),
                "keyword" => rules.keyword.push(value),
                "tld" => rules.tld.push(value.trim_start_matches('.').to_string()),
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!("unsupported domain rule type '{kind}' at line {}", index + 1),
                    ));
                }
            }
        }
        Ok(rules)
    }

    fn is_match(&self, domain: &str) -> bool {
        let domain = normalize_domain_rule(domain);
        if domain.is_empty() {
            return false;
        }
        self.is_normalized_match(&domain)
    }

    fn is_normalized_match(&self, domain: &str) -> bool {
        self.exact.iter().any(|rule| domain == rule)
            || self.suffix.iter().any(|rule| domain_matches_suffix(domain, rule))
            || self.keyword.iter().any(|rule| domain.contains(rule))
            || self.tld.iter().any(|rule| domain_matches_suffix(domain, rule))
    }
}

fn domain_matches_suffix(domain: &str, rule: &str) -> bool {
    domain == rule
        || (domain.len() > rule.len()
            && domain.ends_with(rule)
            && domain.as_bytes()[domain.len() - rule.len() - 1] == b'.')
}

fn normalize_domain_rule(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl Ipv6Prefix {
    fn parse(value: &str) -> std::io::Result<Self> {
        let (addr, prefix_len) = value
            .split_once('/')
            .ok_or_else(|| invalid_input("IPv6 prefix must be in CIDR format, e.g. 2001:470:19:226::/64"))?;

        let ip: Ipv6Addr = addr
            .parse()
            .map_err(|_| invalid_input("invalid IPv6 prefix address"))?;
        let prefix_len: u8 = prefix_len
            .parse()
            .map_err(|_| invalid_input("invalid IPv6 prefix length"))?;

        if prefix_len > 128 {
            return Err(invalid_input("IPv6 prefix length must be between 0 and 128"));
        }

        let mask = prefix_mask(prefix_len);
        Ok(Self {
            network: u128::from(ip) & mask,
            prefix_len,
        })
    }

    fn random_addr(self) -> Ipv6Addr {
        let mask = prefix_mask(self.prefix_len);
        let host_mask = !mask;
        let random_host = rand::random::<u128>() & host_mask;
        Ipv6Addr::from(self.network | random_host)
    }
}

fn prefix_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

fn ipv4_prefix_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

// Normalize ::ffff:a.b.c.d back to a.b.c.d so v4 whitelist entries work when
// the listener is dual-stack ([::]:port).
fn normalize_peer_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v => v,
    }
}

#[derive(Clone, Debug, Default)]
struct IpWhitelist {
    // Each entry stores the network already masked, plus its prefix length.
    v4: Vec<(u32, u8)>,
    v6: Vec<(u128, u8)>,
}

impl IpWhitelist {
    fn load(path: PathBuf) -> std::io::Result<Self> {
        let content = fs::read_to_string(&path).map_err(|err| {
            Error::new(
                err.kind(),
                format!("failed to read whitelist {}: {err}", path.display()),
            )
        })?;
        Self::parse(&content)
    }

    fn parse(content: &str) -> std::io::Result<Self> {
        let mut wl = Self::default();
        for (index, raw_line) in content.lines().enumerate() {
            let line = raw_line.split_once('#').map_or(raw_line, |(value, _)| value).trim();
            if line.is_empty() {
                continue;
            }

            let (addr_str, prefix_opt) = match line.split_once('/') {
                Some((a, p)) => (a.trim(), Some(p.trim())),
                None => (line, None),
            };

            let ip: IpAddr = addr_str.parse().map_err(|_| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("invalid IP at whitelist line {}: {}", index + 1, line),
                )
            })?;

            match ip {
                IpAddr::V4(v4) => {
                    let prefix_len = match prefix_opt {
                        Some(p) => p.parse::<u8>().map_err(|_| {
                            Error::new(
                                ErrorKind::InvalidInput,
                                format!("invalid prefix at whitelist line {}: {}", index + 1, line),
                            )
                        })?,
                        None => 32,
                    };
                    if prefix_len > 32 {
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            format!("v4 prefix length must be 0..=32 at whitelist line {}", index + 1),
                        ));
                    }
                    let net = u32::from(v4) & ipv4_prefix_mask(prefix_len);
                    wl.v4.push((net, prefix_len));
                }
                IpAddr::V6(v6) => {
                    let prefix_len = match prefix_opt {
                        Some(p) => p.parse::<u8>().map_err(|_| {
                            Error::new(
                                ErrorKind::InvalidInput,
                                format!("invalid prefix at whitelist line {}: {}", index + 1, line),
                            )
                        })?,
                        None => 128,
                    };
                    if prefix_len > 128 {
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            format!("v6 prefix length must be 0..=128 at whitelist line {}", index + 1),
                        ));
                    }
                    let net = u128::from(v6) & prefix_mask(prefix_len);
                    wl.v6.push((net, prefix_len));
                }
            }
        }
        Ok(wl)
    }

    fn allows(&self, ip: IpAddr) -> bool {
        match normalize_peer_ip(ip) {
            IpAddr::V4(v4) => {
                let n = u32::from(v4);
                self.v4.iter().any(|(net, prefix)| {
                    let mask = ipv4_prefix_mask(*prefix);
                    (n & mask) == *net
                })
            }
            IpAddr::V6(v6) => {
                let n = u128::from(v6);
                self.v6.iter().any(|(net, prefix)| {
                    let mask = prefix_mask(*prefix);
                    (n & mask) == *net
                })
            }
        }
    }

    fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
}

fn invalid_input(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidInput, message)
}

fn parse_args() -> std::io::Result<Config> {
    let mut dns_listen_strs: Vec<String> = Vec::new();
    let mut proxy_listen_strs: Vec<String> = Vec::new();
    let mut auth = None;
    let mut prefix = None;
    let mut domain_config: Option<PathBuf> = None;
    let mut ipv4_pass_through = false;
    let mut whitelist_path: Option<PathBuf> = None;
    let mut max_conns = DEFAULT_MAX_CONNS;
    let mut max_dns = DEFAULT_MAX_DNS;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-dns" | "--dns" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("missing value for -dns/--dns"))?;
                dns_listen_strs.push(value);
            }
            "-proxy" | "--proxy" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("missing value for -proxy/--proxy"))?;
                proxy_listen_strs.push(value);
            }
            "-u" | "--user" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("missing value for -u/--user"))?;
                let (username, password) = value
                    .split_once(':')
                    .ok_or_else(|| invalid_input("-u/--user must be formatted as user:pass"))?;
                if username.is_empty() || password.is_empty() {
                    return Err(invalid_input("username and password must not be empty"));
                }
                auth = Some(Auth {
                    username: username.as_bytes().to_vec(),
                    password: password.as_bytes().to_vec(),
                });
            }
            "-p" | "--prefix" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("missing value for -p/--prefix"))?;
                prefix = Some(Ipv6Prefix::parse(&value)?);
            }
            "-c" | "--config" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("missing value for -c/--config"))?;
                domain_config = Some(PathBuf::from(value));
            }
            "-ipv4_pass_through" | "--ipv4_pass_through" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("missing value for -ipv4_pass_through/--ipv4_pass_through"))?;
                ipv4_pass_through = parse_bool(&value)?;
            }
            "-w" | "--whitelist" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("missing value for -w/--whitelist"))?;
                whitelist_path = Some(PathBuf::from(value));
            }
            "--max-conns" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("missing value for --max-conns"))?;
                max_conns = value
                    .parse::<usize>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| invalid_input("--max-conns must be a positive integer"))?;
            }
            "--max-dns" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("missing value for --max-dns"))?;
                max_dns = value
                    .parse::<usize>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| invalid_input("--max-dns must be a positive integer"))?;
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("unknown argument: {arg}"),
                ));
            }
        }
    }

    // Default: if neither -dns nor -proxy specified, start a SOCKS5 proxy on 0.0.0.0:1080.
    if dns_listen_strs.is_empty() && proxy_listen_strs.is_empty() {
        proxy_listen_strs.push(String::from("0.0.0.0:1080"));
    }
    let mut dns_listens: Vec<SocketAddr> = Vec::with_capacity(dns_listen_strs.len());
    for s in &dns_listen_strs {
        let addr: SocketAddr = s
            .parse()
            .map_err(|_| invalid_input("invalid -dns/--dns address, e.g. 0.0.0.0:53"))?;
        if dns_listens.contains(&addr) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("duplicate -dns/--dns address: {addr}"),
            ));
        }
        dns_listens.push(addr);
    }

    let mut proxy_listens: Vec<SocketAddr> = Vec::with_capacity(proxy_listen_strs.len());
    for s in &proxy_listen_strs {
        let addr: SocketAddr = s
            .parse()
            .map_err(|_| invalid_input("invalid -proxy/--proxy address, e.g. 0.0.0.0:1080"))?;
        if proxy_listens.contains(&addr) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("duplicate -proxy/--proxy address: {addr}"),
            ));
        }
        proxy_listens.push(addr);
    }

    let prefix = prefix.ok_or_else(|| invalid_input("missing required -p/--prefix IPv6 CIDR"))?;
    // Always load domain config if -c was given; otherwise use the default path
    // when DNS listeners are configured.
    let domain_config_path = domain_config.or_else(|| {
        (!dns_listens.is_empty()).then(default_domain_config_path)
    });
    let domain_rules = match &domain_config_path {
        Some(p) => DomainRules::load(p.clone())?,
        None => DomainRules::default(),
    };

    // Auth only applies to proxy listeners. Strip it if there's nothing for
    // it to gate, so the startup banner doesn't claim auth is on when it never runs.
    if proxy_listens.is_empty() {
        auth = None;
    }

    let whitelist = match &whitelist_path {
        Some(path) => Some(IpWhitelist::load(path.clone())?),
        None => None,
    };

    Ok(Config {
        dns_listens,
        proxy_listens,
        auth,
        prefix,
        ipv4_pass_through,
        domain_config_path,
        whitelist_path,
        max_conns,
        max_dns,
        hot: ArcSwap::from_pointee(HotConfig {
            domain_rules,
            whitelist,
        }),
    })
}

fn parse_bool(value: &str) -> std::io::Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(invalid_input("boolean value must be true or false")),
    }
}

fn default_domain_config_path() -> PathBuf {
    env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join("domain.conf")))
        .unwrap_or_else(|| PathBuf::from("domain.conf"))
}

fn bind_tcp_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(65_535)
}

fn print_usage() {
    println!(
        "Usage: ipv6-pool-proxy [-dns <addr:port> ...] [-proxy <addr:port> ...] [options]\n\n\
Options:\n  -dns, --dns <addr:port>            DNS UDP + SNI TCP 443 listen address (repeatable). DNS hijack answers use this IP.\n  -proxy, --proxy <addr:port>        SOCKS5 proxy listen address (repeatable). Default: 0.0.0.0:1080 if neither flag given.\n  -u, --user <user:pass>             Enable SOCKS5 username/password authentication\n  -p, --prefix <ipv6/cidr>           Required outbound random IPv6 CIDR, e.g. 2001:470:19:226::/64\n  -c, --config <path>                domain.conf path, default: domain.conf next to binary (auto-enabled when -dns is configured)\n  -ipv4_pass_through <true|false>    Fallback to local default IPv4 outbound when target only has IPv4, default: false\n  -w, --whitelist <path>             Inbound IP whitelist file; if omitted, all IPs are allowed\n\n\
Dual-stack DNS example:\n  ipv6-pool-proxy -dns 1.2.3.4:53 -dns [2001:db8::1]:53 -p 2001:db8:abcd::/48 -c domain.conf\n  (A query hits the v4 socket and gets A; AAAA hits the v6 socket and gets AAAA; cross-stack queries return empty NOERROR (NODATA))\n\n\
SOCKS5 proxy only:\n  ipv6-pool-proxy -proxy 0.0.0.0:1080 -p 2001:db8:abcd::/48\n\n\
SOCKS5 + DNS together:\n  ipv6-pool-proxy -dns 1.2.3.4:53 -proxy 0.0.0.0:1080 -u alice:secret -p 2001:db8:abcd::/48 -c domain.conf\n  (DNS+SNI on :53/:443 plus a SOCKS5 listener on :1080 with password auth, all sharing the same IPv6 outbound pool)\n\n\
domain.conf examples:\n  google.com                 Hijack exact domain only\n  suffix:google.com          Hijack domain and all subdomains\n  keyword:google             Hijack domains containing keyword\n  tld:com                    Hijack all domains with this suffix\n\n\
ip.conf examples:\n  1.1.1.1                    Single IPv4\n  1.1.1.0/24                 IPv4 CIDR\n  ::1                        Single IPv6\n  2001:db8::/32              IPv6 CIDR\n  # comments after '#' are ignored"
    );
}

async fn connect_target(target: TargetAddr, prefix: Ipv6Prefix, ipv4_pass_through: bool) -> std::io::Result<TcpStream> {
    let target_addr = resolve_target(target).await?;
    match target_addr.ip() {
        IpAddr::V6(_) => connect_from_random_ipv6(target_addr, prefix).await,
        IpAddr::V4(_) if ipv4_pass_through => {
            let stream = TcpStream::connect(target_addr).await?;
            stream.set_nodelay(true)?;
            Ok(stream)
        }
        IpAddr::V4(_) => Err(Error::new(
            ErrorKind::Unsupported,
            "IPv4 target is unsupported when outbound is bound to an IPv6 subnet",
        )),
    }
}

async fn resolve_target(target: TargetAddr) -> std::io::Result<SocketAddr> {
    match target {
        TargetAddr::Ip(addr) => Ok(addr),
        TargetAddr::Domain(domain, port) => {
            let mut last_v4 = None;
            for addr in lookup_host((domain.as_str(), port)).await? {
                match addr.ip() {
                    IpAddr::V6(_) => return Ok(addr),
                    IpAddr::V4(_) => last_v4 = Some(addr),
                }
            }
            last_v4.ok_or_else(|| Error::new(ErrorKind::NotFound, "domain did not resolve"))
        }
    }
}

async fn connect_from_random_ipv6(target_addr: SocketAddr, prefix: Ipv6Prefix) -> std::io::Result<TcpStream> {
    let local_ip = prefix.random_addr();
    let socket = TcpSocket::new_v6()?;
    socket.set_reuseaddr(true)?;
    socket.bind(SocketAddr::new(IpAddr::V6(local_ip), 0))?;
    let stream = socket.connect(target_addr).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

async fn connect_direct(target: TargetAddr) -> std::io::Result<TcpStream> {
    let stream = match target {
        TargetAddr::Ip(addr) => TcpStream::connect(addr).await?,
        TargetAddr::Domain(domain, port) => TcpStream::connect((domain.as_str(), port)).await?,
    };
    stream.set_nodelay(true)?;
    Ok(stream)
}

async fn handle_client(mut client: TcpStream, config: Arc<Config>) -> std::io::Result<()> {
    // Bound the entire SOCKS5 negotiation to a single timeout so slow / dead
    // peers cannot park a socket indefinitely.
    let target = timeout(HANDSHAKE_TIMEOUT, async {
        socks5_handshake(&mut client, config.auth.as_ref()).await?;
        read_socks5_request(&mut client).await
    })
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "socks5 handshake timeout"))??;

    // SOCKS5 is an explicit proxy: every connection routes through the
    // random IPv6 pool, regardless of dns-mode domain rules (those only
    // gate the SNI proxy's hijack path).
    let connect_fut = connect_target(target, config.prefix, config.ipv4_pass_through);
    match timeout(CONNECT_TIMEOUT, connect_fut).await {
        Ok(Ok(mut remote)) => {
            send_socks5_reply(&mut client, 0x00).await?;
            let _ = relay_bidirectional(&mut client, &mut remote).await;
            Ok(())
        }
        Ok(Err(err)) => {
            let code = socks5_error_code(&err);
            let _ = send_socks5_reply(&mut client, code).await;
            Err(err)
        }
        Err(_) => {
            let _ = send_socks5_reply(&mut client, 0x06).await;
            Err(Error::new(ErrorKind::TimedOut, "connect timeout"))
        }
    }
}

async fn socks5_handshake(client: &mut TcpStream, auth: Option<&Auth>) -> std::io::Result<()> {
    // Read VER + NMETHODS in one syscall, then methods in one more — instead
    // of N+2 individual reads.
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(invalid_input("invalid SOCKS version"));
    }
    let nmethods = head[1] as usize;
    if nmethods == 0 {
        return Err(invalid_input("SOCKS5 client sent no auth methods"));
    }
    let mut methods = [0u8; 255];
    client.read_exact(&mut methods[..nmethods]).await?;
    let methods = &methods[..nmethods];

    match auth {
        Some(auth) => {
            if !methods.contains(&0x02) {
                client.write_all(&[0x05, 0xff]).await?;
                return Err(Error::new(ErrorKind::PermissionDenied, "client does not support username/password auth"));
            }
            client.write_all(&[0x05, 0x02]).await?;
            username_password_auth(client, auth).await
        }
        None => {
            if !methods.contains(&0x00) {
                client.write_all(&[0x05, 0xff]).await?;
                return Err(Error::new(ErrorKind::PermissionDenied, "client does not support no-auth mode"));
            }
            client.write_all(&[0x05, 0x00]).await
        }
    }
}

async fn username_password_auth(client: &mut TcpStream, auth: &Auth) -> std::io::Result<()> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != 0x01 {
        client.write_all(&[0x01, 0x01]).await?;
        return Err(invalid_input("invalid username/password auth version"));
    }
    let ulen = head[1] as usize;
    let mut ubuf = [0u8; 255];
    client.read_exact(&mut ubuf[..ulen]).await?;

    let mut plen_buf = [0u8; 1];
    client.read_exact(&mut plen_buf).await?;
    let plen = plen_buf[0] as usize;
    let mut pbuf = [0u8; 255];
    client.read_exact(&mut pbuf[..plen]).await?;

    let username = &ubuf[..ulen];
    let password = &pbuf[..plen];
    if username == auth.username.as_slice() && password == auth.password.as_slice() {
        client.write_all(&[0x01, 0x00]).await
    } else {
        client.write_all(&[0x01, 0x01]).await?;
        Err(Error::new(ErrorKind::PermissionDenied, "invalid username or password"))
    }
}

async fn read_socks5_request(client: &mut TcpStream) -> std::io::Result<TargetAddr> {
    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;
    let [ver, cmd, rsv, atyp] = head;

    if ver != 0x05 || rsv != 0x00 {
        return Err(invalid_input("invalid SOCKS5 request header"));
    }
    if cmd != 0x01 {
        send_socks5_reply(client, 0x07).await?;
        return Err(Error::new(ErrorKind::Unsupported, "only SOCKS5 CONNECT is supported"));
    }

    match atyp {
        0x01 => {
            let mut tail = [0u8; 6];
            client.read_exact(&mut tail).await?;
            let octets = [tail[0], tail[1], tail[2], tail[3]];
            let port = u16::from_be_bytes([tail[4], tail[5]]);
            Ok(TargetAddr::Ip(SocketAddr::new(IpAddr::from(octets), port)))
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            client.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut tail = [0u8; 257];
            client.read_exact(&mut tail[..len + 2]).await?;
            let port = u16::from_be_bytes([tail[len], tail[len + 1]]);
            let domain = std::str::from_utf8(&tail[..len])
                .map_err(|_| invalid_input("SOCKS5 domain is not valid UTF-8"))?
                .to_string();
            Ok(TargetAddr::Domain(domain, port))
        }
        0x04 => {
            let mut tail = [0u8; 18];
            client.read_exact(&mut tail).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&tail[..16]);
            let port = u16::from_be_bytes([tail[16], tail[17]]);
            Ok(TargetAddr::Ip(SocketAddr::new(IpAddr::from(octets), port)))
        }
        _ => {
            send_socks5_reply(client, 0x08).await?;
            Err(Error::new(ErrorKind::Unsupported, "unsupported SOCKS5 address type"))
        }
    }
}

async fn send_socks5_reply(client: &mut TcpStream, reply: u8) -> std::io::Result<()> {
    client
        .write_all(&[
            0x05, reply, 0x00, 0x04, // VER, REP, RSV, ATYP(IPv6)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // BND.ADDR
            0, 0, // BND.PORT
        ])
        .await
}

fn socks5_error_code(err: &std::io::Error) -> u8 {
    match err.kind() {
        ErrorKind::PermissionDenied => 0x02,
        ErrorKind::ConnectionRefused => 0x05,
        ErrorKind::TimedOut => 0x06,
        ErrorKind::Unsupported => 0x08,
        ErrorKind::AddrNotAvailable | ErrorKind::NotFound => 0x04,
        _ => 0x01,
    }
}

// --- Resilient accept loop with bounded concurrency ---
//
// 1. acquire_owned() BEFORE accept() applies natural backpressure — if all
//    permits are taken, accept() is delayed and the kernel listen backlog
//    (65535) absorbs the burst, instead of us spawning unbounded tasks.
// 2. accept() errors (EMFILE / WSAEMFILE / etc) are caught and retried with
//    exponential backoff. NEVER let an accept error kill the server — that's
//    the #1 cause of crashes around 1k concurrent.
async fn run_accept_loop<F, Fut>(
    listener: TcpListener,
    sem: Arc<Semaphore>,
    config: Arc<Config>,
    handler: F,
) where
    F: Fn(TcpStream, Arc<Config>) -> Fut + Send + Sync + 'static + Copy,
    Fut: std::future::Future<Output = std::io::Result<()>> + Send + 'static,
{
    // accept() FIRST, then acquire permit — this way the kernel backlog keeps
    // draining even when we're at capacity, and excess connections get an
    // immediate RST instead of silently queuing behind a blocked accept().
    let mut backoff_ms = 5u64;
    loop {
        match listener.accept().await {
            Ok((client, peer)) => {
                backoff_ms = 5;
                if !config.allows(peer.ip()) {
                    eprintln!("[whitelist deny tcp] {peer}");
                    continue; // client drops → RST sent
                }
                let permit = match sem.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        eprintln!("[overload] dropping connection from {peer}");
                        continue; // client drops → RST sent
                    }
                };
                let _ = client.set_nodelay(true);
                let cfg = Arc::clone(&config);
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(err) = handler(client, cfg).await {
                        eprintln!("[conn error] {err}");
                    }
                });
            }
            Err(err) => {
                eprintln!("[accept error] {err} (backoff {}ms)", backoff_ms);
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = backoff_ms.saturating_mul(2).min(ACCEPT_BACKOFF_MAX_MS);
            }
        }
    }
}

// --- DNS + SNI proxy helpers (used in dns mode) ---
// One UDP DNS + TCP 443 SNI listener pair per -l address. Each socket's local
// IP is what we put in the DNS hijack answer, so an IPv4 client hitting the v4
// socket gets an A record, an IPv6 client hitting the v6 socket gets AAAA.
async fn start_dns_services(config: Arc<Config>) -> std::io::Result<()> {
    let dns_sem = Arc::new(Semaphore::new(config.max_dns));
    let sni_sem = Arc::new(Semaphore::new(config.max_conns));

    for listen in &config.dns_listens {
        let udp = Arc::new(UdpSocket::bind(*listen).await?);
        let sni_listen = SocketAddr::new(listen.ip(), 443);
        let tcp = bind_tcp_listener(sni_listen)?;
        let listen_ip = listen.ip();

        println!(
            "dns mode: DNS UDP listening on {}, SNI proxy TCP listening on {}",
            listen, sni_listen
        );

        // UDP DNS loop — resilient: never break on errors.
        let udp_cfg = Arc::clone(&config);
        let udp_sem = Arc::clone(&dns_sem);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            loop {
                match udp.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        if !udp_cfg.allows(src.ip()) {
                            eprintln!("[whitelist deny udp] {src}");
                            continue;
                        }
                        let permit = match udp_sem.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => return,
                        };
                        let packet = buf[..len].to_vec();
                        let udp2 = Arc::clone(&udp);
                        let cfg = Arc::clone(&udp_cfg);
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(err) =
                                handle_udp_dns_query(packet, src, udp2, listen_ip, cfg).await
                            {
                                eprintln!("[dns error] {src}: {err}");
                            }
                        });
                    }
                    Err(err) => {
                        eprintln!("[udp recv error on {listen_ip}] {err}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        });

        // TCP SNI accept loop — resilient with semaphore backpressure.
        let tcp_cfg = Arc::clone(&config);
        let tcp_sem = Arc::clone(&sni_sem);
        tokio::spawn(async move {
            run_accept_loop(tcp, tcp_sem, tcp_cfg, |stream, cfg| async move {
                handle_sni_connection(stream, cfg).await
            })
            .await;
        });
    }

    Ok(())
}

async fn handle_udp_dns_query(
    packet: Vec<u8>,
    src: SocketAddr,
    udp: Arc<UdpSocket>,
    listen_ip: IpAddr,
    config: Arc<Config>,
) -> std::io::Result<()> {
    if packet.len() < 12 {
        return Ok(());
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        let _ = udp.send_to(&packet, src).await;
        return Ok(());
    }
    let mut idx = 12usize;
    let mut qname = String::with_capacity(128);
    while idx < packet.len() {
        let len = packet[idx] as usize;
        idx += 1;
        if len == 0 {
            break;
        }
        if idx + len > packet.len() {
            return Ok(());
        }
        if !qname.is_empty() {
            qname.push('.');
        }
        for byte in &packet[idx..idx + len] {
            qname.push(byte.to_ascii_lowercase() as char);
        }
        idx += len;
    }

    if idx + 4 > packet.len() {
        return Ok(());
    }
    let qtype = u16::from_be_bytes([packet[idx], packet[idx + 1]]);

    if config.matches_normalized(&qname) {
        let qend = idx + 4;
        let hijack_answer = dns_query_type_matches_listen_ip(qtype, listen_ip);
        // For matched-but-wrong-stack queries return NOERROR with empty answer
        // (NODATA), not NXDOMAIN: musl libc treats NXDOMAIN on any family as
        // fatal and drops the other family's answer, breaking dual-stack
        // clients.
        let mut resp = build_dns_response_header(&packet, hijack_answer);
        resp.extend_from_slice(&packet[12..qend]);

        if hijack_answer {
            resp.extend_from_slice(&[0xC0, 0x0C]);
            match listen_ip {
                IpAddr::V4(ipv4) => {
                    resp.extend_from_slice(&[0x00, 0x01]); // A
                    resp.extend_from_slice(&[0x00, 0x01]); // IN
                    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60
                    resp.extend_from_slice(&[0x00, 0x04]); // rdlength 4
                    resp.extend_from_slice(&ipv4.octets());
                }
                IpAddr::V6(ipv6) => {
                    resp.extend_from_slice(&[0x00, 0x1C]); // AAAA
                    resp.extend_from_slice(&[0x00, 0x01]); // IN
                    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60
                    resp.extend_from_slice(&[0x00, 0x10]); // rdlength 16
                    resp.extend_from_slice(&ipv6.octets());
                }
            }
        }

        let _ = udp.send_to(&resp, src).await;
        return Ok(());
    }

    // Forward to upstream resolver with a hard timeout so a black-holed query
    // cannot pin a socket forever.
    if let Ok(s) = UdpSocket::bind("0.0.0.0:0").await {
        if s.send_to(&packet, "8.8.8.8:53").await.is_ok() {
            let mut buf = [0u8; 1500];
            if let Ok(Ok((n, _))) = timeout(UPSTREAM_DNS_TIMEOUT, s.recv_from(&mut buf)).await {
                let _ = udp.send_to(&buf[..n], src).await;
            }
        }
    }

    Ok(())
}

fn dns_query_type_matches_listen_ip(qtype: u16, listen_ip: IpAddr) -> bool {
    matches!((qtype, listen_ip), (1, IpAddr::V4(_)) | (28, IpAddr::V6(_)))
}

fn build_dns_response_header(query: &[u8], has_answer: bool) -> Vec<u8> {
    let mut resp = Vec::with_capacity(query.len() + 32);
    resp.extend_from_slice(&query[0..2]);
    resp.extend_from_slice(&[0x81, 0x80]);
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(if has_answer { &[0x00, 0x01] } else { &[0x00, 0x00] });
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp
}

fn extract_sni_from_client_hello(buf: &[u8]) -> Option<String> {
    if buf.len() < 5 { return None; }
    if buf[0] != 0x16 { return None; }
    let _rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 6 { return None; }
    let mut idx = 5;
    if buf[idx] != 0x01 { return None; }
    if buf.len() < idx + 4 { return None; }
    idx += 4;
    if buf.len() < idx + 2 + 32 { return None; }
    idx += 2 + 32;
    if buf.len() < idx + 1 { return None; }
    let sid_len = buf[idx] as usize; idx += 1 + sid_len;
    if buf.len() < idx + 2 { return None; }
    let cs_len = u16::from_be_bytes([buf[idx], buf[idx + 1]]) as usize; idx += 2 + cs_len;
    if buf.len() < idx + 1 { return None; }
    let comp_len = buf[idx] as usize; idx += 1 + comp_len;
    if buf.len() < idx + 2 { return None; }
    let ext_len = u16::from_be_bytes([buf[idx], buf[idx + 1]]) as usize; idx += 2;
    let mut ext_end = idx + ext_len;
    if buf.len() < ext_end { ext_end = buf.len(); }
    while idx + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
        let elen = u16::from_be_bytes([buf[idx + 2], buf[idx + 3]]) as usize;
        idx += 4;
        if idx + elen > ext_end { break; }
        if ext_type == 0x0000 {
            if elen < 2 { return None; }
            let mut subidx = idx + 2;
            let list_end = idx + elen;
            while subidx + 3 <= list_end {
                let name_type = buf[subidx];
                let name_len = u16::from_be_bytes([buf[subidx + 1], buf[subidx + 2]]) as usize;
                subidx += 3;
                if subidx + name_len > list_end { break; }
                if name_type == 0 {
                    if let Ok(s) = std::str::from_utf8(&buf[subidx..subidx + name_len]) {
                        return Some(s.to_ascii_lowercase());
                    } else { return None; }
                }
                subidx += name_len;
            }
        }
        idx += elen;
    }
    None
}

// A single read() can return only the first TCP segment, which truncates large
// TLS 1.3 ClientHellos (PQ key shares, GREASE, big ALPN). Loop until we have
// the full 5 + record_len bytes so SNI parsing and ClientHello forwarding to
// upstream are both correct.
async fn read_tls_client_hello(client: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    // Read exactly the 5-byte TLS record header first.
    let mut header = [0u8; 5];
    client.read_exact(&mut header).await?;

    if header[0] != 0x16 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("not a TLS handshake record (first byte=0x{:02x})", header[0]),
        ));
    }

    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let need = 5 + record_len;
    if need > MAX_CLIENT_HELLO_LEN {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("TLS record length {} exceeds cap", record_len),
        ));
    }

    // Allocate exactly `need` bytes and fill the payload portion precisely —
    // no over-read, so subsequent TLS records remain untouched in the socket.
    let mut buf = vec![0u8; need];
    buf[..5].copy_from_slice(&header);
    client.read_exact(&mut buf[5..]).await?;
    Ok(buf)
}

async fn handle_sni_connection(mut client: TcpStream, config: Arc<Config>) -> std::io::Result<()> {
    let _ = client.set_nodelay(true);
    let peer = client
        .peer_addr()
        .map_or_else(|_| "?".to_string(), |a| a.to_string());

    let initial = match timeout(SNI_READ_TIMEOUT, read_tls_client_hello(&mut client)).await {
        Ok(Ok(buf)) => buf,
        Ok(Err(e)) => {
            eprintln!("[sni read] {peer}: {e}");
            return Err(e);
        }
        Err(_) => {
            eprintln!("[sni read] {peer}: timeout after {:?}", SNI_READ_TIMEOUT);
            return Err(Error::new(ErrorKind::TimedOut, "SNI read timeout"));
        }
    };

    let target_domain = match extract_sni_from_client_hello(&initial) {
        Some(d) => d,
        None => {
            let head_len = initial.len().min(16);
            eprintln!(
                "[sni parse] {peer}: failed, read {} bytes, head={:02x?}",
                initial.len(),
                &initial[..head_len]
            );
            return Ok(());
        }
    };

    let matched = config.matches_domain(&target_domain);
    let connect_fut = async {
        if matched {
            connect_target(
                TargetAddr::Domain(target_domain.clone(), 443),
                config.prefix,
                config.ipv4_pass_through,
            )
            .await
        } else {
            connect_direct(TargetAddr::Domain(target_domain.clone(), 443)).await
        }
    };

    let mut remote_stream = match timeout(CONNECT_TIMEOUT, connect_fut).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            eprintln!("[sni connect] {peer} -> {target_domain} (matched={matched}): {e}");
            return Err(e);
        }
        Err(_) => {
            eprintln!("[sni connect] {peer} -> {target_domain} (matched={matched}): timeout");
            return Err(Error::new(ErrorKind::TimedOut, "SNI connect timeout"));
        }
    };

    if let Err(e) = remote_stream.write_all(&initial).await {
        eprintln!("[sni forward] {peer} -> {target_domain}: {e}");
        return Err(e);
    }
    let _ = relay_bidirectional(&mut client, &mut remote_stream).await;
    Ok(())
}

// --- Zero-copy bidirectional relay ---
// On Linux, shuttle bytes socket<->socket entirely in the kernel via splice()
// through a per-direction pipe: no userspace copy, lower CPU and memory
// bandwidth (matters most on the 2-core ARM box). Everywhere else, fall back to
// tokio's userspace copy.
#[cfg(target_os = "linux")]
async fn relay_bidirectional(a: &mut TcpStream, b: &mut TcpStream) -> std::io::Result<()> {
    splice_relay::bidirectional(a, b).await
}

#[cfg(not(target_os = "linux"))]
async fn relay_bidirectional(a: &mut TcpStream, b: &mut TcpStream) -> std::io::Result<()> {
    tokio::io::copy_bidirectional_with_sizes(a, b, COPY_BUF_SIZE, COPY_BUF_SIZE)
        .await
        .map(|_| ())
}

#[cfg(target_os = "linux")]
mod splice_relay {
    use std::io::{Error, ErrorKind, Result};
    use std::os::unix::io::{AsRawFd, RawFd};
    use tokio::io::Interest;
    use tokio::net::TcpStream;

    // Move up to 64 KiB per splice call. Kept at the default pipe capacity so we
    // never enlarge kernel pipe buffers — under a connection flood, oversized
    // pipes would multiply memory per connection and defeat the OOM guard.
    const CHUNK: usize = 64 * 1024;
    const FLAGS: libc::c_uint = (libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK) as libc::c_uint;

    struct Pipe {
        r: RawFd,
        w: RawFd,
    }

    impl Pipe {
        fn new() -> Result<Self> {
            let mut fds = [0 as libc::c_int; 2];
            // O_NONBLOCK keeps splice from ever blocking the runtime thread;
            // O_CLOEXEC avoids leaking the pipe into any child process.
            let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
            if rc != 0 {
                return Err(Error::last_os_error());
            }
            Ok(Pipe { r: fds[0], w: fds[1] })
        }
    }

    impl Drop for Pipe {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.r);
                libc::close(self.w);
            }
        }
    }

    fn splice(fd_in: RawFd, fd_out: RawFd, len: usize) -> Result<usize> {
        let n = unsafe {
            libc::splice(
                fd_in,
                std::ptr::null_mut(),
                fd_out,
                std::ptr::null_mut(),
                len,
                FLAGS,
            )
        };
        if n < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    // Pump one direction (src -> dst) until src reaches EOF or a fatal error.
    // On clean EOF, half-close dst's write side so the peer observes FIN while
    // the other direction can keep flowing.
    async fn pump(src: &TcpStream, dst: &TcpStream) -> Result<()> {
        let pipe = Pipe::new()?;
        let src_fd = src.as_raw_fd();
        let dst_fd = dst.as_raw_fd();

        loop {
            // socket -> pipe (wait for readable, retry on EAGAIN)
            let n = loop {
                match src.try_io(Interest::READABLE, || splice(src_fd, pipe.w, CHUNK)) {
                    Ok(n) => break n,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => src.readable().await?,
                    Err(e) => return Err(e),
                }
            };
            if n == 0 {
                break; // EOF
            }

            // pipe -> socket; fully drain so the pipe is empty before the next
            // read (guarantees the next splice-in can't hit a full pipe).
            let mut remaining = n;
            while remaining > 0 {
                match dst.try_io(Interest::WRITABLE, || splice(pipe.r, dst_fd, remaining)) {
                    Ok(0) => return Err(Error::new(ErrorKind::WriteZero, "splice wrote zero")),
                    Ok(m) => remaining -= m,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => dst.writable().await?,
                    Err(e) => return Err(e),
                }
            }
        }

        let _ = unsafe { libc::shutdown(dst_fd, libc::SHUT_WR) };
        Ok(())
    }

    pub async fn bidirectional(a: &mut TcpStream, b: &mut TcpStream) -> Result<()> {
        let (a, b) = (&*a, &*b);
        let (r1, r2) = tokio::join!(pump(a, b), pump(b, a));
        // Either direction erroring means the relay ended abnormally; report the
        // first error but always let both halves finish first (join! already
        // awaits both).
        r1.and(r2)
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::io::Result<()> {
    let config = Arc::new(parse_args().inspect_err(|_| print_usage())?);

    let whitelist_state = match config.hot.load().whitelist.as_ref() {
        Some(wl) => format!("enabled ({} entries)", wl.len()),
        None => "disabled".to_string(),
    };

    let dns_str = if config.dns_listens.is_empty() {
        "none".to_string()
    } else {
        config
            .dns_listens
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let proxy_str = if config.proxy_listens.is_empty() {
        "none".to_string()
    } else {
        config
            .proxy_listens
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };

    println!(
        "IPv6 pool proxy starting on dns: [{}], proxy: [{}], auth: {}, prefix: {}/{}, ipv4_pass_through: {}, whitelist: {}, max_conns: {}, max_dns: {}",
        dns_str,
        proxy_str,
        if config.auth.is_some() { "enabled" } else { "disabled" },
        Ipv6Addr::from(config.prefix.network),
        config.prefix.prefix_len,
        config.ipv4_pass_through,
        whitelist_state,
        config.max_conns,
        config.max_dns
    );

    if !config.dns_listens.is_empty() {
        for l in &config.dns_listens {
            if l.ip().is_unspecified() {
                eprintln!(
                    "[warn] dns listener {l} is a wildcard IP; \
DNS hijack answers will return {} which is not connectable. \
Bind to a specific routable IP per stack.",
                    l.ip()
                );
            }
        }
    }

    spawn_reload_on_sighup(Arc::clone(&config))?;

    let socks5_sem = Arc::new(Semaphore::new(config.max_conns));

    // Start DNS services if DNS listeners are configured.
    if !config.dns_listens.is_empty() {
        start_dns_services(Arc::clone(&config)).await?;
    }

    // Start SOCKS5 proxy if proxy listeners are configured.
    if !config.proxy_listens.is_empty() {
        spawn_socks5_listeners(&config.proxy_listens, Arc::clone(&config), socks5_sem)?;
    }

    tokio::signal::ctrl_c().await?;
    Ok(())
}

// Re-read domain.conf + whitelist from disk and swap the HotConfig in place.
// In-flight tasks keep their existing Arc<HotConfig> snapshot; new tasks pick
// up the reloaded one. Returns an error without touching the live config if
// either file fails to parse, so a broken edit can't blank the server out.
fn reload_hot(config: &Config) -> std::io::Result<()> {
    let domain_rules = match &config.domain_config_path {
        Some(p) => DomainRules::load(p.clone())?,
        None => DomainRules::default(),
    };
    let whitelist = match &config.whitelist_path {
        Some(p) => Some(IpWhitelist::load(p.clone())?),
        None => None,
    };
    let rule_count = domain_rules.exact.len()
        + domain_rules.suffix.len()
        + domain_rules.keyword.len()
        + domain_rules.tld.len();
    let wl_count = whitelist.as_ref().map_or(0, |wl| wl.len());
    config.hot.store(Arc::new(HotConfig {
        domain_rules,
        whitelist,
    }));
    eprintln!("[reload] ok: {rule_count} domain rules, {wl_count} whitelist entries");
    Ok(())
}

// Spawn a task that re-reads config files on every SIGHUP. A bad reload is
// logged and skipped; the running config is unchanged.
fn spawn_reload_on_sighup(config: Arc<Config>) -> std::io::Result<()> {
    let mut hup = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
        while hup.recv().await.is_some() {
            if let Err(e) = reload_hot(&config) {
                eprintln!("[reload] failed (keeping previous state): {e}");
            }
        }
    });
    Ok(())
}

fn spawn_socks5_listeners(
    listens: &[SocketAddr],
    config: Arc<Config>,
    sem: Arc<Semaphore>,
) -> std::io::Result<()> {
    for listen in listens {
        let listener = bind_tcp_listener(*listen)?;
        println!("SOCKS5 listening on {listen}");
        let sem = Arc::clone(&sem);
        let cfg = Arc::clone(&config);
        tokio::spawn(async move {
            run_accept_loop(listener, sem, cfg, |client, cfg| async move {
                handle_client(client, cfg).await
            })
            .await;
        });
    }
    Ok(())
}
