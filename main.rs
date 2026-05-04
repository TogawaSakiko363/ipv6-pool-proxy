use rand::Rng;
use std::env;
use std::fs;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpSocket, TcpStream, UdpSocket};

#[derive(Clone, Debug)]
struct Config {
    listen: SocketAddr,
    auth: Option<Auth>,
    prefix: Ipv6Prefix,
    mode: Mode,
    domain_rules: DomainRules,
    ipv4_pass_through: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Proxy,
    Dns,
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

impl Mode {
    fn parse(value: &str) -> std::io::Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "proxy" => Ok(Self::Proxy),
            "dns" => Ok(Self::Dns),
            _ => Err(invalid_input("-m/--mode must be proxy or dns")),
        }
    }
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
        let random_host = rand::thread_rng().gen::<u128>() & host_mask;
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

fn invalid_input(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidInput, message)
}

fn parse_args() -> std::io::Result<Config> {
    let mut listen = String::from("0.0.0.0:1080");
    let mut auth = None;
    let mut prefix = None;
    let mut mode = Mode::Proxy;
    let mut domain_config = None;
    let mut ipv4_pass_through = false;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-l" | "--listen" => {
                listen = args
                    .next()
                    .ok_or_else(|| invalid_input("missing value for -l/--listen"))?;
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
            "-m" | "--mode" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("missing value for -m/--mode"))?;
                mode = Mode::parse(&value)?;
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

    let listen = listen
        .parse()
        .map_err(|_| invalid_input("invalid listen address, e.g. 0.0.0.0:1080"))?;
    let prefix = prefix.ok_or_else(|| invalid_input("missing required -p/--prefix IPv6 CIDR"))?;
    let domain_rules = if mode == Mode::Dns {
        let path = domain_config.unwrap_or_else(default_domain_config_path);
        auth = None;
        DomainRules::load(path)?
    } else {
        DomainRules::default()
    };

    Ok(Config {
        listen,
        auth,
        prefix,
        mode,
        domain_rules,
        ipv4_pass_through,
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
        "Usage: ipv6-pool-proxy -m proxy|dns -l 0.0.0.0:1080 -u user:pass -p 2001:470:19:226::/64 [-c domain.conf] [-ipv4_pass_through true|false]\n\n\
Options:\n  -m, --mode <proxy|dns>              Run mode, default: proxy\n  -l, --listen <addr:port>            Listen address, default: 0.0.0.0:1080\n  -u, --user <user:pass>              Enable SOCKS5 username/password authentication; ignored in dns mode\n  -p, --prefix <ipv6/cidr>            Required outbound random IPv6 CIDR, e.g. 2001:470:19:226::/64\n  -c, --config <path>                 dns mode domain.conf path, default: domain.conf next to binary\n  -ipv4_pass_through <true|false>     Fallback to local default IPv4 outbound when target only has IPv4, default: false\n\n\
domain.conf examples:\n  google.com                 Hijack exact domain only\n  suffix:google.com          Hijack domain and all subdomains\n  keyword:google             Hijack domains containing keyword\n  tld:com                    Hijack all domains with this suffix"
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

async fn connect_by_mode(target: TargetAddr, config: &Config) -> std::io::Result<TcpStream> {
    match config.mode {
        Mode::Proxy => connect_target(target, config.prefix, config.ipv4_pass_through).await,
        Mode::Dns => match &target {
            TargetAddr::Domain(domain, _) if config.domain_rules.is_match(domain) => {
                connect_target(target, config.prefix, config.ipv4_pass_through).await
            }
            _ => connect_direct(target).await,
        },
    }
}

async fn handle_client(mut client: TcpStream, config: Arc<Config>) -> std::io::Result<()> {
    socks5_handshake(&mut client, config.auth.as_ref()).await?;
    let target = read_socks5_request(&mut client).await?;

    match connect_by_mode(target, &config).await {
        Ok(mut remote) => {
            send_socks5_reply(&mut client, 0x00).await?;
            let _ = copy_bidirectional(&mut client, &mut remote).await;
            Ok(())
        }
        Err(err) => {
            let code = socks5_error_code(&err);
            let _ = send_socks5_reply(&mut client, code).await;
            Err(err)
        }
    }
}

async fn socks5_handshake(client: &mut TcpStream, auth: Option<&Auth>) -> std::io::Result<()> {
    let ver = client.read_u8().await?;
    if ver != 0x05 {
        return Err(invalid_input("invalid SOCKS version"));
    }

    let nmethods = client.read_u8().await? as usize;
    if nmethods == 0 {
        return Err(invalid_input("SOCKS5 client sent no auth methods"));
    }

    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;

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
    let ver = client.read_u8().await?;
    if ver != 0x01 {
        client.write_all(&[0x01, 0x01]).await?;
        return Err(invalid_input("invalid username/password auth version"));
    }

    let ulen = client.read_u8().await? as usize;
    let mut username = vec![0u8; ulen];
    client.read_exact(&mut username).await?;

    let plen = client.read_u8().await? as usize;
    let mut password = vec![0u8; plen];
    client.read_exact(&mut password).await?;

    if username == auth.username && password == auth.password {
        client.write_all(&[0x01, 0x00]).await
    } else {
        client.write_all(&[0x01, 0x01]).await?;
        Err(Error::new(ErrorKind::PermissionDenied, "invalid username or password"))
    }
}

async fn read_socks5_request(client: &mut TcpStream) -> std::io::Result<TargetAddr> {
    let ver = client.read_u8().await?;
    let cmd = client.read_u8().await?;
    let rsv = client.read_u8().await?;
    let atyp = client.read_u8().await?;

    if ver != 0x05 || rsv != 0x00 {
        return Err(invalid_input("invalid SOCKS5 request header"));
    }
    if cmd != 0x01 {
        send_socks5_reply(client, 0x07).await?;
        return Err(Error::new(ErrorKind::Unsupported, "only SOCKS5 CONNECT is supported"));
    }

    let target = match atyp {
        0x01 => {
            let mut octets = [0u8; 4];
            client.read_exact(&mut octets).await?;
            let port = client.read_u16().await?;
            TargetAddr::Ip(SocketAddr::new(IpAddr::from(octets), port))
        }
        0x03 => {
            let len = client.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            client.read_exact(&mut name).await?;
            let port = client.read_u16().await?;
            let domain = String::from_utf8(name)
                .map_err(|_| invalid_input("SOCKS5 domain is not valid UTF-8"))?;
            TargetAddr::Domain(domain, port)
        }
        0x04 => {
            let mut octets = [0u8; 16];
            client.read_exact(&mut octets).await?;
            let port = client.read_u16().await?;
            TargetAddr::Ip(SocketAddr::new(IpAddr::from(octets), port))
        }
        _ => {
            send_socks5_reply(client, 0x08).await?;
            return Err(Error::new(ErrorKind::Unsupported, "unsupported SOCKS5 address type"));
        }
    };

    Ok(target)
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

// --- DNS + SNI proxy helpers (used in dns mode) ---
async fn start_dns_services(config: Arc<Config>) -> std::io::Result<()> {
    let udp = Arc::new(UdpSocket::bind(config.listen).await?);
    let sni_listen = SocketAddr::new(config.listen.ip(), 443);
    let tcp = bind_tcp_listener(sni_listen)?;

    println!(
        "dns mode: DNS UDP listening on {}, SNI proxy TCP listening on {}",
        config.listen, sni_listen
    );

    // UDP DNS loop: -l controls DNS listen address and port.
    let udp_cfg = Arc::clone(&config);
    let udp_socket = Arc::clone(&udp);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            match udp_socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    let packet = buf[..len].to_vec();
                    let udp = Arc::clone(&udp_socket);
                    let cfg = Arc::clone(&udp_cfg);
                    tokio::spawn(async move {
                        if let Err(e) = handle_udp_dns_query(packet, src, udp, cfg).await {
                            eprintln!("dns udp handler error: {e}");
                        }
                    });
                }
                Err(err) => {
                    eprintln!("udp recv error: {err}");
                    break;
                }
            }
        }
    });

    // TCP SNI proxy loop: dns mode always receives hijacked HTTPS traffic on TCP 443.
    let tcp_cfg = Arc::clone(&config);
    tokio::spawn(async move {
        loop {
            match tcp.accept().await {
                Ok((stream, peer)) => {
                    let _ = stream.set_nodelay(true);
                    let cfg = Arc::clone(&tcp_cfg);
                    tokio::spawn(async move {
                        if let Err(e) = handle_sni_connection(stream, cfg).await {
                            eprintln!("sni handler {peer} error: {e}");
                        }
                    });
                }
                Err(err) => {
                    eprintln!("tcp accept error: {err}");
                    break;
                }
            }
        }
    });

    Ok(())
}

async fn handle_udp_dns_query(packet: Vec<u8>, src: std::net::SocketAddr, udp: Arc<UdpSocket>, config: Arc<Config>) -> std::io::Result<()> {
    // Minimal DNS parser: support single-question queries, forward unmatched or incompatible queries to upstream (8.8.8.8:53)
    if packet.len() < 12 {
        return Ok(());
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        // nothing to do
        let _ = udp.send_to(&packet, src).await;
        return Ok(());
    }
    // parse qname with a single reusable String and ASCII lowercase in-place.
    let mut idx = 12usize;
    let mut qname = String::with_capacity(128);
    while idx < packet.len() {
        let len = packet[idx] as usize;
        idx += 1;
        if len == 0 { break; }
        if idx + len > packet.len() { return Ok(()); }
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
    let qtype = u16::from_be_bytes([packet[idx], packet[idx+1]]);
    let _qclass = u16::from_be_bytes([packet[idx+2], packet[idx+3]]);

    if config.domain_rules.is_normalized_match(&qname) {
        let qend = idx + 4;
        let hijack_answer = dns_query_type_matches_listen_ip(qtype, config.listen.ip());
        let mut resp = build_dns_response_header(&packet, hijack_answer);
        resp.extend_from_slice(&packet[12..qend]);

        if hijack_answer {
            // answer: NAME pointer to offset 12 -> 0xC00C
            resp.extend_from_slice(&[0xC0, 0x0C]);
            match config.listen.ip() {
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

    // not matched: forward to upstream resolver and proxy the response back
    let upstream = ("8.8.8.8", 53);
    match UdpSocket::bind(("0.0.0.0", 0)).await {
        Ok(s) => {
            s.send_to(&packet, upstream).await.ok();
            let mut buf = vec![0u8; 1500];
            match s.recv_from(&mut buf).await {
                Ok((n, _)) => { let _ = udp.send_to(&buf[..n], src).await; }
                Err(e) => eprintln!("upstream recv error: {e}"),
            }
        }
        Err(e) => eprintln!("failed to bind upstream udp: {e}"),
    }

    Ok(())
}

fn dns_query_type_matches_listen_ip(qtype: u16, listen_ip: IpAddr) -> bool {
    matches!((qtype, listen_ip), (1, IpAddr::V4(_)) | (28, IpAddr::V6(_)))
}

fn build_dns_response_header(query: &[u8], has_answer: bool) -> Vec<u8> {
    let mut resp = Vec::with_capacity(query.len() + 32);
    resp.extend_from_slice(&query[0..2]); // transaction id
    resp.extend_from_slice(&[0x81, 0x80]); // standard response, recursion available, no error
    resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    resp.extend_from_slice(if has_answer { &[0x00, 0x01] } else { &[0x00, 0x00] }); // ANCOUNT
    resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    resp
}

fn extract_sni_from_client_hello(buf: &[u8]) -> Option<String> {
    // minimal TLS ClientHello/SNI parsing
    // record header: 5 bytes
    if buf.len() < 5 { return None; }
    if buf[0] != 0x16 { return None; } // handshake
    // let _version = &buf[1..3];
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + rec_len { /* maybe truncated but try anyway */ }
    // handshake
    if buf.len() < 6 { return None; }
    let mut idx = 5;
    if buf[idx] != 0x01 { return None; } // ClientHello
    if buf.len() < idx + 4 { return None; }
    let _hs_len = ((buf[idx+1] as usize) << 16) | ((buf[idx+2] as usize) << 8) | (buf[idx+3] as usize);
    idx += 4;
    // version (2) + random (32)
    if buf.len() < idx + 2 + 32 { return None; }
    idx += 2 + 32;
    // session id
    if buf.len() < idx + 1 { return None; }
    let sid_len = buf[idx] as usize; idx += 1 + sid_len;
    if buf.len() < idx + 2 { return None; }
    // cipher suites
    let cs_len = u16::from_be_bytes([buf[idx], buf[idx+1]]) as usize; idx += 2 + cs_len;
    if buf.len() < idx + 1 { return None; }
    // compression
    let comp_len = buf[idx] as usize; idx += 1 + comp_len;
    if buf.len() < idx + 2 { return None; }
    let ext_len = u16::from_be_bytes([buf[idx], buf[idx+1]]) as usize; idx += 2;
    let mut ext_end = idx + ext_len;
    if buf.len() < ext_end { ext_end = buf.len(); }
    while idx + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[idx], buf[idx+1]]);
        let elen = u16::from_be_bytes([buf[idx+2], buf[idx+3]]) as usize;
        idx += 4;
        if idx + elen > ext_end { break; }
        if ext_type == 0x0000 {
            // server_name
            if elen < 2 { return None; }
            let _list_len = u16::from_be_bytes([buf[idx], buf[idx+1]]) as usize;
            let mut subidx = idx + 2;
            let list_end = idx + elen;
            while subidx + 3 <= list_end {
                let name_type = buf[subidx];
                let name_len = u16::from_be_bytes([buf[subidx+1], buf[subidx+2]]) as usize;
                subidx += 3;
                if subidx + name_len > list_end { break; }
                if name_type == 0 {
                    if let Ok(s) = std::str::from_utf8(&buf[subidx..subidx+name_len]) {
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

async fn handle_sni_connection(mut client: TcpStream, config: Arc<Config>) -> std::io::Result<()> {
    client.set_nodelay(true)?;
    // Read initial client bytes (ClientHello)
    let mut initial = [0u8; 4096];
    let n = match client.read(&mut initial).await {
        Ok(0) => return Ok(()),
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    let initial = &initial[..n];
    let sni = extract_sni_from_client_hello(initial);
    let target_domain = match sni {
        Some(d) => d,
        None => {
            // cannot extract SNI; drop
            return Ok(());
        }
    };

    // Decide whether to route via IPv6 random or direct
    let remote = if config.domain_rules.is_match(&target_domain) {
        connect_target(TargetAddr::Domain(target_domain.clone(), 443), config.prefix, config.ipv4_pass_through).await
    } else {
        connect_direct(TargetAddr::Domain(target_domain.clone(), 443)).await
    };

    match remote {
        Ok(mut remote_stream) => {
            // forward initial bytes
            remote_stream.write_all(initial).await?;
            let _ = copy_bidirectional(&mut client, &mut remote_stream).await;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let config = Arc::new(parse_args().inspect_err(|_| print_usage())?);

    println!(
        "IPv6 pool proxy starting on {}, mode: {:?}, auth: {}, prefix: {}/{}, ipv4_pass_through: {}",
        config.listen,
        config.mode,
        if config.auth.is_some() { "enabled" } else { "disabled" },
        Ipv6Addr::from(config.prefix.network),
        config.prefix.prefix_len,
        config.ipv4_pass_through
    );

    match config.mode {
        Mode::Proxy => {
            // start socks5 listener
            let listener = bind_tcp_listener(config.listen)?;
            loop {
                let (client, peer) = listener.accept().await?;
                let _ = client.set_nodelay(true);
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    if let Err(err) = handle_client(client, config).await {
                        eprintln!("client {peer} error: {err}");
                    }
                });
            }
        }
        Mode::Dns => {
            // start DNS UDP server on -l and SNIPROXY on TCP 443 of the same listen IP
            start_dns_services(Arc::clone(&config)).await?;
            tokio::signal::ctrl_c().await?;
            Ok(())
        }
    }
}
