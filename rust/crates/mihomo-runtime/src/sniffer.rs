//! Inspect before routing and replay every consumed byte unchanged.
use mihomo_config::{SnifferProtocolConfig, TopLevelSnifferConfig};
use mihomo_core::{BoxedTcpStream, ConnectionContext, DnsMode, Metadata, SessionKind, TcpStream};
use std::io::{self, Cursor, Read, Write};
use std::time::{Duration, Instant};
pub(crate) const MAX_HELLO: usize = 64 * 1024;
#[derive(Default)]
pub(crate) struct Sniffer {
    pub config: TopLevelSnifferConfig,
    pub quic: std::sync::Mutex<crate::sniffer_quic::QuicFlows>,
}
impl std::fmt::Debug for Sniffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sniffer")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}
#[derive(Debug, PartialEq)]
pub(crate) enum Parsed {
    NeedMore,
    NoDomain,
    Domain(String),
}
impl Sniffer {
    pub fn new(config: TopLevelSnifferConfig) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }
    pub fn eligible(&self, m: &Metadata) -> bool {
        let c = &self.config;
        c.enable
            && m.kind != SessionKind::Inner
            && !c.skip_src_address.iter().any(|s| ip_matches(s, m.src_ip))
            && !c.skip_dst_address.iter().any(|s| ip_matches(s, m.dst_ip))
            && ((m.host.as_deref().is_none_or(str::is_empty) && c.parse_pure_ip)
                || m.dns_mode == DnsMode::Mapping && c.force_dns_mapping
                || m.host
                    .as_deref()
                    .is_some_and(|h| c.force_domain.iter().any(|p| domain_matches(p, h))))
    }
    pub fn protocol(&self, kind: &str, port: u16) -> Option<bool> {
        let c = &self.config;
        let protocol = c
            .sniff
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(kind))
            .map(|(_, value)| value);
        if protocol.is_none() && !c.sniff.is_empty() {
            return None;
        }
        if protocol.is_none()
            && !c.sniffing.is_empty()
            && !c.sniffing.iter().any(|n| n.eq_ignore_ascii_case(kind))
        {
            return None;
        }
        let empty = SnifferProtocolConfig::default();
        let protocol = protocol.unwrap_or(&empty);
        let allowed = if protocol.ports.is_empty() {
            match kind {
                "TLS" => [443, 8443].contains(&port),
                "HTTP" => port == 80 || (8080..=8880).contains(&port),
                "QUIC" => port == 443,
                _ => false,
            }
        } else {
            protocol.ports.iter().any(|r| port_matches(r, port))
        };
        (allowed
            && (c.port_whitelist.is_empty()
                || c.port_whitelist.iter().any(|r| port_matches(r, port))))
        .then_some(
            protocol
                .override_destination
                .unwrap_or(c.override_destination),
        )
    }
    pub fn apply_host(&self, m: &mut Metadata, host: String, replace: bool) {
        if self
            .config
            .skip_domain
            .iter()
            .any(|p| domain_matches(p, &host))
        {
            return;
        }
        m.sniff_host = Some(host.clone());
        if replace {
            m.host = Some(host);
            m.dst_ip = None;
            m.dns_mode = DnsMode::Normal;
        }
    }
    pub fn sniff_tcp(&self, context: &mut ConnectionContext) {
        if !self.eligible(context.metadata()) {
            return;
        }
        let port = context.metadata().dst_port.unwrap_or(0);
        let tls = self.protocol("TLS", port);
        let http = self.protocol("HTTP", port);
        if tls.is_none() && http.is_none() {
            return;
        }
        let Ok(previous) = context.stream_mut().read_timeout() else {
            return;
        };
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut prefix = Vec::new();
        let mut found = None;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || prefix.len() >= MAX_HELLO {
                break;
            }
            if context
                .stream_mut()
                .set_read_timeout(Some(remaining))
                .is_err()
            {
                break;
            }
            let mut bytes = [0u8; 4096];
            let limit = bytes.len().min(MAX_HELLO - prefix.len());
            match context.stream_mut().read(&mut bytes[..limit]) {
                Ok(0) => break,
                Ok(n) => prefix.extend_from_slice(&bytes[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
            let (parsed, replace) = if prefix[0] == 22 {
                tls.map(|r| (tls_records(&prefix), r))
                    .unwrap_or((Parsed::NoDomain, false))
            } else {
                http.map(|r| (http_host(&prefix), r))
                    .unwrap_or((Parsed::NoDomain, false))
            };
            match parsed {
                Parsed::NeedMore => {}
                Parsed::NoDomain => break,
                Parsed::Domain(host) => {
                    found = Some((host, replace));
                    break;
                }
            }
        }
        let _ = context.stream_mut().set_read_timeout(previous);
        if !prefix.is_empty() {
            context.wrap_stream(|inner| {
                Box::new(Replay {
                    prefix: Cursor::new(prefix),
                    inner,
                })
            });
        }
        if let Some((host, replace)) = found {
            self.apply_host(context.metadata_mut(), host, replace);
        }
    }
}
pub(crate) fn domain_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim_end_matches('.').to_ascii_lowercase();
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if let Some(s) = p.strip_prefix("+.").or_else(|| p.strip_prefix('.')) {
        return h == s || h.ends_with(&format!(".{s}"));
    }
    if let Some(s) = p.strip_prefix("*.") {
        return h.ends_with(&format!(".{s}"));
    }
    if p.contains('*') {
        let mut rest = h.as_str();
        let mut first = true;
        for part in p.split('*') {
            if part.is_empty() {
                continue;
            }
            let Some(i) = rest.find(part) else {
                return false;
            };
            if first && !p.starts_with('*') && i != 0 {
                return false;
            }
            rest = &rest[i + part.len()..];
            first = false;
        }
        return p.ends_with('*') || rest.is_empty();
    }
    p == h
}
fn port_matches(range: &str, port: u16) -> bool {
    let r = range.trim();
    if let Some((a, b)) = r.split_once('-') {
        return a
            .parse::<u16>()
            .ok()
            .zip(b.parse::<u16>().ok())
            .is_some_and(|(a, b)| a <= port && port <= b);
    }
    r.parse::<u16>() == Ok(port)
}
fn ip_matches(range: &str, ip: Option<std::net::IpAddr>) -> bool {
    let Some(ip) = ip else {
        return false;
    };
    let (net, bits) = range
        .split_once('/')
        .map(|(a, b)| (a, b.parse::<u32>().ok()))
        .unwrap_or((range, None));
    match (net.parse::<std::net::IpAddr>(), ip) {
        (Ok(std::net::IpAddr::V4(a)), std::net::IpAddr::V4(b)) => {
            let n = bits.unwrap_or(32);
            n <= 32 && (n == 0 || (u32::from(a) >> (32 - n)) == (u32::from(b) >> (32 - n)))
        }
        (Ok(std::net::IpAddr::V6(a)), std::net::IpAddr::V6(b)) => {
            let n = bits.unwrap_or(128);
            n <= 128 && (n == 0 || (u128::from(a) >> (128 - n)) == (u128::from(b) >> (128 - n)))
        }
        _ => false,
    }
}
fn hostname(raw: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?.trim_end_matches('.');
    if text.is_empty() || text.len() > 253 || text.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    if !text.split('.').all(|s| {
        !s.is_empty()
            && s.len() <= 63
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }) {
        return None;
    }
    Some(text.to_ascii_lowercase())
}
fn u16_at(b: &[u8], p: usize) -> Option<usize> {
    Some(u16::from_be_bytes(b.get(p..p + 2)?.try_into().ok()?) as usize)
}
pub(crate) fn tls_hello(handshake: &[u8]) -> Parsed {
    if handshake.len() < 4 {
        return Parsed::NeedMore;
    }
    if handshake[0] != 1 {
        return Parsed::NoDomain;
    }
    let n =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | handshake[3] as usize;
    if n > MAX_HELLO - 4 {
        return Parsed::NoDomain;
    }
    if handshake.len() < n + 4 {
        return Parsed::NeedMore;
    }
    let parse = || -> Option<String> {
        let h = &handshake[4..n + 4];
        let mut p = 34;
        let session = *h.get(p)? as usize;
        p += 1 + session;
        let ciphers = u16_at(h, p)?;
        p += 2 + ciphers;
        let compression = *h.get(p)? as usize;
        p += 1 + compression;
        let ext_len = u16_at(h, p)?;
        p += 2;
        let end = p.checked_add(ext_len).filter(|e| *e <= h.len())?;
        let mut host = None;
        while p < end {
            if p + 4 > end {
                return None;
            }
            let kind = u16_at(h, p)?;
            let size = u16_at(h, p + 2)?;
            p += 4;
            let next = p.checked_add(size).filter(|e| *e <= end)?;
            if kind == 0 {
                let total = u16_at(h, p)?;
                let stop = p.checked_add(2 + total).filter(|e| *e <= next)?;
                let mut c = p + 2;
                while c < stop {
                    let kind = *h.get(c)?;
                    let size = u16_at(h, c + 1)?;
                    c += 3;
                    let finish = c.checked_add(size).filter(|e| *e <= stop)?;
                    if kind == 0 {
                        host = hostname(&h[c..finish]);
                    }
                    c = finish;
                }
            }
            p = next;
        }
        host
    };
    parse().map(Parsed::Domain).unwrap_or(Parsed::NoDomain)
}
pub(crate) fn tls_records(bytes: &[u8]) -> Parsed {
    let mut pos = 0;
    let mut handshake = Vec::new();
    loop {
        if bytes.len() - pos < 5 {
            return Parsed::NeedMore;
        }
        if bytes[pos] != 22 || bytes[pos + 1] != 3 {
            return Parsed::NoDomain;
        }
        let n = u16_at(bytes, pos + 3).unwrap();
        if n > 18432 || n == 0 {
            return Parsed::NoDomain;
        }
        pos += 5;
        if bytes.len() - pos < n {
            return Parsed::NeedMore;
        }
        if handshake.len() + n > MAX_HELLO {
            return Parsed::NoDomain;
        }
        handshake.extend_from_slice(&bytes[pos..pos + n]);
        pos += n;
        let result = tls_hello(&handshake);
        if result != Parsed::NeedMore {
            return result;
        }
        if pos == bytes.len() {
            return Parsed::NeedMore;
        }
    }
}
pub(crate) fn http_host(bytes: &[u8]) -> Parsed {
    if bytes.first().is_some_and(|b| !b.is_ascii_uppercase()) {
        return Parsed::NoDomain;
    }
    let Some(end) = bytes.windows(4).position(|p| p == b"\r\n\r\n") else {
        return if bytes.len() > 32768 {
            Parsed::NoDomain
        } else {
            Parsed::NeedMore
        };
    };
    let Ok(text) = std::str::from_utf8(&bytes[..end]) else {
        return Parsed::NoDomain;
    };
    let mut lines = text.split("\r\n");
    let request = lines.next().unwrap_or("");
    let mut words = request.split_whitespace();
    let method = words.next().unwrap_or("");
    let target = words.next().unwrap_or("");
    if ![
        "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
    ]
    .contains(&method)
    {
        return Parsed::NoDomain;
    }
    let authority = if target.starts_with("http://") || target.starts_with("https://") {
        url::Url::parse(target)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
    } else if method == "CONNECT" {
        Some(target.into())
    } else {
        lines
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.trim().to_owned())
    };
    let Some(a) = authority else {
        return Parsed::NoDomain;
    };
    let h = a
        .rsplit_once(':')
        .filter(|(_, p)| p.parse::<u16>().is_ok())
        .map(|(h, _)| h)
        .unwrap_or(&a);
    hostname(h.as_bytes())
        .map(Parsed::Domain)
        .unwrap_or(Parsed::NoDomain)
}
struct Replay {
    prefix: Cursor<Vec<u8>>,
    inner: BoxedTcpStream,
}
impl Read for Replay {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let n = self.prefix.read(b)?;
        if self.prefix.position() as usize == self.prefix.get_ref().len() {
            self.prefix = Cursor::new(Vec::new());
        }
        if n > 0 {
            Ok(n)
        } else {
            self.inner.read(b)
        }
    }
}
impl Write for Replay {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.inner.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl TcpStream for Replay {
    #[cfg(target_os = "linux")]
    fn splice_socket_fd(&self) -> Option<std::os::fd::RawFd> { self.inner.splice_socket_fd() }
    #[cfg(target_os = "linux")]
    fn splice_read_fd(&self) -> Option<std::os::fd::RawFd> {
        (self.prefix.position() as usize >= self.prefix.get_ref().len())
            .then(|| self.inner.splice_read_fd()).flatten()
    }
    #[cfg(target_os = "linux")]
    fn splice_write_fd(&self) -> Option<std::os::fd::RawFd> { self.inner.splice_write_fd() }
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        self.inner.try_clone_box()
    }
    fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.read_timeout()
    }
    fn set_read_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(t)
    }
    fn tcp_stats(&self) -> Option<mihomo_core::TcpStats> {
        self.inner.tcp_stats()
    }
    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }
    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}
