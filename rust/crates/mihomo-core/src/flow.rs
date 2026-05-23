use std::any::Any;
use std::io;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use mihomo_buf::ByteWindow;

static NEXT_CONTEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddrKind {
    Ipv4,
    DomainName,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkKind {
    Tcp,
    Udp,
    All,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionKind {
    Http,
    Https,
    Socks4,
    Socks5,
    ShadowSocks,
    Vmess,
    Vless,
    Redir,
    TProxy,
    Trojan,
    Tunnel,
    Tun,
    Tuic,
    Hysteria2,
    AnyTls,
    Mieru,
    Sudoku,
    TrustTunnel,
    Inner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsMode {
    Normal,
    FakeIp,
    Mapping,
    Hosts,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub network: NetworkKind,
    pub kind: SessionKind,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_geoip: Option<Vec<String>>,
    pub dst_geoip: Option<Vec<String>>,
    pub src_ip_asn: String,
    pub dst_ip_asn: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub inbound_ip: Option<IpAddr>,
    pub inbound_port: Option<u16>,
    pub inbound_name: String,
    pub inbound_user: String,
    pub host: Option<String>,
    pub dns_mode: DnsMode,
    pub uid: Option<u32>,
    pub process: String,
    pub process_path: String,
    pub special_proxy: String,
    pub special_rules: String,
    pub remote_destination: String,
    pub dscp: Option<u8>,
    pub sniff_host: Option<String>,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            network: NetworkKind::Tcp,
            kind: SessionKind::Inner,
            src_ip: None,
            dst_ip: None,
            src_geoip: None,
            dst_geoip: None,
            src_ip_asn: String::new(),
            dst_ip_asn: String::new(),
            src_port: None,
            dst_port: None,
            inbound_ip: None,
            inbound_port: None,
            inbound_name: String::new(),
            inbound_user: String::new(),
            host: None,
            dns_mode: DnsMode::Normal,
            uid: None,
            process: String::new(),
            process_path: String::new(),
            special_proxy: String::new(),
            special_rules: String::new(),
            remote_destination: String::new(),
            dscp: None,
            sniff_host: None,
        }
    }
}

impl Metadata {
    pub fn remote_address(&self) -> Option<String> {
        let port = self.dst_port?;
        Some(format!("{}:{port}", self.display_host()))
    }

    pub fn source_address(&self) -> Option<String> {
        let ip = self.src_ip?;
        let port = self.src_port?;
        Some(format!("{ip}:{port}"))
    }

    pub fn source_socket_addr(&self) -> Option<SocketAddr> {
        Some(SocketAddr::new(self.src_ip?, self.src_port?))
    }

    pub fn destination_socket_addr(&self) -> Option<SocketAddr> {
        Some(SocketAddr::new(self.dst_ip?, self.dst_port?))
    }

    pub fn source_valid(&self) -> bool {
        self.src_ip.is_some() && self.src_port.is_some()
    }

    pub fn addr_kind(&self) -> AddrKind {
        match (self.host.as_ref(), self.dst_ip) {
            (Some(host), _) if !host.is_empty() => AddrKind::DomainName,
            (_, Some(IpAddr::V4(_))) => AddrKind::Ipv4,
            _ => AddrKind::Ipv6,
        }
    }

    pub fn resolved(&self) -> bool {
        self.dst_ip.is_some()
    }

    pub fn rule_host(&self) -> Option<&str> {
        self.sniff_host
            .as_deref()
            .filter(|value| !value.is_empty())
            .or(self.host.as_deref())
    }

    pub fn pure(&self) -> Self {
        let mut cloned = self.clone();
        if matches!(cloned.dns_mode, DnsMode::Mapping | DnsMode::Hosts) && cloned.dst_ip.is_some() {
            cloned.host = None;
        }
        cloned
    }

    pub fn valid(&self) -> bool {
        self.host.as_ref().is_some_and(|value| !value.is_empty()) || self.dst_ip.is_some()
    }

    pub fn display_host(&self) -> String {
        if let Some(host) = self.host.as_ref().filter(|value| !value.is_empty()) {
            host.clone()
        } else if let Some(ip) = self.dst_ip {
            ip.to_string()
        } else {
            "<nil>".to_owned()
        }
    }

    pub fn set_remote_address(&mut self, raw: &str) -> Result<(), ParseMetadataError> {
        let (host, port) = split_host_port(raw)?;
        self.dst_port = Some(port);
        if let Ok(ip) = IpAddr::from_str(&host) {
            self.dst_ip = Some(ip);
            self.host = None;
        } else {
            self.dst_ip = None;
            self.host = Some(host);
        }
        Ok(())
    }

    pub fn swap_src_dst(&mut self) {
        std::mem::swap(&mut self.src_ip, &mut self.dst_ip);
        std::mem::swap(&mut self.src_port, &mut self.dst_port);
        std::mem::swap(&mut self.src_ip_asn, &mut self.dst_ip_asn);
        std::mem::swap(&mut self.src_geoip, &mut self.dst_geoip);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseMetadataError {
    MissingPort(String),
    InvalidPort(String),
}

impl std::fmt::Display for ParseMetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPort(value) => write!(f, "missing port in address {value}"),
            Self::InvalidPort(value) => write!(f, "invalid port in address {value}"),
        }
    }
}

impl std::error::Error for ParseMetadataError {}

pub trait TcpStream: Read + Write + Send + Any {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream>;

    fn shutdown_write(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown_write()
    }
}

impl TcpStream for std::net::TcpStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(self.try_clone()?))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown(Shutdown::Both)
    }
}

impl TcpStream for Box<dyn TcpStream> {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        (**self).try_clone_box()
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        (**self).shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        (**self).shutdown_all()
    }
}

pub type BoxedTcpStream = Box<dyn TcpStream>;

pub struct ConnectionContext {
    id: u64,
    metadata: Metadata,
    stream: BoxedTcpStream,
}

impl ConnectionContext {
    pub fn new(stream: impl TcpStream + 'static, metadata: Metadata) -> Self {
        Self {
            id: NEXT_CONTEXT_ID.fetch_add(1, Ordering::Relaxed),
            metadata,
            stream: Box::new(stream),
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    pub fn metadata_mut(&mut self) -> &mut Metadata {
        &mut self.metadata
    }

    pub fn stream_mut(&mut self) -> &mut dyn TcpStream {
        &mut *self.stream
    }
}

pub trait WriteBack: Send + Sync {
    fn write_back(&self, payload: ByteWindow, source: Option<SocketAddr>) -> io::Result<usize>;
}

pub trait UdpPacket: WriteBack + Send + Sync {
    fn payload(&self) -> ByteWindow;
    fn local_addr(&self) -> SocketAddr;
    fn inbound_addr(&self) -> Option<SocketAddr> {
        None
    }
}

#[derive(Clone)]
pub struct PacketEnvelope {
    packet: Arc<dyn UdpPacket>,
    metadata: Metadata,
    key: String,
}

impl PacketEnvelope {
    pub fn new(packet: Arc<dyn UdpPacket>, metadata: Metadata) -> Self {
        let key = packet.local_addr().to_string();
        Self { packet, metadata, key }
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    pub fn metadata_mut(&mut self) -> &mut Metadata {
        &mut self.metadata
    }

    pub fn payload(&self) -> ByteWindow {
        self.packet.payload()
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.packet.local_addr()
    }

    pub fn inbound_addr(&self) -> Option<SocketAddr> {
        self.packet.inbound_addr()
    }

    pub fn write_back(&self, payload: ByteWindow, source: Option<SocketAddr>) -> io::Result<usize> {
        self.packet.write_back(payload, source)
    }
}

pub trait UdpSession: Send {
    fn resolve_udp(&mut self, metadata: &mut Metadata) -> io::Result<()>;
    fn prepare_send(&mut self, _metadata: &mut Metadata) -> io::Result<()> {
        Ok(())
    }
    fn send_to(&mut self, payload: ByteWindow, target: SocketAddr) -> io::Result<usize>;
}

pub trait Tunnel: Send + Sync {
    fn handle_tcp(&self, context: ConnectionContext);
    fn handle_udp(&self, packet: PacketEnvelope);
}

fn split_host_port(raw: &str) -> Result<(String, u16), ParseMetadataError> {
    if let Some(rest) = raw.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return Err(ParseMetadataError::MissingPort(raw.to_owned()));
        };
        let port = port
            .parse::<u16>()
            .map_err(|_| ParseMetadataError::InvalidPort(raw.to_owned()))?;
        return Ok((host.to_owned(), port));
    }

    let Some((host, port)) = raw.rsplit_once(':') else {
        return Err(ParseMetadataError::MissingPort(raw.to_owned()));
    };
    let port = port
        .parse::<u16>()
        .map_err(|_| ParseMetadataError::InvalidPort(raw.to_owned()))?;
    Ok((host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{DnsMode, Metadata, ParseMetadataError};

    #[test]
    fn pure_clears_host_for_mapping_and_hosts_modes() {
        let mut metadata = Metadata::default();
        metadata.host = Some("example.com".into());
        metadata.dst_ip = Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        metadata.dns_mode = DnsMode::Mapping;
        assert_eq!(metadata.pure().host, None);
    }

    #[test]
    fn set_remote_address_supports_domain_and_ip() {
        let mut metadata = Metadata::default();
        metadata.set_remote_address("example.com:443").unwrap();
        assert_eq!(metadata.host.as_deref(), Some("example.com"));
        assert_eq!(metadata.dst_port, Some(443));

        metadata.set_remote_address("1.1.1.1:53").unwrap();
        assert_eq!(metadata.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert_eq!(metadata.host, None);
    }

    #[test]
    fn set_remote_address_rejects_missing_port() {
        let mut metadata = Metadata::default();
        let err = metadata.set_remote_address("example.com").unwrap_err();
        assert_eq!(err, ParseMetadataError::MissingPort("example.com".into()));
    }
}
