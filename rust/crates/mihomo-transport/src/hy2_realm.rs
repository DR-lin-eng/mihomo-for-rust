use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::{
    tls_client, BasicAuth, SocketOptions, SystemTcpDialer, TcpDialPurpose, TcpDialer,
    TcpTransportExecutor, TlsOptions, TransportAction, TransportError, TransportHop,
    TransportPlan, TransportPlanRunner, TransportTarget,
};

const NONCE_LEN: usize = 16;
const OBFS_LEN: usize = 32;
const PUNCH_SALT_LEN: usize = 8;
const PUNCH_MAGIC: &[u8; 8] = b"HYRLMv1\0";
const MAX_PADDING: usize = 1024;
const STUN_TRANSACTION_ID_LEN: usize = 12;
const STUN_HEADER_LEN: usize = 20;
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_ATTR_XOR_MAPPED_ADDR: u16 = 0x0020;
const STUN_ATTEMPT_TIMEOUTS: &[Duration] = &[
    Duration::from_millis(500),
    Duration::from_secs(2),
    Duration::from_secs(4),
];
const PUNCH_TIMEOUT: Duration = Duration::from_secs(10);
const PUNCH_INTERVAL: Duration = Duration::from_millis(100);
const SYMMETRIC_NAT_PORT_GAP: u16 = 4;
const SYMMETRIC_NAT_EXTRA_PORTS: u16 = 4;
const SYMMETRIC_NAT_MAX_PORTS_PER_HOST: usize = 32;
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Hy2RealmOptions {
    pub enabled: bool,
    pub server_url: String,
    pub token: String,
    pub realm_id: String,
    pub stun_servers: Vec<String>,
    pub sni: String,
    pub skip_cert_verify: bool,
    pub fingerprint: String,
    pub certificate: String,
    pub private_key: String,
    pub alpn: Vec<String>,
    pub proxy: String,
    pub proxy_plan: Option<Box<crate::TransportPlan>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PunchPacketType {
    Hello = 0x01,
    Ack = 0x02,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PunchMetadata {
    pub nonce: [u8; NONCE_LEN],
    pub obfuscation_key: [u8; OBFS_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmConnectResponse {
    pub addresses: Vec<SocketAddr>,
    pub punch_metadata: PunchMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmPunchEvent {
    pub addresses: Vec<SocketAddr>,
    pub punch_metadata: PunchMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmRegistration {
    pub session_id: String,
    pub ttl_secs: u64,
}

#[derive(Clone)]
pub struct RealmControlClient {
    server_url: String,
    token: String,
    tls: TlsOptions,
    alpn: Vec<String>,
    proxy: String,
    proxy_plan: Option<Box<crate::TransportPlan>>,
    connector: Option<RealmHttpConnector>,
}

type RealmHttpConnector = Arc<
    dyn Fn(
            &TransportTarget,
            &TlsOptions,
            &[String],
            &str,
        ) -> Result<mihomo_core::BoxedTcpStream, TransportError>
        + Send
        + Sync,
>;

impl RealmControlClient {
    pub fn new(options: &Hy2RealmOptions) -> Result<Self, TransportError> {
        if options.server_url.trim().is_empty() {
            return Err(TransportError::InvalidPlan(
                "hysteria2 realm server-url is required".to_owned(),
            ));
        }
        Ok(Self {
            server_url: options.server_url.trim_end_matches('/').to_owned(),
            token: options.token.clone(),
            tls: TlsOptions {
                enabled: options.server_url.starts_with("https://"),
                sni: options.sni.clone(),
                skip_cert_verify: options.skip_cert_verify,
                fingerprint: options.fingerprint.clone(),
                certificate: options.certificate.clone(),
                private_key: options.private_key.clone(),
            },
            alpn: options.alpn.clone(),
            proxy: options.proxy.clone(),
            proxy_plan: options.proxy_plan.clone(),
            connector: None,
        })
    }

    pub fn with_connector(mut self, connector: RealmHttpConnector) -> Self {
        self.connector = Some(connector);
        self
    }

    pub fn connect(
        &self,
        realm_id: &str,
        addresses: &[SocketAddr],
        metadata: PunchMetadata,
    ) -> Result<RealmConnectResponse, TransportError> {
        let body = ConnectBody {
            addresses: addresses.iter().map(ToString::to_string).collect(),
            nonce: hex_encode(&metadata.nonce),
            obfs: hex_encode(&metadata.obfuscation_key),
        };
        let response = self.request_json(
            "POST",
            &self.realm_path(realm_id, "/connect"),
            Some(&self.token),
            Some(serde_json::to_vec(&body).map_err(|err| TransportError::InvalidPlan(err.to_string()))?),
        )?;
        let wire: ConnectBody =
            serde_json::from_slice(&response.body).map_err(|err| TransportError::InvalidPlan(err.to_string()))?;
        Ok(RealmConnectResponse {
            addresses: parse_socket_addrs(&wire.addresses)?,
            punch_metadata: decode_wire_metadata(&wire.nonce, &wire.obfs)?,
        })
    }

    #[allow(dead_code)]
    pub fn register(
        &self,
        realm_id: &str,
        addresses: &[SocketAddr],
    ) -> Result<RealmRegistration, TransportError> {
        let body = AddressesBody {
            addresses: addresses.iter().map(ToString::to_string).collect(),
        };
        let response = self.request_json(
            "POST",
            &self.realm_path(realm_id, ""),
            Some(&self.token),
            Some(serde_json::to_vec(&body).map_err(|err| TransportError::InvalidPlan(err.to_string()))?),
        )?;
        let wire: RegistrationBody =
            serde_json::from_slice(&response.body).map_err(|err| TransportError::InvalidPlan(err.to_string()))?;
        Ok(RealmRegistration {
            session_id: wire.session_id,
            ttl_secs: wire.ttl,
        })
    }

    #[allow(dead_code)]
    pub fn heartbeat(
        &self,
        realm_id: &str,
        session_token: &str,
        addresses: &[SocketAddr],
    ) -> Result<u64, TransportError> {
        let body = AddressesBody {
            addresses: addresses.iter().map(ToString::to_string).collect(),
        };
        let response = self.request_json(
            "POST",
            &self.realm_path(realm_id, "/heartbeat"),
            Some(session_token),
            Some(serde_json::to_vec(&body).map_err(|err| TransportError::InvalidPlan(err.to_string()))?),
        )?;
        let wire: TtlBody =
            serde_json::from_slice(&response.body).map_err(|err| TransportError::InvalidPlan(err.to_string()))?;
        Ok(wire.ttl)
    }

    #[allow(dead_code)]
    pub fn connect_response(
        &self,
        realm_id: &str,
        session_token: &str,
        nonce_hex: &str,
        addresses: &[SocketAddr],
    ) -> Result<(), TransportError> {
        let body = AddressesBody {
            addresses: addresses.iter().map(ToString::to_string).collect(),
        };
        let response = self.request_json(
            "POST",
            &self.realm_path(realm_id, &format!("/connects/{nonce_hex}")),
            Some(session_token),
            Some(serde_json::to_vec(&body).map_err(|err| TransportError::InvalidPlan(err.to_string()))?),
        )?;
        if response.status_code != 204 {
            return Err(TransportError::InvalidPlan(format!(
                "unexpected realm connect response status: {}",
                response.status_code
            )));
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn deregister(
        &self,
        realm_id: &str,
        session_token: &str,
    ) -> Result<(), TransportError> {
        let response = self.request_json(
            "DELETE",
            &self.realm_path(realm_id, ""),
            Some(session_token),
            None,
        )?;
        if response.status_code != 204 {
            return Err(TransportError::InvalidPlan(format!(
                "unexpected realm deregister status: {}",
                response.status_code
            )));
        }
        Ok(())
    }

    pub fn events(
        &self,
        realm_id: &str,
        session_token: &str,
    ) -> Result<Vec<RealmPunchEvent>, TransportError> {
        let response = self.request_json(
            "GET",
            &self.realm_path(realm_id, "/events"),
            Some(session_token),
            None,
        )?;
        let body = String::from_utf8_lossy(&response.body);
        let mut events = Vec::new();
        let mut current_event = String::new();
        let mut current_data = String::new();
        for line in body.lines() {
            if line.is_empty() {
                if current_event == "punch" && !current_data.is_empty() {
                    let wire: ConnectBody = serde_json::from_str(&current_data)
                        .map_err(|err| TransportError::InvalidPlan(err.to_string()))?;
                    events.push(RealmPunchEvent {
                        addresses: parse_socket_addrs(&wire.addresses)?,
                        punch_metadata: decode_wire_metadata(&wire.nonce, &wire.obfs)?,
                    });
                }
                current_event.clear();
                current_data.clear();
                continue;
            }
            if let Some(value) = line.strip_prefix("event:") {
                current_event = value.trim().to_owned();
            } else if let Some(value) = line.strip_prefix("data:") {
                if !current_data.is_empty() {
                    current_data.push('\n');
                }
                current_data.push_str(value.trim());
            }
        }
        Ok(events)
    }

    fn realm_path(&self, realm_id: &str, suffix: &str) -> String {
        format!("{}/v1/{}{}", self.server_url, realm_id, suffix)
    }

    fn request_json(
        &self,
        method: &str,
        url: &str,
        bearer: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<SimpleHttpResponse, TransportError> {
        let target = parse_http_target(url)?;
        let mut stream = if let Some(connector) = &self.connector {
            connector(&target.target, &self.tls, &self.alpn, &self.proxy)?
        } else if let Some(proxy_plan) = &self.proxy_plan {
            let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
            executor.run_plan(proxy_plan)?
        } else {
            connect_http_target_via_realm_proxy(&target.target, &self.tls, &self.alpn, &self.proxy)?
        };
        let body = body.unwrap_or_default();
        let path = target.path_with_query();
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: {}\r\n{}{}Content-Length: {}\r\nConnection: close\r\n\r\n",
            target.host_header,
            bearer
                .map(|token| format!("Authorization: Bearer {token}\r\n"))
                .unwrap_or_default(),
            if body.is_empty() { "" } else { "Content-Type: application/json\r\n" },
            body.len(),
        )?;
        if !body.is_empty() {
            stream.write_all(&body)?;
        }
        read_http_response(&mut *stream)
    }
}

pub fn connect_http_target_via_realm_proxy(
    target: &TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    realm_proxy: &str,
) -> Result<mihomo_core::BoxedTcpStream, TransportError> {
    let proxy = realm_proxy.trim();
    if proxy.is_empty() || proxy.eq_ignore_ascii_case("DIRECT") {
        let mut dialer = SystemTcpDialer;
        let mut stream = dialer.connect(target, &SocketOptions::default(), TcpDialPurpose::ProxyServer)?;
        if tls.enabled {
            stream = tls_client::wrap_stream(stream, target, tls, alpn)?;
        }
        return Ok(stream);
    }

    let hop = transport_hop_from_realm_proxy(proxy, target)?;
    let plan = TransportPlan {
        requested: "__hy2_realm_proxy__".to_owned(),
        selected_path: vec!["__hy2_realm_proxy__".to_owned()],
        leaf_name: "__hy2_realm_proxy__".to_owned(),
        hops: vec![hop],
    };
    let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
    executor.run_plan(&plan)
}

fn transport_hop_from_realm_proxy(
    realm_proxy: &str,
    target: &TransportTarget,
) -> Result<TransportHop, TransportError> {
    let parsed = parse_realm_proxy_target(realm_proxy)?;
    let action = match parsed.scheme.as_str() {
        "http" | "https" => TransportAction::HttpConnect {
            proxy: parsed.target,
            auth: parsed.auth,
            tls: TlsOptions {
                enabled: parsed.scheme == "https",
                sni: String::new(),
                skip_cert_verify: false,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            headers: Default::default(),
            socket: SocketOptions::default(),
            target: target.clone(),
        },
        "socks5" => TransportAction::Socks5Connect {
            proxy: parsed.target,
            auth: parsed.auth,
            tls: TlsOptions::default(),
            udp: false,
            socket: SocketOptions::default(),
            target: target.clone(),
        },
        other => {
            return Err(TransportError::InvalidPlan(format!(
                "unsupported hysteria2 realm proxy scheme: {other}"
            )))
        }
    };
    Ok(TransportHop {
        name: "__hy2_realm_proxy__".to_owned(),
        action,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedRealmProxyTarget {
    scheme: String,
    target: TransportTarget,
    auth: Option<BasicAuth>,
}

fn parse_realm_proxy_target(proxy: &str) -> Result<ParsedRealmProxyTarget, TransportError> {
    let (scheme, rest) = proxy
        .split_once("://")
        .ok_or_else(|| TransportError::InvalidPlan(format!("invalid hysteria2 realm proxy: {proxy}")))?;
    let (authority, path_suffix) = rest.split_once('/').unwrap_or((rest, ""));
    if !path_suffix.is_empty() {
        return Err(TransportError::InvalidPlan(format!(
            "hysteria2 realm proxy must not include a path: {proxy}"
        )));
    }
    let (auth, host_port) = if let Some((userinfo, host_port)) = authority.rsplit_once('@') {
        let (username, password) = userinfo
            .split_once(':')
            .ok_or_else(|| TransportError::InvalidPlan(format!("invalid hysteria2 realm proxy auth: {proxy}")))?;
        (
            Some(BasicAuth {
                username: username.to_owned(),
                password: password.to_owned(),
            }),
            host_port,
        )
    } else {
        (None, authority)
    };
    let target = parse_host_port_target(host_port, default_port_for_proxy_scheme(scheme)?)?;
    Ok(ParsedRealmProxyTarget {
        scheme: scheme.to_ascii_lowercase(),
        target,
        auth,
    })
}

fn default_port_for_proxy_scheme(scheme: &str) -> Result<u16, TransportError> {
    match scheme.to_ascii_lowercase().as_str() {
        "http" => Ok(80),
        "https" => Ok(443),
        "socks5" => Ok(1080),
        other => Err(TransportError::InvalidPlan(format!(
            "unsupported hysteria2 realm proxy scheme: {other}"
        ))),
    }
}

fn parse_host_port_target(authority: &str, default_port: u16) -> Result<TransportTarget, TransportError> {
    if authority.is_empty() {
        return Err(TransportError::InvalidPlan(
            "hysteria2 realm proxy authority is empty".to_owned(),
        ));
    }
    if let Some(stripped) = authority.strip_prefix('[') {
        let (host, rest) = stripped
            .split_once(']')
            .ok_or_else(|| TransportError::InvalidPlan(format!("invalid ipv6 proxy authority: {authority}")))?;
        let port = rest
            .strip_prefix(':')
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(default_port);
        return Ok(TransportTarget::new(host, port));
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        if port.chars().all(|ch| ch.is_ascii_digit()) {
            let port = port.parse::<u16>().map_err(|err| {
                TransportError::InvalidPlan(format!("invalid hysteria2 realm proxy port {port:?}: {err}"))
            })?;
            return Ok(TransportTarget::new(host, port));
        }
    }
    Ok(TransportTarget::new(authority, default_port))
}

#[derive(Clone, Debug)]
struct ParsedHttpTarget {
    target: TransportTarget,
    host_header: String,
    path_with_query: String,
}

impl ParsedHttpTarget {
    fn path_with_query(&self) -> &str {
        &self.path_with_query
    }
}

#[derive(Clone, Debug, Default)]
struct SimpleHttpResponse {
    status_code: u16,
    body: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConnectBody {
    addresses: Vec<String>,
    nonce: String,
    obfs: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AddressesBody {
    addresses: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RegistrationBody {
    session_id: String,
    ttl: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TtlBody {
    ttl: u64,
}

pub fn generate_punch_metadata() -> Result<PunchMetadata, TransportError> {
    let mut nonce = [0_u8; NONCE_LEN];
    let mut obfuscation_key = [0_u8; OBFS_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    rand::thread_rng().fill_bytes(&mut obfuscation_key);
    Ok(PunchMetadata {
        nonce,
        obfuscation_key,
    })
}

pub fn encode_punch_packet(
    packet_type: PunchPacketType,
    metadata: PunchMetadata,
) -> Result<Vec<u8>, TransportError> {
    let mut random = vec![0_u8; PUNCH_SALT_LEN + 2 + MAX_PADDING];
    rand::thread_rng().fill_bytes(&mut random);
    let padding_len =
        (((random[PUNCH_SALT_LEN] as usize) << 8) | random[PUNCH_SALT_LEN + 1] as usize) % (MAX_PADDING + 1);
    let body_len = PUNCH_MAGIC.len() + 1 + NONCE_LEN + padding_len;
    let mut packet = vec![0_u8; PUNCH_SALT_LEN + body_len];
    let (salt, body) = packet.split_at_mut(PUNCH_SALT_LEN);
    salt.copy_from_slice(&random[..PUNCH_SALT_LEN]);
    body[..PUNCH_MAGIC.len()].copy_from_slice(PUNCH_MAGIC);
    body[PUNCH_MAGIC.len()] = packet_type as u8;
    body[PUNCH_MAGIC.len() + 1..PUNCH_MAGIC.len() + 1 + NONCE_LEN].copy_from_slice(&metadata.nonce);
    if padding_len > 0 {
        body[PUNCH_MAGIC.len() + 1 + NONCE_LEN..]
            .copy_from_slice(&random[PUNCH_SALT_LEN + 2..PUNCH_SALT_LEN + 2 + padding_len]);
    }
    xor_obfuscate(metadata.obfuscation_key, salt, body);
    Ok(packet)
}

pub fn decode_punch_packet(
    data: &[u8],
    metadata: PunchMetadata,
) -> Result<PunchPacketType, TransportError> {
    if data.len() < PUNCH_SALT_LEN + PUNCH_MAGIC.len() + 1 + NONCE_LEN {
        return Err(TransportError::InvalidPlan("hysteria2 realm punch packet too short".to_owned()));
    }
    let mut body = data[PUNCH_SALT_LEN..].to_vec();
    xor_obfuscate(metadata.obfuscation_key, &data[..PUNCH_SALT_LEN], &mut body);
    if &body[..PUNCH_MAGIC.len()] != PUNCH_MAGIC {
        return Err(TransportError::InvalidPlan("hysteria2 realm punch magic mismatch".to_owned()));
    }
    let packet_type = match body[PUNCH_MAGIC.len()] {
        0x01 => PunchPacketType::Hello,
        0x02 => PunchPacketType::Ack,
        other => {
            return Err(TransportError::InvalidPlan(format!(
                "hysteria2 realm unknown punch packet type: {other}"
            )))
        }
    };
    if body[PUNCH_MAGIC.len() + 1..PUNCH_MAGIC.len() + 1 + NONCE_LEN] != metadata.nonce {
        return Err(TransportError::InvalidPlan("hysteria2 realm punch nonce mismatch".to_owned()));
    }
    Ok(packet_type)
}

fn xor_obfuscate(obfuscation_key: [u8; OBFS_LEN], salt: &[u8], body: &mut [u8]) {
    let mut key_material = [0_u8; OBFS_LEN + PUNCH_SALT_LEN];
    key_material[..OBFS_LEN].copy_from_slice(&obfuscation_key);
    key_material[OBFS_LEN..].copy_from_slice(salt);
    let key = sha2::Sha256::digest(key_material);
    for (index, byte) in body.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}

fn decode_wire_metadata(nonce_hex: &str, obfs_hex: &str) -> Result<PunchMetadata, TransportError> {
    let nonce = hex::decode(nonce_hex).map_err(|err| TransportError::InvalidPlan(err.to_string()))?;
    let obfs = hex::decode(obfs_hex).map_err(|err| TransportError::InvalidPlan(err.to_string()))?;
    if nonce.len() != NONCE_LEN {
        return Err(TransportError::InvalidPlan(format!("invalid nonce length: {}", nonce.len())));
    }
    if obfs.len() != OBFS_LEN {
        return Err(TransportError::InvalidPlan(format!("invalid obfs length: {}", obfs.len())));
    }
    let mut metadata = PunchMetadata {
        nonce: [0_u8; NONCE_LEN],
        obfuscation_key: [0_u8; OBFS_LEN],
    };
    metadata.nonce.copy_from_slice(&nonce);
    metadata.obfuscation_key.copy_from_slice(&obfs);
    Ok(metadata)
}

fn parse_socket_addrs(values: &[String]) -> Result<Vec<SocketAddr>, TransportError> {
    let mut result = Vec::new();
    for value in values {
        let mut addrs = value
            .to_socket_addrs()
            .map_err(|err| TransportError::InvalidPlan(err.to_string()))?;
        let addr = addrs
            .next()
            .ok_or_else(|| TransportError::InvalidPlan(format!("unresolved address: {value}")))?;
        result.push(addr);
    }
    Ok(result)
}

fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0f) as usize] as char);
    }
    out
}

fn parse_http_target(url: &str) -> Result<ParsedHttpTarget, TransportError> {
    let scheme_split = url
        .split_once("://")
        .ok_or_else(|| TransportError::InvalidPlan(format!("invalid url: {url}")))?;
    let (_, rest) = scheme_split;
    let (authority, path) = rest
        .split_once('/')
        .map(|(authority, path)| (authority, format!("/{path}")))
        .unwrap_or((rest, "/".to_owned()));
    let host_header = authority.to_owned();
    let host = if authority.starts_with('[') {
        authority
            .split_once(']')
            .map(|(host, _)| host.trim_start_matches('[').to_owned())
            .unwrap_or_else(|| authority.to_owned())
    } else {
        authority
            .split_once(':')
            .map(|(host, _)| host.to_owned())
            .unwrap_or_else(|| authority.to_owned())
    };
    let port = authority
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .unwrap_or_else(|| if url.starts_with("https://") { 443 } else { 80 });
    Ok(ParsedHttpTarget {
        target: TransportTarget::new(&host, port),
        host_header,
        path_with_query: path,
    })
}

fn read_http_response(stream: &mut dyn Read) -> Result<SimpleHttpResponse, TransportError> {
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(TransportError::from)?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| TransportError::InvalidPlan("invalid http response".to_owned()))?;
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line).map_err(TransportError::from)?;
        if bytes == 0 {
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse::<usize>().unwrap_or_default();
            }
        }
    }
    let mut body = vec![0_u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).map_err(TransportError::from)?;
    }
    Ok(SimpleHttpResponse { status_code, body })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct StunTransactionId(pub [u8; STUN_TRANSACTION_ID_LEN]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StunMessage {
    pub raw: Vec<u8>,
    pub transaction_id: StunTransactionId,
}

pub fn stun_is_message(data: &[u8]) -> bool {
    data.len() >= STUN_HEADER_LEN && u32::from_be_bytes(data[4..8].try_into().unwrap()) == STUN_MAGIC_COOKIE
}

pub fn stun_new_binding_request() -> Result<StunMessage, TransportError> {
    let mut transaction_id = [0_u8; STUN_TRANSACTION_ID_LEN];
    rand::thread_rng().fill_bytes(&mut transaction_id);
    let mut raw = vec![0_u8; STUN_HEADER_LEN];
    raw[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    raw[2..4].copy_from_slice(&0_u16.to_be_bytes());
    raw[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    raw[8..STUN_HEADER_LEN].copy_from_slice(&transaction_id);
    Ok(StunMessage {
        raw,
        transaction_id: StunTransactionId(transaction_id),
    })
}

pub fn stun_decode(data: &[u8]) -> Result<StunMessage, TransportError> {
    if data.len() < STUN_HEADER_LEN {
        return Err(TransportError::InvalidPlan(format!(
            "stun message too short: {}",
            data.len()
        )));
    }
    if u32::from_be_bytes(data[4..8].try_into().unwrap()) != STUN_MAGIC_COOKIE {
        return Err(TransportError::InvalidPlan("invalid stun magic cookie".to_owned()));
    }
    let attr_len = u16::from_be_bytes(data[2..4].try_into().unwrap()) as usize;
    if data.len() < STUN_HEADER_LEN + attr_len {
        return Err(TransportError::InvalidPlan("truncated stun message".to_owned()));
    }
    let mut transaction_id = [0_u8; STUN_TRANSACTION_ID_LEN];
    transaction_id.copy_from_slice(&data[8..STUN_HEADER_LEN]);
    Ok(StunMessage {
        raw: data[..STUN_HEADER_LEN + attr_len].to_vec(),
        transaction_id: StunTransactionId(transaction_id),
    })
}

pub fn stun_xor_mapped_address(message: &StunMessage) -> Result<SocketAddr, TransportError> {
    let attr_len = u16::from_be_bytes(message.raw[2..4].try_into().unwrap()) as usize;
    let mut body = &message.raw[STUN_HEADER_LEN..STUN_HEADER_LEN + attr_len];
    while body.len() >= 4 {
        let attr_type = u16::from_be_bytes(body[0..2].try_into().unwrap());
        let value_len = u16::from_be_bytes(body[2..4].try_into().unwrap()) as usize;
        let padded_len = (value_len + 3) & !3;
        if 4 + padded_len > body.len() {
            return Err(TransportError::InvalidPlan("truncated stun attribute".to_owned()));
        }
        let value = &body[4..4 + value_len];
        body = &body[4 + padded_len..];
        if attr_type != STUN_ATTR_XOR_MAPPED_ADDR {
            continue;
        }
        if value.len() < 4 {
            return Err(TransportError::InvalidPlan("xor-mapped-address too short".to_owned()));
        }
        let family = value[1];
        let port = u16::from_be_bytes(value[2..4].try_into().unwrap()) ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        let ip_len = match family {
            0x01 => 4,
            0x02 => 16,
            other => {
                return Err(TransportError::InvalidPlan(format!(
                    "unknown xor-mapped-address family: {other}"
                )))
            }
        };
        if value.len() != 4 + ip_len {
            return Err(TransportError::InvalidPlan("xor-mapped-address length mismatch".to_owned()));
        }
        let mut key = [0_u8; 4 + STUN_TRANSACTION_ID_LEN];
        key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        key[4..].copy_from_slice(&message.transaction_id.0);
        let mut ip = vec![0_u8; ip_len];
        for index in 0..ip_len {
            ip[index] = value[4 + index] ^ key[index];
        }
        let ip = match ip_len {
            4 => IpAddr::from(<[u8; 4]>::try_from(ip.as_slice()).unwrap()),
            16 => IpAddr::from(<[u8; 16]>::try_from(ip.as_slice()).unwrap()),
            _ => unreachable!(),
        };
        return Ok(SocketAddr::new(ip, port));
    }
    Err(TransportError::InvalidPlan(
        "xor-mapped-address not found".to_owned(),
    ))
}

pub fn discover_stun_addresses(
    socket: &UdpSocket,
    servers: &[String],
) -> Result<Vec<SocketAddr>, TransportError> {
    let requests = servers
        .iter()
        .map(|server| {
            let mut addrs = server
                .to_socket_addrs()
                .map_err(|err| TransportError::InvalidPlan(err.to_string()))?;
            let addr = addrs.next().ok_or_else(|| {
                TransportError::InvalidPlan(format!("unresolved stun server: {server}"))
            })?;
            Ok((addr, stun_new_binding_request()?))
        })
        .collect::<Result<Vec<_>, TransportError>>()?;
    let mut pending = requests
        .iter()
        .map(|(_, request)| request.transaction_id)
        .collect::<Vec<_>>();
    let mut seen = Vec::<SocketAddr>::new();
    let mut buf = [0_u8; 1500];
    for timeout in STUN_ATTEMPT_TIMEOUTS {
        if pending.is_empty() {
            break;
        }
        for (addr, request) in &requests {
            if pending.contains(&request.transaction_id) {
                let _ = socket.send_to(&request.raw, addr);
            }
        }
        let deadline = Instant::now() + *timeout;
        socket
            .set_read_timeout(Some(*timeout))
            .map_err(TransportError::from)?;
        while Instant::now() < deadline && !pending.is_empty() {
            match socket.recv_from(&mut buf) {
                Ok((read, _)) => {
                    let message = match stun_decode(&buf[..read]) {
                        Ok(message) => message,
                        Err(_) => continue,
                    };
                    if !pending.contains(&message.transaction_id) {
                        continue;
                    }
                    pending.retain(|id| id != &message.transaction_id);
                    let address = match stun_xor_mapped_address(&message) {
                        Ok(address) => address,
                        Err(_) => continue,
                    };
                    if !seen.contains(&address) {
                        seen.push(address);
                    }
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(err) => return Err(TransportError::from(err)),
            }
        }
    }
    if seen.is_empty() {
        return Err(TransportError::InvalidPlan(
            "no stun responses received".to_owned(),
        ));
    }
    Ok(seen)
}

pub fn punch_peer_addresses(
    socket: &UdpSocket,
    local_addresses: &[SocketAddr],
    peer_addresses: &[SocketAddr],
    metadata: PunchMetadata,
) -> Result<SocketAddr, TransportError> {
    let candidates = candidate_punch_addrs(local_addresses, peer_addresses, socket.local_addr().ok());
    if candidates.is_empty() {
        return Err(TransportError::InvalidPlan(
            "no compatible peer addresses".to_owned(),
        ));
    }
    let deadline = Instant::now() + PUNCH_TIMEOUT;
    let mut next_send = Instant::now();
    let mut buf = [0_u8; 1600];
    while Instant::now() < deadline {
        let now = Instant::now();
        if now >= next_send {
            let hello = encode_punch_packet(PunchPacketType::Hello, metadata)?;
            for candidate in &candidates {
                let _ = socket.send_to(&hello, candidate);
            }
            next_send = now + PUNCH_INTERVAL;
        }
        let read_deadline = next_send.min(deadline);
        let timeout = read_deadline.saturating_duration_since(Instant::now());
        socket
            .set_read_timeout(Some(timeout))
            .map_err(TransportError::from)?;
        match socket.recv_from(&mut buf) {
            Ok((read, from)) => {
                if stun_is_message(&buf[..read]) {
                    continue;
                }
                let from = match from {
                    SocketAddr::V4(addr) => SocketAddr::V4(addr),
                    SocketAddr::V6(addr) => SocketAddr::V6(addr),
                };
                let packet_type = match decode_punch_packet(&buf[..read], metadata) {
                    Ok(packet_type) => packet_type,
                    Err(_) => continue,
                };
                if packet_type == PunchPacketType::Hello {
                    let ack = encode_punch_packet(PunchPacketType::Ack, metadata)?;
                    let _ = socket.send_to(&ack, from);
                }
                return Ok(from);
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(err) => return Err(TransportError::from(err)),
        }
    }
    Err(TransportError::InvalidPlan("punch timeout".to_owned()))
}

fn candidate_punch_addrs(
    local_addresses: &[SocketAddr],
    peer_addresses: &[SocketAddr],
    socket_local_addr: Option<SocketAddr>,
) -> Vec<SocketAddr> {
    let mut allow_v4 = false;
    let mut allow_v6 = false;
    for address in local_addresses {
        if address.ip().is_ipv4() {
            allow_v4 = true;
        } else {
            allow_v6 = true;
        }
    }
    if !allow_v4 && !allow_v6 {
        match socket_local_addr {
            Some(SocketAddr::V4(_)) => allow_v4 = true,
            Some(SocketAddr::V6(addr)) if !addr.ip().is_unspecified() => allow_v6 = true,
            _ => {
                allow_v4 = true;
                allow_v6 = true;
            }
        }
    }

    let mut seen = Vec::<SocketAddr>::new();
    let mut candidates = Vec::new();
    for address in peer_addresses {
        if address.port() == 0 {
            continue;
        }
        if address.ip().is_ipv4() && !allow_v4 {
            continue;
        }
        if address.ip().is_ipv6() && !allow_v6 {
            continue;
        }
        if !seen.contains(address) {
            seen.push(*address);
            candidates.push(*address);
        }
    }
    expand_symmetric_nat_candidates(candidates, &mut seen)
}

fn expand_symmetric_nat_candidates(
    mut candidates: Vec<SocketAddr>,
    seen: &mut Vec<SocketAddr>,
) -> Vec<SocketAddr> {
    let mut ports_by_ip: std::collections::BTreeMap<IpAddr, Vec<u16>> = std::collections::BTreeMap::new();
    for address in &candidates {
        if address.ip().is_ipv4() {
            ports_by_ip.entry(address.ip()).or_default().push(address.port());
        }
    }
    for (ip, mut ports) in ports_by_ip {
        ports.sort_unstable();
        ports.dedup();
        if !predictable_port_group(&ports) {
            continue;
        }
        let start = ports[0];
        let end = ports[ports.len() - 1].saturating_add(SYMMETRIC_NAT_EXTRA_PORTS);
        let mut added = 0usize;
        let mut port = start;
        while port <= end && added < SYMMETRIC_NAT_MAX_PORTS_PER_HOST {
            let address = SocketAddr::new(ip, port);
            if !seen.contains(&address) {
                seen.push(address);
                candidates.push(address);
                added += 1;
            }
            if port == u16::MAX {
                break;
            }
            port += 1;
        }
    }
    candidates
}

fn predictable_port_group(ports: &[u16]) -> bool {
    if ports.len() < 2 {
        return false;
    }
    for window in ports.windows(2) {
        if window[1] - window[0] > SYMMETRIC_NAT_PORT_GAP {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punch_packet_round_trip_restores_metadata() {
        let metadata = generate_punch_metadata().unwrap();
        let packet = encode_punch_packet(PunchPacketType::Hello, metadata).unwrap();
        let decoded = decode_punch_packet(&packet, metadata).unwrap();
        assert_eq!(decoded, PunchPacketType::Hello);
    }

    #[test]
    fn stun_binding_request_has_expected_cookie() {
        let request = stun_new_binding_request().unwrap();
        assert!(stun_is_message(&request.raw));
        assert_eq!(
            u32::from_be_bytes(request.raw[4..8].try_into().unwrap()),
            STUN_MAGIC_COOKIE
        );
    }

    #[test]
    fn candidate_expansion_adds_predicted_ports_for_ipv4_group() {
        let candidates = vec![
            SocketAddr::from(([1, 2, 3, 4], 5000)),
            SocketAddr::from(([1, 2, 3, 4], 5002)),
        ];
        let mut seen = candidates.clone();
        let expanded = expand_symmetric_nat_candidates(candidates, &mut seen);
        assert!(expanded.contains(&SocketAddr::from(([1, 2, 3, 4], 5001))));
        assert!(expanded.contains(&SocketAddr::from(([1, 2, 3, 4], 5003))));
    }

    #[test]
    fn candidate_filter_respects_local_address_family() {
        let local = vec![SocketAddr::from(([127, 0, 0, 1], 1000))];
        let peers = vec![
            SocketAddr::from(([1, 2, 3, 4], 5000)),
            "[2001:db8::1]:5000".parse().unwrap(),
        ];
        let result = candidate_punch_addrs(&local, &peers, None);
        assert_eq!(result, vec![SocketAddr::from(([1, 2, 3, 4], 5000))]);
    }
}
