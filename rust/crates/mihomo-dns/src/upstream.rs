use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig as QuinnClientConfig, Endpoint as QuinnEndpoint};
use rustls::{Certificate, ClientConfig, ClientConnection, OwnedTrustAnchor, RootCertStore, ServerName, StreamOwned};
use rustls023::crypto::aws_lc_rs;
use rustls023::pki_types::CertificateDer;
use rustls023::{ClientConfig as RustlsClientConfig, RootCertStore as RootCertStore023};
use tokio::runtime::Builder as TokioRuntimeBuilder;
use url::Url;

use crate::packet::{
    build_dns_query, build_dns_response, parse_dns_query_packet, parse_dns_response,
};
use crate::{DnsError, DnsPacketTransport, DnsRecordType, DnsUpstream, NetworkDnsUpstream};

impl<T> NetworkDnsUpstream<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next_request_id: 1,
        }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: DnsPacketTransport> DnsUpstream for NetworkDnsUpstream<T> {
    fn resolve(&mut self, servers: &[String], host: &str) -> Result<Vec<IpAddr>, DnsError> {
        let mut resolved = Vec::new();
        for server in servers {
            match query_server(self, server, host) {
                Ok(ips) if !ips.is_empty() => {
                    for ip in ips {
                        if !resolved.contains(&ip) {
                            resolved.push(ip);
                        }
                    }
                    if !resolved.is_empty() {
                        return Ok(resolved);
                    }
                }
                Ok(_) => {}
                Err(DnsError::UnsupportedNameserver(_)) => continue,
                Err(_) => continue,
            }
        }
        Ok(resolved)
    }

    fn exchange(&mut self, servers: &[String], packet: &[u8]) -> Result<Vec<u8>, DnsError> {
        let mut last_error = None;
        for server in servers {
            match self.transport.exchange(server, packet) {
                Ok(response) => match crate::packet::validate_dns_reply(packet, &response) {
                    Ok(()) => return Ok(response),
                    Err(err) => last_error = Some(err),
                },
                Err(err) => last_error = Some(err),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            DnsError::ResolveFailed("no DNS upstream servers configured".to_owned())
        }))
    }
}

impl crate::DnsPacketTransport for crate::SystemDnsPacketTransport {
    fn exchange(&mut self, server: &str, payload: &[u8]) -> Result<Vec<u8>, DnsError> {
        match parse_nameserver(server)? {
            NameserverTransport::Udp(endpoint) => exchange_udp(&endpoint, payload),
            NameserverTransport::Tcp(endpoint) => exchange_tcp(&endpoint, payload),
            NameserverTransport::Tls(endpoint) => exchange_tls(&endpoint, payload),
            NameserverTransport::Http(url) => exchange_http(&url, payload, false),
            NameserverTransport::Https(url) => exchange_http(&url, payload, true),
            NameserverTransport::Quic(endpoint) => exchange_quic(&endpoint, payload),
            NameserverTransport::RCode(rcode) => exchange_rcode(payload, rcode),
            NameserverTransport::System => exchange_system(server, payload),
        }
    }
}

pub(crate) fn query_server<T: DnsPacketTransport>(
    upstream: &mut NetworkDnsUpstream<T>,
    server: &str,
    host: &str,
) -> Result<Vec<IpAddr>, DnsError> {
    let mut answers = Vec::new();
    for query_type in [DnsRecordType::A, DnsRecordType::Aaaa] {
        let request_id = upstream.next_request_id;
        upstream.next_request_id = upstream.next_request_id.wrapping_add(1);
        let payload = build_dns_query(host, query_type, request_id)?;
        let response = upstream.transport.exchange(server, &payload)?;
        let mut ips = parse_dns_response(&response, request_id, query_type)?;
        answers.append(&mut ips);
    }
    Ok(answers)
}

enum NameserverTransport {
    Udp(String),
    Tcp(String),
    Tls(String),
    Http(Url),
    Https(Url),
    Quic(String),
    RCode(u8),
    System,
}

fn parse_nameserver(raw: &str) -> Result<NameserverTransport, DnsError> {
    let endpoint = raw.split('#').next().unwrap_or(raw).trim();
    if endpoint.is_empty() {
        return Err(DnsError::UnsupportedNameserver(raw.to_owned()));
    }
    if endpoint.eq_ignore_ascii_case("system") || endpoint.eq_ignore_ascii_case("system://") {
        return Ok(NameserverTransport::System);
    }
    if let Some(endpoint) = endpoint.strip_prefix("udp://") {
        return Ok(NameserverTransport::Udp(normalize_host_port(endpoint, 53)?));
    }
    if let Some(endpoint) = endpoint.strip_prefix("tcp://") {
        return Ok(NameserverTransport::Tcp(normalize_host_port(endpoint, 53)?));
    }
    if let Some(endpoint) = endpoint.strip_prefix("tls://") {
        return Ok(NameserverTransport::Tls(normalize_host_port(endpoint, 853)?));
    }
    if let Some(endpoint) = endpoint.strip_prefix("quic://") {
        return Ok(NameserverTransport::Quic(normalize_host_port(endpoint, 853)?));
    }
    if let Some(kind) = endpoint.strip_prefix("rcode://") {
        return Ok(NameserverTransport::RCode(parse_rcode(kind.trim())?));
    }
    if endpoint.starts_with("http://") {
        return Ok(NameserverTransport::Http(
            Url::parse(endpoint).map_err(|_| DnsError::UnsupportedNameserver(raw.to_owned()))?,
        ));
    }
    if endpoint.starts_with("https://") {
        return Ok(NameserverTransport::Https(
            Url::parse(endpoint).map_err(|_| DnsError::UnsupportedNameserver(raw.to_owned()))?,
        ));
    }
    if endpoint.contains("://") {
        return Err(DnsError::UnsupportedNameserver(raw.to_owned()));
    }
    Ok(NameserverTransport::Udp(normalize_host_port(endpoint, 53)?))
}

fn normalize_host_port(endpoint: &str, default_port: u16) -> Result<String, DnsError> {
    if endpoint.starts_with('[') {
        if endpoint.contains("]:") {
            return Ok(endpoint.to_owned());
        }
        return Ok(format!("{endpoint}:{default_port}"));
    }
    if endpoint.rsplit_once(':').is_some() {
        Ok(endpoint.to_owned())
    } else {
        Ok(format!("{endpoint}:{default_port}"))
    }
}

fn exchange_udp(endpoint: &str, payload: &[u8]) -> Result<Vec<u8>, DnsError> {
    let bind_addr = if endpoint.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" };
    let socket = mihomo_core::bind_outbound_udp(bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    socket.send_to(payload, endpoint)?;
    let mut buf = [0_u8; 1500];
    let (read, _) = socket.recv_from(&mut buf)?;
    Ok(buf[..read].to_vec())
}

fn exchange_tcp(endpoint: &str, payload: &[u8]) -> Result<Vec<u8>, DnsError> {
    let mut stream = mihomo_core::connect_outbound_tcp(endpoint)?;
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    let length = u16::try_from(payload.len())
        .map_err(|_| DnsError::DnsProtocol("dns tcp query too large".to_owned()))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;

    let mut header = [0_u8; 2];
    stream.read_exact(&mut header)?;
    let response_len = u16::from_be_bytes(header) as usize;
    let mut response = vec![0_u8; response_len];
    stream.read_exact(&mut response)?;
    Ok(response)
}

fn exchange_tls(endpoint: &str, payload: &[u8]) -> Result<Vec<u8>, DnsError> {
    let stream = mihomo_core::connect_outbound_tcp(endpoint)?;
    exchange_tls_stream(stream, endpoint, endpoint.split(':').next().unwrap_or(endpoint), payload)
}

fn exchange_tls_stream(
    stream: TcpStream,
    endpoint: &str,
    server_name_host: &str,
    payload: &[u8],
) -> Result<Vec<u8>, DnsError> {
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    let server_name = ServerName::try_from(server_name_host.trim_matches(['[', ']']))
        .map_err(|_| DnsError::UnsupportedNameserver(endpoint.to_owned()))?;
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(system_root_store()?)
        .with_no_client_auth();
    let connection = ClientConnection::new(std::sync::Arc::new(config), server_name)
        .map_err(|err| DnsError::Io(err.to_string()))?;
    let mut tls = StreamOwned::new(connection, stream);

    let length = u16::try_from(payload.len())
        .map_err(|_| DnsError::DnsProtocol("dns tls query too large".to_owned()))?;
    tls.write_all(&length.to_be_bytes())?;
    tls.write_all(payload)?;
    tls.flush()?;

    let mut header = [0_u8; 2];
    tls.read_exact(&mut header)?;
    let response_len = u16::from_be_bytes(header) as usize;
    let mut response = vec![0_u8; response_len];
    tls.read_exact(&mut response)?;
    Ok(response)
}

fn exchange_http(url: &Url, payload: &[u8], tls: bool) -> Result<Vec<u8>, DnsError> {
    let host = url
        .host_str()
        .ok_or_else(|| DnsError::UnsupportedNameserver(url.as_str().to_owned()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| DnsError::UnsupportedNameserver(url.as_str().to_owned()))?;
    let endpoint = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let default_port = if tls { 443 } else { 80 };
    let host_header = if port == default_port {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };
    let path = if url.path().is_empty() { "/" } else { url.path() };
    let request_target = if let Some(query) = url.query() {
        format!("{path}?{query}")
    } else {
        path.to_owned()
    };

    let mut raw_stream = mihomo_core::connect_outbound_tcp(&endpoint)?;
    raw_stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    raw_stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    if tls {
        let mut tls_stream = exchange_tls_stream_open(raw_stream, &endpoint, host)?;
        return exchange_http_over_stream(&mut tls_stream, &request_target, &host_header, payload);
    }

    exchange_http_over_stream(&mut raw_stream, &request_target, &host_header, payload)
}

fn exchange_quic(endpoint: &str, payload: &[u8]) -> Result<Vec<u8>, DnsError> {
    let _ = aws_lc_rs::default_provider().install_default();
    let remote_addrs = endpoint.to_socket_addrs()?.collect::<Vec<_>>();
    if remote_addrs.is_empty() {
        return Err(DnsError::ResolveFailed(endpoint.to_owned()));
    }
    let host = endpoint
        .rsplit_once(':')
        .map(|(host, _)| host.trim_matches(['[', ']']).to_owned())
        .ok_or_else(|| DnsError::UnsupportedNameserver(endpoint.to_owned()))?;
    let runtime = TokioRuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| DnsError::Io(err.to_string()))?;
    runtime.block_on(async move {
        let bind_addr = if remote_addrs.iter().all(SocketAddr::is_ipv6) {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let local_addr = bind_addr.parse::<SocketAddr>().map_err(io::Error::other)?;
        let mut endpoint_client = QuinnEndpoint::new(Default::default(), None, mihomo_core::bind_outbound_udp(local_addr)?, Arc::new(quinn::TokioRuntime)).map_err(io::Error::other)?;
        let client_crypto = build_quic_client_config()?;
        let client_config = QuinnClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_crypto).map_err(io::Error::other)?,
        ));
        endpoint_client.set_default_client_config(client_config);
        let connection = connect_quic_endpoint(&endpoint_client, &remote_addrs, &host).await?;
        let (mut send, mut recv) = connection.open_bi().await.map_err(io::Error::other)?;
        let length = u16::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "dns quic query too large"))?;
        send.write_all(&length.to_be_bytes()).await.map_err(io::Error::other)?;
        send.write_all(payload).await.map_err(io::Error::other)?;
        send.finish().map_err(io::Error::other)?;
        let _ = send.stopped().await;
        let mut header = [0_u8; 2];
        recv.read_exact(&mut header).await.map_err(io::Error::other)?;
        let response_len = u16::from_be_bytes(header) as usize;
        let mut response = vec![0_u8; response_len];
        recv.read_exact(&mut response).await.map_err(io::Error::other)?;
        connection.close(0u32.into(), b"");
        endpoint_client.wait_idle().await;
        Ok(response)
    })
}

async fn connect_quic_endpoint(
    endpoint: &QuinnEndpoint,
    remote_addrs: &[SocketAddr],
    host: &str,
) -> io::Result<quinn::Connection> {
    let mut last_err = None;
    for remote_addr in remote_addrs {
        match endpoint.connect(*remote_addr, host) {
            Ok(connecting) => match tokio::time::timeout(Duration::from_secs(3), connecting).await {
                Ok(Ok(connection)) => return Ok(connection),
                Ok(Err(err)) => last_err = Some(io::Error::other(err.to_string())),
                Err(_) => {
                    last_err = Some(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("doq connect to {remote_addr} timed out"),
                    ))
                }
            },
            Err(err) => last_err = Some(io::Error::other(err.to_string())),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "doq server connect failed for all resolved addresses",
        )
    }))
}

fn exchange_tls_stream_open(
    stream: TcpStream,
    endpoint: &str,
    server_name_host: &str,
) -> Result<StreamOwned<ClientConnection, TcpStream>, DnsError> {
    let server_name = ServerName::try_from(server_name_host.trim_matches(['[', ']']))
        .map_err(|_| DnsError::UnsupportedNameserver(endpoint.to_owned()))?;
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(system_root_store()?)
        .with_no_client_auth();
    let connection = ClientConnection::new(std::sync::Arc::new(config), server_name)
        .map_err(|err| DnsError::Io(err.to_string()))?;
    Ok(StreamOwned::new(connection, stream))
}

fn exchange_http_over_stream(
    stream: &mut dyn ReadWrite,
    request_target: &str,
    host_header: &str,
    payload: &[u8],
) -> Result<Vec<u8>, DnsError> {
    let request = format!(
        "POST {request_target} HTTP/1.1\r\nHost: {host_header}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    read_http_response_body_from_stream(stream)
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn read_http_response_body_from_stream(stream: &mut dyn Read) -> Result<Vec<u8>, DnsError> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            return Err(DnsError::DnsProtocol(
                "http response ended before headers were complete".to_owned(),
            ));
        }
        response.extend_from_slice(&buf[..read]);
        if let Some(position) = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            break position + 4;
        }
    };

    let headers = response[..header_end].to_vec();
    let header_text = String::from_utf8_lossy(&headers);
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| DnsError::DnsProtocol("http response missing status line".to_owned()))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| DnsError::DnsProtocol("http response missing status code".to_owned()))?;
    if status != "200" {
        return Err(DnsError::DnsProtocol(format!(
            "http upstream returned status {status}"
        )));
    }

    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_ascii_lowercase();
            if name == "content-length" {
                content_length = value.parse::<usize>().ok();
            } else if name == "transfer-encoding" && value.contains("chunked") {
                chunked = true;
            }
        }
    }

    let mut body = response[header_end..].to_vec();
    if let Some(length) = content_length {
        while body.len() < length {
            let read = stream.read(&mut buf)?;
            if read == 0 {
                return Err(DnsError::DnsProtocol(
                    "http response body shorter than content-length".to_owned(),
                ));
            }
            body.extend_from_slice(&buf[..read]);
        }
        return Ok(body[..length].to_vec());
    }

    if chunked {
        loop {
            let read = stream.read(&mut buf)?;
            if read == 0 {
                break;
            }
            body.extend_from_slice(&buf[..read]);
        }
        return decode_chunked_body(&body);
    }

    loop {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&buf[..read]);
    }
    Ok(body)
}

fn decode_chunked_body(body: &[u8]) -> Result<Vec<u8>, DnsError> {
    let mut cursor = 0;
    let mut decoded = Vec::new();
    loop {
        let line_end = body[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| DnsError::DnsProtocol("chunked body missing size line".to_owned()))?;
        let size_text = std::str::from_utf8(&body[cursor..cursor + line_end])
            .map_err(|_| DnsError::DnsProtocol("chunk size is not utf-8".to_owned()))?;
        let size = usize::from_str_radix(size_text.trim(), 16)
            .map_err(|_| DnsError::DnsProtocol("invalid chunk size".to_owned()))?;
        cursor += line_end + 2;
        if size == 0 {
            break;
        }
        if body.len() < cursor + size + 2 {
            return Err(DnsError::DnsProtocol("chunk body truncated".to_owned()));
        }
        decoded.extend_from_slice(&body[cursor..cursor + size]);
        cursor += size + 2;
    }
    Ok(decoded)
}

fn system_root_store() -> Result<RootCertStore, DnsError> {
    let mut roots = RootCertStore::empty();
    if let Ok(native_certs) = rustls_native_certs::load_native_certs() {
        for cert in native_certs {
            roots
                .add(&Certificate(cert.0))
                .map_err(|err| DnsError::Io(err.to_string()))?;
        }
    }
    if roots.is_empty() {
        roots.add_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS.iter().map(|anchor| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    anchor.subject,
                    anchor.spki,
                    anchor.name_constraints,
                )
            }),
        );
    }
    for cert in extra_root_certificates()
        .lock()
        .expect("extra root certificate registry poisoned")
        .iter()
    {
        roots
            .add(cert)
            .map_err(|err| DnsError::Io(err.to_string()))?;
    }
    Ok(roots)
}

pub(crate) fn quic_root_store() -> Result<RootCertStore023, DnsError> {
    let mut roots = RootCertStore023::empty();
    roots.extend(
        webpki_roots::TLS_SERVER_ROOTS.iter().map(|anchor| rustls023::pki_types::TrustAnchor {
            subject: anchor.subject.into(),
            subject_public_key_info: anchor.spki.into(),
            name_constraints: anchor.name_constraints.map(Into::into),
        }),
    );
    for cert in extra_root_certificates_023()
        .lock()
        .expect("extra root certificate registry poisoned")
        .iter()
    {
        roots
            .add(cert.clone())
            .map_err(|err| DnsError::Io(err.to_string()))?;
    }
    Ok(roots)
}

fn extra_root_certificates() -> &'static Mutex<Vec<Certificate>> {
    static EXTRA_ROOT_CERTIFICATES: OnceLock<Mutex<Vec<Certificate>>> = OnceLock::new();
    EXTRA_ROOT_CERTIFICATES.get_or_init(|| Mutex::new(Vec::new()))
}

fn extra_root_certificates_023() -> &'static Mutex<Vec<CertificateDer<'static>>> {
    static EXTRA_ROOT_CERTIFICATES_023: OnceLock<Mutex<Vec<CertificateDer<'static>>>> =
        OnceLock::new();
    EXTRA_ROOT_CERTIFICATES_023.get_or_init(|| Mutex::new(Vec::new()))
}

fn build_quic_client_config() -> Result<Arc<RustlsClientConfig>, DnsError> {
    let mut crypto = RustlsClientConfig::builder()
        .with_root_certificates(quic_root_store()?)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"doq".to_vec()];
    Ok(Arc::new(crypto))
}

pub(crate) fn register_test_root_certificate(pem: &str) -> Result<(), DnsError> {
    let mut reader = std::io::Cursor::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|err| DnsError::Io(err.to_string()))?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<_>>();
    extra_root_certificates()
        .lock()
        .expect("extra root certificate registry poisoned")
        .extend(certs.iter().cloned());
    extra_root_certificates_023()
        .lock()
        .expect("extra root certificate registry poisoned")
        .extend(certs.into_iter().map(|cert| CertificateDer::from(cert.0)));
    Ok(())
}

fn exchange_system(_raw: &str, payload: &[u8]) -> Result<Vec<u8>, DnsError> {
    let query = parse_dns_query_packet(payload)?;
    if matches!(query.query_type, DnsRecordType::Other(_)) {
        let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        for line in resolv.lines() {
            let mut fields = line.split_whitespace();
            if fields.next() == Some("nameserver") {
                if let Some(server) = fields.next().and_then(|server| server.parse::<IpAddr>().ok()) {
                    if let Ok(response) = exchange_udp(&SocketAddr::new(server, 53).to_string(), payload) { return Ok(response); }
                }
            }
        }
        return Err(DnsError::ResolveFailed("system resolver cannot exchange this DNS record type; configure a nameserver".into()));
    }
    let mut ips = match (query.host.as_str(), 0_u16).to_socket_addrs() {
        Ok(addrs) => addrs
            .map(|addr| addr.ip())
            .filter(|ip| match query.query_type {
                DnsRecordType::A => matches!(ip, IpAddr::V4(_)),
                DnsRecordType::Aaaa => matches!(ip, IpAddr::V6(_)),
                DnsRecordType::Other(_) => false,
            })
            .collect::<Vec<_>>(),
        Err(_) => Vec::new(),
    };
    ips.sort();
    ips.dedup();
    Ok(build_dns_response(&query, 60, &ips))
}

fn exchange_rcode(payload: &[u8], rcode: u8) -> Result<Vec<u8>, DnsError> {
    if payload.len() < 12 {
        return Err(DnsError::DnsProtocol("query too short".to_owned()));
    }
    let mut response = payload.to_vec();
    response[2] |= 0x80;
    response[3] = (response[3] & 0xF0) | (rcode & 0x0F);
    response[6] = 0;
    response[7] = 0;
    response[8] = 0;
    response[9] = 0;
    response[10] = 0;
    response[11] = 0;
    Ok(response)
}

fn parse_rcode(kind: &str) -> Result<u8, DnsError> {
    match kind {
        "success" => Ok(0),
        "format_error" => Ok(1),
        "server_failure" => Ok(2),
        "name_error" => Ok(3),
        "not_implemented" => Ok(4),
        "refused" => Ok(5),
        _ => Err(DnsError::UnsupportedNameserver(format!("rcode://{kind}"))),
    }
}

impl From<io::Error> for DnsError {
    fn from(value: io::Error) -> Self {
        Self::Io(value.to_string())
    }
}
