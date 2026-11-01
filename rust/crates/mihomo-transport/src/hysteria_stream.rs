use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::pin::Pin;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;

use base64::Engine;
use mihomo_core::{BoxedTcpStream, TcpStream};
use rand::Rng;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::SendDatagramError;
use quinn::{ClientConfig as QuinnClientConfig, Connection as QuinnConnection, Endpoint as QuinnEndpoint};
use quinn::{AsyncUdpSocket, Runtime as QuinnRuntime, UdpPoller};
use rustls023::crypto::aws_lc_rs;
use rustls023::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls023::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls023::{ClientConfig as RustlsClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Builder;
use tokio::sync::mpsc as tokio_mpsc;

use crate::udp_channel::{encode_udp_channel_frame, UdpChannelStream, UdpStreamCommand};
use crate::{TransportError, TransportTarget};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HysteriaOptions {
    pub ports: String,
    pub protocol: String,
    pub auth: String,
    pub auth_str: String,
    pub obfs: String,
    pub sni: String,
    pub alpn: Vec<String>,
    pub up: String,
    pub down: String,
    pub up_speed: u32,
    pub down_speed: u32,
    pub disable_mtu_discovery: bool,
    pub fast_open: bool,
    pub hop_interval: u32,
    pub skip_cert_verify: bool,
}

enum WriteCommand {
    Data(Vec<u8>),
    Close,
}

enum Ready<T> {
    Ok(T),
    Err(io::Error),
}

pub(crate) fn connect_stream(
    dialer: &mut impl crate::TcpDialer,
    proxy: &TransportTarget,
    options: &HysteriaOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let auth = decode_auth(options)?;
    let send_bps = parse_bps(options.up_speed, &options.up)?;
    let recv_bps = parse_bps(options.down_speed, &options.down)?;
    let protocol = normalize_protocol(&options.protocol);
    let _obfs = normalize_obfs(&options.obfs)?;

    let (read_tx, read_rx) = mpsc::channel();
    let (write_tx, write_rx) = tokio_mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let proxy_authority = proxy.authority();
    let proxy = proxy.clone();
    let remote_addrs = dialer
        .resolve_addrs(&proxy, &crate::SocketOptions::default(), crate::TcpDialPurpose::ProxyServer)?
        .into_iter()
        .map(|addr| addr.0)
        .collect::<Vec<_>>();
    let target = target.clone();
    let options = options.clone();

    thread::spawn(move || {
        let runtime = Builder::new_current_thread().enable_all().build();
        match runtime {
            Ok(runtime) => {
                let worker_read_tx = read_tx.clone();
                let worker_ready_tx = ready_tx.clone();
                let result = runtime.block_on(async move {
                    ensure_crypto_provider();
                    let connection =
                        connect_quic(&proxy, &remote_addrs, &options, &protocol, None, None).await?;
                    authenticate(&connection, send_bps, recv_bps, &auth).await?;
                    let (send, recv, _) = open_connect_stream(
                        &connection,
                        &target,
                        false,
                    )
                    .await?;
                    bridge_hysteria_quic_stream(send, recv, worker_read_tx, write_rx, &worker_ready_tx, options.fast_open)
                        .await
                });
                if let Err(err) = result {
                    let err = io::Error::new(err.kind(), format!("{proxy_authority}: {err}"));
                    let _ = read_tx.send(Err(io::Error::new(err.kind(), err.to_string())));
                    let _ = ready_tx.send(Ready::Err(err));
                }
            }
            Err(err) => {
                let err = io::Error::new(io::ErrorKind::Other, err.to_string());
                let _ = read_tx.send(Err(io::Error::new(err.kind(), err.to_string())));
                let _ = ready_tx.send(Ready::Err(err));
            }
        }
    });

    match ready_rx.recv() {
        Ok(Ready::Ok(())) => Ok(Box::new(HysteriaChannelStream::new(read_rx, write_tx))),
        Ok(Ready::Err(err)) => Err(TransportError::from(err)),
        Err(_) => Err(TransportError::Io {
            kind: io::ErrorKind::ConnectionAborted,
            message: "hysteria client setup thread exited early".to_owned(),
        }),
    }
}

pub(crate) fn open_udp_stream(
    dialer: &mut impl crate::TcpDialer,
    proxy: &TransportTarget,
    options: &HysteriaOptions,
) -> Result<BoxedTcpStream, TransportError> {
    open_udp_stream_with_socks5_stream(dialer, proxy, options, None, None)
}

pub(crate) fn open_udp_stream_with_socks5_stream(
    dialer: &mut impl crate::TcpDialer,
    proxy: &TransportTarget,
    options: &HysteriaOptions,
    control_stream: Option<BoxedTcpStream>,
    auth: Option<crate::BasicAuth>,
) -> Result<BoxedTcpStream, TransportError> {
    let hysteria_auth = decode_auth(options)?;
    let send_bps = parse_bps(options.up_speed, &options.up)?;
    let recv_bps = parse_bps(options.down_speed, &options.down)?;
    let protocol = normalize_protocol(&options.protocol);
    let _obfs = normalize_obfs(&options.obfs)?;

    let (read_tx, read_rx) = mpsc::channel();
    let (write_tx, write_rx) = tokio_mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let proxy_authority = proxy.authority();
    let proxy = proxy.clone();
    let remote_addrs = dialer
        .resolve_addrs(&proxy, &crate::SocketOptions::default(), crate::TcpDialPurpose::ProxyServer)?
        .into_iter()
        .map(|addr| addr.0)
        .collect::<Vec<_>>();
    let options = options.clone();
    let outer_control_stream = control_stream;
    let outer_auth = auth;

    thread::spawn(move || {
        let runtime = Builder::new_current_thread().enable_all().build();
        match runtime {
            Ok(runtime) => {
                let worker_read_tx = read_tx.clone();
                let worker_ready_tx = ready_tx.clone();
                let result = runtime.block_on(async move {
                    ensure_crypto_provider();
                    let connection = connect_quic(
                        &proxy,
                        &remote_addrs,
                        &options,
                        &protocol,
                        outer_control_stream,
                        outer_auth,
                    )
                    .await?;
                    authenticate(&connection, send_bps, recv_bps, &hysteria_auth).await?;
                    let target = TransportTarget::new("127.0.0.1", 0);
                    let (send, recv, session_id) =
                        open_connect_stream(&connection, &target, true).await?;
                    bridge_hysteria_udp(
                        connection,
                        send,
                        recv,
                        session_id,
                        worker_read_tx,
                        write_rx,
                        &worker_ready_tx,
                    )
                    .await
                });
                if let Err(err) = result {
                    let err = io::Error::new(err.kind(), format!("{proxy_authority}: {err}"));
                    let _ = read_tx.send(Err(io::Error::new(err.kind(), err.to_string())));
                    let _ = ready_tx.send(Ready::Err(err));
                }
            }
            Err(err) => {
                let err = io::Error::new(io::ErrorKind::Other, err.to_string());
                let _ = read_tx.send(Err(io::Error::new(err.kind(), err.to_string())));
                let _ = ready_tx.send(Ready::Err(err));
            }
        }
    });

    match ready_rx.recv() {
        Ok(Ready::Ok(())) => Ok(Box::new(UdpChannelStream::new(
            read_rx,
            write_tx,
            "hysteria udp stream",
        ))),
        Ok(Ready::Err(err)) => Err(TransportError::from(err)),
        Err(_) => Err(TransportError::Io {
            kind: io::ErrorKind::ConnectionAborted,
            message: "hysteria udp client setup thread exited early".to_owned(),
        }),
    }
}

pub(crate) fn write_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    let frame = encode_udp_channel_frame(target, payload);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(payload.len())
}

pub(crate) fn read_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    let mut atyp = [0_u8; 1];
    stream.read_exact(&mut atyp)?;
    let host = match atyp[0] {
        0x01 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets)?;
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)).to_string()
        }
        0x02 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets)?;
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)).to_string()
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected hysteria udp atyp {other}"),
            ))
        }
    };
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port)?;
    let port = u16::from_be_bytes(port);
    let mut len = [0_u8; 2];
    stream.read_exact(&mut len)?;
    let len = u16::from_be_bytes(len) as usize;
    let mut payload = vec![0_u8; len];
    stream.read_exact(&mut payload)?;
    let source = format!("{host}:{port}")
        .parse::<std::net::SocketAddr>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    Ok((source, payload))
}

fn decode_auth(options: &HysteriaOptions) -> Result<Vec<u8>, TransportError> {
    if !options.auth.is_empty() {
        return base64::engine::general_purpose::STANDARD
            .decode(options.auth.trim())
            .map_err(|err| TransportError::InvalidPlan(err.to_string()));
    }
    Ok(options.auth_str.as_bytes().to_vec())
}

fn parse_bps(speed_mbps: u32, raw: &str) -> Result<u64, TransportError> {
    if speed_mbps != 0 {
        return Ok(speed_mbps as u64 * 125_000);
    }
    parse_speed_string(raw).ok_or_else(|| {
        TransportError::InvalidPlan(format!("invalid hysteria speed: {raw}"))
    })
}

fn parse_speed_string(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let number = lower
        .split_whitespace()
        .next()
        .and_then(|part| part.parse::<u64>().ok())?;
    if lower.contains("mbps") || lower.contains("mb") {
        Some(number * 125_000)
    } else if lower.contains("kbps") || lower.contains("kb") {
        Some(number * 125)
    } else if lower.contains("gbps") || lower.contains("gb") {
        Some(number * 125_000_000)
    } else {
        Some(number)
    }
}

fn normalize_protocol(protocol: &str) -> String {
    let trimmed = protocol.trim();
    if trimmed.is_empty() {
        "udp".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn normalize_obfs(obfs: &str) -> Result<String, TransportError> {
    let trimmed = obfs.trim();
    if trimmed.is_empty() {
        Ok(String::new())
    } else {
        Ok(trimmed.to_owned())
    }
}

fn ensure_crypto_provider() {
    static PROVIDER: OnceLock<()> = OnceLock::new();
    let _ = PROVIDER.get_or_init(|| {
        let _ = aws_lc_rs::default_provider().install_default();
    });
}

async fn resolve_socket_addrs(host: &str, port: u16, unresolved: &str) -> io::Result<Vec<SocketAddr>> {
    let addrs = tokio::net::lookup_host((host, port)).await?.collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, unresolved));
    }
    Ok(addrs)
}

async fn connect_quinn_endpoint(
    endpoint: &QuinnEndpoint,
    remote_addrs: &[SocketAddr],
    server_name: &ServerName<'_>,
    connect_error: &str,
) -> io::Result<QuinnConnection> {
    let mut last_err = None;
    for remote_addr in remote_addrs {
        match endpoint.connect(*remote_addr, server_name.to_str().as_ref()) {
            Ok(connecting) => match tokio::time::timeout(Duration::from_secs(3), connecting).await {
                Ok(Ok(connection)) => return Ok(connection),
                Ok(Err(err)) => last_err = Some(io::Error::other(err.to_string())),
                Err(_) => {
                    last_err = Some(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("hysteria connect to {remote_addr} timed out"),
                    ))
                }
            },
            Err(err) => last_err = Some(io::Error::other(err.to_string())),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, connect_error)))
}

async fn connect_quic(
    proxy: &TransportTarget,
    remote_addrs: &[SocketAddr],
    options: &HysteriaOptions,
    protocol: &str,
    control_stream: Option<BoxedTcpStream>,
    auth: Option<crate::BasicAuth>,
) -> io::Result<QuinnConnection> {
    if protocol != "udp" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported hysteria protocol: {protocol}"),
        ));
    }
    if remote_addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "hysteria server address unresolved",
        ));
    }
    let bind_addr = if remote_addrs.iter().all(SocketAddr::is_ipv6) {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let local_addr = bind_addr.parse::<SocketAddr>().map_err(io::Error::other)?;
    let mut endpoint = if let Some(mut control) = control_stream {
        let (udp_socket, relay_addr) = crate::socks5_udp_underlay::connect_socks5_udp_associate_over_stream(
            &mut *control,
            local_addr,
            auth.as_ref(),
        )
        .map_err(|err| io::Error::other(err.to_string()))?;
        if options.obfs.trim().is_empty() {
            let runtime = Arc::new(TokioQuinnRuntime);
            let socket = Arc::new(crate::socks5_udp_underlay::Socks5UdpAssociateSocket::new(
                udp_socket,
                relay_addr,
                control,
            )?);
            QuinnEndpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                socket,
                runtime,
            )?
        } else {
            let runtime = Arc::new(TokioQuinnRuntime);
            let socket = Arc::new(XPlusUdpSocket::new(
                udp_socket,
                options.obfs.as_bytes().to_vec(),
            )?);
            QuinnEndpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                socket,
                runtime,
            )?
        }
    } else if options.obfs.trim().is_empty() {
        QuinnEndpoint::new(Default::default(), None, mihomo_core::bind_outbound_udp(local_addr)?, Arc::new(quinn::TokioRuntime)).map_err(io::Error::other)?
    } else {
        let runtime = Arc::new(TokioQuinnRuntime);
        let socket = Arc::new(XPlusUdpSocket::new(
            mihomo_core::bind_outbound_udp(local_addr)?,
            options.obfs.as_bytes().to_vec(),
        )?);
        QuinnEndpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime,
        )?
    };
    let client_crypto = build_client_config(proxy, options)?;
    let client_config = QuinnClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto).map_err(io::Error::other)?,
    ));
    endpoint.set_default_client_config(client_config);
    let server_name = resolve_server_name(proxy, options)?;
    connect_quinn_endpoint(
        &endpoint,
        &remote_addrs,
        &server_name,
        "hysteria server connect failed for all resolved addresses",
    )
    .await
}

const XPLUS_SALT_LEN: usize = 16;

fn apply_xplus_obfs(password: &[u8], salt: &[u8], payload: &mut [u8]) {
    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.update(salt);
    let key = hasher.finalize();
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}

#[derive(Debug)]
struct XPlusUdpSocket {
    io: tokio::net::UdpSocket,
    local_addr: SocketAddr,
    obfs_password: Vec<u8>,
}

impl XPlusUdpSocket {
    fn new(socket: std::net::UdpSocket, obfs_password: Vec<u8>) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        let local_addr = socket.local_addr()?;
        Ok(Self {
            io: tokio::net::UdpSocket::from_std(socket)?,
            local_addr,
            obfs_password,
        })
    }

    fn maybe_decode_recv(
        &self,
        meta: &mut quinn_udp::RecvMeta,
        buf: &mut [u8],
    ) {
        if self.obfs_password.is_empty() || meta.len <= XPLUS_SALT_LEN {
            return;
        }
        let payload_len = meta.len - XPLUS_SALT_LEN;
        let salt = buf[..XPLUS_SALT_LEN].to_vec();
        buf.copy_within(XPLUS_SALT_LEN..meta.len, 0);
        let payload = &mut buf[..payload_len];
        apply_xplus_obfs(&self.obfs_password, &salt, payload);
        meta.len = payload_len;
        meta.stride = payload_len;
    }
}

impl AsyncUdpSocket for XPlusUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(XPlusUdpPoller { socket: self })
    }

    fn try_send(&self, transmit: &quinn_udp::Transmit) -> io::Result<()> {
        let mut owned;
        let tx = if self.obfs_password.is_empty() {
            transmit.clone()
        } else {
            let mut salt = [0_u8; XPLUS_SALT_LEN];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
            owned = Vec::with_capacity(XPLUS_SALT_LEN + transmit.contents.len());
            owned.extend_from_slice(&salt);
            owned.extend_from_slice(transmit.contents);
            apply_xplus_obfs(
                &self.obfs_password,
                &salt,
                &mut owned[XPLUS_SALT_LEN..],
            );
            quinn_udp::Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &owned,
                segment_size: None,
                src_ip: transmit.src_ip,
            }
        };
        self.io.try_send_to(tx.contents, tx.destination).map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.io.poll_recv_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
            let buf = match bufs.first_mut() {
                Some(buf) => buf,
                None => return Poll::Ready(Ok(0)),
            };
            let mut recv_buf = vec![0_u8; buf.len()];
            match self.io.try_recv_from(&mut recv_buf) {
                Ok((len, addr)) => {
                    let dst = &mut buf[..len];
                    dst.copy_from_slice(&recv_buf[..len]);
                    meta[0] = quinn_udp::RecvMeta {
                        addr,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: None,
                    };
                    self.maybe_decode_recv(&mut meta[0], dst);
                    return Poll::Ready(Ok(1));
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct XPlusUdpPoller {
    socket: Arc<XPlusUdpSocket>,
}

impl UdpPoller for XPlusUdpPoller {
    fn poll_writable(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.socket.io.poll_send_ready(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::{apply_xplus_obfs, normalize_obfs, HysteriaOptions};

    #[test]
    fn xplus_obfs_round_trip_restores_payload() {
        let password = b"secret";
        let salt = *b"1234567890abcdef";
        let mut payload = b"hello hysteria".to_vec();
        let original = payload.clone();

        apply_xplus_obfs(password, &salt, &mut payload);
        assert_ne!(payload, original);
        apply_xplus_obfs(password, &salt, &mut payload);
        assert_eq!(payload, original);
    }

    #[test]
    fn normalize_obfs_preserves_configured_value() {
        assert_eq!(normalize_obfs("").unwrap(), "");
        assert_eq!(normalize_obfs(" demo ").unwrap(), "demo");
    }

    #[test]
    fn hysteria_options_carry_obfs_field() {
        let options = HysteriaOptions {
            ports: String::new(),
            protocol: "udp".into(),
            auth: String::new(),
            auth_str: "secret".into(),
            obfs: "demo".into(),
            sni: "localhost".into(),
            alpn: vec!["hysteria".into()],
            up: "10 Mbps".into(),
            down: "50 Mbps".into(),
            up_speed: 0,
            down_speed: 0,
            disable_mtu_discovery: false,
            fast_open: false,
            hop_interval: 10,
            skip_cert_verify: true,
        };
        assert_eq!(options.obfs, "demo");
    }
}

#[derive(Debug)]
struct TokioQuinnRuntime;

impl QuinnRuntime for TokioQuinnRuntime {
    fn new_timer(&self, i: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(i)))
    }

    fn spawn(&self, future: Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        Ok(Arc::new(XPlusUdpSocket::new(socket, Vec::new())?))
    }
}

fn build_client_config(
    proxy: &TransportTarget,
    options: &HysteriaOptions,
) -> io::Result<Arc<RustlsClientConfig>> {
    let builder = RustlsClientConfig::builder();
    let mut crypto = if options.skip_cert_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification023))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().map(|anchor| rustls023::pki_types::TrustAnchor {
            subject: anchor.subject.into(),
            subject_public_key_info: anchor.spki.into(),
            name_constraints: anchor.name_constraints.map(Into::into),
        }));
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    crypto.alpn_protocols = if options.alpn.is_empty() {
        vec![b"hysteria".to_vec()]
    } else {
        options.alpn.iter().map(|value| value.as_bytes().to_vec()).collect()
    };
    let _ = proxy;
    Ok(Arc::new(crypto))
}

fn resolve_server_name<'a>(
    proxy: &TransportTarget,
    options: &'a HysteriaOptions,
) -> io::Result<ServerName<'a>> {
    let server_name = if options.sni.trim().is_empty() {
        proxy.host.as_str()
    } else {
        options.sni.trim()
    };
    ServerName::try_from(server_name.to_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid hysteria server name"))
}

async fn authenticate(
    connection: &QuinnConnection,
    send_bps: u64,
    recv_bps: u64,
    auth: &[u8],
) -> io::Result<()> {
    let mut stream = connection.open_uni().await.map_err(io::Error::other)?;
    let mut hello = Vec::with_capacity(1 + 8 + 8 + 2 + auth.len());
    hello.push(3);
    hello.extend_from_slice(&send_bps.to_be_bytes());
    hello.extend_from_slice(&recv_bps.to_be_bytes());
    hello.extend_from_slice(&(auth.len() as u16).to_be_bytes());
    hello.extend_from_slice(auth);
    stream.write_all(&hello).await.map_err(io::Error::other)?;
    stream.finish().map_err(io::Error::other)?;

    let mut recv = connection.accept_uni().await.map_err(io::Error::other)?;
    let ok = recv.read_u8().await? == 1;
    let _send = recv.read_u64().await?;
    let _recv = recv.read_u64().await?;
    let msg_len = recv.read_u16().await? as usize;
    let mut message = vec![0_u8; msg_len];
    if msg_len > 0 {
        recv.read_exact(&mut message).await.map_err(io::Error::other)?;
    }
    if !ok {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("hysteria auth failed: {}", String::from_utf8_lossy(&message)),
        ));
    }
    Ok(())
}

async fn open_connect_stream(
    connection: &QuinnConnection,
    target: &TransportTarget,
    udp: bool,
) -> io::Result<(quinn::SendStream, quinn::RecvStream, u32)> {
    let (mut send, mut recv) = connection.open_bi().await.map_err(io::Error::other)?;
    let host = target.host.as_bytes();
    let mut frame = Vec::with_capacity(1 + 2 + host.len() + 2);
    frame.push(if udp { 1 } else { 0 });
    frame.extend_from_slice(&(host.len() as u16).to_be_bytes());
    frame.extend_from_slice(host);
    frame.extend_from_slice(&target.port.to_be_bytes());
    send.write_all(&frame).await.map_err(io::Error::other)?;
    send.flush().await.map_err(io::Error::other)?;

    let ok = recv.read_u8().await? == 1;
    let session_id = recv.read_u32().await?;
    let msg_len = recv.read_u16().await? as usize;
    let mut message = vec![0_u8; msg_len];
    if msg_len > 0 {
        recv.read_exact(&mut message).await.map_err(io::Error::other)?;
    }
    if !ok {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("hysteria connect failed: {}", String::from_utf8_lossy(&message)),
        ));
    }
    Ok((send, recv, session_id))
}

async fn bridge_hysteria_quic_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    read_tx: mpsc::Sender<io::Result<Vec<u8>>>,
    mut write_rx: tokio_mpsc::UnboundedReceiver<WriteCommand>,
    ready_tx: &mpsc::SyncSender<Ready<()>>,
    fast_open: bool,
) -> io::Result<()> {
    let _ = fast_open;
    ready_tx
        .send(Ready::Ok(()))
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "hysteria setup receiver dropped"))?;

    let mut read_buf = vec![0_u8; 64 * 1024];
    let mut write_closed = false;
    loop {
        tokio::select! {
            result = recv.read(&mut read_buf) => {
                match result {
                    Ok(Some(read)) => {
                        if read == 0 {
                            let _ = read_tx.send(Ok(Vec::new()));
                            return Ok(());
                        }
                        let _ = read_tx.send(Ok(read_buf[..read].to_vec()));
                    }
                    Ok(None) => {
                        let _ = read_tx.send(Ok(Vec::new()));
                        return Ok(());
                    }
                    Err(err) => return Err(io::Error::other(err)),
                }
            }
            maybe = write_rx.recv(), if !write_closed => {
                match maybe {
                    Some(WriteCommand::Data(data)) => {
                        send.write_all(&data).await.map_err(io::Error::other)?;
                        send.flush().await.map_err(io::Error::other)?;
                    }
                    Some(WriteCommand::Close) | None => {
                        write_closed = true;
                        send.finish().map_err(io::Error::other)?;
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
struct HysteriaUdpMessage {
    session_id: u32,
    host: String,
    port: u16,
    msg_id: u16,
    frag_id: u8,
    frag_count: u8,
    payload: Vec<u8>,
}

impl HysteriaUdpMessage {
    fn header_size(&self) -> usize {
        4 + 2 + self.host.len() + 2 + 2 + 1 + 1 + 2
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.header_size() + self.payload.len());
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&(self.host.len() as u16).to_be_bytes());
        out.extend_from_slice(self.host.as_bytes());
        out.extend_from_slice(&self.port.to_be_bytes());
        out.extend_from_slice(&self.msg_id.to_be_bytes());
        out.push(self.frag_id);
        out.push(self.frag_count);
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    fn decode(data: &[u8]) -> io::Result<Self> {
        let mut reader = std::io::Cursor::new(data);
        let mut session = [0_u8; 4];
        std::io::Read::read_exact(&mut reader, &mut session)?;
        let session_id = u32::from_be_bytes(session);
        let mut host_len = [0_u8; 2];
        std::io::Read::read_exact(&mut reader, &mut host_len)?;
        let host_len = u16::from_be_bytes(host_len) as usize;
        let mut host = vec![0_u8; host_len];
        std::io::Read::read_exact(&mut reader, &mut host)?;
        let mut port = [0_u8; 2];
        std::io::Read::read_exact(&mut reader, &mut port)?;
        let port = u16::from_be_bytes(port);
        let mut msg_id = [0_u8; 2];
        std::io::Read::read_exact(&mut reader, &mut msg_id)?;
        let msg_id = u16::from_be_bytes(msg_id);
        let mut frag_id = [0_u8; 1];
        std::io::Read::read_exact(&mut reader, &mut frag_id)?;
        let mut frag_count = [0_u8; 1];
        std::io::Read::read_exact(&mut reader, &mut frag_count)?;
        let mut len = [0_u8; 2];
        std::io::Read::read_exact(&mut reader, &mut len)?;
        let len = u16::from_be_bytes(len) as usize;
        if reader.get_ref().len() - reader.position() as usize != len {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid hysteria udp data length"));
        }
        let mut payload = vec![0_u8; len];
        std::io::Read::read_exact(&mut reader, &mut payload)?;
        Ok(Self {
            session_id,
            host: String::from_utf8_lossy(&host).into_owned(),
            port,
            msg_id,
            frag_id: frag_id[0],
            frag_count: frag_count[0],
            payload,
        })
    }
}

fn fragment_hysteria_udp_message(
    message: &HysteriaUdpMessage,
    max_datagram_size: usize,
) -> Vec<HysteriaUdpMessage> {
    let payload_mtu = max_datagram_size.saturating_sub(message.header_size()).max(1);
    if message.payload.len() <= payload_mtu {
        return vec![message.clone()];
    }
    let msg_id = rand::thread_rng().gen_range(1..=u16::MAX);
    let chunks = message.payload.chunks(payload_mtu).collect::<Vec<_>>();
    let frag_count = chunks.len() as u8;
    chunks
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| HysteriaUdpMessage {
            session_id: message.session_id,
            host: message.host.clone(),
            port: message.port,
            msg_id,
            frag_id: index as u8,
            frag_count,
            payload: chunk.to_vec(),
        })
        .collect()
}

fn defragment_hysteria_udp_message(
    fragments: &mut BTreeMap<(u32, u16), Vec<Option<HysteriaUdpMessage>>>,
    message: HysteriaUdpMessage,
) -> Option<HysteriaUdpMessage> {
    if message.frag_count <= 1 {
        return Some(message);
    }
    if message.frag_id >= message.frag_count {
        return None;
    }
    let key = (message.session_id, message.msg_id);
    let entry = fragments
        .entry(key)
        .or_insert_with(|| vec![None; message.frag_count as usize]);
    if entry.len() != message.frag_count as usize {
        *entry = vec![None; message.frag_count as usize];
    }
    if entry[message.frag_id as usize].is_some() {
        return None;
    }
    let index = message.frag_id as usize;
    entry[index] = Some(message);
    if entry.iter().any(Option::is_none) {
        return None;
    }
    let mut completed = entry
        .iter_mut()
        .map(|fragment| fragment.take().unwrap())
        .collect::<Vec<_>>();
    fragments.remove(&key);
    let first = completed.first().cloned()?;
    let mut payload = Vec::new();
    for fragment in completed.drain(..) {
        payload.extend_from_slice(&fragment.payload);
    }
    Some(HysteriaUdpMessage {
        payload,
        frag_id: 0,
        frag_count: 1,
        ..first
    })
}

fn resolve_hysteria_udp_socket_addr(host: &str, port: u16) -> io::Result<std::net::SocketAddr> {
    let mut addrs = (host, port).to_socket_addrs()?;
    addrs.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "hysteria udp target unresolved",
        )
    })
}

async fn bridge_hysteria_udp(
    connection: QuinnConnection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    session_id: u32,
    read_tx: mpsc::Sender<io::Result<Vec<u8>>>,
    mut write_rx: tokio_mpsc::UnboundedReceiver<UdpStreamCommand>,
    ready_tx: &mpsc::SyncSender<Ready<()>>,
) -> io::Result<()> {
    let datagram_conn = connection.clone();
    let datagram_tx = read_tx.clone();
    tokio::spawn(async move {
        let mut fragments = BTreeMap::new();
        loop {
            match datagram_conn.read_datagram().await {
                Ok(bytes) => {
                    let Ok(message) = HysteriaUdpMessage::decode(bytes.as_ref()) else {
                        continue;
                    };
                    if message.session_id != session_id {
                        continue;
                    }
                    let Some(message) = defragment_hysteria_udp_message(&mut fragments, message) else {
                        continue;
                    };
                    let Ok(source) = resolve_hysteria_udp_socket_addr(&message.host, message.port) else {
                        continue;
                    };
                    let _ = datagram_tx.send(Ok(encode_udp_channel_frame(source, &message.payload)));
                }
                Err(err) => {
                    let _ = datagram_tx.send(Err(io::Error::other(err.to_string())));
                    break;
                }
            }
        }
    });

    ready_tx
        .send(Ready::Ok(()))
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "hysteria udp setup receiver dropped"))?;

    let mut read_buf = [0_u8; 1];
    let mut write_closed = false;
    loop {
        tokio::select! {
            result = recv.read(&mut read_buf) => {
                match result {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        let _ = read_tx.send(Ok(Vec::new()));
                        return Ok(());
                    }
                    Err(err) => return Err(io::Error::other(err)),
                }
            }
            maybe = write_rx.recv(), if !write_closed => {
                match maybe {
                    Some(UdpStreamCommand::Datagram { target, payload }) => {
                        let message = HysteriaUdpMessage {
                            session_id,
                            host: target.ip().to_string(),
                            port: target.port(),
                            msg_id: 0,
                            frag_id: 0,
                            frag_count: 1,
                            payload,
                        };
                        let packet = message.encode();
                        let packet_len = packet.len();
                        match connection.send_datagram(packet.into()) {
                            Ok(()) => {}
                            Err(SendDatagramError::TooLarge) => {
                                let max_size = connection.max_datagram_size().unwrap_or(packet_len);
                                for fragment in fragment_hysteria_udp_message(&message, max_size) {
                                    connection.send_datagram(fragment.encode().into()).map_err(io::Error::other)?;
                                }
                            }
                            Err(err) => return Err(io::Error::other(err.to_string())),
                        }
                    }
                    Some(UdpStreamCommand::Close) | None => {
                        write_closed = true;
                        send.finish().map_err(io::Error::other)?;
                    }
                }
            }
        }
    }
}

struct HysteriaChannelStream {
    read_rx: Receiver<io::Result<Vec<u8>>>,
    write_tx: tokio_mpsc::UnboundedSender<WriteCommand>,
    pending: Vec<u8>,
    offset: usize,
    write_closed: bool,
}

struct HysteriaWriteClone {
    write_tx: tokio_mpsc::UnboundedSender<WriteCommand>,
    write_closed: bool,
}

impl HysteriaChannelStream {
    fn new(
        read_rx: Receiver<io::Result<Vec<u8>>>,
        write_tx: tokio_mpsc::UnboundedSender<WriteCommand>,
    ) -> Self {
        Self {
            read_rx,
            write_tx,
            pending: Vec::new(),
            offset: 0,
            write_closed: false,
        }
    }
}

impl Read for HysteriaChannelStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.offset < self.pending.len() {
            let available = &self.pending[self.offset..];
            let copied = available.len().min(buf.len());
            buf[..copied].copy_from_slice(&available[..copied]);
            self.offset += copied;
            if self.offset == self.pending.len() {
                self.pending.clear();
                self.offset = 0;
            }
            return Ok(copied);
        }

        match self.read_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(bytes)) if bytes.is_empty() => Ok(0),
            Ok(Ok(bytes)) => {
                let copied = bytes.len().min(buf.len());
                buf[..copied].copy_from_slice(&bytes[..copied]);
                if copied < bytes.len() {
                    self.pending = bytes;
                    self.offset = copied;
                }
                Ok(copied)
            }
            Ok(Err(err)) => Err(err),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "hysteria stream read timed out",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(0),
        }
    }
}

impl Write for HysteriaChannelStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(WriteCommand::Data(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "hysteria stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for HysteriaChannelStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(HysteriaWriteClone {
            write_tx: self.write_tx.clone(),
            write_closed: false,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        if !self.write_closed {
            self.write_closed = true;
            let _ = self.write_tx.send(WriteCommand::Close);
        }
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown_write()
    }
}

impl Read for HysteriaWriteClone {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "hysteria write clone does not support reads",
        ))
    }
}

impl Write for HysteriaWriteClone {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(WriteCommand::Data(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "hysteria stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for HysteriaWriteClone {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            write_tx: self.write_tx.clone(),
            write_closed: false,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        if !self.write_closed {
            self.write_closed = true;
            let _ = self.write_tx.send(WriteCommand::Close);
        }
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown_write()
    }
}

#[derive(Debug)]
struct NoCertificateVerification023;

impl ServerCertVerifier for NoCertificateVerification023 {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls023::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls023::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls023::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}
