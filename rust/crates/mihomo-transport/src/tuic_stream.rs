use std::io::{self, IoSliceMut, Read, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

use blake3::hash as blake3_hash;
use bytes::Bytes;
use mihomo_core::{BoxedTcpStream, TcpStream};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig as QuinnClientConfig, Connection as QuinnConnection, Endpoint as QuinnEndpoint};
use rustls023::crypto::aws_lc_rs;
use rustls023::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls023::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls023::{ClientConfig as RustlsClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::AsyncWriteExt;
use tokio::runtime::Builder;
use tokio::sync::mpsc as tokio_mpsc;
use uuid::Uuid;

use crate::udp_channel::{
    decode_socket_addr, encode_socket_addr, encode_udp_channel_frame,
    UdpChannelStream, UdpStreamCommand,
};
use crate::socks5_udp_underlay::{
    connect_socks5_udp_associate_over_stream, Socks5UdpAssociateSocket,
};
use crate::{TransportError, TransportTarget};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TuicOptions {
    pub uuid: String,
    pub password: String,
    pub token: String,
    pub udp: bool,
    pub sni: String,
    pub alpn: Vec<String>,
    pub disable_sni: bool,
    pub request_timeout_ms: u64,
    pub heartbeat_interval_ms: u64,
    pub congestion_controller: String,
    pub max_open_streams: u32,
    pub max_udp_relay_packet_size: u32,
    pub skip_cert_verify: bool,
    pub certificate: String,
    pub private_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TuicUdpOptions {
    pub uuid: String,
    pub password: String,
    pub token: String,
    pub sni: String,
    pub alpn: Vec<String>,
    pub disable_sni: bool,
    pub request_timeout_ms: u64,
    pub heartbeat_interval_ms: u64,
    pub congestion_controller: String,
    pub max_open_streams: u32,
    pub max_udp_relay_packet_size: u32,
    pub skip_cert_verify: bool,
    pub certificate: String,
    pub private_key: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TuicUdpRelayMode {
    Quic,
    Native,
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
    options: &TuicOptions,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    if options.udp {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: "tuic udp relay".to_owned(),
        });
    }
    if options.uuid.trim().is_empty() || options.password.trim().is_empty() {
        if options.token.trim().is_empty() {
            return Err(TransportError::InvalidPlan(format!(
                "tuic transport requires uuid/password or token for {}",
                proxy.authority()
            )));
        }
    }

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
                        connect_quic(&proxy, &remote_addrs, &options, None, None).await?;
                    authenticate(&connection, &options).await?;
                    let (send, recv) = open_connect_stream(&connection, &target).await?;
                    bridge_tuic_quic_stream(send, recv, worker_read_tx, write_rx, &worker_ready_tx)
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
        Ok(Ready::Ok(())) => Ok(Box::new(TuicChannelStream::new(read_rx, write_tx))),
        Ok(Ready::Err(err)) => Err(TransportError::from(err)),
        Err(_) => Err(TransportError::Io {
            kind: io::ErrorKind::ConnectionAborted,
            message: "tuic client setup thread exited early".to_owned(),
        }),
    }
}

pub(crate) fn open_udp_stream(
    dialer: &mut impl crate::TcpDialer,
    proxy: &TransportTarget,
    options: &TuicUdpOptions,
) -> Result<BoxedTcpStream, TransportError> {
    open_udp_stream_with_socks5_stream(dialer, proxy, options, None, None)
}

pub(crate) fn open_udp_stream_with_socks5_stream(
    dialer: &mut impl crate::TcpDialer,
    proxy: &TransportTarget,
    options: &TuicUdpOptions,
    control_stream: Option<BoxedTcpStream>,
    auth: Option<crate::BasicAuth>,
) -> Result<BoxedTcpStream, TransportError> {
    let options = TuicOptions {
        uuid: options.uuid.clone(),
        password: options.password.clone(),
        token: options.token.clone(),
        udp: true,
        sni: options.sni.clone(),
        alpn: options.alpn.clone(),
        disable_sni: options.disable_sni,
        request_timeout_ms: options.request_timeout_ms,
        heartbeat_interval_ms: options.heartbeat_interval_ms,
        congestion_controller: options.congestion_controller.clone(),
        max_open_streams: options.max_open_streams,
        max_udp_relay_packet_size: options.max_udp_relay_packet_size,
        skip_cert_verify: options.skip_cert_verify,
        certificate: options.certificate.clone(),
        private_key: options.private_key.clone(),
    };
    let relay_mode = TuicUdpRelayMode::Native;
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
    thread::spawn(move || {
        let runtime = Builder::new_current_thread().enable_all().build();
        match runtime {
            Ok(runtime) => {
                let worker_read_tx = read_tx.clone();
                let worker_ready_tx = ready_tx.clone();
                let result = runtime.block_on(async move {
                    ensure_crypto_provider();
                    let connection =
                        connect_quic(&proxy, &remote_addrs, &options, control_stream, auth).await?;
                    authenticate(&connection, &options).await?;
                    if !options.token.trim().is_empty() {
                        bridge_tuic_udp_v4(
                            connection,
                            relay_mode,
                            options.max_udp_relay_packet_size,
                            worker_read_tx,
                            write_rx,
                            &worker_ready_tx,
                        )
                        .await
                    } else {
                        bridge_tuic_udp_v5(
                            connection,
                            relay_mode,
                            options.max_udp_relay_packet_size,
                            worker_read_tx,
                            write_rx,
                            &worker_ready_tx,
                        )
                        .await
                    }
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
            "tuic udp stream",
        ))),
        Ok(Ready::Err(err)) => Err(TransportError::from(err)),
        Err(_) => Err(TransportError::Io {
            kind: io::ErrorKind::ConnectionAborted,
            message: "tuic udp client setup thread exited early".to_owned(),
        }),
    }
}

pub(crate) fn write_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    let mut frame = Vec::with_capacity(1 + 16 + 2 + 2 + payload.len());
    encode_socket_addr(target, &mut frame)?;
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(payload.len())
}

pub(crate) fn read_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    let source = decode_socket_addr(stream)?;
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length)?;
    let length = u16::from_be_bytes(length) as usize;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok((source, payload))
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
                        format!("tuic connect to {remote_addr} timed out"),
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
    options: &TuicOptions,
    control_stream: Option<BoxedTcpStream>,
    auth: Option<crate::BasicAuth>,
) -> io::Result<QuinnConnection> {
    if remote_addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "tuic server address unresolved",
        ));
    }

    let bind_addr = if remote_addrs.iter().all(SocketAddr::is_ipv6) {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let local_addr = bind_addr.parse::<SocketAddr>().map_err(io::Error::other)?;
    let mut endpoint = if let Some(mut control) = control_stream {
        let (udp_socket, relay_addr) = connect_socks5_udp_associate_over_stream(
            &mut *control,
            local_addr,
            auth.as_ref(),
        )
        .map_err(|err| io::Error::other(err.to_string()))?;
        let runtime = Arc::new(TokioQuinnRuntime);
        let socket = Arc::new(Socks5UdpAssociateSocket::new(
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
        QuinnEndpoint::new(Default::default(), None, mihomo_core::bind_outbound_udp(local_addr)?, Arc::new(quinn::TokioRuntime)).map_err(io::Error::other)?
    };
    let client_crypto = build_client_config(options)?;
    let client_config = QuinnClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto).map_err(io::Error::other)?,
    ));
    endpoint.set_default_client_config(client_config);
    let server_name = resolve_server_name(proxy, options)?;
    let connection = connect_quinn_endpoint(
        &endpoint,
        &remote_addrs,
        &server_name,
        "tuic server connect failed for all resolved addresses",
    )
    .await?;
    if !options.certificate.trim().is_empty() || !options.private_key.trim().is_empty() {
        match tokio::time::timeout(Duration::from_millis(150), connection.closed()).await {
            Ok(err) => Err(io::Error::other(format!(
                "tuic connection closed during setup: {err}"
            ))),
            Err(_) => Ok(connection),
        }
    } else {
        Ok(connection)
    }
}

#[derive(Debug)]
struct TokioQuinnRuntime;

impl quinn::Runtime for TokioQuinnRuntime {
    fn new_timer(&self, i: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(i)))
    }

    fn spawn(&self, future: Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        let socket = tokio::net::UdpSocket::from_std(socket)?;
        Ok(Arc::new(SimpleUdpSocket::new(socket)?))
    }
}

#[derive(Debug)]
struct SimpleUdpSocket {
    io: tokio::net::UdpSocket,
    local_addr: SocketAddr,
}

impl SimpleUdpSocket {
    fn new(io: tokio::net::UdpSocket) -> io::Result<Self> {
        let local_addr = io.local_addr()?;
        Ok(Self { io, local_addr })
    }
}

impl quinn::AsyncUdpSocket for SimpleUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(SimpleUdpPoller { socket: self })
    }

    fn try_send(&self, transmit: &quinn_udp::Transmit) -> io::Result<()> {
        self.io
            .try_send_to(transmit.contents, transmit.destination)
            .map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn_udp::RecvMeta],
    ) -> std::task::Poll<io::Result<usize>> {
        loop {
            match self.io.poll_recv_ready(cx) {
                std::task::Poll::Ready(Ok(())) => {}
                std::task::Poll::Ready(Err(err)) => return std::task::Poll::Ready(Err(err)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
            let buf = match bufs.first_mut() {
                Some(buf) => buf,
                None => return std::task::Poll::Ready(Ok(0)),
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
                    return std::task::Poll::Ready(Ok(1));
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => return std::task::Poll::Ready(Err(err)),
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
struct SimpleUdpPoller {
    socket: Arc<SimpleUdpSocket>,
}

impl quinn::UdpPoller for SimpleUdpPoller {
    fn poll_writable(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.socket.io.poll_send_ready(cx)
    }
}

fn build_client_config(
    options: &TuicOptions,
) -> io::Result<Arc<RustlsClientConfig>> {
    let builder = RustlsClientConfig::builder();
    let client_auth_enabled =
        !options.certificate.trim().is_empty() || !options.private_key.trim().is_empty();
    let mut crypto = if options.skip_cert_verify {
        let builder = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification023));
        if client_auth_enabled {
            let certs = parse_client_certificates(&options.certificate)?;
            let key = parse_client_private_key(&options.private_key)?;
            builder.with_client_auth_cert(certs, key).map_err(io::Error::other)?
        } else {
            builder.with_no_client_auth()
        }
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().map(|anchor| rustls023::pki_types::TrustAnchor {
            subject: anchor.subject.into(),
            subject_public_key_info: anchor.spki.into(),
            name_constraints: anchor.name_constraints.map(Into::into),
        }));
        if !client_auth_enabled {
            builder.with_root_certificates(roots).with_no_client_auth()
        } else {
            let certs = parse_client_certificates(&options.certificate)?;
            let key = parse_client_private_key(&options.private_key)?;
            builder
                .with_root_certificates(roots)
                .with_client_auth_cert(certs, key)
                .map_err(io::Error::other)?
        }
    };
    crypto.alpn_protocols = if options.alpn.is_empty() {
        vec![b"h3".to_vec()]
    } else {
        options.alpn.iter().map(|entry| entry.as_bytes().to_vec()).collect()
    };
    Ok(Arc::new(crypto))
}

fn parse_client_certificates(
    cert_pem: &str,
) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut reader = io::Cursor::new(cert_pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "failed to parse tuic client certificate",
        ));
    }
    Ok(certs.into_iter().map(CertificateDer::from).collect())
}

fn parse_client_private_key(
    key_pem: &str,
) -> io::Result<rustls023::pki_types::PrivateKeyDer<'static>> {
    let mut reader = io::Cursor::new(key_pem.as_bytes());
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?
        .into_iter()
        .next()
    {
        return Ok(rustls023::pki_types::PrivatePkcs8KeyDer::from(key).into());
    }
    let mut reader = io::Cursor::new(key_pem.as_bytes());
    let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?
        .into_iter()
        .next()
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "failed to parse tuic client private key",
        ));
    };
    Ok(rustls023::pki_types::PrivatePkcs1KeyDer::from(key).into())
}

fn resolve_server_name<'a>(
    proxy: &TransportTarget,
    options: &'a TuicOptions,
) -> io::Result<ServerName<'a>> {
    let server_name = if options.disable_sni {
        proxy.host.as_str()
    } else if options.sni.trim().is_empty() {
        proxy.host.as_str()
    } else {
        options.sni.trim()
    };
    ServerName::try_from(server_name.to_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tuic server name"))
}

async fn authenticate(connection: &QuinnConnection, options: &TuicOptions) -> io::Result<()> {
    if !options.token.trim().is_empty() {
        return authenticate_v4(connection, options).await;
    }
    authenticate_v5(connection, options).await
}

async fn authenticate_v5(connection: &QuinnConnection, options: &TuicOptions) -> io::Result<()> {
    let uuid = Uuid::parse_str(options.uuid.trim())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let mut token = [0_u8; 32];
    connection
        .export_keying_material(&mut token, uuid.as_bytes(), options.password.as_bytes())
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("{err:?}")))?;

    let mut stream = connection.open_uni().await.map_err(io::Error::other)?;
    let mut frame = Vec::with_capacity(2 + 16 + 32);
    frame.push(0x05);
    frame.push(0x00);
    frame.extend_from_slice(uuid.as_bytes());
    frame.extend_from_slice(&token);
    stream.write_all(&frame).await.map_err(io::Error::other)?;
    stream.finish().map_err(io::Error::other)?;
    Ok(())
}

async fn authenticate_v4(connection: &QuinnConnection, options: &TuicOptions) -> io::Result<()> {
    let mut stream = connection.open_uni().await.map_err(io::Error::other)?;
    let token = blake3_hash(options.token.trim().as_bytes());
    let mut frame = Vec::with_capacity(2 + 32);
    frame.push(0x04);
    frame.push(0x00);
    frame.extend_from_slice(token.as_bytes());
    stream.write_all(&frame).await.map_err(io::Error::other)?;
    stream.finish().map_err(io::Error::other)?;
    Ok(())
}

async fn open_connect_stream(
    connection: &QuinnConnection,
    target: &TransportTarget,
) -> io::Result<(quinn::SendStream, quinn::RecvStream)> {
    let (mut send, recv) = connection.open_bi().await.map_err(io::Error::other)?;
    let mut frame = Vec::new();
    frame.push(0x05);
    frame.push(0x01);
    frame.extend_from_slice(&encode_address(target)?);
    send.write_all(&frame).await.map_err(io::Error::other)?;
    send.flush().await.map_err(io::Error::other)?;
    Ok((send, recv))
}

fn encode_address(target: &TransportTarget) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(0x02);
                out.extend_from_slice(&v6.octets());
            }
        }
    } else {
        let host = target.host.as_bytes();
        let host_len = u8::try_from(host.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "tuic hostname too long"))?;
        out.push(0x00);
        out.push(host_len);
        out.extend_from_slice(host);
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(out)
}

fn encode_v5_native_packet(
    assoc_id: u16,
    target: SocketAddr,
    payload: &[u8],
    max_payload: usize,
) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(2 + 2 + 1 + 1 + 2 + 32 + payload.len());
    out.push(0x05);
    out.push(0x02);
    out.extend_from_slice(&assoc_id.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.push(1);
    out.push(0);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encode_socket_addr(target, &mut out)?;
    ensure_udp_payload_fits(payload, out.len(), max_payload)?;
    out.extend_from_slice(payload);
    Ok(out)
}

fn encode_v5_quic_packet(
    assoc_id: u16,
    target: SocketAddr,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    encode_v5_native_packet(assoc_id, target, payload, usize::MAX)
}

fn decode_v5_native_packet(reader: &mut dyn Read) -> io::Result<(u16, SocketAddr, Vec<u8>)> {
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header)?;
    if header != [0x05, 0x02] {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid tuic v5 packet header"));
    }
    let mut assoc = [0_u8; 2];
    reader.read_exact(&mut assoc)?;
    let assoc_id = u16::from_be_bytes(assoc);
    let mut packet_id = [0_u8; 2];
    reader.read_exact(&mut packet_id)?;
    let _ = packet_id;
    let mut frag_total = [0_u8; 1];
    reader.read_exact(&mut frag_total)?;
    let mut frag_id = [0_u8; 1];
    reader.read_exact(&mut frag_id)?;
    let _ = (frag_total, frag_id);
    let mut size = [0_u8; 2];
    reader.read_exact(&mut size)?;
    let size = u16::from_be_bytes(size) as usize;
    let source = decode_socket_addr(reader)?;
    let mut payload = vec![0_u8; size];
    reader.read_exact(&mut payload)?;
    Ok((assoc_id, source, payload))
}

fn decode_v5_quic_packet(reader: &mut dyn Read) -> io::Result<(u16, SocketAddr, Vec<u8>)> {
    decode_v5_native_packet(reader)
}

fn encode_v4_native_packet(
    assoc_id: u32,
    target: SocketAddr,
    payload: &[u8],
    max_payload: usize,
) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(2 + 4 + 2 + 32 + payload.len());
    out.push(0x04);
    out.push(0x02);
    out.extend_from_slice(&assoc_id.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encode_socket_addr(target, &mut out)?;
    ensure_udp_payload_fits(payload, out.len(), max_payload)?;
    out.extend_from_slice(payload);
    Ok(out)
}

fn ensure_udp_payload_fits(
    payload: &[u8],
    overhead_bytes: usize,
    max_payload: usize,
) -> io::Result<()> {
    let payload_len = u16::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "tuic udp payload exceeds 65535 bytes",
        )
    })?;
    let frame_len = overhead_bytes
        .checked_add(payload_len as usize)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "tuic udp frame too large"))?;
    if frame_len > max_payload {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tuic udp frame exceeds max payload: frame={frame_len}, limit={max_payload}"),
        ));
    }
    Ok(())
}

fn encode_v4_quic_packet(
    assoc_id: u32,
    target: SocketAddr,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    encode_v4_native_packet(assoc_id, target, payload, usize::MAX)
}

fn decode_v4_native_packet(reader: &mut dyn Read) -> io::Result<(u32, SocketAddr, Vec<u8>)> {
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header)?;
    if header != [0x04, 0x02] {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid tuic v4 packet header"));
    }
    let mut assoc = [0_u8; 4];
    reader.read_exact(&mut assoc)?;
    let assoc_id = u32::from_be_bytes(assoc);
    let mut len = [0_u8; 2];
    reader.read_exact(&mut len)?;
    let size = u16::from_be_bytes(len) as usize;
    let source = decode_socket_addr(reader)?;
    let mut payload = vec![0_u8; size];
    reader.read_exact(&mut payload)?;
    Ok((assoc_id, source, payload))
}

fn decode_v4_quic_packet(reader: &mut dyn Read) -> io::Result<(u32, SocketAddr, Vec<u8>)> {
    decode_v4_native_packet(reader)
}

async fn bridge_tuic_quic_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    read_tx: mpsc::Sender<io::Result<Vec<u8>>>,
    mut write_rx: tokio_mpsc::UnboundedReceiver<WriteCommand>,
    ready_tx: &mpsc::SyncSender<Ready<()>>,
) -> io::Result<()> {
    ready_tx
        .send(Ready::Ok(()))
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tuic setup receiver dropped"))?;

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

async fn bridge_tuic_udp_v5(
    connection: QuinnConnection,
    relay_mode: TuicUdpRelayMode,
    max_udp_relay_packet_size: u32,
    read_tx: mpsc::Sender<io::Result<Vec<u8>>>,
    mut write_rx: tokio_mpsc::UnboundedReceiver<UdpStreamCommand>,
    ready_tx: &mpsc::SyncSender<Ready<()>>,
) -> io::Result<()> {
    const ASSOC_ID: u16 = 1;
    let connection_recv = connection.clone();
    let read_tx_datagram = read_tx.clone();
    tokio::spawn(async move {
        loop {
            match connection_recv.read_datagram().await {
                Ok(bytes) => {
                    let mut cursor = std::io::Cursor::new(bytes.to_vec());
                    let Ok((assoc_id, source, payload)) = decode_v5_native_packet(&mut cursor) else {
                        continue;
                    };
                    if assoc_id == ASSOC_ID {
                        let _ = read_tx_datagram.send(Ok(encode_udp_channel_frame(source, &payload)));
                    }
                }
                Err(_) => break,
            }
        }
    });

    let connection_recv = connection.clone();
    let read_tx_uni = read_tx.clone();
    tokio::spawn(async move {
        loop {
            let Ok(mut recv) = connection_recv.accept_uni().await else {
                break;
            };
            let mut buf = Vec::new();
            if recv.read_to_end(64 * 1024).await.map(|value| buf = value).is_err() {
                continue;
            }
            let mut cursor = std::io::Cursor::new(buf);
            let Ok((assoc_id, source, payload)) = decode_v5_quic_packet(&mut cursor) else {
                continue;
            };
            if assoc_id == ASSOC_ID {
                let _ = read_tx_uni.send(Ok(encode_udp_channel_frame(source, &payload)));
            }
        }
    });

    ready_tx
        .send(Ready::Ok(()))
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tuic udp setup receiver dropped"))?;

    while let Some(command) = write_rx.recv().await {
        match command {
            UdpStreamCommand::Datagram { target, payload } => {
                match relay_mode {
                    TuicUdpRelayMode::Native => {
                        let packet = encode_v5_native_packet(ASSOC_ID, target, &payload, max_udp_relay_packet_size as usize)?;
                        connection
                            .send_datagram(Bytes::from(packet))
                            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
                    }
                    TuicUdpRelayMode::Quic => {
                        let packet = encode_v5_quic_packet(ASSOC_ID, target, &payload)?;
                        let mut send = connection.open_uni().await.map_err(io::Error::other)?;
                        send.write_all(&packet).await.map_err(io::Error::other)?;
                        send.finish().map_err(io::Error::other)?;
                    }
                }
            }
            UdpStreamCommand::Close => break,
        }
    }
    Ok(())
}

async fn bridge_tuic_udp_v4(
    connection: QuinnConnection,
    relay_mode: TuicUdpRelayMode,
    max_udp_relay_packet_size: u32,
    read_tx: mpsc::Sender<io::Result<Vec<u8>>>,
    mut write_rx: tokio_mpsc::UnboundedReceiver<UdpStreamCommand>,
    ready_tx: &mpsc::SyncSender<Ready<()>>,
) -> io::Result<()> {
    const ASSOC_ID: u32 = 1;
    let connection_recv = connection.clone();
    let read_tx_datagram = read_tx.clone();
    tokio::spawn(async move {
        loop {
            match connection_recv.read_datagram().await {
                Ok(bytes) => {
                    let mut cursor = std::io::Cursor::new(bytes.to_vec());
                    let Ok((assoc_id, source, payload)) = decode_v4_native_packet(&mut cursor) else {
                        continue;
                    };
                    if assoc_id == ASSOC_ID {
                        let _ = read_tx_datagram.send(Ok(encode_udp_channel_frame(source, &payload)));
                    }
                }
                Err(_) => break,
            }
        }
    });

    let connection_recv = connection.clone();
    let read_tx_uni = read_tx.clone();
    tokio::spawn(async move {
        loop {
            let Ok(mut recv) = connection_recv.accept_uni().await else {
                break;
            };
            let mut buf = Vec::new();
            if recv.read_to_end(64 * 1024).await.map(|value| buf = value).is_err() {
                continue;
            }
            let mut cursor = std::io::Cursor::new(buf);
            let Ok((assoc_id, source, payload)) = decode_v4_quic_packet(&mut cursor) else {
                continue;
            };
            if assoc_id == ASSOC_ID {
                let _ = read_tx_uni.send(Ok(encode_udp_channel_frame(source, &payload)));
            }
        }
    });

    ready_tx
        .send(Ready::Ok(()))
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tuic udp setup receiver dropped"))?;

    while let Some(command) = write_rx.recv().await {
        match command {
            UdpStreamCommand::Datagram { target, payload } => {
                match relay_mode {
                    TuicUdpRelayMode::Native => {
                        let packet = encode_v4_native_packet(ASSOC_ID, target, &payload, max_udp_relay_packet_size as usize)?;
                        connection
                            .send_datagram(Bytes::from(packet))
                            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
                    }
                    TuicUdpRelayMode::Quic => {
                        let packet = encode_v4_quic_packet(ASSOC_ID, target, &payload)?;
                        let mut send = connection.open_uni().await.map_err(io::Error::other)?;
                        send.write_all(&packet).await.map_err(io::Error::other)?;
                        send.finish().map_err(io::Error::other)?;
                    }
                }
            }
            UdpStreamCommand::Close => break,
        }
    }
    Ok(())
}

struct TuicChannelStream {
    read_rx: Receiver<io::Result<Vec<u8>>>,
    write_tx: tokio_mpsc::UnboundedSender<WriteCommand>,
    pending: Vec<u8>,
    offset: usize,
    write_closed: bool,
}

struct TuicWriteClone {
    write_tx: tokio_mpsc::UnboundedSender<WriteCommand>,
    write_closed: bool,
}

impl TuicChannelStream {
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

impl Read for TuicChannelStream {
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
                "tuic stream read timed out",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(0),
        }
    }
}

impl Write for TuicChannelStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(WriteCommand::Data(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tuic stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for TuicChannelStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(TuicWriteClone {
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

impl Read for TuicWriteClone {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tuic write clone does not support reads",
        ))
    }
}

impl Write for TuicWriteClone {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(WriteCommand::Data(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tuic stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for TuicWriteClone {
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
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::sync::mpsc;

    use mihomo_core::TcpStream;
    use tokio::sync::mpsc as tokio_mpsc;

    use super::{
        TuicChannelStream, TuicOptions, WriteCommand, encode_address, encode_v4_native_packet,
        encode_v5_native_packet,
    };
    use crate::TransportTarget;

    #[test]
    fn tuic_write_clone_supports_write_only_duplication() {
        let (_read_tx, read_rx) = mpsc::channel();
        let (write_tx, mut write_rx) = tokio_mpsc::unbounded_channel();
        let stream = TuicChannelStream::new(read_rx, write_tx);
        let mut writer = stream.try_clone_box().unwrap();

        writer.write_all(b"ping").unwrap();
        assert!(matches!(write_rx.blocking_recv(), Some(WriteCommand::Data(bytes)) if bytes == b"ping"));
        writer.shutdown_write().unwrap();
        assert!(matches!(write_rx.blocking_recv(), Some(WriteCommand::Close)));

        let err = writer.read(&mut [0_u8; 1]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }

    #[test]
    fn tuic_options_keep_uuid_password_and_udp_flags() {
        let options = TuicOptions {
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            password: "secret".into(),
            token: String::new(),
            udp: false,
            sni: "edge.example".into(),
            certificate: String::new(),
            private_key: String::new(),
            alpn: vec!["h3".into()],
            disable_sni: false,
            request_timeout_ms: 8_000,
            heartbeat_interval_ms: 10_000,
            congestion_controller: "bbr".into(),
            max_open_streams: 100,
            max_udp_relay_packet_size: 1_252,
            skip_cert_verify: true,
        };
        assert_eq!(options.uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
        assert_eq!(options.password, "secret");
        assert!(!options.udp);
    }

    #[test]
    fn tuic_encode_address_supports_domain_targets() {
        let encoded = encode_address(&TransportTarget::new("final.example.com", 443)).unwrap();
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1] as usize, "final.example.com".len());
        assert_eq!(&encoded[2..2 + "final.example.com".len()], b"final.example.com");
        assert_eq!(&encoded[encoded.len() - 2..], &443_u16.to_be_bytes());
    }

    #[test]
    fn tuic_udp_encoding_rejects_frames_larger_than_limit() {
        let target: std::net::SocketAddr = "127.0.0.1:53".parse().unwrap();
        let err = encode_v5_native_packet(1, target, &[0_u8; 8], 16).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

        let err = encode_v4_native_packet(1, target, &[0_u8; 8], 16).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
