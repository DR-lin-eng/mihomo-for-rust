use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::io::IoSliceMut;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::mpsc::{self, Receiver};
use std::sync::OnceLock;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use bytes::Bytes;
use http::Request;
use hysteria2::config::Config as Hysteria2Config;
use mihomo_core::{BoxedTcpStream, TcpStream};
use quinn::{ClientConfig as QuinnClientConfig, Connection as QuinnConnection, Endpoint as QuinnEndpoint, EndpointConfig as QuinnEndpointConfig};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::SendDatagramError;
use quinn::{AsyncTimer as QuinnAsyncTimer, AsyncUdpSocket, Runtime as QuinnRuntime, UdpPoller};
use quinn_udp::{RecvMeta, Transmit};
use rustls023::crypto::aws_lc_rs;
use rustls023::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls023::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls023::{ClientConfig as RustlsClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Builder;
use tokio::sync::mpsc as tokio_mpsc;

use crate::udp_channel::{
    encode_udp_channel_frame, UdpChannelStream, UdpStreamCommand,
};
use crate::hy2_realm::{
    discover_stun_addresses, generate_punch_metadata, punch_peer_addresses, Hy2RealmOptions,
    RealmControlClient,
};
use crate::{TransportError, TransportTarget};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Hy2Options {
    pub password: String,
    pub sni: String,
    pub skip_cert_verify: bool,
    pub certificate: String,
    pub private_key: String,
    pub obfs: String,
    pub obfs_password: String,
    pub udp_mtu: usize,
    pub realm: Hy2RealmOptions,
}

enum WriteCommand {
    Data(Vec<u8>),
    Close,
}

enum Ready<T> {
    Ok(T),
    Err(io::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hy2UdpOptions {
    pub password: String,
    pub sni: String,
    pub skip_cert_verify: bool,
    pub certificate: String,
    pub private_key: String,
    pub obfs: String,
    pub obfs_password: String,
    pub udp_mtu: usize,
    pub realm: Hy2RealmOptions,
}

pub(crate) fn connect_stream(
    dialer: &mut impl crate::TcpDialer,
    proxy: &TransportTarget,
    options: &Hy2Options,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    if options.password.trim().is_empty() {
        return Err(TransportError::InvalidPlan(format!(
            "hysteria2 transport requires password for {}",
            proxy.authority()
        )));
    }

    let config = Hysteria2Config {
        auth: options.password.clone(),
        server_addr: format!("{}:{}", format_proxy_host(&proxy.host), proxy.port),
        server_name: if options.sni.trim().is_empty() {
            proxy.host.clone()
        } else {
            options.sni.clone()
        },
        insecure: options.skip_cert_verify,
        port_hopping_range: None,
    };

    if options.obfs.trim().is_empty() {
        if options.realm.enabled {
            connect_stream_from_config(
                proxy,
                &[],
                config,
                target,
                options.realm.clone(),
                &options.certificate,
                &options.private_key,
            )
        } else {
            let remote_addrs = dialer
                .resolve_addrs(proxy, &crate::SocketOptions::default(), crate::TcpDialPurpose::ProxyServer)?
                .into_iter()
                .map(|addr| addr.0)
                .collect::<Vec<_>>();
            connect_stream_from_config(
                proxy,
                &remote_addrs,
                config,
                target,
                options.realm.clone(),
                &options.certificate,
                &options.private_key,
            )
        }
    } else if options.obfs == "salamander" {
        if options.obfs_password.trim().is_empty() {
            return Err(TransportError::InvalidPlan(format!(
                "hysteria2 salamander obfs requires obfs-password for {}",
                proxy.authority()
            )));
        }
        if options.realm.enabled {
            connect_stream_with_salamander(
                proxy,
                &[],
                config,
                target,
                options.obfs_password.clone(),
                options.realm.clone(),
                &options.certificate,
                &options.private_key,
            )
        } else {
            let remote_addrs = dialer
                .resolve_addrs(proxy, &crate::SocketOptions::default(), crate::TcpDialPurpose::ProxyServer)?
                .into_iter()
                .map(|addr| addr.0)
                .collect::<Vec<_>>();
            connect_stream_with_salamander(
                proxy,
                &remote_addrs,
                config,
                target,
                options.obfs_password.clone(),
                options.realm.clone(),
                &options.certificate,
                &options.private_key,
            )
        }
    } else {
        Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("hysteria2 obfs={}", options.obfs),
        })
    }
}

pub(crate) fn open_udp_stream(
    dialer: &mut impl crate::TcpDialer,
    proxy: &TransportTarget,
    options: &Hy2UdpOptions,
) -> Result<BoxedTcpStream, TransportError> {
    open_udp_stream_with_socks5_stream(dialer, proxy, options, None, None)
}

pub(crate) fn open_udp_stream_with_socks5_stream(
    dialer: &mut impl crate::TcpDialer,
    proxy: &TransportTarget,
    options: &Hy2UdpOptions,
    control_stream: Option<BoxedTcpStream>,
    auth: Option<crate::BasicAuth>,
) -> Result<BoxedTcpStream, TransportError> {
    if options.password.trim().is_empty() {
        return Err(TransportError::InvalidPlan(format!(
            "hysteria2 transport requires password for {}",
            proxy.authority()
        )));
    }
    if !options.obfs.trim().is_empty() && options.obfs != "salamander" {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("hysteria2 obfs={}", options.obfs),
        });
    }

    let config = Hysteria2Config {
        auth: options.password.clone(),
        server_addr: format!("{}:{}", format_proxy_host(&proxy.host), proxy.port),
        server_name: if options.sni.trim().is_empty() {
            proxy.host.clone()
        } else {
            options.sni.clone()
        },
        insecure: options.skip_cert_verify,
        port_hopping_range: None,
    };
    let remote_addrs = dialer
        .resolve_addrs(proxy, &crate::SocketOptions::default(), crate::TcpDialPurpose::ProxyServer)?
        .into_iter()
        .map(|addr| addr.0)
        .collect::<Vec<_>>();

    let (read_tx, read_rx) = mpsc::channel();
    let (write_tx, write_rx) = tokio_mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let proxy_authority = proxy.authority();
    let options = options.clone();
    let control_stream = control_stream;
    let auth = auth;

    thread::spawn(move || {
        let runtime = Builder::new_current_thread().enable_all().build();
        match runtime {
            Ok(runtime) => {
                let worker_read_tx = read_tx.clone();
                let worker_ready_tx = ready_tx.clone();
                let result = runtime.block_on(async move {
                    ensure_crypto_provider();
                    if options.obfs.trim().is_empty() {
                        let connection = connect_hy2_connection(
                            &remote_addrs,
                            &config,
                            &options.realm,
                            control_stream,
                            auth,
                            &options.certificate,
                            &options.private_key,
                        )
                        .await?;
                        bridge_hy2_udp(
                            connection,
                            options.udp_mtu,
                            worker_read_tx,
                            write_rx,
                            &worker_ready_tx,
                        )
                        .await
                    } else {
                        let connection =
                            connect_hy2_salamander_connection(
                                &remote_addrs,
                                &config,
                                &options.obfs_password,
                                &options.realm,
                                control_stream,
                                auth,
                                &options.certificate,
                                &options.private_key,
                            )
                                .await?;
                        bridge_hy2_udp(
                            connection,
                            options.udp_mtu,
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
            "hysteria2 udp stream",
        ))),
        Ok(Ready::Err(err)) => Err(TransportError::from(err)),
        Err(_) => Err(TransportError::Io {
            kind: io::ErrorKind::ConnectionAborted,
            message: "hysteria2 udp client setup thread exited early".to_owned(),
        }),
    }
}

pub(crate) fn write_udp_packet(
    stream: &mut dyn Write,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    let mut frame = Vec::new();
    crate::udp_channel::encode_socket_addr(target, &mut frame)?;
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(payload.len())
}

pub(crate) fn read_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(std::net::SocketAddr, Vec<u8>)> {
    let source = crate::udp_channel::decode_socket_addr(stream)?;
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length)?;
    let length = u16::from_be_bytes(length) as usize;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok((source, payload))
}

fn connect_stream_from_config(
    proxy: &TransportTarget,
    remote_addrs: &[SocketAddr],
    config: Hysteria2Config,
    target: &TransportTarget,
    realm: Hy2RealmOptions,
    certificate: &str,
    private_key: &str,
) -> Result<BoxedTcpStream, TransportError> {
    let (read_tx, read_rx) = mpsc::channel();
    let (write_tx, write_rx) = tokio_mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let target_authority = target.authority();
    let proxy_authority = proxy.authority();
    let remote_addrs = remote_addrs.to_vec();
    let certificate = certificate.to_owned();
    let private_key = private_key.to_owned();

    thread::spawn(move || {
        let runtime = Builder::new_current_thread().enable_all().build();
        match runtime {
            Ok(runtime) => {
                let worker_read_tx = read_tx.clone();
                let worker_ready_tx = ready_tx.clone();
                let result = runtime.block_on(async move {
                    ensure_crypto_provider();
                    let connection =
                        connect_hy2_connection(
                            &remote_addrs,
                            &config,
                            &realm,
                            None,
                            None,
                            &certificate,
                            &private_key,
                        )
                        .await?;
                    let (mut send, mut recv) = connection.open_bi().await.map_err(io::Error::other)?;
                    let request = encode_hy2_tcp_request(&target_authority, 0);
                    send.write_all(&request).await.map_err(io::Error::other)?;
                    let (status_ok, message) = decode_hy2_tcp_response(&mut recv).await?;
                    if !status_ok {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("hysteria2 tcp connect failed: {message}"),
                        ));
                    }
                    bridge_hy2_quic_stream(send, recv, worker_read_tx, write_rx, &worker_ready_tx).await
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
        Ok(Ready::Ok(())) => Ok(Box::new(Hy2ChannelStream::new(read_rx, write_tx))),
        Ok(Ready::Err(err)) => Err(TransportError::from(err)),
        Err(_) => Err(TransportError::Io {
            kind: io::ErrorKind::ConnectionAborted,
            message: "hysteria2 client setup thread exited early".to_owned(),
        }),
    }
}

fn connect_stream_with_salamander(
    proxy: &TransportTarget,
    remote_addrs: &[SocketAddr],
    config: Hysteria2Config,
    target: &TransportTarget,
    obfs_password: String,
    realm: Hy2RealmOptions,
    certificate: &str,
    private_key: &str,
) -> Result<BoxedTcpStream, TransportError> {
    let (read_tx, read_rx) = mpsc::channel();
    let (write_tx, write_rx) = tokio_mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let target_authority = target.authority();
    let proxy_authority = proxy.authority();
    let remote_addrs = remote_addrs.to_vec();
    let certificate = certificate.to_owned();
    let private_key = private_key.to_owned();

    thread::spawn(move || {
        let runtime = Builder::new_current_thread().enable_all().build();
        match runtime {
            Ok(runtime) => {
                let worker_read_tx = read_tx.clone();
                let worker_ready_tx = ready_tx.clone();
                let result = runtime.block_on(async move {
                    ensure_crypto_provider();
                    let realm_conn = connect_hy2_salamander_connection(
                        &remote_addrs,
                        &config,
                        &obfs_password,
                        &realm,
                        None,
                        None,
                        &certificate,
                        &private_key,
                    )
                    .await?;
                    let (send, recv) = if realm.enabled {
                        let (mut send, mut recv) = realm_conn.open_bi().await.map_err(io::Error::other)?;
                        let request = encode_hy2_tcp_request(&target_authority, 0);
                        send.write_all(&request).await.map_err(io::Error::other)?;
                        let (status_ok, message) = decode_hy2_tcp_response(&mut recv).await?;
                        if !status_ok {
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                format!("hysteria2 tcp connect failed: {message}"),
                            ));
                        }
                        (send, recv)
                    } else {
                        connect_hy2_salamander_stream(
                            &remote_addrs,
                            &config,
                            &target_authority,
                            &obfs_password,
                            &certificate,
                            &private_key,
                        )
                            .await?
                    };
                    bridge_hy2_quic_stream(send, recv, worker_read_tx, write_rx, &worker_ready_tx)
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
        Ok(Ready::Ok(())) => Ok(Box::new(Hy2ChannelStream::new(read_rx, write_tx))),
        Ok(Ready::Err(err)) => Err(TransportError::from(err)),
        Err(_) => Err(TransportError::Io {
            kind: io::ErrorKind::ConnectionAborted,
            message: "hysteria2 salamander client setup thread exited early".to_owned(),
        }),
    }
}

fn ensure_crypto_provider() {
    static PROVIDER: OnceLock<()> = OnceLock::new();
    let _ = PROVIDER.get_or_init(|| {
        let _ = aws_lc_rs::default_provider().install_default();
    });
}

async fn resolve_socket_addrs(server_addr: &str, unresolved: &str) -> io::Result<Vec<SocketAddr>> {
    let addrs = tokio::net::lookup_host(server_addr).await?.collect::<Vec<_>>();
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
                        format!("hysteria2 connect to {remote_addr} timed out"),
                    ))
                }
            },
            Err(err) => last_err = Some(io::Error::other(err.to_string())),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, connect_error)))
}

type Blake2b256 = Blake2b<U32>;
const SALAMANDER_SALT_LEN: usize = 8;
const HYSTERIA_AUTH_STATUS: u16 = 233;

fn apply_salamander_obfs(password: &[u8], salt: &[u8], payload: &mut [u8]) {
    let mut hasher = Blake2b256::new();
    hasher.update(password);
    hasher.update(salt);
    let key = hasher.finalize();
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}

fn build_hy2_auth_request(config: &Hysteria2Config) -> Result<Request<()>, io::Error> {
    Request::builder()
        .method("POST")
        .uri("https://hysteria/auth")
        .header("Host", "hysteria")
        .header("Hysteria-Auth", &config.auth)
        .header("Hysteria-CC-RX", "0")
        .header("Hysteria-Padding", random_padding())
        .body(())
        .map_err(io::Error::other)
}

fn validate_hy2_auth_response(resp: &http::Response<()>) -> io::Result<()> {
    if resp.status().as_u16() != HYSTERIA_AUTH_STATUS {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("hysteria2 authentication failed: status {}", resp.status()),
        ));
    }
    Ok(())
}

fn random_padding() -> String {
    const PADDING_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let padding_len = rand::Rng::gen_range(&mut rng, 8..40);
    let mut padding = String::with_capacity(padding_len);
    for _ in 0..padding_len {
        let idx = rand::Rng::gen_range(&mut rng, 0..PADDING_CHARS.len());
        padding.push(PADDING_CHARS[idx] as char);
    }
    padding
}

fn format_proxy_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') && !host.ends_with(']') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

fn map_hysteria_error(err: hysteria2::HysteriaError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}

#[derive(Debug)]
struct TokioQuinnRuntime;

impl QuinnRuntime for TokioQuinnRuntime {
    fn new_timer(&self, i: std::time::Instant) -> Pin<Box<dyn QuinnAsyncTimer>> {
        Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(i)))
    }

    fn spawn(&self, future: Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        Ok(Arc::new(SalamanderUdpSocket::new(socket, Vec::new())?))
    }

    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}

#[derive(Debug)]
struct SalamanderUdpSocket {
    io: tokio::net::UdpSocket,
    local_addr: SocketAddr,
    obfs_password: Vec<u8>,
}

impl SalamanderUdpSocket {
    fn new(socket: std::net::UdpSocket, obfs_password: Vec<u8>) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        let local_addr = socket.local_addr()?;
        Ok(Self {
            io: tokio::net::UdpSocket::from_std(socket)?,
            local_addr,
            obfs_password,
        })
    }

    fn maybe_decode_recv(&self, meta: &mut RecvMeta, buf: &mut [u8]) {
        if self.obfs_password.is_empty() || meta.len <= SALAMANDER_SALT_LEN {
            return;
        }
        let payload_len = meta.len - SALAMANDER_SALT_LEN;
        let salt = buf[..SALAMANDER_SALT_LEN].to_vec();
        buf.copy_within(SALAMANDER_SALT_LEN..meta.len, 0);
        let payload = &mut buf[..payload_len];
        apply_salamander_obfs(&self.obfs_password, &salt, payload);
        meta.len = payload_len;
        meta.stride = payload_len;
    }
}

impl AsyncUdpSocket for SalamanderUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SalamanderUdpPoller { socket: self })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let mut owned;
        let tx = if self.obfs_password.is_empty() {
            transmit.clone()
        } else {
            let mut salt = [0_u8; SALAMANDER_SALT_LEN];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
            owned = Vec::with_capacity(SALAMANDER_SALT_LEN + transmit.contents.len());
            owned.extend_from_slice(&salt);
            owned.extend_from_slice(transmit.contents);
            apply_salamander_obfs(
                &self.obfs_password,
                &salt,
                &mut owned[SALAMANDER_SALT_LEN..],
            );
            Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &owned,
                segment_size: None,
                src_ip: transmit.src_ip,
            }
        };
        let _ = tx.contents.len();
        self.io.try_send_to(tx.contents, tx.destination).map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
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
                    meta[0] = RecvMeta {
                        addr,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: None,
                    };
                    self.maybe_decode_recv(&mut meta[0], dst);
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
struct SalamanderUdpPoller {
    socket: Arc<SalamanderUdpSocket>,
}

impl UdpPoller for SalamanderUdpPoller {
    fn poll_writable(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.socket.io.poll_send_ready(cx)
    }
}

fn build_rustls_client_config_023(
    config: &Hysteria2Config,
    certificate: &str,
    private_key: &str,
) -> io::Result<std::sync::Arc<RustlsClientConfig>> {
    let builder = RustlsClientConfig::builder();
    let client_auth_enabled = !certificate.trim().is_empty() || !private_key.trim().is_empty();
    let mut crypto = if config.insecure {
        let builder = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification023));
        if client_auth_enabled {
            let certs = parse_client_certificates(certificate)?;
            let key = parse_client_private_key(private_key)?;
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
            let certs = parse_client_certificates(certificate)?;
            let key = parse_client_private_key(private_key)?;
            builder
                .with_root_certificates(roots)
                .with_client_auth_cert(certs, key)
                .map_err(io::Error::other)?
        }
    };
    crypto.alpn_protocols = vec![b"h3".to_vec()];
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
            "failed to parse hysteria2 client certificate",
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
            "failed to parse hysteria2 client private key",
        ));
    };
    Ok(rustls023::pki_types::PrivatePkcs1KeyDer::from(key).into())
}

async fn connect_hy2_salamander_stream(
    remote_addrs: &[SocketAddr],
    config: &Hysteria2Config,
    target_authority: &str,
    obfs_password: &str,
    certificate: &str,
    private_key: &str,
) -> io::Result<(quinn::SendStream, quinn::RecvStream)> {
    let conn =
        connect_hy2_salamander_connection(
            remote_addrs,
            config,
            obfs_password,
            &Hy2RealmOptions::default(),
            None,
            None,
            certificate,
            private_key,
        )
            .await?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(io::Error::other)?;
    let request = encode_hy2_tcp_request(target_authority, 0);
    send.write_all(&request).await?;
    let (status_ok, message) = decode_hy2_tcp_response(&mut recv).await?;
    if !status_ok {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("hysteria2 tcp connect failed: {message}"),
        ));
    }
    Ok((send, recv))
}

async fn connect_hy2_connection(
    remote_addrs: &[SocketAddr],
    config: &Hysteria2Config,
    realm: &Hy2RealmOptions,
    control_stream: Option<BoxedTcpStream>,
    auth: Option<crate::BasicAuth>,
    certificate: &str,
    private_key: &str,
) -> io::Result<QuinnConnection> {
    if realm.enabled {
        return connect_hy2_realm_connection(config, realm, None, certificate, private_key).await;
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
        let runtime = Arc::new(TokioQuinnRuntime);
        let socket = Arc::new(crate::socks5_udp_underlay::Socks5UdpAssociateSocket::new(
            udp_socket,
            relay_addr,
            control,
        )?);
        QuinnEndpoint::new_with_abstract_socket(
            QuinnEndpointConfig::default(),
            None,
            socket,
            runtime,
        )?
    } else {
        QuinnEndpoint::new(Default::default(), None, mihomo_core::bind_outbound_udp(local_addr)?, Arc::new(quinn::TokioRuntime)).map_err(io::Error::other)?
    };
    let client_crypto = build_rustls_client_config_023(config, certificate, private_key)?;
    let client_config = QuinnClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto).map_err(io::Error::other)?,
    ));
    endpoint.set_default_client_config(client_config);
    let server_name = ServerName::try_from(config.server_name.clone())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid hysteria2 server name"))?;
    let conn = connect_quinn_endpoint(
        &endpoint,
        &remote_addrs,
        &server_name,
        "hysteria2 server connect failed for all resolved addresses",
    )
    .await?;
    authenticate_hy2_connection(&conn, config).await?;
    Ok(conn)
}

async fn connect_hy2_salamander_connection(
    remote_addrs: &[SocketAddr],
    config: &Hysteria2Config,
    obfs_password: &str,
    realm: &Hy2RealmOptions,
    control_stream: Option<BoxedTcpStream>,
    auth: Option<crate::BasicAuth>,
    certificate: &str,
    private_key: &str,
) -> io::Result<QuinnConnection> {
    if realm.enabled {
        return connect_hy2_realm_connection(
            config,
            realm,
            Some(obfs_password),
            certificate,
            private_key,
        )
        .await;
    }
    let local_addr: SocketAddr = "0.0.0.0:0".parse().map_err(io::Error::other)?;
    let runtime = Arc::new(TokioQuinnRuntime);
    let mut endpoint = if let Some(mut control) = control_stream {
        let (udp_socket, relay_addr) = crate::socks5_udp_underlay::connect_socks5_udp_associate_over_stream(
            &mut *control,
            local_addr,
            auth.as_ref(),
        )
        .map_err(|err| io::Error::other(err.to_string()))?;
        let socket = Arc::new(SalamanderUdpSocket::new(
            udp_socket,
            obfs_password.as_bytes().to_vec(),
        )?);
        QuinnEndpoint::new_with_abstract_socket(
            QuinnEndpointConfig::default(),
            None,
            socket,
            runtime,
        )?
    } else {
        let socket = Arc::new(SalamanderUdpSocket::new(
            mihomo_core::bind_outbound_udp(local_addr)?,
            obfs_password.as_bytes().to_vec(),
        )?);
        QuinnEndpoint::new_with_abstract_socket(
            QuinnEndpointConfig::default(),
            None,
            socket,
            runtime,
        )?
    };
    let client_crypto = build_rustls_client_config_023(config, certificate, private_key)?;
    let client_config = QuinnClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto).map_err(io::Error::other)?,
    ));
    endpoint.set_default_client_config(client_config);
    let server_name = ServerName::try_from(config.server_name.clone())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid hysteria2 server name"))?;
    let conn = connect_quinn_endpoint(
        &endpoint,
        &remote_addrs,
        &server_name,
        "hysteria2 salamander server connect failed for all resolved addresses",
    )
    .await?;
    authenticate_hy2_connection(&conn, config).await?;
    Ok(conn)
}

async fn connect_hy2_realm_connection(
    config: &Hysteria2Config,
    realm: &Hy2RealmOptions,
    obfs_password: Option<&str>,
    certificate: &str,
    private_key: &str,
) -> io::Result<QuinnConnection> {
    if realm.stun_servers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hysteria2 realm-opts requires stun-servers",
        ));
    }
    if realm.realm_id.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hysteria2 realm-opts requires realm-id",
        ));
    }

    let bind_addr = resolve_realm_bind_addr(&realm.stun_servers)?;
    let raw_socket = mihomo_core::bind_outbound_udp(bind_addr)?;
    let punch_socket = raw_socket.try_clone()?;
    let local_addresses = discover_stun_addresses(&punch_socket, &realm.stun_servers)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    let metadata = generate_punch_metadata()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    let control = RealmControlClient::new(realm)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let response = control
        .connect(&realm.realm_id, &local_addresses, metadata)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    let peer_addr = punch_peer_addresses(
        &punch_socket,
        &local_addresses,
        &response.addresses,
        response.punch_metadata,
    )
    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;

    raw_socket.set_read_timeout(None)?;
    raw_socket.set_write_timeout(None)?;

    let runtime = Arc::new(TokioQuinnRuntime);
    let socket = Arc::new(SalamanderUdpSocket::new(
        raw_socket,
        obfs_password
            .map(|password| password.as_bytes().to_vec())
            .unwrap_or_default(),
    )?);
    let mut endpoint = QuinnEndpoint::new_with_abstract_socket(
        QuinnEndpointConfig::default(),
        None,
        socket,
        runtime,
    )?;
    let client_crypto = build_rustls_client_config_023(config, certificate, private_key)?;
    let client_config = QuinnClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto).map_err(io::Error::other)?,
    ));
    endpoint.set_default_client_config(client_config);
    let server_name = ServerName::try_from(config.server_name.clone())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid hysteria2 server name"))?;
    let conn = endpoint
        .connect(peer_addr, server_name.to_str().as_ref())
        .map_err(io::Error::other)?
        .await
        .map_err(io::Error::other)?;
    authenticate_hy2_connection(&conn, config).await?;
    Ok(conn)
}

fn resolve_realm_bind_addr(servers: &[String]) -> io::Result<SocketAddr> {
    let mut has_ipv4 = false;
    let mut has_ipv6 = false;
    for server in servers {
        if let Ok(iter) = server.to_socket_addrs() {
            for addr in iter {
                if addr.is_ipv4() {
                    has_ipv4 = true;
                } else {
                    has_ipv6 = true;
                }
            }
        }
    }
    let bind = if has_ipv4 || !has_ipv6 {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    bind.parse().map_err(io::Error::other)
}

async fn authenticate_hy2_connection(
    conn: &QuinnConnection,
    config: &Hysteria2Config,
) -> io::Result<()> {
    let (h3_conn, mut request_stream) =
        h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .map_err(io::Error::other)?;
    let req = build_hy2_auth_request(config)?;
    let mut stream = request_stream
        .send_request(req)
        .await
        .map_err(io::Error::other)?;
    stream.finish().await.map_err(io::Error::other)?;
    let resp = stream.recv_response().await.map_err(io::Error::other)?;
    let closed = conn.clone();
    tokio::spawn(async move {
        let _h3_guard = h3_conn;
        let _request_guard = request_stream;
        let _ = closed.closed().await;
    });
    validate_hy2_auth_response(&resp)
}

fn encode_hy2_tcp_request(address: &str, padding_len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + address.len() + padding_len);
    put_varint(0x401, &mut buf);
    put_varint(address.len() as u64, &mut buf);
    buf.extend_from_slice(address.as_bytes());
    put_varint(padding_len as u64, &mut buf);
    if padding_len > 0 {
        let mut padding = vec![0_u8; padding_len];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding);
        buf.extend_from_slice(&padding);
    }
    buf
}

async fn decode_hy2_tcp_response<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> io::Result<(bool, String)> {
    let status = reader.read_u8().await? == 0x00;
    let msg_len = read_varint(reader).await? as usize;
    let mut msg_buf = vec![0_u8; msg_len];
    reader.read_exact(&mut msg_buf).await?;
    let message = String::from_utf8_lossy(&msg_buf).to_string();
    let padding_len = read_varint(reader).await? as usize;
    if padding_len > 0 {
        let mut discard = vec![0_u8; padding_len];
        reader.read_exact(&mut discard).await?;
    }
    Ok((status, message))
}

async fn bridge_hy2_quic_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    read_tx: mpsc::Sender<io::Result<Vec<u8>>>,
    mut write_rx: tokio_mpsc::UnboundedReceiver<WriteCommand>,
    ready_tx: &mpsc::SyncSender<Ready<()>>,
) -> io::Result<()> {
    ready_tx
        .send(Ready::Ok(()))
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "hy2 setup receiver dropped"))?;

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
struct Hy2UdpMessage {
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_total: u8,
    destination: String,
    payload: Vec<u8>,
}

fn encode_hy2_udp_varint(value: u64, out: &mut Vec<u8>) {
    put_varint(value, out);
}

fn decode_hy2_udp_varint(reader: &mut dyn Read) -> io::Result<u64> {
    let mut first = [0_u8; 1];
    reader.read_exact(&mut first)?;
    let tag = first[0] >> 6;
    let mut buf = [0_u8; 8];
    match tag {
        0 => Ok((first[0] & 0x3f) as u64),
        1 => {
            buf[0] = first[0];
            reader.read_exact(&mut buf[1..2])?;
            Ok(u16::from_be_bytes(buf[..2].try_into().unwrap()) as u64 & 0x3fff)
        }
        2 => {
            buf[0] = first[0];
            reader.read_exact(&mut buf[1..4])?;
            Ok(u32::from_be_bytes(buf[..4].try_into().unwrap()) as u64 & 0x3fff_ffff)
        }
        _ => {
            buf[0] = first[0];
            reader.read_exact(&mut buf[1..8])?;
            Ok(u64::from_be_bytes(buf) & 0x3fff_ffff_ffff_ffff)
        }
    }
}

fn encode_hy2_udp_message(message: &Hy2UdpMessage) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(8 + message.destination.len() + message.payload.len());
    out.extend_from_slice(&message.session_id.to_be_bytes());
    out.extend_from_slice(&message.packet_id.to_be_bytes());
    out.push(message.fragment_id);
    out.push(message.fragment_total);
    encode_hy2_udp_varint(message.destination.len() as u64, &mut out);
    out.extend_from_slice(message.destination.as_bytes());
    out.extend_from_slice(&message.payload);
    Ok(out)
}

fn decode_hy2_udp_message(data: &[u8]) -> io::Result<Hy2UdpMessage> {
    let mut reader = std::io::Cursor::new(data);
    let mut session = [0_u8; 4];
    std::io::Read::read_exact(&mut reader, &mut session)?;
    let session_id = u32::from_be_bytes(session);
    let mut packet = [0_u8; 2];
    std::io::Read::read_exact(&mut reader, &mut packet)?;
    let packet_id = u16::from_be_bytes(packet);
    let mut fragment_id = [0_u8; 1];
    std::io::Read::read_exact(&mut reader, &mut fragment_id)?;
    let mut fragment_total = [0_u8; 1];
    std::io::Read::read_exact(&mut reader, &mut fragment_total)?;
    let address_len = decode_hy2_udp_varint(&mut reader)? as usize;
    let mut address = vec![0_u8; address_len];
    std::io::Read::read_exact(&mut reader, &mut address)?;
    let mut payload = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut payload)?;
    Ok(Hy2UdpMessage {
        session_id,
        packet_id,
        fragment_id: fragment_id[0],
        fragment_total: fragment_total[0],
        destination: String::from_utf8_lossy(&address).into_owned(),
        payload,
    })
}

fn resolve_hy2_udp_socket_addr(value: &str) -> io::Result<SocketAddr> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let mut addrs = value.to_socket_addrs()?;
    addrs.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "hysteria2 udp fqdn target unresolved",
        )
    })
}

fn fragment_hy2_udp_message(message: &Hy2UdpMessage, max_datagram_size: usize) -> Vec<Hy2UdpMessage> {
    let mut header = Vec::new();
    header.extend_from_slice(&message.session_id.to_be_bytes());
    header.extend_from_slice(&message.packet_id.to_be_bytes());
    header.push(0);
    header.push(0);
    encode_hy2_udp_varint(message.destination.len() as u64, &mut header);
    header.extend_from_slice(message.destination.as_bytes());
    let payload_mtu = max_datagram_size.saturating_sub(header.len()).max(1);
    if message.payload.len() <= payload_mtu {
        return vec![message.clone()];
    }
    let chunks = message.payload.chunks(payload_mtu).collect::<Vec<_>>();
    let total = chunks.len() as u8;
    chunks
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| Hy2UdpMessage {
            session_id: message.session_id,
            packet_id: message.packet_id,
            fragment_id: index as u8,
            fragment_total: total,
            destination: message.destination.clone(),
            payload: chunk.to_vec(),
        })
        .collect()
}

fn defragment_hy2_udp_message(
    fragments: &mut BTreeMap<(u32, u16), Vec<Option<Hy2UdpMessage>>>,
    message: Hy2UdpMessage,
) -> Option<Hy2UdpMessage> {
    if message.fragment_total <= 1 {
        return Some(message);
    }
    if message.fragment_id >= message.fragment_total {
        return None;
    }
    let key = (message.session_id, message.packet_id);
    let entry = fragments
        .entry(key)
        .or_insert_with(|| vec![None; message.fragment_total as usize]);
    if entry.len() != message.fragment_total as usize {
        *entry = vec![None; message.fragment_total as usize];
    }
    if entry[message.fragment_id as usize].is_some() {
        return None;
    }
    let fragment_index = message.fragment_id as usize;
    entry[fragment_index] = Some(message);
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
    Some(Hy2UdpMessage {
        payload,
        fragment_id: 0,
        fragment_total: 1,
        ..first
    })
}

async fn send_hy2_udp_message(
    connection: &QuinnConnection,
    message: Hy2UdpMessage,
    udp_mtu: usize,
) -> io::Result<()> {
    let max_datagram_size = connection.max_datagram_size().unwrap_or(udp_mtu.max(1200));
    let fragments = fragment_hy2_udp_message(&message, max_datagram_size);
    for fragment in fragments {
        let packet = encode_hy2_udp_message(&fragment)?;
        match connection.send_datagram(Bytes::from(packet)) {
            Ok(()) => {}
            Err(SendDatagramError::TooLarge) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "hysteria2 udp datagram too large",
                ));
            }
            Err(SendDatagramError::UnsupportedByPeer) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "hysteria2 udp is disabled by peer",
                ));
            }
            Err(SendDatagramError::Disabled) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "hysteria2 udp datagrams are disabled",
                ));
            }
            Err(SendDatagramError::ConnectionLost(err)) => return Err(io::Error::other(err)),
        }
    }
    Ok(())
}

async fn bridge_hy2_udp(
    connection: QuinnConnection,
    udp_mtu: usize,
    read_tx: mpsc::Sender<io::Result<Vec<u8>>>,
    mut write_rx: tokio_mpsc::UnboundedReceiver<UdpStreamCommand>,
    ready_tx: &mpsc::SyncSender<Ready<()>>,
) -> io::Result<()> {
    let recv_connection = connection.clone();
    let recv_tx = read_tx.clone();
    tokio::spawn(async move {
        let mut fragments = BTreeMap::new();
        loop {
            let bytes = match recv_connection.read_datagram().await {
                Ok(bytes) => bytes,
                Err(err) => {
                    let _ = recv_tx.send(Err(io::Error::other(err.to_string())));
                    break;
                }
            };
            let Ok(message) = decode_hy2_udp_message(bytes.as_ref()) else {
                continue;
            };
            let Some(message) = defragment_hy2_udp_message(&mut fragments, message) else {
                continue;
            };
            let Ok(source) = resolve_hy2_udp_socket_addr(&message.destination) else {
                continue;
            };
            let _ = recv_tx.send(Ok(encode_udp_channel_frame(source, &message.payload)));
        }
    });

    ready_tx
        .send(Ready::Ok(()))
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "hy2 udp setup receiver dropped"))?;

    let mut packet_id = 0_u16;
    while let Some(command) = write_rx.recv().await {
        match command {
            UdpStreamCommand::Datagram { target, payload } => {
                packet_id = packet_id.wrapping_add(1);
                let message = Hy2UdpMessage {
                    session_id: 1,
                    packet_id,
                    fragment_id: 0,
                    fragment_total: 1,
                    destination: target.to_string(),
                    payload,
                };
                send_hy2_udp_message(&connection, message, udp_mtu).await?;
            }
            UdpStreamCommand::Close => break,
        }
    }
    Ok(())
}


fn put_varint(value: u64, out: &mut Vec<u8>) {
    if value < (1 << 6) {
        out.push(value as u8);
    } else if value < (1 << 14) {
        let mut bytes = ((1_u16 << 14) | value as u16).to_be_bytes();
        bytes[0] |= 0b01 << 6;
        out.extend_from_slice(&bytes);
    } else if value < (1 << 30) {
        let mut bytes = ((1_u32 << 30) | value as u32).to_be_bytes();
        bytes[0] |= 0b10 << 6;
        out.extend_from_slice(&bytes);
    } else {
        let mut bytes = ((1_u64 << 62) | value).to_be_bytes();
        bytes[0] |= 0b11 << 6;
        out.extend_from_slice(&bytes);
    }
}

async fn read_varint<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<u64> {
    let first = reader.read_u8().await?;
    let tag = first >> 6;
    let mut buf = [0_u8; 8];
    match tag {
        0 => Ok((first & 0x3f) as u64),
        1 => {
            buf[0] = first;
            reader.read_exact(&mut buf[1..2]).await?;
            Ok(u16::from_be_bytes(buf[..2].try_into().unwrap()) as u64 & 0x3fff)
        }
        2 => {
            buf[0] = first;
            reader.read_exact(&mut buf[1..4]).await?;
            Ok(u32::from_be_bytes(buf[..4].try_into().unwrap()) as u64 & 0x3fff_ffff)
        }
        _ => {
            buf[0] = first;
            reader.read_exact(&mut buf[1..8]).await?;
            Ok(u64::from_be_bytes(buf) & 0x3fff_ffff_ffff_ffff)
        }
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

async fn bridge_hy2_stream(
    mut stream: hysteria2::DuplexStream,
    read_tx: mpsc::Sender<io::Result<Vec<u8>>>,
    mut write_rx: tokio_mpsc::UnboundedReceiver<WriteCommand>,
    ready_tx: &mpsc::SyncSender<Ready<()>>,
) -> io::Result<()> {
    ready_tx
        .send(Ready::Ok(()))
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "hy2 setup receiver dropped"))?;

    let mut read_buf = vec![0_u8; 64 * 1024];
    let mut write_closed = false;

    loop {
        tokio::select! {
            result = stream.read(&mut read_buf) => {
                match result {
                    Ok(0) => {
                        let _ = read_tx.send(Ok(Vec::new()));
                        return Ok(());
                    }
                    Ok(read) => {
                        let _ = read_tx.send(Ok(read_buf[..read].to_vec()));
                    }
                    Err(err) => return Err(err),
                }
            }
            maybe = write_rx.recv(), if !write_closed => {
                match maybe {
                    Some(WriteCommand::Data(data)) => {
                        stream.write_all(&data).await?;
                        stream.flush().await?;
                    }
                    Some(WriteCommand::Close) | None => {
                        write_closed = true;
                        stream.shutdown().await?;
                    }
                }
            }
        }
    }
}

struct Hy2ChannelStream {
    read_rx: Receiver<io::Result<Vec<u8>>>,
    write_tx: tokio_mpsc::UnboundedSender<WriteCommand>,
    pending: Vec<u8>,
    offset: usize,
    write_closed: bool,
}

struct Hy2WriteClone {
    write_tx: tokio_mpsc::UnboundedSender<WriteCommand>,
    write_closed: bool,
}

impl Hy2ChannelStream {
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

impl Read for Hy2ChannelStream {
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
                "hysteria2 stream read timed out",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(0),
        }
    }
}

impl Write for Hy2ChannelStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(WriteCommand::Data(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "hysteria2 stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for Hy2ChannelStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Hy2WriteClone {
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

impl Read for Hy2WriteClone {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "hysteria2 write clone does not support reads",
        ))
    }
}

impl Write for Hy2WriteClone {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(WriteCommand::Data(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "hysteria2 stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for Hy2WriteClone {
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

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::sync::mpsc;

    use crate::hy2_realm::Hy2RealmOptions;
    use crate::hy2_stream::{Hy2ChannelStream, Hy2Options, WriteCommand, apply_salamander_obfs};
    use mihomo_core::TcpStream;
    use tokio::sync::mpsc as tokio_mpsc;

    use super::format_proxy_host;

    #[test]
    fn formats_ipv6_proxy_host_for_url_authority() {
        assert_eq!(format_proxy_host("2001:db8::1"), "[2001:db8::1]");
        assert_eq!(format_proxy_host("[2001:db8::1]"), "[2001:db8::1]");
        assert_eq!(format_proxy_host("example.com"), "example.com");
    }

    #[test]
    fn hy2_write_clone_supports_write_only_duplication() {
        let (_read_tx, read_rx) = mpsc::channel();
        let (write_tx, mut write_rx) = tokio_mpsc::unbounded_channel();
        let stream = Hy2ChannelStream::new(read_rx, write_tx);
        let mut writer = stream.try_clone_box().unwrap();

        writer.write_all(b"ping").unwrap();
        assert!(matches!(write_rx.blocking_recv(), Some(WriteCommand::Data(bytes)) if bytes == b"ping"));
        writer.shutdown_write().unwrap();
        assert!(matches!(write_rx.blocking_recv(), Some(WriteCommand::Close)));

        let err = writer.read(&mut [0_u8; 1]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }

    #[test]
    fn salamander_obfs_round_trip_restores_payload() {
        let password = b"secret";
        let salt = *b"12345678";
        let mut payload = b"hello salamander".to_vec();
        let original = payload.clone();

        apply_salamander_obfs(password, &salt, &mut payload);
        assert_ne!(payload, original);
        apply_salamander_obfs(password, &salt, &mut payload);
        assert_eq!(payload, original);
    }

    #[test]
    fn hy2_options_carry_obfs_fields() {
        let options = Hy2Options {
            password: "pass".into(),
            sni: "edge.example".into(),
            skip_cert_verify: true,
            certificate: String::new(),
            private_key: String::new(),
            obfs: "salamander".into(),
            obfs_password: "hidden".into(),
            udp_mtu: 1200,
            realm: Hy2RealmOptions::default(),
        };
        assert_eq!(options.obfs, "salamander");
        assert_eq!(options.obfs_password, "hidden");
    }
}
