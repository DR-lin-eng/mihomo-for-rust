use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::client;
use http::{Request, Uri, Version};
use mihomo_core::{BoxedTcpStream, TcpStream};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{
    ClientConfig as QuinnClientConfig, Connection as QuinnConnection, Endpoint as QuinnEndpoint,
    EndpointConfig as QuinnEndpointConfig, Runtime as QuinnRuntime, UdpPoller,
};
use rustls023::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls023::crypto::aws_lc_rs;
use rustls023::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls023::{ClientConfig as RustlsClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::runtime::Builder;
use tokio::sync::mpsc as tokio_mpsc;

use crate::{TransportError, TransportTarget};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct H3RequestOptions {
    pub authority: String,
    pub path: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
}

#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H3AcceptedTestRequest {
    pub method: String,
    pub authority: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H3ConnectOptions {
    pub sni: String,
    pub alpn: Vec<String>,
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

pub(crate) fn wrap_quic_stream_with_request(
    proxy: &TransportTarget,
    tls: &H3ConnectOptions,
    request: H3RequestOptions,
) -> Result<BoxedTcpStream, TransportError> {
    wrap_quic_stream_with_request_and_socks5_stream(proxy, tls, request, None, None)
}

pub(crate) fn wrap_quic_stream_with_request_and_socks5_stream(
    proxy: &TransportTarget,
    tls: &H3ConnectOptions,
    request: H3RequestOptions,
    control_stream: Option<BoxedTcpStream>,
    auth: Option<crate::BasicAuth>,
) -> Result<BoxedTcpStream, TransportError> {
    let (read_tx, read_rx) = mpsc::channel();
    let (write_tx, write_rx) = tokio_mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let proxy = proxy.clone();
    let tls = tls.clone();
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
                    let connection = connect_quic(&proxy, &tls, control_stream, auth).await?;
                    run_h3_client(connection, request, worker_read_tx, write_rx, &worker_ready_tx).await
                });
                if let Err(err) = result {
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
        Ok(Ready::Ok(())) => Ok(Box::new(H3ChannelStream::new(read_rx, write_tx))),
        Ok(Ready::Err(err)) => Err(TransportError::from(err)),
        Err(_) => Err(TransportError::Io {
            kind: io::ErrorKind::ConnectionAborted,
            message: "h3 client setup thread exited early".to_owned(),
        }),
    }
}

fn ensure_crypto_provider() {
    static PROVIDER: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    let _ = PROVIDER.get_or_init(|| {
        let _ = aws_lc_rs::default_provider().install_default();
    });
}

async fn connect_quic(
    proxy: &TransportTarget,
    tls: &H3ConnectOptions,
    control_stream: Option<BoxedTcpStream>,
    auth: Option<crate::BasicAuth>,
) -> io::Result<QuinnConnection> {
    let remote_addr = tokio::net::lookup_host((proxy.host.as_str(), proxy.port))
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "h3 server address unresolved"))?;
    let bind_addr = if remote_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let local_addr = bind_addr.parse::<SocketAddr>().map_err(io::Error::other)?;
    let mut endpoint = if let Some(mut control) = control_stream {
        let (udp_socket, relay_addr) =
            crate::socks5_udp_underlay::connect_socks5_udp_associate_over_stream(
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
    let client_crypto = build_client_config(tls)?;
    let client_config = QuinnClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto).map_err(io::Error::other)?,
    ));
    endpoint.set_default_client_config(client_config);
    let server_name = resolve_server_name(proxy, tls)?;
    endpoint
        .connect(remote_addr, server_name.to_str().as_ref())
        .map_err(io::Error::other)?
        .await
        .map_err(io::Error::other)
}

fn build_client_config(
    tls: &H3ConnectOptions,
) -> io::Result<Arc<RustlsClientConfig>> {
    let builder = RustlsClientConfig::builder();
    let mut crypto = if tls.skip_cert_verify {
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
    crypto.alpn_protocols = if tls.alpn.is_empty() {
        vec![b"h3".to_vec()]
    } else {
        tls.alpn.iter().map(|value| value.as_bytes().to_vec()).collect()
    };
    Ok(Arc::new(crypto))
}

fn resolve_server_name<'a>(
    proxy: &TransportTarget,
    tls: &'a H3ConnectOptions,
) -> io::Result<ServerName<'a>> {
    let server_name = if tls.sni.trim().is_empty() {
        proxy.host.as_str()
    } else {
        tls.sni.trim()
    };
    ServerName::try_from(server_name.to_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid h3 server name"))
}

fn build_h3_uri(authority: &str, path: &str) -> io::Result<Uri> {
    Uri::from_str(&format!("https://{authority}{path}"))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))
}

async fn run_h3_client(
    connection: QuinnConnection,
    request: H3RequestOptions,
    read_tx: mpsc::Sender<io::Result<Vec<u8>>>,
    mut write_rx: tokio_mpsc::UnboundedReceiver<WriteCommand>,
    ready_tx: &SyncSender<Ready<()>>,
) -> io::Result<()> {
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut driver, mut sender) = client::new(h3_connection)
        .await
        .map_err(io::Error::other)?;
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let mut builder = Request::builder()
        .method(request.method.as_str())
        .version(Version::HTTP_3)
        .uri(build_h3_uri(&request.authority, &request.path)?);
    for (name, value) in &request.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let request = builder
        .body(())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let mut request_stream = sender.send_request(request).await.map_err(io::Error::other)?;
    let response = request_stream.recv_response().await.map_err(io::Error::other)?;
    if response.status() != http::StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("unexpected h3 status {}", response.status()),
        ));
    }
    let (mut send_stream, mut recv_stream) = request_stream.split();
    let _ = ready_tx.send(Ready::Ok(()));

    let mut send_closed = false;
    loop {
        tokio::select! {
            maybe = write_rx.recv(), if !send_closed => {
                match maybe {
                    Some(WriteCommand::Data(data)) => {
                        send_stream.send_data(Bytes::from(data)).await.map_err(io::Error::other)?;
                    }
                    Some(WriteCommand::Close) | None => {
                        send_stream.finish().await.map_err(io::Error::other)?;
                        send_closed = true;
                    }
                }
            }
            data = recv_stream.recv_data() => {
                match data.map_err(io::Error::other)? {
                    Some(mut bytes) => {
                        let copied = bytes.copy_to_bytes(bytes.remaining());
                        let _ = read_tx.send(Ok(copied.to_vec()));
                    }
                    None => {
                        let _ = read_tx.send(Ok(Vec::new()));
                        break;
                    }
                }
            }
        }
    }
    driver_task.abort();
    Ok(())
}

struct H3ChannelStream {
    read_rx: Receiver<io::Result<Vec<u8>>>,
    write_tx: tokio_mpsc::UnboundedSender<WriteCommand>,
    pending: Vec<u8>,
    offset: usize,
    write_closed: bool,
}

struct H3WriteClone {
    write_tx: tokio_mpsc::UnboundedSender<WriteCommand>,
    write_closed: bool,
}

impl H3ChannelStream {
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

impl Read for H3ChannelStream {
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
                "h3 stream read timed out",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(0),
        }
    }
}

impl Write for H3ChannelStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(WriteCommand::Data(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "h3 stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for H3ChannelStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(H3WriteClone {
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

impl Read for H3WriteClone {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "h3 write clone does not support reads",
        ))
    }
}

impl Write for H3WriteClone {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(WriteCommand::Data(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "h3 stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for H3WriteClone {
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

struct BlockingIo {
    inner: BoxedTcpStream,
}

impl AsyncRead for BlockingIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let unfilled = buf.initialize_unfilled();
        match self.inner.read(unfilled) {
            Ok(0) => Poll::Ready(Ok(())),
            Ok(read) => {
                buf.advance(read);
                Poll::Ready(Ok(()))
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

impl AsyncWrite for BlockingIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(self.inner.write(buf))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.inner.flush())
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.inner.shutdown_write())
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
    ) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        Ok(Arc::new(SimpleUdpSocket::new(TokioUdpSocket::from_std(socket)?)?))
    }
}

#[derive(Debug)]
struct SimpleUdpSocket {
    io: TokioUdpSocket,
    local_addr: SocketAddr,
}

impl SimpleUdpSocket {
    fn new(io: TokioUdpSocket) -> io::Result<Self> {
        let local_addr = io.local_addr()?;
        Ok(Self { io, local_addr })
    }
}

impl quinn::AsyncUdpSocket for SimpleUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SimpleUdpPoller { socket: self })
    }

    fn try_send(&self, transmit: &quinn_udp::Transmit) -> io::Result<()> {
        self.io
            .try_send_to(transmit.contents, transmit.destination)
            .map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
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
struct SimpleUdpPoller {
    socket: Arc<SimpleUdpSocket>,
}

impl UdpPoller for SimpleUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.io.poll_send_ready(cx)
    }
}
