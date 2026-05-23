use std::any::Any;
use std::collections::BTreeMap;
use std::future::Future;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;

use bytes::Bytes;
use h2::{client, server};
use http::{Request, Response, Uri, Version};
use mihomo_core::{BoxedTcpStream, TcpStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::runtime::Builder;
use tokio::sync::mpsc as tokio_mpsc;
use tokio_rustls::TlsAcceptor;

use crate::TransportError;
use crate::{TlsOptions, TransportTarget};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Http2Options {
    pub host: Vec<String>,
    pub path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct H2RequestOptions {
    pub authority: String,
    pub path: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
}

#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H2AcceptedTestRequest {
    pub method: String,
    pub authority: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
}

enum WriteCommand {
    Data(Vec<u8>),
    Close,
}

enum Ready<T> {
    Ok(T),
    Err(io::Error),
}

pub(crate) fn wrap_stream(
    stream: BoxedTcpStream,
    options: &Http2Options,
) -> Result<BoxedTcpStream, TransportError> {
    let authority = select_authority(options)?;
    let path = normalize_path(&options.path);
    wrap_stream_with_request(
        stream,
        H2RequestOptions {
            authority,
            path,
            method: "PUT".to_owned(),
            headers: vec![("accept-encoding".to_owned(), "identity".to_owned())],
        },
    )
}

pub(crate) fn wrap_stream_with_request(
    stream: BoxedTcpStream,
    request: H2RequestOptions,
) -> Result<BoxedTcpStream, TransportError> {
    if let Some(raw) = (stream.as_ref() as &dyn Any).downcast_ref::<std::net::TcpStream>() {
        return start_h2_client_std(raw.try_clone()?, request).map_err(TransportError::from);
    }
    start_h2_client_io(BlockingIo { inner: stream }, request).map_err(TransportError::from)
}

pub(crate) fn wrap_tls_stream_with_request(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    tls: &TlsOptions,
    alpn: &[String],
    request: H2RequestOptions,
) -> Result<BoxedTcpStream, TransportError> {
    if let Some(raw) = (stream.as_ref() as &dyn Any).downcast_ref::<std::net::TcpStream>() {
        return start_h2_client_std_tls(raw.try_clone()?, proxy.clone(), tls.clone(), alpn.to_vec(), request)
            .map_err(TransportError::from);
    }
    Err(TransportError::UnsupportedFeature {
        proxy: proxy.authority(),
        feature: "h2/grpc over chained non-raw stream".to_owned(),
    })
}

pub(crate) fn accept_server_stream(
    stream: BoxedTcpStream,
) -> io::Result<(H2AcceptedTestRequest, BoxedTcpStream)> {
    if let Some(raw) = (stream.as_ref() as &dyn Any).downcast_ref::<std::net::TcpStream>() {
        return start_h2_server_std(raw.try_clone()?);
    }
    start_h2_server_io(BlockingIo { inner: stream })
}

pub(crate) fn accept_tls_server_stream(
    stream: BoxedTcpStream,
    tls_config: std::sync::Arc<rustls::ServerConfig>,
) -> io::Result<(H2AcceptedTestRequest, BoxedTcpStream)> {
    if let Some(raw) = (stream.as_ref() as &dyn Any).downcast_ref::<std::net::TcpStream>() {
        return start_h2_server_std_tls(raw.try_clone()?, tls_config);
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "h2 tls test server requires raw tcp stream",
    ))
}

fn select_authority(options: &Http2Options) -> Result<String, TransportError> {
    options
        .host
        .iter()
        .find(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| TransportError::InvalidPlan("http2 transport requires h2 host".to_owned()))
}

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        "/".to_owned()
    } else if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    }
}

fn build_h2_uri(authority: &str, path: &str) -> io::Result<Uri> {
    Uri::from_str(&format!("https://{authority}{path}"))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))
}

fn start_h2_client_std(
    stream: std::net::TcpStream,
    request: H2RequestOptions,
) -> io::Result<BoxedTcpStream> {
    let (read_tx, read_rx) = mpsc::channel();
    let (write_tx, write_rx) = tokio_mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);

    thread::spawn(move || {
        let runtime = Builder::new_current_thread().enable_all().build();
        match runtime {
            Ok(runtime) => {
                let worker_read_tx = read_tx.clone();
                let worker_ready_tx = ready_tx.clone();
                let result = runtime.block_on(async move {
                    stream.set_nonblocking(true)?;
                    let stream = TokioTcpStream::from_std(stream)?;
                    run_h2_client(
                        stream,
                        request,
                        worker_read_tx,
                        write_rx,
                        &worker_ready_tx,
                    )
                    .await
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
        Ok(Ready::Ok(())) => Ok(Box::new(H2ChannelStream::new(read_rx, write_tx))),
        Ok(Ready::Err(err)) => Err(err),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "h2 client setup thread exited early",
        )),
    }
}

fn start_h2_client_std_tls(
    stream: std::net::TcpStream,
    proxy: TransportTarget,
    tls: TlsOptions,
    alpn: Vec<String>,
    request: H2RequestOptions,
) -> io::Result<BoxedTcpStream> {
    let (read_tx, read_rx) = mpsc::channel();
    let (write_tx, write_rx) = tokio_mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);

    thread::spawn(move || {
        let runtime = Builder::new_current_thread().enable_all().build();
        match runtime {
            Ok(runtime) => {
                let worker_read_tx = read_tx.clone();
                let worker_ready_tx = ready_tx.clone();
                let result = runtime.block_on(async move {
                    stream.set_nonblocking(true)?;
                    let stream = TokioTcpStream::from_std(stream)?;
                    let stream = crate::tls_client::wrap_tokio_stream(stream, &proxy, &tls, &alpn)
                        .await
                        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
                    run_h2_client(
                        stream,
                        request,
                        worker_read_tx,
                        write_rx,
                        &worker_ready_tx,
                    )
                    .await
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
        Ok(Ready::Ok(())) => Ok(Box::new(H2ChannelStream::new(read_rx, write_tx))),
        Ok(Ready::Err(err)) => Err(err),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "h2 tls client setup thread exited early",
        )),
    }
}

fn start_h2_client_io<S>(
    stream: S,
    request: H2RequestOptions,
) -> io::Result<BoxedTcpStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (read_tx, read_rx) = mpsc::channel();
    let (write_tx, write_rx) = tokio_mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);

    thread::spawn(move || {
        let runtime = Builder::new_current_thread().enable_all().build();
        match runtime {
            Ok(runtime) => {
                let result = runtime.block_on(run_h2_client(
                    stream,
                    request,
                    read_tx.clone(),
                    write_rx,
                    &ready_tx,
                ));
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
        Ok(Ready::Ok(())) => Ok(Box::new(H2ChannelStream::new(read_rx, write_tx))),
        Ok(Ready::Err(err)) => Err(err),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "h2 client setup thread exited early",
        )),
    }
}

fn start_h2_server_std(
    stream: std::net::TcpStream,
) -> io::Result<(H2AcceptedTestRequest, BoxedTcpStream)> {
    let (read_tx, read_rx) = mpsc::channel();
    let (write_tx, write_rx) = tokio_mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);

    thread::spawn(move || {
        let runtime = Builder::new_current_thread().enable_all().build();
        match runtime {
            Ok(runtime) => {
                let worker_read_tx = read_tx.clone();
                let worker_ready_tx = ready_tx.clone();
                let result = runtime.block_on(async move {
                    stream.set_nonblocking(true)?;
                    let stream = TokioTcpStream::from_std(stream)?;
                    run_h2_server(stream, worker_read_tx, write_rx, &worker_ready_tx).await
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
        Ok(Ready::Ok(request)) => Ok((request, Box::new(H2ChannelStream::new(read_rx, write_tx)))),
        Ok(Ready::Err(err)) => Err(err),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "h2 server setup thread exited early",
        )),
    }
}

fn start_h2_server_std_tls(
    stream: std::net::TcpStream,
    tls_config: std::sync::Arc<rustls::ServerConfig>,
) -> io::Result<(H2AcceptedTestRequest, BoxedTcpStream)> {
    let (read_tx, read_rx) = mpsc::channel();
    let (write_tx, write_rx) = tokio_mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);

    thread::spawn(move || {
        let runtime = Builder::new_current_thread().enable_all().build();
        match runtime {
            Ok(runtime) => {
                let worker_read_tx = read_tx.clone();
                let worker_ready_tx = ready_tx.clone();
                let result = runtime.block_on(async move {
                    stream.set_nonblocking(true)?;
                    let stream = TokioTcpStream::from_std(stream)?;
                    let acceptor = TlsAcceptor::from(tls_config);
                    let stream = acceptor
                        .accept(stream)
                        .await
                        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
                    run_h2_server(stream, worker_read_tx, write_rx, &worker_ready_tx).await
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
        Ok(Ready::Ok(request)) => Ok((request, Box::new(H2ChannelStream::new(read_rx, write_tx)))),
        Ok(Ready::Err(err)) => Err(err),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "h2 tls server setup thread exited early",
        )),
    }
}

fn start_h2_server_io<S>(stream: S) -> io::Result<(H2AcceptedTestRequest, BoxedTcpStream)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (read_tx, read_rx) = mpsc::channel();
    let (write_tx, write_rx) = tokio_mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);

    thread::spawn(move || {
        let runtime = Builder::new_current_thread().enable_all().build();
        match runtime {
            Ok(runtime) => {
                let result = runtime.block_on(run_h2_server(
                    stream,
                    read_tx.clone(),
                    write_rx,
                    &ready_tx,
                ));
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
        Ok(Ready::Ok(request)) => Ok((request, Box::new(H2ChannelStream::new(read_rx, write_tx)))),
        Ok(Ready::Err(err)) => Err(err),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "h2 server setup thread exited early",
        )),
    }
}

async fn run_h2_client<S>(
    stream: S,
    request: H2RequestOptions,
    read_tx: mpsc::Sender<io::Result<Vec<u8>>>,
    mut write_rx: tokio_mpsc::UnboundedReceiver<WriteCommand>,
    ready_tx: &SyncSender<Ready<()>>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = client::handshake(stream)
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    tokio::pin!(connection);

    let mut builder = Request::builder()
        .method(request.method.as_str())
        .version(Version::HTTP_2)
        .uri(build_h2_uri(&request.authority, &request.path)?);
    for (name, value) in &request.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let request = builder
        .body(())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let (response, mut send_stream) = sender
        .send_request(request, false)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    let _ = ready_tx.send(Ready::Ok(()));

    bridge_h2_client_stream(read_tx, &mut write_rx, &mut send_stream, response, &mut connection).await
}

async fn run_h2_server<S>(
    stream: S,
    read_tx: mpsc::Sender<io::Result<Vec<u8>>>,
    mut write_rx: tokio_mpsc::UnboundedReceiver<WriteCommand>,
    ready_tx: &SyncSender<Ready<H2AcceptedTestRequest>>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = server::handshake(stream)
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    let Some(result) = connection.accept().await else {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "h2 server received no request",
        ));
    };
    let (request, mut respond) =
        result.map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    let accepted = H2AcceptedTestRequest {
        method: request.method().to_string(),
        authority: request
            .uri()
            .authority()
            .map(|value| value.as_str().to_owned())
            .unwrap_or_default(),
        path: request
            .uri()
            .path_and_query()
            .map(|value| value.as_str().to_owned())
            .unwrap_or_else(|| "/".to_owned()),
        headers: request
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
            })
            .collect(),
    };
    let response = Response::builder()
        .status(200)
        .version(Version::HTTP_2)
        .body(())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let mut send_stream = respond
        .send_response(response, false)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    let mut recv_stream = request.into_body();
    let _ = ready_tx.send(Ready::Ok(accepted));

    bridge_h2_server_stream(
        read_tx,
        &mut write_rx,
        &mut send_stream,
        &mut recv_stream,
        &mut connection,
    )
    .await
}

async fn bridge_h2_server_stream<S>(
    read_tx: mpsc::Sender<io::Result<Vec<u8>>>,
    write_rx: &mut tokio_mpsc::UnboundedReceiver<WriteCommand>,
    send_stream: &mut h2::SendStream<Bytes>,
    recv_stream: &mut h2::RecvStream,
    connection: &mut server::Connection<S, Bytes>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut send_closed = false;
    let mut request_closed = false;
    loop {
        tokio::select! {
            result = std::future::poll_fn(|cx| connection.poll_closed(cx)) => {
                match result {
                    Ok(()) => {
                        let _ = read_tx.send(Ok(Vec::new()));
                        return Ok(());
                    }
                    Err(err) => {
                        return Err(io::Error::new(io::ErrorKind::Other, err.to_string()));
                    }
                }
            }
            maybe = write_rx.recv(), if !send_closed => {
                match maybe {
                    Some(WriteCommand::Data(data)) => {
                        send_stream
                            .send_data(Bytes::from(data), false)
                            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
                    }
                    Some(WriteCommand::Close) | None => {
                        send_stream
                            .send_data(Bytes::new(), true)
                            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
                        send_closed = true;
                    }
                }
            }
            frame = recv_stream.data(), if !request_closed => {
                match frame {
                    Some(Ok(bytes)) => {
                        if !bytes.is_empty() {
                            let _ = read_tx.send(Ok(bytes.to_vec()));
                        }
                    }
                    Some(Err(err)) => {
                        return Err(io::Error::new(io::ErrorKind::Other, err.to_string()));
                    }
                    None => {
                        request_closed = true;
                        let _ = read_tx.send(Ok(Vec::new()));
                    }
                }
            }
        }
    }
}

async fn bridge_h2_client_stream<C>(
    read_tx: mpsc::Sender<io::Result<Vec<u8>>>,
    write_rx: &mut tokio_mpsc::UnboundedReceiver<WriteCommand>,
    send_stream: &mut h2::SendStream<Bytes>,
    mut response: h2::client::ResponseFuture,
    connection: &mut C,
) -> io::Result<()>
where
    C: Future<Output = Result<(), h2::Error>> + Unpin,
{
    let mut send_closed = false;
    let mut recv_stream: Option<h2::RecvStream> = None;
    let mut response_ready = false;

    loop {
        tokio::select! {
            result = &mut *connection, if !send_closed || !response_ready || recv_stream.is_some() => {
                match result {
                    Ok(()) => {
                        let _ = read_tx.send(Ok(Vec::new()));
                        return Ok(());
                    }
                    Err(err) => {
                        return Err(io::Error::new(io::ErrorKind::Other, err.to_string()));
                    }
                }
            }
            maybe = write_rx.recv(), if !send_closed => {
                match maybe {
                    Some(WriteCommand::Data(data)) => {
                        send_stream
                            .send_data(Bytes::from(data), false)
                            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
                    }
                    Some(WriteCommand::Close) | None => {
                        send_stream
                            .send_data(Bytes::new(), true)
                            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
                        send_closed = true;
                    }
                }
            }
            result = &mut response, if !response_ready => {
                let response = result
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
                if !response.status().is_success() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("http2 proxy replied with {}", response.status()),
                    ));
                }
                recv_stream = Some(response.into_body());
                response_ready = true;
            }
            frame = async {
                match recv_stream.as_mut() {
                    Some(stream) => stream.data().await,
                    None => std::future::pending().await,
                }
            }, if response_ready => {
                match frame {
                    Some(Ok(bytes)) => {
                        if !bytes.is_empty() {
                            let _ = read_tx.send(Ok(bytes.to_vec()));
                        }
                    }
                    Some(Err(err)) => {
                        return Err(io::Error::new(io::ErrorKind::Other, err.to_string()));
                    }
                    None => {
                        let _ = read_tx.send(Ok(Vec::new()));
                        return Ok(());
                    }
                }
            }
        }
    }
}

struct H2ChannelStream {
    read_rx: Receiver<io::Result<Vec<u8>>>,
    write_tx: tokio_mpsc::UnboundedSender<WriteCommand>,
    pending: Vec<u8>,
    offset: usize,
    write_closed: bool,
}

impl H2ChannelStream {
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

impl Read for H2ChannelStream {
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
                "http2 stream read timed out",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(0),
        }
    }
}

impl Write for H2ChannelStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(WriteCommand::Data(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "h2 stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for H2ChannelStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "http2 stream does not support cloning",
        ))
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

struct BlockingIo {
    inner: BoxedTcpStream,
}

impl AsyncRead for BlockingIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let read = self.inner.read(buf.initialize_unfilled())?;
        buf.advance(read);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for BlockingIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Poll::Ready(self.inner.write(buf))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(self.inner.flush())
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(self.inner.shutdown_write())
    }
}
