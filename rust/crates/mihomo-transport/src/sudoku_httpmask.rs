use std::collections::HashMap;
use std::io::{self, Cursor, Read, Write};
use std::net::TcpStream as NetTcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use hmac::{Hmac, Mac};
use mihomo_core::{BoxedTcpStream, TcpStream};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;

use crate::{prepend_bytes, tls_client, TlsOptions, TransportError, TransportTarget};

type HmacSha256 = Hmac<Sha256>;
type BoxedRead = Box<dyn Read + Send>;

const HTTP_MASK_AUTH_HEADER_PREFIX: &str = "Bearer ";
const HTTP_MASK_AUTH_QUERY_KEY: &str = "auth";
const HTTP_MASK_AUTH_SKEW_SECS: i64 = 60;
const HTTP_MASK_MAX_HEADERS: usize = 64 * 1024;
const HTTP_MASK_CONTROL_BODY_LIMIT: usize = 64 * 1024;

pub(crate) fn dial_http_tunnel(
    initial_stream: BoxedTcpStream,
    proxy: &TransportTarget,
    key: &str,
    mode: &str,
    tls_enabled: bool,
    host_override: &str,
    path_root: &str,
) -> Result<BoxedTcpStream, TransportError> {
    let normalized_mode = normalize_http_tunnel_mode(mode)?;
    let auth_key = crate::sudoku::client_aead_seed(key)?;
    let settings = Arc::new(HttpMaskSettings {
        header_host: http_mask_header_host(proxy, tls_enabled, host_override),
        path_root: normalize_path_root(path_root),
        auth: HttpMaskAuth::new(&auth_key),
    });
    let connector = Arc::new(HttpMaskConnector::new(
        initial_stream,
        proxy,
        tls_enabled,
        host_override,
    ));
    match normalized_mode {
        HttpMaskTunnelMode::Stream => open_stream_tunnel(connector, settings),
        HttpMaskTunnelMode::Poll => open_poll_tunnel(connector, settings),
        HttpMaskTunnelMode::Auto => open_stream_tunnel(Arc::clone(&connector), Arc::clone(&settings))
            .or_else(|_| open_poll_tunnel(connector, settings)),
        HttpMaskTunnelMode::Legacy | HttpMaskTunnelMode::Ws => Err(TransportError::InvalidPlan(
            format!("http tunnel mode {:?} is not a split HTTP tunnel", normalized_mode),
        )),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpMaskTunnelMode {
    Legacy,
    Stream,
    Poll,
    Auto,
    Ws,
}

impl HttpMaskTunnelMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Stream => "stream",
            Self::Poll => "poll",
            Self::Auto => "auto",
            Self::Ws => "ws",
        }
    }
}

fn normalize_http_tunnel_mode(mode: &str) -> Result<HttpMaskTunnelMode, TransportError> {
    match mode.trim().to_ascii_lowercase().as_str() {
        "" | "legacy" => Ok(HttpMaskTunnelMode::Legacy),
        "stream" => Ok(HttpMaskTunnelMode::Stream),
        "poll" => Ok(HttpMaskTunnelMode::Poll),
        "auto" => Ok(HttpMaskTunnelMode::Auto),
        "ws" => Ok(HttpMaskTunnelMode::Ws),
        other => Err(TransportError::UnsupportedFeature {
            proxy: "<sudoku>".to_owned(),
            feature: format!("http-mask-mode={other}"),
        }),
    }
}

pub struct HttpMaskServerAcceptor {
    inner: Mutex<HttpMaskServer>,
}

pub enum HttpMaskAcceptResult {
    Tunnel(BoxedTcpStream),
    PassThrough(BoxedTcpStream),
    Rejected(BoxedTcpStream),
}

impl std::fmt::Debug for HttpMaskServerAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HttpMaskServerAcceptor(..)")
    }
}

impl HttpMaskServerAcceptor {
    pub fn new(
        key: &str,
        mode: &str,
        tls_enabled: bool,
        expected_host: &str,
        path_root: &str,
        pass_through_on_reject: bool,
    ) -> Result<Option<Self>, TransportError> {
        let mode = normalize_http_tunnel_mode(mode)?;
        match mode {
            HttpMaskTunnelMode::Stream
            | HttpMaskTunnelMode::Poll
            | HttpMaskTunnelMode::Auto
            | HttpMaskTunnelMode::Ws => {}
            HttpMaskTunnelMode::Legacy => return Ok(None),
        }

        let auth_key = crate::sudoku::client_aead_seed(key)?;
        let auth = HttpMaskAuth::new(&auth_key).ok_or_else(|| {
            TransportError::invalid_proxy_response("missing sudoku http-mask auth key")
        })?;
        Ok(Some(Self {
            inner: Mutex::new(HttpMaskServer::new(
                mode,
                auth,
                normalize_path_root(path_root),
                expected_host.trim().to_owned(),
                tls_enabled,
                pass_through_on_reject,
            )),
        }))
    }

    pub fn accept(
        &self,
        stream: BoxedTcpStream,
    ) -> Result<Option<HttpMaskAcceptResult>, TransportError> {
        self.inner
            .lock()
            .expect("sudoku http-mask acceptor mutex poisoned")
            .handle(stream)
    }
}

#[derive(Clone)]
struct HttpMaskSettings {
    header_host: String,
    path_root: String,
    auth: Option<HttpMaskAuth>,
}

struct HttpMaskConnector {
    initial: Mutex<Option<BoxedTcpStream>>,
    proxy: TransportTarget,
    tls_enabled: bool,
    tls_sni: String,
}

impl HttpMaskConnector {
    fn new(
        initial_stream: BoxedTcpStream,
        proxy: &TransportTarget,
        tls_enabled: bool,
        host_override: &str,
    ) -> Self {
        Self {
            initial: Mutex::new(Some(initial_stream)),
            proxy: proxy.clone(),
            tls_enabled,
            tls_sni: http_mask_sni(proxy, host_override),
        }
    }

    fn connect(&self) -> Result<BoxedTcpStream, TransportError> {
        let stream = if let Some(stream) = self.initial.lock().expect("http mask initial stream mutex poisoned").take() {
            stream
        } else {
            Box::new(NetTcpStream::connect(self.proxy.authority())?)
        };
        if !self.tls_enabled {
            return Ok(stream);
        }
        tls_client::wrap_stream(
            stream,
            &self.proxy,
            &TlsOptions {
                enabled: true,
                sni: self.tls_sni.clone(),
                skip_cert_verify: false,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &["http/1.1".to_owned()],
        )
    }
}

#[derive(Clone)]
struct HttpMaskAuth {
    key: [u8; 32],
}

impl HttpMaskAuth {
    fn new(key: &str) -> Option<Self> {
        let trimmed = key.trim();
        if trimmed.is_empty() {
            return None;
        }
        let digest = Sha256::digest(format!("sudoku-httpmask-auth-v1:{trimmed}").as_bytes());
        let mut sum = [0_u8; 32];
        sum.copy_from_slice(&digest);
        Some(Self { key: sum })
    }

    fn token(&self, mode: HttpMaskTunnelMode, method: &str, path: &str, now: SystemTime) -> String {
        let ts = now
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let sig = self.sign(mode, method, path, ts);
        let mut raw = [0_u8; 24];
        raw[..8].copy_from_slice(&(ts as u64).to_be_bytes());
        raw[8..].copy_from_slice(&sig);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
    }

    fn sign(&self, mode: HttpMaskTunnelMode, method: &str, path: &str, ts: i64) -> [u8; 16] {
        let method = if method.trim().is_empty() {
            "GET".to_owned()
        } else {
            method.trim().to_ascii_uppercase()
        };
        let path = path.trim();
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("valid hmac key");
        mac.update(mode.as_str().as_bytes());
        mac.update(&[0]);
        mac.update(method.as_bytes());
        mac.update(&[0]);
        mac.update(path.as_bytes());
        mac.update(&[0]);
        mac.update(&(ts as u64).to_be_bytes());
        let full = mac.finalize().into_bytes();
        let mut out = [0_u8; 16];
        out.copy_from_slice(&full[..16]);
        out
    }

    fn verify_value(
        &self,
        value: &str,
        mode: HttpMaskTunnelMode,
        method: &str,
        path: &str,
        now: SystemTime,
    ) -> bool {
        let mut raw = value.trim();
        if raw.is_empty() {
            return false;
        }
        if raw.len() > HTTP_MASK_AUTH_HEADER_PREFIX.len()
            && raw[..HTTP_MASK_AUTH_HEADER_PREFIX.len()].eq_ignore_ascii_case(HTTP_MASK_AUTH_HEADER_PREFIX)
        {
            raw = raw[HTTP_MASK_AUTH_HEADER_PREFIX.len()..].trim();
        }
        let Ok(decoded) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw) else {
            return false;
        };
        if decoded.len() != 24 {
            return false;
        }
        let ts = i64::from_be_bytes(decoded[..8].try_into().expect("auth timestamp slice"));
        let now_ts = now
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if (now_ts - ts).abs() > HTTP_MASK_AUTH_SKEW_SECS {
            return false;
        }
        self.sign(mode, method, path, ts).as_slice() == &decoded[8..]
    }
}

pub(crate) fn client_auth_token_for_ws(key: &str) -> Option<String> {
    HttpMaskAuth::new(key).map(|auth| auth.token(HttpMaskTunnelMode::Ws, "GET", "/ws", SystemTime::now()))
}

fn open_stream_tunnel(
    connector: Arc<HttpMaskConnector>,
    settings: Arc<HttpMaskSettings>,
) -> Result<BoxedTcpStream, TransportError> {
    let token = authorize_session(&connector, &settings, HttpMaskTunnelMode::Stream)?;
    Ok(Box::new(HttpMaskTunnelConn::spawn(
        Arc::clone(&connector),
        settings,
        token,
        HttpMaskTunnelMode::Stream,
    )))
}

fn open_poll_tunnel(
    connector: Arc<HttpMaskConnector>,
    settings: Arc<HttpMaskSettings>,
) -> Result<BoxedTcpStream, TransportError> {
    let token = authorize_session(&connector, &settings, HttpMaskTunnelMode::Poll)?;
    Ok(Box::new(HttpMaskTunnelConn::spawn(
        Arc::clone(&connector),
        settings,
        token,
        HttpMaskTunnelMode::Poll,
    )))
}

fn authorize_session(
    connector: &Arc<HttpMaskConnector>,
    settings: &Arc<HttpMaskSettings>,
    mode: HttpMaskTunnelMode,
) -> Result<String, TransportError> {
    let body = request_control_body(
        connector,
        settings,
        mode,
        "GET",
        "/session",
        &[("token", None), ("fin", None), ("close", None)],
        &[],
        None,
    )?;
    for line in String::from_utf8_lossy(&body).lines() {
        if let Some(token) = line.strip_prefix("token=") {
            let trimmed = token.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_owned());
            }
        }
    }
    Err(TransportError::invalid_proxy_response(
        "sudoku http-mask authorize response missing token",
    ))
}

struct HttpMaskServer {
    mode: HttpMaskTunnelMode,
    auth: HttpMaskAuth,
    path_root: String,
    expected_host: String,
    _tls_enabled: bool,
    pass_through_on_reject: bool,
    sessions: HashMap<String, NetTcpStream>,
    next_token: u64,
}

impl HttpMaskServer {
    fn new(
        mode: HttpMaskTunnelMode,
        auth: HttpMaskAuth,
        path_root: String,
        expected_host: String,
        tls_enabled: bool,
        pass_through_on_reject: bool,
    ) -> Self {
        Self {
            mode,
            auth,
            path_root,
            expected_host,
            _tls_enabled: tls_enabled,
            pass_through_on_reject,
            sessions: HashMap::new(),
            next_token: 1,
        }
    }

    fn handle(
        &mut self,
        mut stream: BoxedTcpStream,
    ) -> Result<Option<HttpMaskAcceptResult>, TransportError> {
        let mut first = [0_u8; 4];
        let mut first_len = 0usize;
        while first_len < first.len() {
            let read = stream.read(&mut first[first_len..])?;
            if read == 0 {
                if first_len == 0 {
                    return Ok(None);
                }
                let stream = prepend_bytes(stream, first[..first_len].to_vec());
                return Ok(Some(HttpMaskAcceptResult::PassThrough(stream)));
            }
            first_len += read;
        }
        let stream = prepend_bytes(stream, first.to_vec());
        if !looks_like_http_request_start(&first) {
            return Ok(Some(HttpMaskAcceptResult::PassThrough(stream)));
        }
        let mut stream = stream;
        loop {
            let (request, tail) = read_http_request_headers_with_tail(&mut *stream)?;
            let (method, target, headers) = parse_http_request_head(&request)?;
            let host = headers
                .get("host")
                .ok_or_else(|| TransportError::invalid_proxy_response("missing Host header"))?;
            if !self.expected_host.is_empty() && host != &self.expected_host {
                if self.pass_through_on_reject {
                    let prefix = merge_header_and_tail(request.as_bytes(), tail);
                    let rejected = prepend_bytes(stream, prefix);
                    return Ok(Some(HttpMaskAcceptResult::Rejected(rejected)));
                }
                return Err(TransportError::invalid_proxy_response(
                    "unexpected sudoku http-mask Host header",
                ));
            }
            let Some(tunnel) = headers.get("x-sudoku-tunnel") else {
                if self.pass_through_on_reject {
                    let prefix = merge_header_and_tail(request.as_bytes(), tail);
                    let rejected = prepend_bytes(stream, prefix);
                    return Ok(Some(HttpMaskAcceptResult::Rejected(rejected)));
                }
                write_http_response_basic(&mut *stream, 404, b"not found")?;
                return Ok(None);
            };
            let requested_mode = match tunnel.as_str() {
                "stream" => HttpMaskTunnelMode::Stream,
                "poll" => HttpMaskTunnelMode::Poll,
                "ws" => HttpMaskTunnelMode::Ws,
                other => {
                    if self.pass_through_on_reject {
                        let prefix = merge_header_and_tail(request.as_bytes(), tail);
                        let rejected = prepend_bytes(stream, prefix);
                        return Ok(Some(HttpMaskAcceptResult::Rejected(rejected)));
                    }
                    return Err(TransportError::invalid_proxy_response(format!(
                        "unexpected sudoku http-mask tunnel mode {other}"
                    )))
                }
            };
            let (path, query) = split_request_target_path_query(&target);
            let relative_path = path
                .strip_prefix(&self.path_root)
                .unwrap_or(path.as_str());
            if requested_mode == HttpMaskTunnelMode::Ws {
                let auth_value = headers
                    .get("authorization")
                    .cloned()
                    .or_else(|| query.get(HTTP_MASK_AUTH_QUERY_KEY).cloned())
                    .ok_or_else(|| {
                        TransportError::invalid_proxy_response("missing sudoku http-mask auth token")
                    })?;
                if !self.auth.verify_value(
                    &auth_value,
                    requested_mode,
                    &method,
                    "/ws",
                    SystemTime::now(),
                ) {
                    if self.pass_through_on_reject {
                        let prefix = merge_header_and_tail(request.as_bytes(), tail);
                        let rejected = prepend_bytes(stream, prefix);
                        return Ok(Some(HttpMaskAcceptResult::Rejected(rejected)));
                    }
                    write_http_response_basic(&mut *stream, 404, b"not found")?;
                    return Ok(None);
                }
                let mode_compatible = matches!(
                    self.mode,
                    HttpMaskTunnelMode::Ws | HttpMaskTunnelMode::Auto
                );
                if !mode_compatible {
                    write_http_response_basic(&mut *stream, 404, b"not found")?;
                    return Ok(None);
                }
                let ws_stream = accept_websocket_http_mask_stream_from_request(
                    stream,
                    &path,
                    &self.path_root,
                    &request,
                    tail,
                )?;
                return Ok(Some(HttpMaskAcceptResult::Tunnel(ws_stream)));
            }
            let auth_value = headers
                .get("authorization")
                .cloned()
                .or_else(|| query.get(HTTP_MASK_AUTH_QUERY_KEY).cloned())
                .ok_or_else(|| {
                    TransportError::invalid_proxy_response("missing sudoku http-mask auth token")
                })?;
            if !self.auth.verify_value(
                &auth_value,
                requested_mode,
                &method,
                relative_path,
                SystemTime::now(),
            ) {
                if self.pass_through_on_reject {
                    let prefix = merge_header_and_tail(request.as_bytes(), tail);
                    let rejected = prepend_bytes(stream, prefix);
                    return Ok(Some(HttpMaskAcceptResult::Rejected(rejected)));
                }
                write_http_response_basic(&mut *stream, 404, b"not found")?;
                return Ok(None);
            }
            let mode_compatible = match self.mode {
                HttpMaskTunnelMode::Stream => requested_mode == HttpMaskTunnelMode::Stream,
                HttpMaskTunnelMode::Poll => {
                    requested_mode == HttpMaskTunnelMode::Poll
                        || requested_mode == HttpMaskTunnelMode::Stream
                }
                HttpMaskTunnelMode::Auto => {
                    requested_mode == HttpMaskTunnelMode::Stream
                        || requested_mode == HttpMaskTunnelMode::Poll
                }
                HttpMaskTunnelMode::Ws => false,
                _ => false,
            };
            if !mode_compatible {
                if self.pass_through_on_reject {
                    let prefix = merge_header_and_tail(request.as_bytes(), tail);
                    let rejected = prepend_bytes(stream, prefix);
                    return Ok(Some(HttpMaskAcceptResult::Rejected(rejected)));
                }
                write_http_response_basic(&mut *stream, 404, b"not found")?;
                return Ok(None);
            }
            match (method.as_str(), relative_path) {
                ("GET", "/session") => {
                    if self.mode == HttpMaskTunnelMode::Poll
                        && requested_mode == HttpMaskTunnelMode::Stream
                    {
                        write_http_response_basic(&mut *stream, 404, b"not found")
                            .map_err(|err| transport_io_error("sudoku http-mask stream/session reject reply", err))?;
                        return Ok(None);
                    }
                    let token = format!("token-{}", self.next_token);
                    self.next_token += 1;
                    let (server, client) =
                        tcp_pair().map_err(|err| transport_io_error("sudoku http-mask session tcp_pair", err))?;
                    self.sessions.insert(token.clone(), client);
                    write_http_response_basic(
                        &mut *stream,
                        200,
                        format!("token={token}").as_bytes(),
                    )
                    .map_err(|err| transport_io_error("sudoku http-mask session authorize reply", err))?;
                    return Ok(Some(HttpMaskAcceptResult::Tunnel(Box::new(server))));
                }
                ("POST", "/api/v1/upload") => {
                    let token = query.get("token").cloned().ok_or_else(|| {
                        TransportError::invalid_proxy_response("missing sudoku http-mask token")
                    })?;
                    if query.get("close").is_some_and(|value| value == "1") {
                        if let Some(session) = self.sessions.remove(&token) {
                            let _ = session.shutdown(std::net::Shutdown::Both);
                        }
                        write_http_response_basic(&mut *stream, 200, b"")
                            .map_err(|err| transport_io_error("sudoku http-mask close reply", err))?;
                        return Ok(None);
                    }
                    if query.get("fin").is_some_and(|value| value == "1") {
                        if let Some(session) = self.sessions.get(&token) {
                            let session = session
                                .try_clone()
                                .map_err(|err| transport_io_error("sudoku http-mask fin clone session", err))?;
                            let _ = session.shutdown(std::net::Shutdown::Write);
                        }
                        write_http_response_basic(&mut *stream, 200, b"")
                            .map_err(|err| transport_io_error("sudoku http-mask fin reply", err))?;
                        return Ok(None);
                    }
                    let Some(session) = self.sessions.get(&token) else {
                        write_http_response_basic(&mut *stream, 404, b"not found")
                            .map_err(|err| transport_io_error("sudoku http-mask upload missing-session reply", err))?;
                        return Ok(None);
                    };
                    let mut session = session
                        .try_clone()
                        .map_err(|err| transport_io_error("sudoku http-mask upload clone session", err))?;
                    let body = read_http_request_body(&request, tail, &mut *stream)?;
                    match requested_mode {
                        HttpMaskTunnelMode::Stream => session
                            .write_all(&body)
                            .map_err(|err| transport_io_error("sudoku http-mask stream upload write", err))?,
                        HttpMaskTunnelMode::Poll => {
                            for line in String::from_utf8_lossy(&body).lines() {
                                let trimmed = line.trim();
                                if trimmed.is_empty() {
                                    continue;
                                }
                                let payload = base64::engine::general_purpose::STANDARD
                                    .decode(trimmed)
                                    .map_err(|_| {
                                        TransportError::invalid_proxy_response(
                                            "invalid sudoku http-mask poll payload",
                                        )
                                    })?;
                                session
                                    .write_all(&payload)
                                    .map_err(|err| transport_io_error("sudoku http-mask poll upload write", err))?;
                            }
                        }
                        _ => {}
                    }
                    write_http_response_basic(&mut *stream, 200, b"")
                        .map_err(|err| transport_io_error("sudoku http-mask upload ack reply", err))?;
                    return Ok(None);
                }
                ("GET", "/stream") => {
                    let token = query.get("token").cloned().ok_or_else(|| {
                        TransportError::invalid_proxy_response("missing sudoku http-mask token")
                    })?;
                    let Some(session) = self.sessions.get(&token) else {
                        write_http_response_basic(&mut *stream, 404, b"not found")
                            .map_err(|err| transport_io_error("sudoku http-mask stream missing-session reply", err))?;
                        return Ok(None);
                    };
                    let mut session = session
                        .try_clone()
                        .map_err(|err| transport_io_error("sudoku http-mask stream pull clone session", err))?;
                    session
                        .set_nonblocking(true)
                        .map_err(|err| transport_io_error("sudoku http-mask stream pull set_nonblocking", err))?;
                    let mut payload = Vec::new();
                    let mut buf = [0_u8; 32 * 1024];
                    let deadline =
                        std::time::Instant::now() + std::time::Duration::from_secs(1);
                    loop {
                        match session.read(&mut buf) {
                            Ok(0) => {
                                self.sessions.remove(&token);
                                break;
                            }
                            Ok(read) => payload.extend_from_slice(&buf[..read]),
                            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                                if std::time::Instant::now() >= deadline {
                                    break;
                                }
                                std::thread::sleep(std::time::Duration::from_millis(10));
                            }
                            Err(err) => {
                                self.sessions.remove(&token);
                                return Err(transport_io_error(
                                    "sudoku http-mask stream pull read session",
                                    err,
                                ))
                            }
                        }
                    }
                    let _ = session.set_nonblocking(false);
                    match requested_mode {
                        HttpMaskTunnelMode::Stream => {
                            write_chunked_http_response(&mut *stream, &payload).map_err(|err| {
                                transport_io_error("sudoku http-mask stream pull chunked reply", err)
                            })?
                        }
                        HttpMaskTunnelMode::Poll => {
                            let body = if payload.is_empty() {
                                b"\n".to_vec()
                            } else {
                                let mut encoded = base64::engine::general_purpose::STANDARD
                                    .encode(payload)
                                    .into_bytes();
                                encoded.push(b'\n');
                                encoded
                            };
                            write_http_response_basic(&mut *stream, 200, &body).map_err(|err| {
                                transport_io_error("sudoku http-mask poll pull reply", err)
                            })?
                        }
                        _ => {}
                    }
                    return Ok(None);
                }
                _ => {
                    return Err(TransportError::invalid_proxy_response(
                        "unexpected sudoku http-mask request",
                    ))
                }
            }
        }
    }
}

struct HttpMaskTunnelConn {
    inner: Arc<HttpMaskTunnelShared>,
}

struct HttpMaskTunnelShared {
    reader: Mutex<HttpMaskTunnelReader>,
    writer: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    closed: AtomicBool,
}

struct HttpMaskTunnelReader {
    rx: mpsc::Receiver<Option<Vec<u8>>>,
    pending: Cursor<Vec<u8>>,
    eof: bool,
}

impl HttpMaskTunnelConn {
    fn spawn(
        connector: Arc<HttpMaskConnector>,
        settings: Arc<HttpMaskSettings>,
        token: String,
        mode: HttpMaskTunnelMode,
    ) -> Self {
        let (read_tx, read_rx) = mpsc::channel::<Option<Vec<u8>>>();
        let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>();
        let shared = Arc::new(HttpMaskTunnelShared {
            reader: Mutex::new(HttpMaskTunnelReader {
                rx: read_rx,
                pending: Cursor::new(Vec::new()),
                eof: false,
            }),
            writer: Mutex::new(Some(write_tx)),
            closed: AtomicBool::new(false),
        });

        {
            let connector = Arc::clone(&connector);
            let settings = Arc::clone(&settings);
            let token = token.clone();
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || {
                loop {
                    if shared.closed.load(Ordering::Relaxed) {
                        break;
                    }
                    let response = match open_body_request(
                        &connector,
                        &settings,
                        mode,
                        "GET",
                        "/stream",
                        &[
                            ("token", Some(token.clone())),
                            ("fin", None),
                            ("close", None),
                        ],
                        &[],
                        None,
                    ) {
                        Ok(response) => response,
                        Err(_) => break,
                    };
                    let mut body = response;
                    match mode {
                        HttpMaskTunnelMode::Stream => {
                            let mut buf = [0_u8; 32 * 1024];
                            loop {
                                match body.read(&mut buf) {
                                    Ok(0) => break,
                                    Ok(read) => {
                                        if read_tx.send(Some(buf[..read].to_vec())).is_err() {
                                            return;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                        HttpMaskTunnelMode::Poll => {
                            let mut text = String::new();
                            if body.read_to_string(&mut text).is_err() {
                                break;
                            }
                            for line in text.lines() {
                                let trimmed = line.trim();
                                if trimmed.is_empty() {
                                    continue;
                                }
                                let Ok(payload) = base64::engine::general_purpose::STANDARD.decode(trimmed) else {
                                    let _ = read_tx.send(None);
                                    return;
                                };
                                if read_tx.send(Some(payload)).is_err() {
                                    return;
                                }
                            }
                        }
                        _ => break,
                    }
                }
                let _ = read_tx.send(None);
            });
        }

        {
            let connector = Arc::clone(&connector);
            let settings = Arc::clone(&settings);
            let token = token.clone();
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || {
                while let Ok(payload) = write_rx.recv() {
                    if shared.closed.load(Ordering::Relaxed) {
                        break;
                    }
                    let body = match mode {
                        HttpMaskTunnelMode::Stream => payload,
                        HttpMaskTunnelMode::Poll => {
                            let mut encoded = base64::engine::general_purpose::STANDARD.encode(payload).into_bytes();
                            encoded.push(b'\n');
                            encoded
                        }
                        _ => Vec::new(),
                    };
                    let content_type = match mode {
                        HttpMaskTunnelMode::Stream => Some("application/octet-stream"),
                        HttpMaskTunnelMode::Poll => Some("text/plain"),
                        _ => None,
                    };
                    if request_control_body(
                        &connector,
                        &settings,
                        mode,
                        "POST",
                        "/api/v1/upload",
                        &[
                            ("token", Some(token.clone())),
                            ("fin", None),
                            ("close", None),
                        ],
                        &body,
                        content_type,
                    )
                    .is_err()
                    {
                        break;
                    }
                }
                let _ = request_control_body(
                    &connector,
                    &settings,
                    mode,
                    "POST",
                    "/api/v1/upload",
                    &[
                        ("token", Some(token.clone())),
                        ("fin", Some("1".to_owned())),
                        ("close", None),
                    ],
                    &[],
                    None,
                );
            });
        }

        Self { inner: shared }
    }
}

impl Read for HttpMaskTunnelConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut state = self.inner.reader.lock().expect("http mask reader mutex poisoned");
        loop {
            let read = state.pending.read(buf)?;
            if read != 0 {
                return Ok(read);
            }
            if state.eof {
                return Ok(0);
            }
            match state.rx.recv() {
                Ok(Some(payload)) if payload.is_empty() => continue,
                Ok(Some(payload)) => {
                    state.pending = Cursor::new(payload);
                }
                Ok(None) | Err(_) => {
                    state.eof = true;
                    return Ok(0);
                }
            }
        }
    }
}

impl Write for HttpMaskTunnelConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let tx = self
            .inner
            .writer
            .lock()
            .expect("http mask writer mutex poisoned")
            .as_ref()
            .cloned();
        let Some(tx) = tx else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sudoku http-mask tunnel write side is closed",
            ));
        };
        tx.send(buf.to_vec()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sudoku http-mask tunnel writer thread exited",
            )
        })?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for HttpMaskTunnelConn {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            inner: Arc::clone(&self.inner),
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner
            .writer
            .lock()
            .expect("http mask writer mutex poisoned")
            .take();
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.closed.store(true, Ordering::Relaxed);
        self.inner
            .writer
            .lock()
            .expect("http mask writer mutex poisoned")
            .take();
        Ok(())
    }
}

fn read_http_request_headers_with_tail(stream: &mut dyn Read) -> io::Result<(String, Vec<u8>)> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "request closed before headers completed",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_end = position + 4;
            return Ok((
                String::from_utf8_lossy(&buffer[..header_end]).into_owned(),
                buffer[header_end..].to_vec(),
            ));
        }
    }
}

fn parse_http_request_head(
    request: &str,
) -> Result<(String, String, HashMap<String, String>), TransportError> {
    let mut lines = request.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| TransportError::invalid_proxy_response("missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| TransportError::invalid_proxy_response("missing request method"))?
        .to_owned();
    let target = parts
        .next()
        .ok_or_else(|| TransportError::invalid_proxy_response("missing request target"))?
        .to_owned();
    let mut headers = HashMap::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    Ok((method, target, headers))
}

fn split_request_target_path_query(target: &str) -> (String, HashMap<String, String>) {
    let Some((path, query)) = target.split_once('?') else {
        return (target.to_owned(), HashMap::new());
    };
    let mut params = HashMap::new();
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        params.insert(key.to_owned(), value.to_owned());
    }
    (path.to_owned(), params)
}

fn looks_like_http_request_start(peek4: &[u8]) -> bool {
    matches!(
        peek4,
        b"GET " | b"POST" | b"HEAD" | b"PUT " | b"OPTI" | b"PATC" | b"DELE"
    )
}

fn merge_header_and_tail(header: &[u8], tail: Vec<u8>) -> Vec<u8> {
    let mut merged = Vec::with_capacity(header.len() + tail.len());
    merged.extend_from_slice(header);
    merged.extend_from_slice(&tail);
    merged
}

fn read_http_request_body(
    request: &str,
    mut tail: Vec<u8>,
    stream: &mut dyn Read,
) -> io::Result<Vec<u8>> {
    let mut content_length = 0usize;
    for line in request.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("Content-Length") {
            content_length = value.trim().parse::<usize>().unwrap_or(0);
        }
    }
    if tail.len() < content_length {
        let mut rest = vec![0_u8; content_length - tail.len()];
        stream.read_exact(&mut rest)?;
        tail.extend_from_slice(&rest);
    }
    tail.truncate(content_length);
    Ok(tail)
}

fn write_http_response_basic(
    stream: &mut dyn Write,
    status: u16,
    body: &[u8],
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "OK",
    };
    stream.write_all(
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )?;
    stream.write_all(body)?;
    stream.flush()
}

fn write_chunked_http_response(stream: &mut dyn Write, body: &[u8]) -> io::Result<()> {
    stream.write_all(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
    )?;
    if !body.is_empty() {
        stream.write_all(format!("{:x}\r\n", body.len()).as_bytes())?;
        stream.write_all(body)?;
        stream.write_all(b"\r\n")?;
    }
    stream.write_all(b"0\r\n\r\n")?;
    stream.flush()
}

fn tcp_pair() -> io::Result<(std::net::TcpStream, std::net::TcpStream)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let client = std::net::TcpStream::connect(addr)?;
    let (server, _) = listener.accept()?;
    Ok((server, client))
}

fn transport_io_error(context: &str, err: io::Error) -> TransportError {
    TransportError::Io {
        kind: err.kind(),
        message: format!("{context}: {err}"),
    }
}

fn with_transport_context(context: &str, err: TransportError) -> TransportError {
    match err {
        TransportError::Io { kind, message } => TransportError::Io {
            kind,
            message: format!("{context}: {message}"),
        },
        TransportError::InvalidPlan(message) => {
            TransportError::InvalidPlan(format!("{context}: {message}"))
        }
        TransportError::InvalidProxyResponse(message) => {
            TransportError::InvalidProxyResponse(format!("{context}: {message}"))
        }
        other => other,
    }
}

fn accept_websocket_http_mask_stream_from_request(
    mut stream: BoxedTcpStream,
    path: &str,
    path_root: &str,
    request: &str,
    tail: Vec<u8>,
) -> Result<BoxedTcpStream, TransportError> {
    let expected = http_mask_ws_path(path_root);
    if path != expected {
        return Err(TransportError::invalid_proxy_response(format!(
            "unexpected sudoku websocket path {path}"
        )));
    }
    let key = request
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("Sec-WebSocket-Key") {
                Some(value.trim().to_owned())
            } else {
                None
            }
        })
        .ok_or_else(|| TransportError::invalid_proxy_response("missing Sec-WebSocket-Key"))?;
    let accept = websocket_accept_key(&key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    let stream = prepend_bytes(stream, tail);
    Ok(Box::new(ServerWebsocketStream::new(stream)))
}

fn http_mask_ws_path(path_root: &str) -> String {
    let root = path_root.trim_matches('/');
    if root.is_empty() {
        "/ws".to_owned()
    } else {
        format!("/{root}/ws")
    }
}

fn websocket_accept_key(key: &str) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(key.as_bytes());
    sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(sha1.finalize())
}

struct ServerWebsocketStream {
    inner: BoxedTcpStream,
    pending: Vec<u8>,
    offset: usize,
}

impl ServerWebsocketStream {
    fn new(inner: BoxedTcpStream) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            offset: 0,
        }
    }

    fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut header = [0_u8; 2];
        match self.inner.read_exact(&mut header) {
            Ok(()) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                ) =>
            {
                return Ok(None);
            }
            Err(err) => return Err(err),
        }
        let fin = header[0] & 0x80 != 0;
        let opcode = header[0] & 0x0f;
        let masked = header[1] & 0x80 != 0;
        let mut len = u64::from(header[1] & 0x7f);
        if len == 126 {
            let mut ext = [0_u8; 2];
            self.inner.read_exact(&mut ext)?;
            len = u64::from(u16::from_be_bytes(ext));
        } else if len == 127 {
            let mut ext = [0_u8; 8];
            self.inner.read_exact(&mut ext)?;
            len = u64::from_be_bytes(ext);
        }
        let mask = if masked {
            let mut mask = [0_u8; 4];
            self.inner.read_exact(&mut mask)?;
            Some(mask)
        } else {
            None
        };
        let mut payload = vec![0_u8; len as usize];
        self.inner.read_exact(&mut payload)?;
        if let Some(mask) = mask {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
        }
        match opcode {
            0x1 | 0x2 => {
                if !fin {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "fragmented websocket frames are unsupported",
                    ));
                }
                Ok(Some(payload))
            }
            0x8 => Ok(None),
            0x9 => {
                self.write_frame(0xA, &payload)?;
                Ok(Some(Vec::new()))
            }
            0xA => Ok(Some(Vec::new())),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected websocket opcode {other}"),
            )),
        }
    }

    fn write_frame(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        let mut header = Vec::with_capacity(10);
        header.push(0x80 | (opcode & 0x0f));
        if payload.len() < 126 {
            header.push(payload.len() as u8);
        } else if payload.len() < 65_536 {
            header.push(126);
            header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            header.push(127);
            header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        self.inner.write_all(&header)?;
        self.inner.write_all(payload)?;
        self.inner.flush()
    }
}

impl Read for ServerWebsocketStream {
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
        loop {
            let Some(frame) = self.read_frame()? else {
                return Ok(0);
            };
            if frame.is_empty() {
                continue;
            }
            let copied = frame.len().min(buf.len());
            buf[..copied].copy_from_slice(&frame[..copied]);
            if copied < frame.len() {
                self.pending = frame;
                self.offset = copied;
            }
            return Ok(copied);
        }
    }
}

impl Write for ServerWebsocketStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.write_frame(0x2, buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for ServerWebsocketStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sudoku websocket http-mask stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

fn request_control_body(
    connector: &Arc<HttpMaskConnector>,
    settings: &Arc<HttpMaskSettings>,
    mode: HttpMaskTunnelMode,
    method: &str,
    path: &str,
    query: &[(&str, Option<String>)],
    body: &[u8],
    content_type: Option<&str>,
) -> Result<Vec<u8>, TransportError> {
    let mut response = open_http_request(connector, settings, mode, method, path, query, body, content_type)?;
    let mut bytes = Vec::new();
    response
        .body
        .read_to_end(&mut bytes)
        .map_err(TransportError::from)?;
    Ok(bytes)
}

fn open_body_request(
    connector: &Arc<HttpMaskConnector>,
    settings: &Arc<HttpMaskSettings>,
    mode: HttpMaskTunnelMode,
    method: &str,
    path: &str,
    query: &[(&str, Option<String>)],
    body: &[u8],
    content_type: Option<&str>,
) -> Result<BoxedRead, TransportError> {
    Ok(open_http_request(connector, settings, mode, method, path, query, body, content_type)?.body)
}

struct HttpResponse {
    body: BoxedRead,
}

fn open_http_request(
    connector: &Arc<HttpMaskConnector>,
    settings: &Arc<HttpMaskSettings>,
    mode: HttpMaskTunnelMode,
    method: &str,
    path: &str,
    query: &[(&str, Option<String>)],
    body: &[u8],
    content_type: Option<&str>,
) -> Result<HttpResponse, TransportError> {
    let mut stream = connector
        .connect()
        .map_err(|err| with_transport_context("sudoku http-mask connect", err))?;
    let auth_token = settings
        .auth
        .as_ref()
        .map(|auth| auth.token(mode, method, path, SystemTime::now()));
    let target = build_request_target(settings, path, query, auth_token.as_deref());
    let request = build_http_request(
        &settings.header_host,
        mode,
        method,
        &target,
        auth_token.as_deref(),
        body,
        content_type,
    );
    stream
        .write_all(&request)
        .map_err(|err| transport_io_error("sudoku http-mask write request", err))?;
    stream
        .flush()
        .map_err(|err| transport_io_error("sudoku http-mask flush request", err))?;
    let (status, headers, body_reader) = read_http_response(stream)
        .map_err(|err| with_transport_context("sudoku http-mask read response", err))?;
    if !(200..300).contains(&status) {
        let mut body = Vec::new();
        let mut limited = body_reader.take(HTTP_MASK_CONTROL_BODY_LIMIT as u64);
        limited.read_to_end(&mut body).map_err(TransportError::from)?;
        return Err(TransportError::invalid_proxy_response(format!(
            "sudoku http-mask {method} {path} failed with status {status}: {}",
            String::from_utf8_lossy(&body).trim()
        )));
    }
    let _ = headers;
    Ok(HttpResponse { body: body_reader })
}

fn build_request_target(
    settings: &HttpMaskSettings,
    path: &str,
    query: &[(&str, Option<String>)],
    auth_token: Option<&str>,
) -> String {
    let mut target = join_path_root(&settings.path_root, path);
    for (key, value) in query {
        if let Some(value) = value {
            append_query_param(&mut target, key, value);
        }
    }
    if let Some(token) = auth_token {
        append_query_param(&mut target, HTTP_MASK_AUTH_QUERY_KEY, token);
    }
    target
}

fn build_http_request(
    host: &str,
    mode: HttpMaskTunnelMode,
    method: &str,
    target: &str,
    auth_token: Option<&str>,
    body: &[u8],
    content_type: Option<&str>,
) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(format!("{} {} HTTP/1.1\r\n", method.trim().to_ascii_uppercase(), target).as_bytes());
    request.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
    request.extend_from_slice(b"User-Agent: Mozilla/5.0\r\n");
    request.extend_from_slice(b"Accept: */*\r\n");
    request.extend_from_slice(b"Accept-Language: en-US,en;q=0.9\r\n");
    request.extend_from_slice(b"Accept-Encoding: gzip\r\n");
    request.extend_from_slice(b"Cache-Control: no-cache\r\n");
    request.extend_from_slice(b"Pragma: no-cache\r\n");
    request.extend_from_slice(b"Connection: close\r\n");
    request.extend_from_slice(format!("X-Sudoku-Tunnel: {}\r\n", mode.as_str()).as_bytes());
    request.extend_from_slice(b"X-Sudoku-Version: 1\r\n");
    if let Some(token) = auth_token {
        request.extend_from_slice(
            format!("Authorization: {HTTP_MASK_AUTH_HEADER_PREFIX}{token}\r\n").as_bytes(),
        );
    }
    if let Some(content_type) = content_type {
        request.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    }
    request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    request.extend_from_slice(body);
    request
}

fn read_http_response(
    mut stream: BoxedTcpStream,
) -> Result<(u16, HashMap<String, String>, BoxedRead), TransportError> {
    let (head, tail) = read_http_headers_with_tail(&mut *stream)?;
    let (status, headers) = parse_http_response_head(&head)?;
    let prefixed = Box::new(PrefixedReader {
        prefix: Cursor::new(tail),
        inner: stream,
    }) as BoxedRead;
    let body = if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        Box::new(ChunkedReader::new(prefixed)) as BoxedRead
    } else if let Some(length) = headers
        .get("content-length")
        .and_then(|value| value.trim().parse::<usize>().ok())
    {
        Box::new(ContentLengthReader::new(prefixed, length)) as BoxedRead
    } else {
        prefixed
    };
    Ok((status, headers, body))
}

fn read_http_headers_with_tail(stream: &mut dyn Read) -> io::Result<(String, Vec<u8>)> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "http response closed before headers completed",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_end = position + 4;
            return Ok((
                String::from_utf8_lossy(&buffer[..header_end]).into_owned(),
                buffer[header_end..].to_vec(),
            ));
        }
        if buffer.len() > HTTP_MASK_MAX_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http response headers exceeded limit",
            ));
        }
    }
}

fn parse_http_response_head(head: &str) -> Result<(u16, HashMap<String, String>), TransportError> {
    let mut lines = head.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| TransportError::invalid_proxy_response("missing HTTP status line"))?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| TransportError::invalid_proxy_response("invalid HTTP status line"))?;
    if !version.starts_with("HTTP/") {
        return Err(TransportError::invalid_proxy_response(
            "unexpected HTTP response version",
        ));
    }
    let mut headers = HashMap::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers
            .entry(name.trim().to_ascii_lowercase())
            .or_insert_with(|| value.trim().to_owned());
    }
    Ok((status, headers))
}

struct PrefixedReader {
    prefix: Cursor<Vec<u8>>,
    inner: BoxedTcpStream,
}

impl Read for PrefixedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.prefix.read(buf)?;
        if read != 0 {
            return Ok(read);
        }
        self.inner.read(buf)
    }
}

struct ContentLengthReader {
    inner: BoxedRead,
    remaining: usize,
}

impl ContentLengthReader {
    fn new(inner: BoxedRead, remaining: usize) -> Self {
        Self { inner, remaining }
    }
}

impl Read for ContentLengthReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let limit = buf.len().min(self.remaining);
        let read = self.inner.read(&mut buf[..limit])?;
        self.remaining = self.remaining.saturating_sub(read);
        Ok(read)
    }
}

struct ChunkedReader {
    inner: BoxedRead,
    chunk_remaining: usize,
    finished: bool,
    need_crlf: bool,
}

impl ChunkedReader {
    fn new(inner: BoxedRead) -> Self {
        Self {
            inner,
            chunk_remaining: 0,
            finished: false,
            need_crlf: false,
        }
    }

    fn read_line(&mut self) -> io::Result<String> {
        let mut line = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            self.inner.read_exact(&mut byte)?;
            line.push(byte[0]);
            if line.ends_with(b"\r\n") {
                line.truncate(line.len() - 2);
                return Ok(String::from_utf8_lossy(&line).into_owned());
            }
        }
    }

    fn consume_crlf(&mut self) -> io::Result<()> {
        let mut crlf = [0_u8; 2];
        self.inner.read_exact(&mut crlf)?;
        if crlf != *b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid chunked response terminator",
            ));
        }
        Ok(())
    }
}

impl Read for ChunkedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.finished {
            return Ok(0);
        }
        loop {
            if self.need_crlf {
                self.consume_crlf()?;
                self.need_crlf = false;
            }
            if self.chunk_remaining == 0 {
                let line = self.read_line()?;
                let size = line
                    .split(';')
                    .next()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .and_then(|value| usize::from_str_radix(value, 16).ok())
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk length"))?;
                if size == 0 {
                    loop {
                        let trailer = self.read_line()?;
                        if trailer.is_empty() {
                            self.finished = true;
                            return Ok(0);
                        }
                    }
                }
                self.chunk_remaining = size;
            }
            if self.chunk_remaining == 0 {
                continue;
            }
            let limit = buf.len().min(self.chunk_remaining);
            let read = self
                .inner
                .read(&mut buf[..limit])?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "chunked response ended mid-chunk",
                ));
            }
            self.chunk_remaining -= read;
            if self.chunk_remaining == 0 {
                self.need_crlf = true;
            }
            return Ok(read);
        }
    }
}

fn append_query_param(target: &mut String, key: &str, value: &str) {
    if target.contains('?') {
        target.push('&');
    } else {
        target.push('?');
    }
    target.push_str(key);
    target.push('=');
    target.push_str(value);
}

fn normalize_path_root(root: &str) -> String {
    let trimmed = root.trim().trim_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        format!("/{trimmed}")
    } else {
        String::new()
    }
}

fn join_path_root(root: &str, path: &str) -> String {
    let normalized = normalize_path_root(root);
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    if normalized.is_empty() {
        path
    } else {
        format!("{normalized}{path}")
    }
}

fn http_mask_header_host(
    proxy: &TransportTarget,
    tls_enabled: bool,
    host_override: &str,
) -> String {
    let raw = if host_override.trim().is_empty() {
        proxy.authority()
    } else {
        host_override.trim().to_owned()
    };
    let default_port = if tls_enabled { "443" } else { "80" };
    if let Some((host, port)) = split_host_port_lossy(&raw) {
        if port == default_port {
            return host;
        }
    }
    raw
}

fn http_mask_sni(proxy: &TransportTarget, host_override: &str) -> String {
    let raw = if host_override.trim().is_empty() {
        proxy.host.as_str()
    } else {
        host_override.trim()
    };
    split_host_port_lossy(raw)
        .map(|(host, _)| host)
        .unwrap_or_else(|| raw.trim_start_matches('[').trim_end_matches(']').to_owned())
}

fn split_host_port_lossy(raw: &str) -> Option<(String, String)> {
    if let Some(rest) = raw.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some((host.to_owned(), port.to_owned()));
    }
    let (host, port) = raw.rsplit_once(':')?;
    if host.contains(':') {
        return None;
    }
    Some((host.to_owned(), port.to_owned()))
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use rcgen::generate_simple_self_signed;
    use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection, StreamOwned};
    use std::collections::HashMap;
    use std::io::{self, Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{mpsc, Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime};

    use super::{HttpMaskAuth, HttpMaskTunnelMode};
    use crate::sudoku::{
        accept_server_stream_for_tests, open_udp_stream, read_udp_packet, wrap_stream,
        write_udp_packet, SudokuServerSession,
    };
    use crate::{register_test_root_certificate, TransportTarget};

    fn httpmask_test_guard() -> std::sync::MutexGuard<'static, ()> {
        static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
        GUARD
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|err| err.into_inner())
    }

    trait TestHttpIoStream: Read + Write + Send {}
    impl<T: Read + Write + Send> TestHttpIoStream for T {}
    type BoxedTestHttpIoStream = Box<dyn TestHttpIoStream>;

    struct TestRustlsServerStream(StreamOwned<ServerConnection, TcpStream>);

    impl Read for TestRustlsServerStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for TestRustlsServerStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    struct TestHttpMaskServer {
        accept_timeout: Duration,
        addr: SocketAddr,
        accepted: mpsc::Receiver<TcpStream>,
        errors: mpsc::Receiver<String>,
        stop: mpsc::Sender<()>,
        join: Option<thread::JoinHandle<()>>,
    }

    impl TestHttpMaskServer {
        fn start(
            mode: HttpMaskTunnelMode,
            key: &str,
            path_root: &str,
            expected_host: &str,
        ) -> Self {
            Self::start_with_tls(mode, key, path_root, expected_host, None)
        }

        fn start_with_tls(
            mode: HttpMaskTunnelMode,
            key: &str,
            path_root: &str,
            expected_host: &str,
            tls_config: Option<Arc<ServerConfig>>,
        ) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener
                .set_nonblocking(true)
                .expect("set nonblocking listener");
            let addr = listener.local_addr().unwrap();
            let (accepted_tx, accepted_rx) = mpsc::channel();
            let (error_tx, error_rx) = mpsc::channel();
            let (stop_tx, stop_rx) = mpsc::channel();
            let auth = HttpMaskAuth::new(
                &crate::sudoku::client_aead_seed(key).expect("derive client aead seed"),
            )
            .expect("expected auth");
            let sessions: Arc<Mutex<HashMap<String, TcpStream>>> = Arc::new(Mutex::new(HashMap::new()));
            let next_token = Arc::new(AtomicU64::new(1));
            let accept_timeout = if tls_config.is_some() {
                Duration::from_secs(15)
            } else {
                Duration::from_secs(5)
            };
            let expected_path_root = path_root.to_owned();
            let expected_host = if expected_host.is_empty() {
                addr.to_string()
            } else {
                expected_host.to_owned()
            };
            let join = thread::spawn(move || loop {
                if stop_rx.try_recv().is_ok() {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("set accepted stream blocking");
                        let accepted_tx = accepted_tx.clone();
                        let error_tx = error_tx.clone();
                        let sessions = Arc::clone(&sessions);
                        let auth = auth.clone();
                        let next_token = Arc::clone(&next_token);
                        let expected_path_root = expected_path_root.clone();
                        let expected_host = expected_host.clone();
                        let tls_config = tls_config.clone();
                        thread::spawn(move || {
                            let stream: BoxedTestHttpIoStream = if let Some(tls_config) = tls_config {
                                let conn = ServerConnection::new(tls_config).unwrap();
                                Box::new(TestRustlsServerStream(StreamOwned::new(conn, stream)))
                            } else {
                                Box::new(stream)
                            };
                            if let Err(err) = handle_test_http_mask_request(
                                stream,
                                mode,
                                &auth,
                                &expected_path_root,
                                &expected_host,
                                &sessions,
                                &accepted_tx,
                                &next_token,
                            ) {
                                let _ = error_tx.send(err);
                            }
                        });
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) => {
                        let _ = error_tx.send(err.to_string());
                        break;
                    }
                }
            });
            Self {
                accept_timeout,
                addr,
                accepted: accepted_rx,
                errors: error_rx,
                stop: stop_tx,
                join: Some(join),
            }
        }

        fn next_stream(&self) -> TcpStream {
            self.accepted
                .recv_timeout(self.accept_timeout)
                .expect("expected accepted session stream")
        }

        fn assert_clean(&mut self) {
            self.stop.send(()).ok();
            if let Some(join) = self.join.take() {
                join.join().unwrap();
            }
            if let Ok(err) = self.errors.try_recv() {
                panic!("{err}");
            }
        }
    }

    fn handle_test_http_mask_request(
        mut stream: BoxedTestHttpIoStream,
        mode: HttpMaskTunnelMode,
        auth: &HttpMaskAuth,
        path_root: &str,
        expected_host: &str,
        sessions: &Arc<Mutex<HashMap<String, TcpStream>>>,
        accepted_tx: &mpsc::Sender<TcpStream>,
        next_token: &Arc<AtomicU64>,
    ) -> Result<(), String> {
        let (request, tail) = read_test_http_headers_with_tail(&mut *stream).map_err(|err| err.to_string())?;
        if request.is_empty() {
            return Ok(());
        }
        let (method, target, headers) = parse_test_http_request(&request)?;
        let Some(host) = headers.get("host") else {
            return Err("missing Host header".to_owned());
        };
        if host != expected_host {
            return Err(format!("unexpected Host header: {host}"));
        }
        let Some(tunnel) = headers.get("x-sudoku-tunnel") else {
            return Err("missing X-Sudoku-Tunnel header".to_owned());
        };
        let requested_mode = match tunnel.as_str() {
            "stream" => HttpMaskTunnelMode::Stream,
            "poll" => HttpMaskTunnelMode::Poll,
            other => return Err(format!("unexpected tunnel mode header {other}")),
        };
        let (path, query) = split_target_path_query(&target);
        let normalized_root = super::normalize_path_root(path_root);
        let relative_path = path
            .strip_prefix(&normalized_root)
            .unwrap_or(path.as_str());
        match relative_path {
            "/session" | "/stream" | "/api/v1/upload" => {}
            other => return Err(format!("unexpected path {path} (relative {other})")),
        }
        let auth_value = headers
            .get("authorization")
            .cloned()
            .or_else(|| query.get(super::HTTP_MASK_AUTH_QUERY_KEY).cloned())
            .ok_or_else(|| "missing auth token".to_owned())?;
        if !auth.verify_value(
            &auth_value,
            requested_mode,
            &method,
            relative_path,
            SystemTime::now(),
        ) {
            write_test_http_response(&mut *stream, 404, b"not found")?;
            return Ok(());
        }
        match requested_mode {
            HttpMaskTunnelMode::Stream | HttpMaskTunnelMode::Poll => {}
            other => return Err(format!("unexpected requested mode {other:?}")),
        }
        if requested_mode != mode && !(mode == HttpMaskTunnelMode::Poll && requested_mode == HttpMaskTunnelMode::Stream) {
            write_test_http_response(&mut *stream, 404, b"not found")?;
            return Ok(());
        }
        match (method.as_str(), relative_path) {
            ("GET", "/session") => {
                if mode == HttpMaskTunnelMode::Poll && requested_mode == HttpMaskTunnelMode::Stream {
                    write_test_http_response(&mut *stream, 404, b"not found")?;
                    return Ok(());
                }
                let token = format!("token-{}", next_token.fetch_add(1, Ordering::Relaxed));
                let session_stream = tcp_pair().map_err(|err| err.to_string())?;
                sessions
                    .lock()
                    .expect("test session map poisoned")
                    .insert(token.clone(), session_stream.1);
                accepted_tx
                    .send(session_stream.0)
                    .map_err(|err| err.to_string())?;
                write_test_http_response(
                    &mut *stream,
                    200,
                    format!("token={token}").as_bytes(),
                )?;
            }
            ("POST", "/api/v1/upload") => {
                let token = query
                    .get("token")
                    .cloned()
                    .ok_or_else(|| "missing token".to_owned())?;
                let mut sessions_guard = sessions.lock().expect("test session map poisoned");
                let Some(session) = sessions_guard.get(&token) else {
                    write_test_http_response(&mut *stream, 403, b"forbidden")?;
                    return Ok(());
                };
                if query.get("close").is_some_and(|value| value == "1") {
                    let _ = session.shutdown(Shutdown::Both);
                    sessions_guard.remove(&token);
                    write_test_http_response(&mut *stream, 200, b"")?;
                    return Ok(());
                }
                if query.get("fin").is_some_and(|value| value == "1") {
                    let session = session.try_clone().map_err(|err| err.to_string())?;
                    drop(sessions_guard);
                    let _ = session.shutdown(Shutdown::Write);
                    write_test_http_response(&mut *stream, 200, b"")?;
                    return Ok(());
                }
                let mut session = session.try_clone().map_err(|err| err.to_string())?;
                drop(sessions_guard);
                let body = read_test_http_body(&request, tail, &mut *stream).map_err(|err| err.to_string())?;
                match requested_mode {
                    HttpMaskTunnelMode::Stream => {
                        session.write_all(&body).map_err(|err| err.to_string())?;
                    }
                    HttpMaskTunnelMode::Poll => {
                        for line in String::from_utf8_lossy(&body).lines() {
                            let trimmed = line.trim();
                            if trimmed.is_empty() {
                                continue;
                            }
                            let payload = base64::engine::general_purpose::STANDARD
                                .decode(trimmed)
                                .map_err(|err| err.to_string())?;
                            session.write_all(&payload).map_err(|err| err.to_string())?;
                        }
                    }
                    _ => unreachable!(),
                }
                write_test_http_response(&mut *stream, 200, b"")?;
            }
            ("GET", "/stream") => {
                let token = query
                    .get("token")
                    .cloned()
                    .ok_or_else(|| "missing token".to_owned())?;
                let session = {
                    let sessions_guard = sessions.lock().expect("test session map poisoned");
                    let Some(session) = sessions_guard.get(&token) else {
                        write_test_http_response(&mut *stream, 404, b"not found")?;
                        return Ok(());
                    };
                    session.try_clone().map_err(|err| err.to_string())?
                };
                let mut session = session;
                session
                    .set_nonblocking(true)
                    .map_err(|err| err.to_string())?;
                let mut payload = Vec::new();
                let mut buf = [0_u8; 32 * 1024];
                let deadline = Instant::now() + Duration::from_secs(3);
                loop {
                    match session.read(&mut buf) {
                        Ok(0) => {
                            sessions.lock().expect("test session map poisoned").remove(&token);
                            break;
                        }
                        Ok(read) => payload.extend_from_slice(&buf[..read]),
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                break;
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(err) => {
                            sessions.lock().expect("test session map poisoned").remove(&token);
                            return Err(err.to_string());
                        }
                    }
                }
                let _ = session.set_nonblocking(false);
                match requested_mode {
                    HttpMaskTunnelMode::Stream => write_test_chunked_response(&mut *stream, &payload)?,
                    HttpMaskTunnelMode::Poll => {
                        let body = if payload.is_empty() {
                            b"\n".to_vec()
                        } else {
                            let mut encoded = base64::engine::general_purpose::STANDARD
                                .encode(payload)
                                .into_bytes();
                            encoded.push(b'\n');
                            encoded
                        };
                        write_test_http_response(&mut *stream, 200, &body)?;
                    }
                    _ => unreachable!(),
                }
            }
            other => return Err(format!("unexpected request {other:?}")),
        }
        Ok(())
    }

    fn read_test_http_headers_with_tail(stream: &mut dyn Read) -> io::Result<(String, Vec<u8>)> {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = match stream.read(&mut chunk) {
                Ok(read) => read,
                Err(err)
                    if buffer.is_empty()
                        && matches!(
                            err.kind(),
                            io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionAborted
                                | io::ErrorKind::BrokenPipe
                        ) =>
                {
                    return Ok((String::new(), Vec::new()));
                }
                Err(err) => return Err(err),
            };
            if read == 0 {
                if buffer.is_empty() {
                    return Ok((String::new(), Vec::new()));
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "request closed before headers completed",
                ));
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                let header_end = position + 4;
                return Ok((
                    String::from_utf8_lossy(&buffer[..header_end]).into_owned(),
                    buffer[header_end..].to_vec(),
                ));
            }
        }
    }

    fn parse_test_http_request(
        request: &str,
    ) -> Result<(String, String, HashMap<String, String>), String> {
        let mut lines = request.lines();
        let request_line = lines.next().ok_or_else(|| "missing request line".to_owned())?;
        let mut parts = request_line.split_whitespace();
        let method = parts
            .next()
            .ok_or_else(|| "missing request method".to_owned())?
            .to_owned();
        let target = parts
            .next()
            .ok_or_else(|| "missing request target".to_owned())?
            .to_owned();
        let mut headers = HashMap::new();
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
        Ok((method, target, headers))
    }

    fn split_target_path_query(target: &str) -> (String, HashMap<String, String>) {
        let Some((path, query)) = target.split_once('?') else {
            return (target.to_owned(), HashMap::new());
        };
        let mut params = HashMap::new();
        for pair in query.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            params.insert(key.to_owned(), value.to_owned());
        }
        (path.to_owned(), params)
    }

    fn read_test_http_body(
        request: &str,
        mut tail: Vec<u8>,
        stream: &mut dyn Read,
    ) -> io::Result<Vec<u8>> {
        let mut content_length = 0usize;
        for line in request.lines() {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("Content-Length") {
                content_length = value.trim().parse::<usize>().unwrap_or(0);
            }
        }
        if tail.len() < content_length {
            let mut rest = vec![0_u8; content_length - tail.len()];
            stream.read_exact(&mut rest)?;
            tail.extend_from_slice(&rest);
        }
        tail.truncate(content_length);
        Ok(tail)
    }

    fn write_test_http_response(stream: &mut dyn Write, status: u16, body: &[u8]) -> Result<(), String> {
        let reason = match status {
            200 => "OK",
            403 => "Forbidden",
            404 => "Not Found",
            other => return Err(format!("unsupported test status {other}")),
        };
        stream
            .write_all(
                format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .map_err(|err| err.to_string())?;
        stream.write_all(body).map_err(|err| err.to_string())?;
        stream.flush().map_err(|err| err.to_string())
    }

    fn write_test_chunked_response(stream: &mut dyn Write, body: &[u8]) -> Result<(), String> {
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .map_err(|err| err.to_string())?;
        if !body.is_empty() {
            stream
                .write_all(format!("{:x}\r\n", body.len()).as_bytes())
                .map_err(|err| err.to_string())?;
            stream.write_all(body).map_err(|err| err.to_string())?;
            stream.write_all(b"\r\n").map_err(|err| err.to_string())?;
        }
        stream.write_all(b"0\r\n\r\n").map_err(|err| err.to_string())?;
        stream.flush().map_err(|err| err.to_string())
    }

    fn tcp_pair() -> io::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let client = TcpStream::connect(addr)?;
        let (server, _) = listener.accept()?;
        Ok((server, client))
    }

    fn build_tls_server_config_with_pem() -> (Arc<ServerConfig>, String) {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let cert_pem = cert.cert.pem();
        let key_der = cert.key_pair.serialize_der();
        (
            Arc::new(
                ServerConfig::builder()
                    .with_safe_defaults()
                    .with_no_client_auth()
                    .with_single_cert(vec![Certificate(cert_der)], PrivateKey(key_der))
                    .unwrap(),
            ),
            cert_pem,
        )
    }

    #[test]
    fn sudoku_http_mask_stream_tcp_round_trip_preserves_target_and_payload() {
        let _guard = httpmask_test_guard();
        let mut server = TestHttpMaskServer::start(
            HttpMaskTunnelMode::Stream,
            "secret-seed",
            "mask",
            "cdn.example.com:8443",
        );
        let addr = server.addr;
        let worker = thread::spawn(move || {
            let stream = server.next_stream();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuServerSession::Tcp { target, mut stream } = session else {
                panic!("expected tcp session");
            };
            assert_eq!(target, "stream.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-stream").unwrap();
            stream.shutdown_write().unwrap();
            server.assert_clean();
        });

        let mut stream = wrap_stream(
            Box::new(TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            true,
            "stream",
            false,
            "cdn.example.com:8443",
            "mask",
            "",
            &[],
            &TransportTarget::new("stream.example.com", 443),
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-stream");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_http_mask_stream_over_tls_tcp_round_trip_preserves_target_and_payload() {
        let _guard = httpmask_test_guard();
        let (tls_config, cert_pem) = build_tls_server_config_with_pem();
        register_test_root_certificate(&cert_pem).unwrap();
        let mut server = TestHttpMaskServer::start_with_tls(
            HttpMaskTunnelMode::Stream,
            "secret-seed",
            "mask",
            "localhost:8443",
            Some(tls_config),
        );
        let addr = server.addr;
        let worker = thread::spawn(move || {
            let stream = server.next_stream();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuServerSession::Tcp { target, mut stream } = session else {
                panic!("expected tcp session");
            };
            assert_eq!(target, "tls.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-stream-tls").unwrap();
            stream.shutdown_write().unwrap();
            server.assert_clean();
        });

        let mut stream = wrap_stream(
            Box::new(TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            true,
            "stream",
            true,
            "localhost:8443",
            "mask",
            "",
            &[],
            &TransportTarget::new("tls.example.com", 443),
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-stream-tls");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_http_mask_poll_udp_round_trip_preserves_target_and_payload() {
        let _guard = httpmask_test_guard();
        let mut server = TestHttpMaskServer::start(
            HttpMaskTunnelMode::Poll,
            "secret-seed",
            "mask",
            "",
        );
        let addr = server.addr;
        let worker = thread::spawn(move || {
            let stream = server.next_stream();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "aes-128-gcm",
                "prefer_ascii",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuServerSession::Udp { mut stream } = session else {
                panic!("expected udp session");
            };
            let (target, payload) = read_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
            assert_eq!(payload, b"via-poll");
            write_udp_packet(&mut *stream, target, b"poll-ok").unwrap();
            stream.shutdown_write().unwrap();
            server.assert_clean();
        });

        let mut stream = open_udp_stream(
            Box::new(TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "aes-128-gcm",
            "prefer_ascii",
            10,
            30,
            true,
            true,
            "poll",
            false,
            "",
            "mask",
            "",
            &[],
        )
        .unwrap();
        write_udp_packet(&mut *stream, "127.0.0.1:5353".parse().unwrap(), b"via-poll").unwrap();
        let (target, payload) = read_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(payload, b"poll-ok");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_http_mask_poll_tcp_round_trip_preserves_target_and_payload() {
        let _guard = httpmask_test_guard();
        let mut server = TestHttpMaskServer::start(
            HttpMaskTunnelMode::Poll,
            "secret-seed",
            "mask",
            "",
        );
        let addr = server.addr;
        let worker = thread::spawn(move || {
            let stream = server.next_stream();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuServerSession::Tcp { target, mut stream } = session else {
                panic!("expected tcp session");
            };
            assert_eq!(target, "poll.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-poll").unwrap();
            stream.shutdown_write().unwrap();
            server.assert_clean();
        });

        let mut stream = wrap_stream(
            Box::new(TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            true,
            "poll",
            false,
            "",
            "mask",
            "",
            &[],
            &TransportTarget::new("poll.example.com", 443),
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-poll");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_http_mask_poll_over_tls_tcp_round_trip_preserves_target_and_payload() {
        let _guard = httpmask_test_guard();
        let (tls_config, cert_pem) = build_tls_server_config_with_pem();
        register_test_root_certificate(&cert_pem).unwrap();
        let mut server = TestHttpMaskServer::start_with_tls(
            HttpMaskTunnelMode::Poll,
            "secret-seed",
            "mask",
            "localhost:8443",
            Some(tls_config),
        );
        let addr = server.addr;
        let worker = thread::spawn(move || {
            let stream = server.next_stream();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuServerSession::Tcp { target, mut stream } = session else {
                panic!("expected tcp session");
            };
            assert_eq!(target, "poll-tls.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-poll-tls").unwrap();
            stream.shutdown_write().unwrap();
            server.assert_clean();
        });

        let mut stream = wrap_stream(
            Box::new(TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            true,
            "poll",
            true,
            "localhost:8443",
            "mask",
            "",
            &[],
            &TransportTarget::new("poll-tls.example.com", 443),
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-poll-tls");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_http_mask_poll_over_tls_udp_round_trip_preserves_target_and_payload() {
        let _guard = httpmask_test_guard();
        let (tls_config, cert_pem) = build_tls_server_config_with_pem();
        register_test_root_certificate(&cert_pem).unwrap();
        let mut server = TestHttpMaskServer::start_with_tls(
            HttpMaskTunnelMode::Poll,
            "secret-seed",
            "mask",
            "localhost:8443",
            Some(tls_config),
        );
        let addr = server.addr;
        let worker = thread::spawn(move || {
            let stream = server.next_stream();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "aes-128-gcm",
                "prefer_ascii",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuServerSession::Udp { mut stream } = session else {
                panic!("expected udp session");
            };
            let (target, payload) = read_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
            assert_eq!(payload, b"via-poll-tls");
            write_udp_packet(&mut *stream, target, b"poll-tls-ok").unwrap();
            stream.shutdown_write().unwrap();
            server.assert_clean();
        });

        let mut stream = open_udp_stream(
            Box::new(TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "aes-128-gcm",
            "prefer_ascii",
            10,
            30,
            true,
            true,
            "poll",
            true,
            "localhost:8443",
            "mask",
            "",
            &[],
        )
        .unwrap();
        write_udp_packet(
            &mut *stream,
            "127.0.0.1:5353".parse().unwrap(),
            b"via-poll-tls",
        )
        .unwrap();
        let (target, payload) = read_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(payload, b"poll-tls-ok");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_http_mask_stream_over_tls_udp_round_trip_preserves_target_and_payload() {
        let _guard = httpmask_test_guard();
        let (tls_config, cert_pem) = build_tls_server_config_with_pem();
        register_test_root_certificate(&cert_pem).unwrap();
        let mut server = TestHttpMaskServer::start_with_tls(
            HttpMaskTunnelMode::Stream,
            "secret-seed",
            "mask",
            "localhost:8443",
            Some(tls_config),
        );
        let addr = server.addr;
        let worker = thread::spawn(move || {
            let stream = server.next_stream();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "aes-128-gcm",
                "prefer_ascii",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuServerSession::Udp { mut stream } = session else {
                panic!("expected udp session");
            };
            let (target, payload) = read_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
            assert_eq!(payload, b"via-stream-tls");
            write_udp_packet(&mut *stream, target, b"stream-tls-ok").unwrap();
            stream.shutdown_write().unwrap();
            server.assert_clean();
        });

        let mut stream = open_udp_stream(
            Box::new(TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "aes-128-gcm",
            "prefer_ascii",
            10,
            30,
            true,
            true,
            "stream",
            true,
            "localhost:8443",
            "mask",
            "",
            &[],
        )
        .unwrap();
        write_udp_packet(
            &mut *stream,
            "127.0.0.1:5353".parse().unwrap(),
            b"via-stream-tls",
        )
        .unwrap();
        let (target, payload) = read_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(payload, b"stream-tls-ok");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_http_mask_stream_udp_round_trip_preserves_target_and_payload() {
        let _guard = httpmask_test_guard();
        let mut server = TestHttpMaskServer::start(
            HttpMaskTunnelMode::Stream,
            "secret-seed",
            "mask",
            "cdn.example.com:8443",
        );
        let addr = server.addr;
        let worker = thread::spawn(move || {
            let stream = server.next_stream();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "aes-128-gcm",
                "prefer_ascii",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuServerSession::Udp { mut stream } = session else {
                panic!("expected udp session");
            };
            let (target, payload) = read_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
            assert_eq!(payload, b"via-stream");
            write_udp_packet(&mut *stream, target, b"stream-ok").unwrap();
            stream.shutdown_write().unwrap();
            server.assert_clean();
        });

        let mut stream = open_udp_stream(
            Box::new(TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "aes-128-gcm",
            "prefer_ascii",
            10,
            30,
            true,
            true,
            "stream",
            false,
            "cdn.example.com:8443",
            "mask",
            "",
            &[],
        )
        .unwrap();
        write_udp_packet(
            &mut *stream,
            "127.0.0.1:5353".parse().unwrap(),
            b"via-stream",
        )
        .unwrap();
        let (target, payload) = read_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(payload, b"stream-ok");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_http_mask_auto_falls_back_to_poll() {
        let _guard = httpmask_test_guard();
        let mut server = TestHttpMaskServer::start(
            HttpMaskTunnelMode::Poll,
            "secret-seed",
            "mask",
            "",
        );
        let addr = server.addr;
        let worker = thread::spawn(move || {
            let stream = server.next_stream();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuServerSession::Tcp { target, mut stream } = session else {
                panic!("expected tcp session");
            };
            assert_eq!(target, "auto.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-auto").unwrap();
            stream.shutdown_write().unwrap();
            server.assert_clean();
        });

        let mut stream = wrap_stream(
            Box::new(TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            true,
            "auto",
            false,
            "",
            "mask",
            "",
            &[],
            &TransportTarget::new("auto.example.com", 443),
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-auto");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_http_mask_auto_over_tls_falls_back_to_poll() {
        let _guard = httpmask_test_guard();
        let (tls_config, cert_pem) = build_tls_server_config_with_pem();
        register_test_root_certificate(&cert_pem).unwrap();
        let mut server = TestHttpMaskServer::start_with_tls(
            HttpMaskTunnelMode::Poll,
            "secret-seed",
            "mask",
            "localhost:8443",
            Some(tls_config),
        );
        let addr = server.addr;
        let worker = thread::spawn(move || {
            let stream = server.next_stream();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuServerSession::Tcp { target, mut stream } = session else {
                panic!("expected tcp session");
            };
            assert_eq!(target, "auto-tls.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-auto-tls").unwrap();
            stream.shutdown_write().unwrap();
            server.assert_clean();
        });

        let mut stream = wrap_stream(
            Box::new(TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            true,
            "auto",
            true,
            "localhost:8443",
            "mask",
            "",
            &[],
            &TransportTarget::new("auto-tls.example.com", 443),
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-auto-tls");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_http_mask_auto_udp_falls_back_to_poll() {
        let _guard = httpmask_test_guard();
        let mut server = TestHttpMaskServer::start(
            HttpMaskTunnelMode::Poll,
            "secret-seed",
            "mask",
            "",
        );
        let addr = server.addr;
        let worker = thread::spawn(move || {
            let stream = server.next_stream();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "aes-128-gcm",
                "prefer_ascii",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuServerSession::Udp { mut stream } = session else {
                panic!("expected udp session");
            };
            let (target, payload) = read_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
            assert_eq!(payload, b"via-auto-poll");
            write_udp_packet(&mut *stream, target, b"auto-poll-ok").unwrap();
            stream.shutdown_write().unwrap();
            server.assert_clean();
        });

        let mut stream = open_udp_stream(
            Box::new(TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "aes-128-gcm",
            "prefer_ascii",
            10,
            30,
            true,
            true,
            "auto",
            false,
            "",
            "mask",
            "",
            &[],
        )
        .unwrap();
        write_udp_packet(
            &mut *stream,
            "127.0.0.1:5353".parse().unwrap(),
            b"via-auto-poll",
        )
        .unwrap();
        let (target, payload) = read_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(payload, b"auto-poll-ok");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_http_mask_auto_udp_over_tls_falls_back_to_poll() {
        let _guard = httpmask_test_guard();
        let (tls_config, cert_pem) = build_tls_server_config_with_pem();
        register_test_root_certificate(&cert_pem).unwrap();
        let mut server = TestHttpMaskServer::start_with_tls(
            HttpMaskTunnelMode::Poll,
            "secret-seed",
            "mask",
            "localhost:8443",
            Some(tls_config),
        );
        let addr = server.addr;
        let worker = thread::spawn(move || {
            let stream = server.next_stream();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "aes-128-gcm",
                "prefer_ascii",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuServerSession::Udp { mut stream } = session else {
                panic!("expected udp session");
            };
            let (target, payload) = read_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
            assert_eq!(payload, b"via-auto-tls-poll");
            write_udp_packet(&mut *stream, target, b"auto-tls-poll-ok").unwrap();
            stream.shutdown_write().unwrap();
            server.assert_clean();
        });

        let mut stream = open_udp_stream(
            Box::new(TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "aes-128-gcm",
            "prefer_ascii",
            10,
            30,
            true,
            true,
            "auto",
            true,
            "localhost:8443",
            "mask",
            "",
            &[],
        )
        .unwrap();
        write_udp_packet(
            &mut *stream,
            "127.0.0.1:5353".parse().unwrap(),
            b"via-auto-tls-poll",
        )
        .unwrap();
        let (target, payload) = read_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(payload, b"auto-tls-poll-ok");
        worker.join().unwrap();
    }
}
