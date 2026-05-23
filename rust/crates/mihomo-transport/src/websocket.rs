use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use base64::Engine as _;
use mihomo_core::{BoxedTcpStream, TcpStream};
use rand::rngs::OsRng;
use rand::RngCore;
use sha1::{Digest, Sha1};

use crate::{prepend_bytes, TransportError, TransportTarget};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WebsocketOptions {
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub max_early_data: i32,
    pub early_data_header_name: String,
    pub v2ray_http_upgrade: bool,
    pub v2ray_http_upgrade_fast_open: bool,
}

pub(crate) fn wrap_stream(
    mut stream: BoxedTcpStream,
    proxy: &TransportTarget,
    options: &WebsocketOptions,
) -> Result<BoxedTcpStream, TransportError> {
    let options = normalized_options(options);
    if options.v2ray_http_upgrade_fast_open && !options.v2ray_http_upgrade {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: "ws v2ray-http-upgrade-fast-open without v2ray-http-upgrade".to_owned(),
        });
    }

    if options.max_early_data > 0 {
        Ok(Box::new(WebsocketEarlyDataStream::new(
            stream,
            proxy.clone(),
            options,
        )))
    } else {
        let mut raw_key = [0_u8; 16];
        OsRng.fill_bytes(&mut raw_key);
        let sec_key = base64::engine::general_purpose::STANDARD.encode(raw_key);
        let request = build_websocket_request(proxy, &options, &sec_key, None);
        stream.write_all(request.as_bytes())?;
        stream.flush()?;
        if options.v2ray_http_upgrade_fast_open {
            return Ok(Box::new(WebsocketUpgradeFastOpenStream::new(
                prepend_bytes(stream, Vec::new()),
                sec_key,
            )));
        }
        let buffered = read_websocket_response(&mut *stream, &sec_key, options.v2ray_http_upgrade)?;
        let stream = prepend_bytes(stream, buffered);
        if options.v2ray_http_upgrade {
            Ok(stream)
        } else {
            Ok(Box::new(WebsocketClientStream::new(stream)))
        }
    }
}

fn normalized_options(options: &WebsocketOptions) -> WebsocketOptions {
    let mut normalized = options.clone();
    if let Some((path, query)) = normalized.path.split_once('?') {
        let mut pairs = Vec::new();
        let mut ed_value = None;
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            if key == "ed" && !value.is_empty() {
                if let Ok(parsed) = value.parse::<i32>() {
                    if parsed > 0 {
                        ed_value = Some(parsed);
                        continue;
                    }
                }
            }
            pairs.push(pair.to_owned());
        }
        if let Some(parsed) = ed_value {
            normalized.max_early_data = parsed;
            normalized.early_data_header_name = "Sec-WebSocket-Protocol".to_owned();
            let mut rebuilt = path.to_owned();
            if !pairs.is_empty() {
                rebuilt.push('?');
                rebuilt.push_str(&pairs.join("&"));
            }
            normalized.path = rebuilt;
        }
    }
    normalized
}

fn build_websocket_request(
    proxy: &TransportTarget,
    options: &WebsocketOptions,
    sec_key: &str,
    early_data: Option<&str>,
) -> String {
    let mut request = String::new();
    let path = websocket_path(&options.path, early_data, &options.early_data_header_name);
    let host = options
        .headers
        .get("Host")
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| proxy.host.clone());
    request.push_str(&format!("GET {path} HTTP/1.1\r\n"));
    request.push_str(&format!("Host: {host}\r\n"));
    request.push_str("Connection: Upgrade\r\n");
    request.push_str("Upgrade: websocket\r\n");
    if !options.v2ray_http_upgrade {
        request.push_str("Sec-WebSocket-Version: 13\r\n");
        request.push_str(&format!("Sec-WebSocket-Key: {sec_key}\r\n"));
    }
    for (name, value) in &options.headers {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("upgrade")
            || name.eq_ignore_ascii_case("sec-websocket-version")
            || name.eq_ignore_ascii_case("sec-websocket-key")
        {
            continue;
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    if let Some(value) = early_data {
        if !value.is_empty() && !options.early_data_header_name.trim().is_empty() {
            request.push_str(options.early_data_header_name.trim());
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
    }
    request.push_str("\r\n");
    request
}

fn websocket_path(path: &str, early_data: Option<&str>, early_data_header_name: &str) -> String {
    let trimmed = path.trim();
    let normalized = if trimmed.is_empty() {
        "/".to_owned()
    } else if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    };
    if let Some(value) = early_data {
        if !value.is_empty() && early_data_header_name.trim().is_empty() {
            let (path_part, query_part) = normalized
                .split_once('?')
                .map(|(path, query)| (path.to_owned(), Some(query.to_owned())))
                .unwrap_or_else(|| (normalized.clone(), None));
            let mut with_early = path_part;
            with_early.push_str(value);
            if let Some(query) = query_part {
                with_early.push('?');
                with_early.push_str(&query);
            }
            return with_early;
        }
    }
    normalized
}

struct WebsocketEarlyDataStream {
    inner: Option<BoxedTcpStream>,
    underlay: Option<BoxedTcpStream>,
    proxy: TransportTarget,
    options: WebsocketOptions,
}

impl WebsocketEarlyDataStream {
    fn new(underlay: BoxedTcpStream, proxy: TransportTarget, options: WebsocketOptions) -> Self {
        Self {
            inner: None,
            underlay: Some(underlay),
            proxy,
            options,
        }
    }

    fn ensure_connected(&mut self, initial_write: Option<&[u8]>) -> io::Result<()> {
        if self.inner.is_some() {
            return Ok(());
        }
        let underlay = self
            .underlay
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "websocket underlay is unavailable"))?;
        let mut raw_key = [0_u8; 16];
        OsRng.fill_bytes(&mut raw_key);
        let sec_key = base64::engine::general_purpose::STANDARD.encode(raw_key);
        let max_early_data = self.options.max_early_data.max(0) as usize;
        let (early_chunk, remainder) = if let Some(payload) = initial_write {
            let split = payload.len().min(max_early_data);
            (&payload[..split], &payload[split..])
        } else {
            (&[][..], &[][..])
        };
        let encoded_early_data = if early_chunk.is_empty() {
            None
        } else {
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(early_chunk))
        };
        let request = build_websocket_request(
            &self.proxy,
            &self.options,
            &sec_key,
            encoded_early_data.as_deref(),
        );
        let mut underlay = underlay;
        underlay.write_all(request.as_bytes())?;
        underlay.flush()?;
        if self.options.v2ray_http_upgrade_fast_open {
            if !remainder.is_empty() {
                underlay.write_all(remainder)?;
                underlay.flush()?;
            }
            self.inner = Some(Box::new(WebsocketUpgradeFastOpenStream::new(
                prepend_bytes(underlay, Vec::new()),
                sec_key,
            )));
        } else {
            let buffered = read_websocket_response(&mut *underlay, &sec_key, self.options.v2ray_http_upgrade)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
            if self.options.v2ray_http_upgrade {
                let mut stream = prepend_bytes(underlay, buffered);
                if !remainder.is_empty() {
                    stream.write_all(remainder)?;
                }
                self.inner = Some(stream);
            } else {
                let mut stream = Box::new(WebsocketClientStream::new(prepend_bytes(underlay, buffered)));
                if !remainder.is_empty() {
                    stream.write_all(remainder)?;
                }
                self.inner = Some(stream);
            }
        }
        Ok(())
    }

    fn inner_mut(&mut self) -> io::Result<&mut BoxedTcpStream> {
        self.inner
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "websocket stream is not connected"))
    }
}

fn websocket_accept(key: &str) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(key.as_bytes());
    sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(sha1.finalize())
}

fn read_websocket_response(
    stream: &mut dyn Read,
    sec_key: &str,
    v2ray_http_upgrade: bool,
) -> Result<Vec<u8>, TransportError> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(TransportError::invalid_proxy_response(
                "proxy closed before websocket response completed",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_end = position + 4;
            return validate_websocket_response(&buffer, header_end, sec_key, v2ray_http_upgrade);
        }
        if buffer.len() > 64 * 1024 {
            return Err(TransportError::invalid_proxy_response(
                "websocket response headers exceeded 64KiB",
            ));
        }
    }
}

fn validate_websocket_response(
    buffer: &[u8],
    header_end: usize,
    sec_key: &str,
    v2ray_http_upgrade: bool,
) -> Result<Vec<u8>, TransportError> {
    let text = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = text.split("\r\n").filter(|line| !line.is_empty());
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| {
            TransportError::invalid_proxy_response(format!(
                "missing websocket HTTP status in {status_line:?}"
            ))
        })?;
    if !version.starts_with("HTTP/") {
        return Err(TransportError::invalid_proxy_response(format!(
            "unexpected websocket HTTP version in {status_line:?}"
        )));
    }
    if status != 101 {
        return Err(TransportError::invalid_proxy_response(format!(
            "websocket upgrade failed with status {status}"
        )));
    }

    let mut connection_ok = false;
    let mut upgrade_ok = false;
    let mut accept = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("Connection")
            && value
                .split(',')
                .any(|item| item.trim().eq_ignore_ascii_case("upgrade"))
        {
            connection_ok = true;
        } else if name.eq_ignore_ascii_case("Upgrade")
            && value.eq_ignore_ascii_case("websocket")
        {
            upgrade_ok = true;
        } else if name.eq_ignore_ascii_case("Sec-WebSocket-Accept") {
            accept = Some(value.to_owned());
        }
    }
    if !connection_ok || !upgrade_ok {
        return Err(TransportError::invalid_proxy_response(
            "websocket upgrade response missing upgrade headers",
        ));
    }
    if !v2ray_http_upgrade {
        let expected = websocket_accept(sec_key);
        if accept.as_deref() != Some(expected.as_str()) {
            return Err(TransportError::invalid_proxy_response(
                "unexpected Sec-WebSocket-Accept",
            ));
        }
    }
    Ok(buffer[header_end..].to_vec())
}

struct WebsocketClientStream {
    inner: BoxedTcpStream,
    pending: Vec<u8>,
    offset: usize,
    closed: bool,
}

impl WebsocketClientStream {
    fn new(inner: BoxedTcpStream) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            offset: 0,
            closed: false,
        }
    }

    fn read_raw_frame(&mut self) -> io::Result<Option<(bool, u8, Vec<u8>)>> {
        let mut header = [0_u8; 2];
        match self.inner.read_exact(&mut header) {
            Ok(()) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                ) =>
            {
                self.closed = true;
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
        if len > usize::MAX as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "websocket frame too large",
            ));
        }
        let mut payload = vec![0_u8; len as usize];
        self.inner.read_exact(&mut payload)?;
        if let Some(mask) = mask {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
        }

        Ok(Some((fin, opcode, payload)))
    }

    fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        let Some((fin, opcode, payload)) = self.read_raw_frame()? else {
            return Ok(None);
        };

        match opcode {
            0x1 | 0x2 => {
                if fin {
                    return Ok(Some(payload));
                }
                let mut assembled = payload;
                loop {
                    let Some((fin, opcode, payload)) = self.read_raw_frame()? else {
                        self.closed = true;
                        return Ok(None);
                    };
                    match opcode {
                        0x0 => {
                            assembled.extend_from_slice(&payload);
                            if fin {
                                return Ok(Some(assembled));
                            }
                        }
                        0x8 => {
                            self.closed = true;
                            return Ok(None);
                        }
                        0x9 => {
                            self.write_control_frame(0xA, &payload)?;
                        }
                        0xA => {}
                        other => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("unexpected websocket opcode {other} during fragmented message"),
                            ))
                        }
                    }
                }
            }
            0x8 => {
                self.closed = true;
                Ok(None)
            }
            0x9 => {
                self.write_control_frame(0xA, &payload)?;
                Ok(Some(Vec::new()))
            }
            0xA => Ok(Some(Vec::new())),
            0x0 => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "websocket continuation frame without fragmented message",
            )),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected websocket opcode {other}"),
            )),
        }
    }

    fn write_control_frame(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        self.write_frame(opcode, payload)
    }

    fn write_frame(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        let mut header = Vec::with_capacity(14);
        header.push(0x80 | (opcode & 0x0f));
        if payload.len() < 126 {
            header.push(0x80 | payload.len() as u8);
        } else if payload.len() < 65_536 {
            header.push(0x80 | 126);
            header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            header.push(0x80 | 127);
            header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        let mut mask = [0_u8; 4];
        OsRng.fill_bytes(&mut mask);
        header.extend_from_slice(&mask);
        self.inner.write_all(&header)?;
        if !payload.is_empty() {
            let mut framed = payload.to_vec();
            for (index, byte) in framed.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
            self.inner.write_all(&framed)?;
        }
        self.inner.flush()
    }
}

struct WebsocketUpgradeFastOpenStream {
    inner: BoxedTcpStream,
    sec_key: String,
    validated: bool,
    pending: Vec<u8>,
    offset: usize,
}

impl WebsocketUpgradeFastOpenStream {
    fn new(inner: BoxedTcpStream, sec_key: String) -> Self {
        Self {
            inner,
            sec_key,
            validated: false,
            pending: Vec::new(),
            offset: 0,
        }
    }

    fn ensure_validated(&mut self) -> io::Result<()> {
        if self.validated {
            return Ok(());
        }
        let buffered = read_websocket_response(&mut *self.inner, &self.sec_key, true)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        self.pending = buffered;
        self.offset = 0;
        self.validated = true;
        Ok(())
    }
}

impl Read for WebsocketEarlyDataStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.ensure_connected(None)?;
        self.inner_mut()?.read(buf)
    }
}

impl Write for WebsocketEarlyDataStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.inner.is_none() {
            self.ensure_connected(Some(buf))?;
            Ok(buf.len())
        } else {
            self.inner_mut()?.write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(inner) = self.inner.as_mut() {
            inner.flush()
        } else {
            Ok(())
        }
    }
}

impl Read for WebsocketUpgradeFastOpenStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.ensure_validated()?;
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
        self.inner.read(buf)
    }
}

impl Write for WebsocketUpgradeFastOpenStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for WebsocketUpgradeFastOpenStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "websocket upgrade fast-open stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

impl TcpStream for WebsocketEarlyDataStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "websocket early-data stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.ensure_connected(None)?;
        self.inner_mut()?.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        if self.inner.is_none() {
            self.ensure_connected(None)?;
        }
        self.inner_mut()?.shutdown_all()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read, Write};
    use std::sync::{Arc, Mutex};

    use mihomo_core::{BoxedTcpStream, TcpStream};

    use super::{build_websocket_request, normalized_options, WebsocketClientStream, WebsocketOptions};
    use crate::TransportTarget;

    #[derive(Default)]
    struct ScriptedState {
        reader: Cursor<Vec<u8>>,
        writes: Vec<u8>,
    }

    #[derive(Clone)]
    struct ScriptedStreamHandle(Arc<Mutex<ScriptedState>>);

    impl ScriptedStreamHandle {
        fn new(readable: Vec<u8>) -> Self {
            Self(Arc::new(Mutex::new(ScriptedState {
                reader: Cursor::new(readable),
                writes: Vec::new(),
            })))
        }

        fn stream(&self) -> ScriptedStream {
            ScriptedStream(Arc::clone(&self.0))
        }

        fn writes(&self) -> Vec<u8> {
            self.0.lock().unwrap().writes.clone()
        }
    }

    struct ScriptedStream(Arc<Mutex<ScriptedState>>);

    impl Read for ScriptedStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.lock().unwrap().reader.read(buf)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().writes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl TcpStream for ScriptedStream {
        fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
            Ok(Box::new(ScriptedStream(Arc::clone(&self.0))))
        }

        fn shutdown_write(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn shutdown_all(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn server_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push((if fin { 0x80 } else { 0x00 }) | (opcode & 0x0f));
        if payload.len() < 126 {
            out.push(payload.len() as u8);
        } else if payload.len() < 65_536 {
            out.push(126);
            out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            out.push(127);
            out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn build_websocket_request_uses_standard_headers_by_default() {
        let request = build_websocket_request(
            &TransportTarget::new("example.com", 443),
            &WebsocketOptions {
                path: "/ws".into(),
                ..Default::default()
            },
            "test-key",
            None,
        );
        assert!(request.starts_with("GET /ws HTTP/1.1\r\n"));
        assert!(request.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(request.contains("Sec-WebSocket-Key: test-key\r\n"));
    }

    #[test]
    fn build_websocket_request_omits_sec_websocket_headers_for_v2ray_http_upgrade() {
        let request = build_websocket_request(
            &TransportTarget::new("example.com", 443),
            &WebsocketOptions {
                path: "/ws".into(),
                v2ray_http_upgrade: true,
                ..Default::default()
            },
            "ignored-key",
            None,
        );
        assert!(request.starts_with("GET /ws HTTP/1.1\r\n"));
        assert!(!request.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(!request.contains("Sec-WebSocket-Key:"));
        assert!(request.contains("Connection: Upgrade\r\n"));
        assert!(request.contains("Upgrade: websocket\r\n"));
    }

    #[test]
    fn build_websocket_request_places_early_data_in_header() {
        let request = build_websocket_request(
            &TransportTarget::new("example.com", 443),
            &WebsocketOptions {
                path: "/ws".into(),
                max_early_data: 2048,
                early_data_header_name: "Sec-WebSocket-Protocol".into(),
                ..Default::default()
            },
            "test-key",
            Some("cGluZw"),
        );
        assert!(request.contains("Sec-WebSocket-Protocol: cGluZw\r\n"));
        assert!(request.starts_with("GET /ws HTTP/1.1\r\n"));
    }

    #[test]
    fn build_websocket_request_supports_early_data_with_v2ray_http_upgrade() {
        let request = build_websocket_request(
            &TransportTarget::new("example.com", 443),
            &WebsocketOptions {
                path: "/ws".into(),
                max_early_data: 2048,
                early_data_header_name: "Sec-WebSocket-Protocol".into(),
                v2ray_http_upgrade: true,
                ..Default::default()
            },
            "ignored-key",
            Some("cGluZw"),
        );
        assert!(request.contains("Sec-WebSocket-Protocol: cGluZw\r\n"));
        assert!(!request.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(!request.contains("Sec-WebSocket-Key:"));
    }

    #[test]
    fn build_websocket_request_places_early_data_in_path_when_header_is_empty() {
        let request = build_websocket_request(
            &TransportTarget::new("example.com", 443),
            &WebsocketOptions {
                path: "/ws?foo=bar".into(),
                max_early_data: 2048,
                ..Default::default()
            },
            "test-key",
            Some("cGluZw"),
        );
        assert!(request.starts_with("GET /wscGluZw?foo=bar HTTP/1.1\r\n"));
    }

    #[test]
    fn build_websocket_request_ignores_early_data_header_name_without_early_data() {
        let request = build_websocket_request(
            &TransportTarget::new("example.com", 443),
            &WebsocketOptions {
                path: "/ws".into(),
                early_data_header_name: "X-Early".into(),
                ..Default::default()
            },
            "test-key",
            None,
        );
        assert!(request.starts_with("GET /ws HTTP/1.1\r\n"));
        assert!(!request.contains("X-Early:"));
    }

    #[test]
    fn normalized_options_extracts_ed_query_into_early_data_settings() {
        let normalized = normalized_options(&WebsocketOptions {
            path: "/ws?ed=2048&foo=bar".into(),
            ..Default::default()
        });
        assert_eq!(normalized.path, "/ws?foo=bar");
        assert_eq!(normalized.max_early_data, 2048);
        assert_eq!(normalized.early_data_header_name, "Sec-WebSocket-Protocol");
    }

    #[test]
    fn normalized_options_rejects_fast_open_without_http_upgrade_later() {
        let normalized = normalized_options(&WebsocketOptions {
            path: "/ws".into(),
            v2ray_http_upgrade_fast_open: true,
            ..Default::default()
        });
        assert!(normalized.v2ray_http_upgrade_fast_open);
        assert!(!normalized.v2ray_http_upgrade);
    }

    #[test]
    fn websocket_client_stream_reassembles_fragmented_frames_and_replies_to_ping() {
        let readable = [
            server_frame(false, 0x2, b"hel"),
            server_frame(true, 0x9, b"!"),
            server_frame(true, 0x0, b"lo"),
        ]
        .concat();
        let handle = ScriptedStreamHandle::new(readable);
        let mut stream = WebsocketClientStream::new(Box::new(handle.stream()));
        let mut buf = [0_u8; 5];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");

        let writes = handle.writes();
        assert!(!writes.is_empty());
        assert_eq!(writes[0], 0x8A);
        assert_eq!(writes[1] & 0x80, 0x80);
    }

    #[test]
    fn websocket_client_stream_rejects_bare_continuation_frame() {
        let readable = server_frame(true, 0x0, b"oops");
        let handle = ScriptedStreamHandle::new(readable);
        let mut stream = WebsocketClientStream::new(Box::new(handle.stream()));
        let mut buf = [0_u8; 4];
        let err = stream.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err
            .to_string()
            .contains("continuation frame without fragmented message"));
    }
}

impl Read for WebsocketClientStream {
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

impl Write for WebsocketClientStream {
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

impl TcpStream for WebsocketClientStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self::new(self.inner.try_clone_box()?)))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}
