use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use mihomo_core::BoxedTcpStream;
use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection, StreamOwned};
use sha1::{Digest, Sha1};

pub(crate) fn accept_tls_server_stream(
    stream: TcpStream,
    tls_config: Arc<ServerConfig>,
) -> io::Result<BoxedTcpStream> {
    let conn = ServerConnection::new(tls_config)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    Ok(Box::new(ServerTlsStream(Arc::new(Mutex::new(StreamOwned::new(
        conn, stream,
    ))))))
}

pub(crate) fn accept_websocket_server_stream(
    mut stream: BoxedTcpStream,
    expected_path: &str,
) -> io::Result<BoxedTcpStream> {
    let (request, tail) = read_http_headers_with_tail(&mut *stream)?;
    let request_line = request
        .lines()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing websocket request line"))?;
    let request_target = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing websocket request target"))?;
    let request_path = request_target
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(request_target);
    let expected_path = normalize_ws_path(expected_path);
    if request_path != expected_path {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected websocket request line: {request_line}"),
        ));
    }

    let key = request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("Sec-WebSocket-Key") {
            Some(value.trim().to_owned())
        } else {
            None
        }
    });
    let early_data = request
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("Sec-WebSocket-Protocol") {
                Some(
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(value.trim())
                        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string())),
                )
            } else {
                None
            }
        })
        .transpose()?
        .unwrap_or_default();

    let response = if let Some(key) = key {
        let accept = websocket_accept_key(&key);
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
    } else {
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            .to_owned()
    };
    stream.write_all(response.as_bytes())?;
    stream.flush()?;

    if request.lines().any(|line| line.starts_with("Sec-WebSocket-Key:")) {
        let inner: BoxedTcpStream = if tail.is_empty() {
            Box::new(ServerWebsocketStream::new(stream))
        } else {
            Box::new(ServerWebsocketStream::new(Box::new(PrefixedTcpStream {
                prefix: io::Cursor::new(tail),
                inner: stream,
            })))
        };
        if early_data.is_empty() {
            Ok(inner)
        } else {
            Ok(Box::new(PrefixedTcpStream {
                prefix: io::Cursor::new(early_data),
                inner,
            }))
        }
    } else {
        let mut prefix = early_data;
        prefix.extend_from_slice(&tail);
        if prefix.is_empty() {
            Ok(stream)
        } else {
            Ok(Box::new(PrefixedTcpStream {
                prefix: io::Cursor::new(prefix),
                inner: stream,
            }))
        }
    }
}

pub(crate) fn accept_http_server_stream(
    mut stream: BoxedTcpStream,
) -> io::Result<(String, BoxedTcpStream)> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "http stream closed before request headers completed",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let request = String::from_utf8(buffer[..header_end].to_vec())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    let mut content_length = 0usize;
    for line in request.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("Content-Length") {
            content_length = value.trim().parse::<usize>().map_err(|err| {
                io::Error::new(io::ErrorKind::InvalidData, format!("invalid Content-Length: {err}"))
            })?;
        }
    }
    let mut prefix = buffer[header_end..].to_vec();
    if prefix.len() < content_length {
        let mut rest = vec![0_u8; content_length - prefix.len()];
        stream.read_exact(&mut rest)?;
        prefix.extend_from_slice(&rest);
    }
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")?;
    stream.flush()?;
    Ok((request, prefix_tcp_stream(stream, prefix)))
}

pub(crate) fn prefix_tcp_stream(stream: BoxedTcpStream, prefix: Vec<u8>) -> BoxedTcpStream {
    if prefix.is_empty() {
        stream
    } else {
        Box::new(PrefixedTcpStream {
            prefix: io::Cursor::new(prefix),
            inner: stream,
        })
    }
}

fn websocket_accept_key(key: &str) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(key.as_bytes());
    sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(sha1.finalize())
}

fn normalize_ws_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        "/".to_owned()
    } else if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    }
}

fn read_http_headers_with_tail(stream: &mut dyn Read) -> io::Result<(String, Vec<u8>)> {
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
                "http request closed before headers completed",
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
