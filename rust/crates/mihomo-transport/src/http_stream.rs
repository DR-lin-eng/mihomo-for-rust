#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use mihomo_core::{BoxedTcpStream, TcpStream};

use crate::{TransportError, TransportTarget};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HttpStreamOptions {
    pub method: String,
    pub host: Vec<String>,
    pub path: Vec<String>,
    pub headers: BTreeMap<String, Vec<String>>,
}

pub(crate) fn wrap_stream(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    options: &HttpStreamOptions,
) -> BoxedTcpStream {
    Box::new(HttpClientStream {
        inner: stream,
        options: options.clone(),
        default_host: proxy.host.clone(),
        reader: None,
        writer_handshake: false,
    })
}

struct HttpClientStream {
    inner: BoxedTcpStream,
    options: HttpStreamOptions,
    default_host: String,
    reader: Option<io::Cursor<Vec<u8>>>,
    writer_handshake: bool,
}

impl HttpClientStream {
    fn ensure_response(&mut self) -> io::Result<()> {
        if self.reader.is_some() {
            return Ok(());
        }
        let buffered = read_http_response(&mut *self.inner)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        self.reader = Some(io::Cursor::new(buffered));
        Ok(())
    }
}

impl Read for HttpClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.ensure_response()?;
        if let Some(reader) = &mut self.reader {
            let read = reader.read(buf)?;
            if read != 0 {
                return Ok(read);
            }
        }
        self.inner.read(buf)
    }
}

impl Write for HttpClientStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.writer_handshake {
            return self.inner.write(buf);
        }

        let request = build_http_request(&self.default_host, &self.options, buf);
        self.inner.write_all(&request)?;
        self.inner.flush()?;
        self.writer_handshake = true;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for HttpClientStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "http stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

fn build_http_request(default_host: &str, options: &HttpStreamOptions, payload: &[u8]) -> Vec<u8> {
    let method = if options.method.trim().is_empty() {
        "GET"
    } else {
        options.method.trim()
    };
    let path = options
        .path
        .first()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            if value.starts_with('/') {
                value.clone()
            } else {
                format!("/{value}")
            }
        })
        .unwrap_or_else(|| "/".to_owned());
    let host = options
        .headers
        .get("Host")
        .and_then(|values| values.first())
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .or_else(|| {
            options
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("host"))
                .and_then(|(_, values)| values.first().cloned())
        })
        .or_else(|| options.host.first().cloned())
        .unwrap_or_else(|| default_host.to_owned());

    let mut request = Vec::new();
    request.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
    request.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
    for (name, values) in &options.headers {
        if name.eq_ignore_ascii_case("host") || values.is_empty() {
            continue;
        }
        request.extend_from_slice(name.as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(values[0].as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(format!("Content-Length: {}\r\n", payload.len()).as_bytes());
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(payload);
    request
}

fn read_http_response(stream: &mut dyn Read) -> Result<Vec<u8>, TransportError> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(TransportError::invalid_proxy_response(
                "proxy closed before HTTP response completed",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_end = position + 4;
            return validate_http_response(&buffer, header_end);
        }
        if buffer.len() > 64 * 1024 {
            return Err(TransportError::invalid_proxy_response(
                "HTTP response headers exceeded 64KiB",
            ));
        }
    }
}

fn validate_http_response(
    buffer: &[u8],
    header_end: usize,
) -> Result<Vec<u8>, TransportError> {
    let text = String::from_utf8_lossy(&buffer[..header_end]);
    let status_line = text.lines().next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| {
            TransportError::invalid_proxy_response(format!("missing HTTP status in {status_line:?}"))
        })?;
    if !version.starts_with("HTTP/") {
        return Err(TransportError::invalid_proxy_response(format!(
            "unexpected HTTP version in {status_line:?}"
        )));
    }
    if !(200..300).contains(&status) {
        return Err(TransportError::invalid_proxy_response(format!(
            "HTTP stream setup failed with status {status}"
        )));
    }
    Ok(buffer[header_end..].to_vec())
}
