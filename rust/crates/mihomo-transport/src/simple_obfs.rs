#![allow(dead_code)]

use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use mihomo_core::{BoxedTcpStream, TcpStream};
use rand::RngCore;

const CHUNK_SIZE: usize = 1 << 14;

pub(crate) fn wrap_tls_stream(stream: BoxedTcpStream, server: &str) -> BoxedTcpStream {
    Box::new(TlsObfsClientStream {
        inner: stream,
        server: server.to_owned(),
        remain: 0,
        first_request: true,
        first_response: true,
    })
}

pub(crate) fn wrap_http_stream(stream: BoxedTcpStream, host: &str, port: &str) -> BoxedTcpStream {
    Box::new(HttpObfsClientStream {
        inner: stream,
        host: host.to_owned(),
        port: port.to_owned(),
        pending: Vec::new(),
        offset: 0,
        first_request: true,
        first_response: true,
    })
}

pub(crate) fn wrap_tls_server_stream(stream: BoxedTcpStream) -> BoxedTcpStream {
    Box::new(TlsObfsServerStream {
        inner: stream,
        remain: 0,
        first_request: true,
        session_ticket_done: false,
        first_response: true,
    })
}

pub(crate) fn wrap_http_server_stream(stream: BoxedTcpStream) -> BoxedTcpStream {
    Box::new(HttpObfsServerStream {
        inner: stream,
        pending: Vec::new(),
        offset: 0,
        first_request: true,
        first_response: true,
    })
}

struct TlsObfsClientStream {
    inner: BoxedTcpStream,
    server: String,
    remain: usize,
    first_request: bool,
    first_response: bool,
}

impl TlsObfsClientStream {
    fn read_frame(&mut self, buf: &mut [u8], discard_n: usize) -> io::Result<usize> {
        let mut discard = vec![0_u8; discard_n];
        if !read_exact_or_initial_eof(&mut *self.inner, &mut discard)? {
            return Ok(0);
        }
        let mut size_buf = [0_u8; 2];
        if !read_exact_or_initial_eof(&mut *self.inner, &mut size_buf)? {
            return Ok(0);
        }
        let length = u16::from_be_bytes(size_buf) as usize;
        if length > buf.len() {
            let read = self.inner.read(buf)?;
            self.remain = length.saturating_sub(read);
            return Ok(read);
        }
        self.inner.read_exact(&mut buf[..length])?;
        Ok(length)
    }

    fn write_chunk(&mut self, payload: &[u8]) -> io::Result<usize> {
        if self.first_request {
            let hello = make_tls_client_hello(payload, &self.server);
            self.inner.write_all(&hello)?;
            self.first_request = false;
            return Ok(payload.len());
        }
        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.extend_from_slice(&[0x17, 0x03, 0x03]);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        self.inner.write_all(&frame)?;
        Ok(payload.len())
    }
}

impl Read for TlsObfsClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remain > 0 {
            let length = self.remain.min(buf.len());
            let read = self.inner.read(&mut buf[..length])?;
            self.remain = self.remain.saturating_sub(read);
            return Ok(read);
        }
        if self.first_response {
            self.first_response = false;
            return self.read_frame(buf, 105);
        }
        self.read_frame(buf, 3)
    }
}

impl Write for TlsObfsClientStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            let end = (written + CHUNK_SIZE).min(buf.len());
            self.write_chunk(&buf[written..end])?;
            written = end;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for TlsObfsClientStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "simple-obfs tls stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

struct HttpObfsClientStream {
    inner: BoxedTcpStream,
    host: String,
    port: String,
    pending: Vec<u8>,
    offset: usize,
    first_request: bool,
    first_response: bool,
}

impl HttpObfsClientStream {
    fn read_pending(&mut self, buf: &mut [u8]) -> usize {
        let available = &self.pending[self.offset..];
        let copied = available.len().min(buf.len());
        buf[..copied].copy_from_slice(&available[..copied]);
        self.offset += copied;
        if self.offset == self.pending.len() {
            self.pending.clear();
            self.offset = 0;
        }
        copied
    }

    fn first_request_host(&self) -> String {
        if self.port == "80" {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl Read for HttpObfsClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.offset < self.pending.len() {
            return Ok(self.read_pending(buf));
        }
        if self.first_response {
            let mut header_buf = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                let read = self.inner.read(&mut chunk)?;
                if read == 0 {
                    return Ok(0);
                }
                header_buf.extend_from_slice(&chunk[..read]);
                if let Some(position) = header_buf.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    let header_end = position + 4;
                    self.pending = header_buf[header_end..].to_vec();
                    self.offset = 0;
                    self.first_response = false;
                    if self.pending.is_empty() {
                        return self.inner.read(buf);
                    }
                    return Ok(self.read_pending(buf));
                }
            }
        }
        self.inner.read(buf)
    }
}

impl Write for HttpObfsClientStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.first_request {
            let mut rand_bytes = [0_u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut rand_bytes);
            let request = format!(
                "GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/7.88.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nContent-Length: {length}\r\n\r\n",
                host = self.first_request_host(),
                key = base64::engine::general_purpose::STANDARD.encode(rand_bytes),
                length = buf.len(),
            );
            self.inner.write_all(request.as_bytes())?;
            self.inner.write_all(buf)?;
            self.first_request = false;
            return Ok(buf.len());
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for HttpObfsClientStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "simple-obfs http stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

struct TlsObfsServerStream {
    inner: BoxedTcpStream,
    remain: usize,
    first_request: bool,
    session_ticket_done: bool,
    first_response: bool,
}

impl TlsObfsServerStream {
    fn read_frame(&mut self, buf: &mut [u8], discard_n: usize) -> io::Result<usize> {
        let mut discard = vec![0_u8; discard_n];
        if !read_exact_or_initial_eof(&mut *self.inner, &mut discard)? {
            return Ok(0);
        }
        let mut size_buf = [0_u8; 2];
        if !read_exact_or_initial_eof(&mut *self.inner, &mut size_buf)? {
            return Ok(0);
        }
        let length = u16::from_be_bytes(size_buf) as usize;
        if length > buf.len() {
            let read = self.inner.read(buf)?;
            self.remain = length.saturating_sub(read);
            return Ok(read);
        }
        self.inner.read_exact(&mut buf[..length])?;
        Ok(length)
    }

    fn skip_other_exts(&mut self) -> io::Result<()> {
        let mut buf = vec![0_u8; 256];
        let _ = self.read_frame(&mut buf, 7)?;
        let mut rest = vec![0_u8; 4 * 16 + 2];
        self.inner.read_exact(&mut rest)?;
        Ok(())
    }

    fn write_chunk(&mut self, payload: &[u8]) -> io::Result<usize> {
        if self.first_response {
            let hello = make_tls_server_hello(payload);
            self.inner.write_all(&hello)?;
            self.first_response = false;
            return Ok(payload.len());
        }
        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.extend_from_slice(&[0x17, 0x03, 0x03]);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        self.inner.write_all(&frame)?;
        Ok(payload.len())
    }
}

impl Read for TlsObfsServerStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remain > 0 {
            let length = self.remain.min(buf.len());
            let read = self.inner.read(&mut buf[..length])?;
            self.remain = self.remain.saturating_sub(read);
            return Ok(read);
        }
        if self.first_request {
            self.first_request = false;
            return self.read_frame(buf, 9 * 16 - 4);
        }
        if !self.session_ticket_done {
            self.session_ticket_done = true;
            self.skip_other_exts()?;
        }
        self.read_frame(buf, 3)
    }
}

impl Write for TlsObfsServerStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            let end = (written + CHUNK_SIZE).min(buf.len());
            self.write_chunk(&buf[written..end])?;
            written = end;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for TlsObfsServerStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "simple-obfs tls server stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

struct HttpObfsServerStream {
    inner: BoxedTcpStream,
    pending: Vec<u8>,
    offset: usize,
    first_request: bool,
    first_response: bool,
}

impl HttpObfsServerStream {
    fn read_pending(&mut self, buf: &mut [u8]) -> usize {
        let available = &self.pending[self.offset..];
        let copied = available.len().min(buf.len());
        buf[..copied].copy_from_slice(&available[..copied]);
        self.offset += copied;
        if self.offset == self.pending.len() {
            self.pending.clear();
            self.offset = 0;
        }
        copied
    }
}

impl Read for HttpObfsServerStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.offset < self.pending.len() {
            return Ok(self.read_pending(buf));
        }
        if self.first_request {
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            let header_end = loop {
                let read = self.inner.read(&mut chunk)?;
                if read == 0 {
                    return Ok(0);
                }
                request.extend_from_slice(&chunk[..read]);
                if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break position + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            if !headers.starts_with("GET ") || !headers.contains("\r\nConnection: Upgrade\r\n") {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid simple-obfs http request"));
            }
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.eq_ignore_ascii_case("Content-Length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            let raw = request[header_end..].to_vec();
            let already_have = raw.len().min(content_length);
            let mut body = raw[..already_have].to_vec();
            let extra = raw[already_have..].to_vec();
            if body.len() < content_length {
                let mut remaining = vec![0_u8; content_length - body.len()];
                self.inner.read_exact(&mut remaining)?;
                body.extend_from_slice(&remaining);
            }
            self.pending = body;
            self.pending.extend_from_slice(&extra);
            self.offset = 0;
            self.first_request = false;
            return Ok(self.read_pending(buf));
        }
        self.inner.read(buf)
    }
}

impl Write for HttpObfsServerStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.first_response {
            let mut rand_bytes = [0_u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut rand_bytes);
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nServer: nginx/1.23.4\r\nDate: Thu, 01 Jan 1970 00:00:00 GMT\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                base64::engine::general_purpose::STANDARD.encode(rand_bytes)
            );
            self.inner.write_all(response.as_bytes())?;
            self.first_response = false;
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for HttpObfsServerStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "simple-obfs http server stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

fn make_tls_client_hello(data: &[u8], server: &str) -> Vec<u8> {
    let mut random = [0_u8; 28];
    let mut session_id = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    rand::rngs::OsRng.fill_bytes(&mut session_id);

    let mut buf = Vec::new();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    let length = 212 + data.len() + server.len();
    buf.push(22);
    buf.extend_from_slice(&[0x03, 0x01]);
    buf.extend_from_slice(&(length as u16).to_be_bytes());
    buf.extend_from_slice(&[1, 0]);
    buf.extend_from_slice(&((208 + data.len() + server.len()) as u16).to_be_bytes());
    buf.extend_from_slice(&[0x03, 0x03]);
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf.extend_from_slice(&random);
    buf.push(32);
    buf.extend_from_slice(&session_id);
    buf.extend_from_slice(&[
        0x00, 0x38, 0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa,
        0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23,
        0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13,
        0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f,
        0x00, 0xff, 0x01, 0x00,
    ]);
    buf.extend_from_slice(&((79 + data.len() + server.len()) as u16).to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x23]);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&((server.len() + 5) as u16).to_be_bytes());
    buf.extend_from_slice(&((server.len() + 3) as u16).to_be_bytes());
    buf.push(0);
    buf.extend_from_slice(&(server.len() as u16).to_be_bytes());
    buf.extend_from_slice(server.as_bytes());
    buf.extend_from_slice(&[
        0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08,
        0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e,
        0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01,
        0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02,
        0x02, 0x03, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
    ]);
    buf
}

fn read_exact_or_initial_eof(stream: &mut dyn Read, mut buf: &mut [u8]) -> io::Result<bool> {
    let mut read_any = false;
    while !buf.is_empty() {
        match stream.read(buf) {
            Ok(0) if !read_any => return Ok(false),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                ))
            }
            Ok(read) => {
                read_any = true;
                let (_, rest) = buf.split_at_mut(read);
                buf = rest;
            }
            Err(err) => return Err(err),
        }
    }
    Ok(true)
}

fn make_tls_server_hello(data: &[u8]) -> Vec<u8> {
    let mut rand_bytes = [0_u8; 28];
    let mut session_id = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut rand_bytes);
    rand::rngs::OsRng.fill_bytes(&mut session_id);

    let mut buf = Vec::new();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    buf.push(0x16);
    buf.extend_from_slice(&0x0301_u16.to_be_bytes());
    buf.extend_from_slice(&91_u16.to_be_bytes());
    buf.extend_from_slice(&[2, 0, 0, 87, 0x03, 0x03]);
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf.extend_from_slice(&rand_bytes);
    buf.push(32);
    buf.extend_from_slice(&session_id);
    buf.extend_from_slice(&[
        0xcc, 0xa8, 0x00, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00,
        0x0b, 0x00, 0x02, 0x01, 0x00, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03,
    ]);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    buf
}
