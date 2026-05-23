use std::io::{self, Read, Write};

use mihomo_core::{BoxedTcpStream, TcpStream};
use rand::Rng;

#[derive(Clone)]
pub(crate) struct SsrHttpObfsOptions {
    pub host: String,
    pub port: u16,
    pub param: String,
    pub iv_size: usize,
    pub post: bool,
}

pub(crate) fn wrap_stream(
    inner: BoxedTcpStream,
    options: SsrHttpObfsOptions,
) -> BoxedTcpStream {
    Box::new(SsrHttpObfsClientStream {
        inner,
        options,
        has_sent_header: false,
        has_recv_header: false,
        header_buf: Vec::new(),
        pending: Vec::new(),
        pending_off: 0,
    })
}

struct SsrHttpObfsClientStream {
    inner: BoxedTcpStream,
    options: SsrHttpObfsOptions,
    has_sent_header: bool,
    has_recv_header: bool,
    header_buf: Vec<u8>,
    pending: Vec<u8>,
    pending_off: usize,
}

impl Read for SsrHttpObfsClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pending_off < self.pending.len() {
            let available = &self.pending[self.pending_off..];
            let copied = available.len().min(buf.len());
            buf[..copied].copy_from_slice(&available[..copied]);
            self.pending_off += copied;
            if self.pending_off == self.pending.len() {
                self.pending.clear();
                self.pending_off = 0;
            }
            return Ok(copied);
        }
        if self.has_recv_header {
            return self.inner.read(buf);
        }

        loop {
            if let Some(pos) = self
                .header_buf
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
            {
                self.has_recv_header = true;
                let payload = self.header_buf.split_off(pos + 4);
                self.header_buf.clear();
                if payload.is_empty() {
                    return self.inner.read(buf);
                }
                let copied = payload.len().min(buf.len());
                buf[..copied].copy_from_slice(&payload[..copied]);
                if copied < payload.len() {
                    self.pending = payload;
                    self.pending_off = copied;
                }
                return Ok(copied);
            }

            let mut scratch = vec![0_u8; buf.len().max(16 * 1024)];
            let read = self.inner.read(&mut scratch)?;
            if read == 0 {
                if self.header_buf.is_empty() {
                    return Ok(0);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "ssr http obfs response header is truncated",
                ));
            }
            self.header_buf.extend_from_slice(&scratch[..read]);
        }
    }
}

impl Write for SsrHttpObfsClientStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.has_sent_header {
            return self.inner.write(buf);
        }
        let head_len = self.options.iv_size + 30;
        let mut head_data_len = buf.len();
        if buf.len().saturating_sub(head_len) > 64 {
            head_data_len = head_len + rand::thread_rng().gen_range(0..=64);
        }
        let (head_data, tail) = buf.split_at(head_data_len.min(buf.len()));
        let (host, body) = parse_param(&self.options.host, &self.options.param);
        let selected_host = pick_host(&host);

        let mut request = Vec::new();
        if self.options.post {
            request.extend_from_slice(b"POST /");
        } else {
            request.extend_from_slice(b"GET /");
        }
        append_url_encoded(&mut request, head_data);
        request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        request.extend_from_slice(selected_host.as_bytes());
        if self.options.port != 80 {
            request.extend_from_slice(format!(":{}", self.options.port).as_bytes());
        }
        request.extend_from_slice(b"\r\n");
        if let Some(body) = body {
            request.extend_from_slice(body.as_bytes());
            request.extend_from_slice(b"\r\n\r\n");
        } else {
            request.extend_from_slice(
                b"User-Agent: Mozilla/5.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\n",
            );
            if self.options.post {
                request.extend_from_slice(b"Content-Type: multipart/form-data; boundary=----ssrhttpobfsboundary\r\n");
            }
            request.extend_from_slice(b"DNT: 1\r\nConnection: keep-alive\r\n\r\n");
        }
        request.extend_from_slice(tail);
        self.inner.write_all(&request)?;
        self.has_sent_header = true;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for SsrHttpObfsClientStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            inner: self.inner.try_clone_box()?,
            options: self.options.clone(),
            has_sent_header: self.has_sent_header,
            has_recv_header: self.has_recv_header,
            header_buf: self.header_buf.clone(),
            pending: self.pending[self.pending_off..].to_vec(),
            pending_off: 0,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

fn parse_param(default_host: &str, param: &str) -> (String, Option<String>) {
    if param.trim().is_empty() {
        return (default_host.to_owned(), None);
    }
    if let Some((host, body)) = param.split_once('#') {
        let body = body
            .replace("\\n", "\r\n")
            .replace('\n', "\r\n");
        return (host.to_owned(), Some(body));
    }
    (param.to_owned(), None)
}

fn pick_host(hosts: &str) -> String {
    let parts = hosts
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return String::new();
    }
    parts[rand::thread_rng().gen_range(0..parts.len())].to_owned()
}

fn append_url_encoded(buf: &mut Vec<u8>, data: &[u8]) {
    for byte in data {
        buf.extend_from_slice(format!("%{byte:02x}").as_bytes());
    }
}
