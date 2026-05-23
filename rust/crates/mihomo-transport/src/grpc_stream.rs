use std::io::{self, Read, Write};

use mihomo_core::{BoxedTcpStream, TcpStream};

use crate::{h2_stream, TlsOptions, TransportError, TransportTarget};

const DEFAULT_SERVICE_NAME: &str = "GunService";
const DEFAULT_USER_AGENT: &str = "grpc-go/1.36.0";
const CONTENT_TYPE_GRPC: &str = "application/grpc";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GrpcOptions {
    pub service_name: String,
    pub user_agent: String,
    pub ping_interval: i32,
    pub max_connections: i32,
    pub min_streams: i32,
    pub max_streams: i32,
}

pub(crate) fn wrap_stream(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    options: &GrpcOptions,
) -> Result<BoxedTcpStream, TransportError> {
    let stream = h2_stream::wrap_stream_with_request(stream, request_options(proxy, options))?;
    Ok(Box::new(GrpcStream::new(stream)))
}

pub(crate) fn wrap_tls_stream(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    tls: &TlsOptions,
    options: &GrpcOptions,
) -> Result<BoxedTcpStream, TransportError> {
    let alpn = vec!["h2".to_owned()];
    let stream = h2_stream::wrap_tls_stream_with_request(
        stream,
        proxy,
        tls,
        &alpn,
        request_options(proxy, options),
    )?;
    Ok(Box::new(GrpcStream::new(stream)))
}

#[doc(hidden)]
pub fn accept_test_stream(stream: BoxedTcpStream) -> BoxedTcpStream {
    Box::new(GrpcStream::new(stream))
}

fn service_name_to_path(service_name: &str) -> String {
    let trimmed = service_name.trim();
    if trimmed.is_empty() {
        return format!("/{DEFAULT_SERVICE_NAME}/Tun");
    }
    if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}/Tun")
    }
}

fn request_options(proxy: &TransportTarget, options: &GrpcOptions) -> h2_stream::H2RequestOptions {
    let authority = proxy.authority();
    let path = service_name_to_path(&options.service_name);
    let user_agent = if options.user_agent.trim().is_empty() {
        DEFAULT_USER_AGENT.to_owned()
    } else {
        options.user_agent.clone()
    };
    h2_stream::H2RequestOptions {
        authority,
        path,
        method: "POST".to_owned(),
        headers: vec![
            ("content-type".to_owned(), CONTENT_TYPE_GRPC.to_owned()),
            ("user-agent".to_owned(), user_agent),
        ],
    }
}

fn uvarint_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

fn encode_uvarint(mut value: usize, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push(((value as u8) & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn decode_uvarint(stream: &mut dyn Read) -> io::Result<usize> {
    let mut value = 0usize;
    let mut shift = 0usize;
    loop {
        if shift >= usize::BITS as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "grpc uvarint is too large",
            ));
        }
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte)?;
        value |= ((byte[0] & 0x7f) as usize) << shift;
        if byte[0] & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

struct GrpcStream {
    inner: BoxedTcpStream,
    remaining: usize,
}

impl GrpcStream {
    fn new(inner: BoxedTcpStream) -> Self {
        Self { inner, remaining: 0 }
    }
}

impl Read for GrpcStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining > 0 {
            let to_read = self.remaining.min(buf.len());
            let read = self.inner.read(&mut buf[..to_read])?;
            self.remaining = self.remaining.saturating_sub(read);
            return Ok(read);
        }

        let mut prefix = [0_u8; 6];
        let read = self.inner.read(&mut prefix[..1])?;
        if read == 0 {
            return Ok(0);
        }
        self.inner.read_exact(&mut prefix[1..])?;
        if prefix[0] != 0x00 || prefix[5] != 0x0a {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid grpc frame header",
            ));
        }
        let payload_len = decode_uvarint(&mut *self.inner)?;
        self.remaining = payload_len;
        self.read(buf)
    }
}

impl Write for GrpcStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let var_len = uvarint_len(buf.len());
        let total_len = 1usize
            .checked_add(var_len)
            .and_then(|len| len.checked_add(buf.len()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "grpc frame too large"))?;
        let total_len = u32::try_from(total_len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "grpc frame too large"))?;
        let mut frame = Vec::with_capacity(6 + var_len + buf.len());
        frame.push(0x00);
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.push(0x0a);
        encode_uvarint(buf.len(), &mut frame);
        frame.extend_from_slice(buf);
        self.inner.write_all(&frame)?;
        self.inner.flush()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for GrpcStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "grpc stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}
