use std::io::{self, Read, Write};

use mihomo_core::{BoxedTcpStream, TcpStream};

pub(crate) struct PrefixedTcpStream {
    pub(crate) prefix: io::Cursor<Vec<u8>>,
    pub(crate) inner: BoxedTcpStream,
}

impl PrefixedTcpStream {
    pub(crate) fn inner(&self) -> &dyn TcpStream {
        self.inner.as_ref()
    }
}

impl Read for PrefixedTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.prefix.read(buf)?;
        if read != 0 {
            return Ok(read);
        }
        self.inner.read(buf)
    }
}

impl Write for PrefixedTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for PrefixedTcpStream {
    fn tcp_stats(&self)->Option<mihomo_core::TcpStats>{self.inner.tcp_stats()}
    fn set_timeouts(&self,read:Option<std::time::Duration>,write:Option<std::time::Duration>)->io::Result<()>{self.inner.set_timeouts(read,write)}

    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        let remaining = self.prefix.get_ref()[self.prefix.position() as usize..].to_vec();
        Ok(Box::new(Self {
            prefix: io::Cursor::new(remaining),
            inner: self.inner.try_clone_box()?,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

struct HttpResponsePrefixedTcpStream {
    header_sent: bool,
    inner: BoxedTcpStream,
}

impl Read for HttpResponsePrefixedTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for HttpResponsePrefixedTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.header_sent {
            self.inner.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nConnection: keep-alive\r\n\r\n",
            )?;
            self.header_sent = true;
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for HttpResponsePrefixedTcpStream {
    fn tcp_stats(&self)->Option<mihomo_core::TcpStats>{self.inner.tcp_stats()}
    fn set_timeouts(&self,read:Option<std::time::Duration>,write:Option<std::time::Duration>)->io::Result<()>{self.inner.set_timeouts(read,write)}

    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            header_sent: self.header_sent,
            inner: self.inner.try_clone_box()?,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

pub(crate) fn accept_ssr_http_obfs_test_stream(
    mut stream: BoxedTcpStream,
) -> io::Result<(String, BoxedTcpStream)> {
    let (request, tail) = read_http_headers_with_tail(&mut *stream)?;
    let encoded_path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let path = encoded_path.strip_prefix('/').unwrap_or(encoded_path);
    let mut prefix = decode_percent_path(path)?;
    prefix.extend_from_slice(&tail);
    Ok((
        request,
        Box::new(PrefixedTcpStream {
            prefix: io::Cursor::new(prefix),
            inner: Box::new(HttpResponsePrefixedTcpStream {
                header_sent: false,
                inner: stream,
            }),
        }),
    ))
}

fn read_http_headers_with_tail(stream: &mut dyn Read) -> io::Result<(String, Vec<u8>)> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "http headers ended before terminator",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let request = String::from_utf8(buffer[..position + 4].to_vec())
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            let tail = buffer[position + 4..].to_vec();
            return Ok((request, tail));
        }
    }
}

fn decode_percent_path(path: &str) -> io::Result<Vec<u8>> {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated percent-encoded path",
                ));
            }
            let value = u8::from_str_radix(&path[index + 1..index + 3], 16)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            out.push(value);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    Ok(out)
}
