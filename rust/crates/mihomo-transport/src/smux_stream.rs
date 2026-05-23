use std::io::{self, Read, Write};

use mihomo_core::{BoxedTcpStream, TcpStream};

const SMUX_VERSION: u8 = 1;
const CMD_SYN: u8 = 0;
const CMD_FIN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_NOP: u8 = 3;
const CMD_UPD: u8 = 4;

pub(crate) fn wrap_stream(mut inner: BoxedTcpStream) -> io::Result<BoxedTcpStream> {
    let stream_id = 1_u32;
    write_frame_header(&mut *inner, SMUX_VERSION, CMD_SYN, stream_id, 0)?;
    inner.flush()?;
    Ok(Box::new(SmuxStream {
        inner,
        version: SMUX_VERSION,
        stream_id,
        remain: 0,
        ended: false,
    }))
}

pub(crate) fn accept_test_stream(mut inner: BoxedTcpStream) -> io::Result<BoxedTcpStream> {
    let (version, cmd, stream_id, length) = read_frame_header(&mut *inner)?;
    if cmd != CMD_SYN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected smux SYN frame",
        ));
    }
    if length != 0 {
        drain_exact(&mut *inner, length as usize)?;
    }
    Ok(Box::new(SmuxStream {
        inner,
        version,
        stream_id,
        remain: 0,
        ended: false,
    }))
}

struct SmuxStream {
    inner: BoxedTcpStream,
    version: u8,
    stream_id: u32,
    remain: usize,
    ended: bool,
}

impl Read for SmuxStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.remain != 0 {
            let len = self.remain.min(buf.len());
            let read = self.inner.read(&mut buf[..len])?;
            self.remain = self.remain.saturating_sub(read);
            return Ok(read);
        }
        loop {
            let (version, cmd, _stream_id, length) = match read_frame_header(&mut *self.inner) {
                Ok(header) => header,
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(err) => return Err(err),
            };
            if version == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid smux version",
                ));
            }
            match cmd {
                CMD_NOP => {
                    if length != 0 {
                        drain_exact(&mut *self.inner, length as usize)?;
                    }
                    continue;
                }
                CMD_FIN => {
                    if length != 0 {
                        drain_exact(&mut *self.inner, length as usize)?;
                    }
                    return Ok(0);
                }
                CMD_UPD => {
                    drain_exact(&mut *self.inner, length as usize)?;
                    continue;
                }
                CMD_PSH => {
                    self.remain = length as usize;
                    if self.remain == 0 {
                        continue;
                    }
                    let len = self.remain.min(buf.len());
                    let read = self.inner.read(&mut buf[..len])?;
                    self.remain = self.remain.saturating_sub(read);
                    return Ok(read);
                }
                CMD_SYN => {
                    if length != 0 {
                        drain_exact(&mut *self.inner, length as usize)?;
                    }
                    continue;
                }
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected smux command {other}"),
                    ))
                }
            }
        }
    }
}

impl Write for SmuxStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut written = 0;
        while written < buf.len() {
            let chunk_len = (buf.len() - written).min(u16::MAX as usize);
            write_frame_header(
                &mut *self.inner,
                self.version,
                CMD_PSH,
                self.stream_id,
                chunk_len as u16,
            )?;
            self.inner.write_all(&buf[written..written + chunk_len])?;
            written += chunk_len;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for SmuxStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            inner: self.inner.try_clone_box()?,
            version: self.version,
            stream_id: self.stream_id,
            remain: 0,
            ended: self.ended,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.send_fin()?;
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.send_fin()?;
        self.inner.shutdown_all()
    }
}

impl SmuxStream {
    fn send_fin(&mut self) -> io::Result<()> {
        if self.ended {
            return Ok(());
        }
        write_frame_header(&mut *self.inner, self.version, CMD_FIN, self.stream_id, 0)?;
        self.inner.flush()?;
        self.ended = true;
        Ok(())
    }
}

fn write_frame_header(
    stream: &mut dyn Write,
    version: u8,
    cmd: u8,
    stream_id: u32,
    length: u16,
) -> io::Result<()> {
    let mut header = [0_u8; 8];
    header[0] = version;
    header[1] = cmd;
    header[2..4].copy_from_slice(&length.to_le_bytes());
    header[4..8].copy_from_slice(&stream_id.to_le_bytes());
    stream.write_all(&header)
}

fn read_frame_header(stream: &mut dyn Read) -> io::Result<(u8, u8, u32, u16)> {
    let mut header = [0_u8; 8];
    stream.read_exact(&mut header)?;
    Ok((
        header[0],
        header[1],
        u32::from_le_bytes(header[4..8].try_into().unwrap()),
        u16::from_le_bytes(header[2..4].try_into().unwrap()),
    ))
}

fn drain_exact(stream: &mut dyn Read, len: usize) -> io::Result<()> {
    let mut remaining = len;
    let mut buf = [0_u8; 256];
    while remaining != 0 {
        let len = remaining.min(buf.len());
        let read = stream.read(&mut buf[..len])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "smux frame truncated",
            ));
        }
        remaining -= read;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{accept_test_stream, wrap_stream};
    use mihomo_core::BoxedTcpStream;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn smux_stream_round_trip_preserves_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = accept_test_stream(Box::new(stream)).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").unwrap();
            stream.flush().unwrap();
            stream.shutdown_write().unwrap();
        });

        let stream = std::net::TcpStream::connect(addr).unwrap();
        let mut stream = wrap_stream(Box::new(stream) as BoxedTcpStream).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).unwrap();
        assert_eq!(payload, b"pong");
        worker.join().unwrap();
    }
}
