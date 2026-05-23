use std::io::{self, Read, Write};
use std::net::Ipv4Addr;

use mihomo_core::{BoxedTcpStream, TcpStream};

const SESSION_STATUS_NEW: u8 = 0x01;
const SESSION_STATUS_KEEP: u8 = 0x02;
const SESSION_STATUS_END: u8 = 0x03;
const SESSION_STATUS_KEEPALIVE: u8 = 0x04;

const OPTION_NONE: u8 = 0x00;
const OPTION_DATA: u8 = 0x01;

const NETWORK_TCP: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;

pub(crate) fn wrap_stream(mut inner: BoxedTcpStream) -> io::Result<BoxedTcpStream> {
    let id = [0_u8, 0_u8];
    write_new_session_frame(&mut *inner, id)?;
    Ok(Box::new(V2rayPluginMuxStream {
        inner,
        id,
        remain: 0,
        ended: false,
    }))
}

pub(crate) fn accept_test_stream(mut inner: BoxedTcpStream) -> io::Result<BoxedTcpStream> {
    let id = read_new_session_frame(&mut *inner)?;
    Ok(Box::new(V2rayPluginMuxStream {
        inner,
        id,
        remain: 0,
        ended: false,
    }))
}

struct V2rayPluginMuxStream {
    inner: BoxedTcpStream,
    id: [u8; 2],
    remain: usize,
    ended: bool,
}

impl Read for V2rayPluginMuxStream {
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
            let mut len_buf = [0_u8; 2];
            match self.inner.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(err) => return Err(err),
            }
            let metalen = u16::from_be_bytes(len_buf) as usize;
            if metalen > 512 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid v2ray-plugin mux metadata length",
                ));
            }
            if metalen < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated v2ray-plugin mux metadata",
                ));
            }
            let mut metadata = vec![0_u8; metalen];
            self.inner.read_exact(&mut metadata)?;
            let opcode = metadata[2];
            let option = metadata[3];

            if opcode == SESSION_STATUS_KEEPALIVE {
                continue;
            }
            if opcode == SESSION_STATUS_END {
                return Ok(0);
            }
            if option != OPTION_DATA {
                continue;
            }

            let mut data_len_buf = [0_u8; 2];
            self.inner.read_exact(&mut data_len_buf)?;
            self.remain = u16::from_be_bytes(data_len_buf) as usize;
            if self.remain == 0 {
                continue;
            }

            let len = self.remain.min(buf.len());
            let read = self.inner.read(&mut buf[..len])?;
            self.remain = self.remain.saturating_sub(read);
            return Ok(read);
        }
    }
}

impl Write for V2rayPluginMuxStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let data_len = u16::try_from(buf.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "v2ray-plugin mux payload too large",
            )
        })?;
        self.inner.write_all(&4_u16.to_be_bytes())?;
        self.inner.write_all(&self.id)?;
        self.inner
            .write_all(&[SESSION_STATUS_KEEP, OPTION_DATA])?;
        self.inner.write_all(&data_len.to_be_bytes())?;
        self.inner.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for V2rayPluginMuxStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "v2ray-plugin mux stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.send_end_frame()?;
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.send_end_frame()?;
        self.inner.shutdown_all()
    }
}

impl V2rayPluginMuxStream {
    fn send_end_frame(&mut self) -> io::Result<()> {
        if self.ended {
            return Ok(());
        }
        self.inner.write_all(&4_u16.to_be_bytes())?;
        self.inner.write_all(&self.id)?;
        self.inner
            .write_all(&[SESSION_STATUS_END, OPTION_NONE])?;
        self.inner.flush()?;
        self.ended = true;
        Ok(())
    }
}

fn write_new_session_frame(stream: &mut dyn Write, id: [u8; 2]) -> io::Result<()> {
    let host = Ipv4Addr::LOCALHOST.octets();
    let metalen = 2 + 2 + 1 + 2 + 1 + host.len();
    let metalen = u16::try_from(metalen).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "v2ray-plugin mux metadata too large",
        )
    })?;
    stream.write_all(&metalen.to_be_bytes())?;
    stream.write_all(&id)?;
    stream.write_all(&[SESSION_STATUS_NEW, OPTION_NONE])?;
    stream.write_all(&[NETWORK_TCP])?;
    stream.write_all(&0_u16.to_be_bytes())?;
    stream.write_all(&[ATYP_IPV4])?;
    stream.write_all(&host)?;
    stream.flush()
}

fn read_new_session_frame(stream: &mut dyn Read) -> io::Result<[u8; 2]> {
    let mut len_buf = [0_u8; 2];
    stream.read_exact(&mut len_buf)?;
    let metalen = u16::from_be_bytes(len_buf) as usize;
    if metalen < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated v2ray-plugin mux session metadata",
        ));
    }
    let mut metadata = vec![0_u8; metalen];
    stream.read_exact(&mut metadata)?;
    if metadata[2] != SESSION_STATUS_NEW {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected v2ray-plugin mux new session frame",
        ));
    }
    let mut id = [0_u8; 2];
    id.copy_from_slice(&metadata[0..2]);
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::{accept_test_stream, wrap_stream};
    use mihomo_core::BoxedTcpStream;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn mux_stream_round_trip_preserves_payload() {
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
        });

        let stream = std::net::TcpStream::connect(addr).unwrap();
        let mut stream = wrap_stream(Box::new(stream) as BoxedTcpStream).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.flush().unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"pong");
        worker.join().unwrap();
    }
}
