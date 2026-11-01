struct ServerWebsocketStream {
    inner: BoxedTcpStream,
    pending: Vec<u8>,
    offset: usize,
}

#[derive(Clone)]
struct ServerTlsStream(Arc<Mutex<StreamOwned<ServerConnection, TcpStream>>>);

pub(crate) struct PrefixedTcpStream {
    pub(crate) prefix: io::Cursor<Vec<u8>>,
    pub(crate) inner: BoxedTcpStream,
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

impl Read for ServerTlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("server tls stream mutex poisoned"))?
            .read(buf)
    }
}

impl Write for ServerTlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("server tls stream mutex poisoned"))?
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("server tls stream mutex poisoned"))?
            .flush()
    }
}

impl mihomo_core::TcpStream for ServerTlsStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(self.clone()))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        let mut stream = self
            .0
            .lock()
            .map_err(|_| io::Error::other("server tls stream mutex poisoned"))?;
        stream.conn.send_close_notify();
        stream.flush()?;
        stream.sock.shutdown(std::net::Shutdown::Write)
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        let mut stream = self
            .0
            .lock()
            .map_err(|_| io::Error::other("server tls stream mutex poisoned"))?;
        stream.conn.send_close_notify();
        stream.flush()?;
        stream.sock.shutdown(std::net::Shutdown::Both)
    }
}

impl mihomo_core::TcpStream for ServerWebsocketStream {
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

impl mihomo_core::TcpStream for PrefixedTcpStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "prefixed websocket stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}
