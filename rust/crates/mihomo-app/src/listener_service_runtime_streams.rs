struct PrefixedStream {
    prefix: Cursor<Vec<u8>>,
    inner: BoxedTcpStream,
}

impl Read for PrefixedStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.prefix.read(buf)?;
        if read != 0 {
            return Ok(read);
        }
        self.inner.read(buf)
    }
}

impl Write for PrefixedStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl mihomo_core::TcpStream for PrefixedStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        self.inner.try_clone_box()
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}
