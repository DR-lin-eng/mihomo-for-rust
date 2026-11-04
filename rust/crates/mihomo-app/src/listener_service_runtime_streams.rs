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
    #[cfg(target_os = "linux")]
    fn splice_socket_fd(&self) -> Option<std::os::fd::RawFd> { self.inner.splice_socket_fd() }
    #[cfg(target_os = "linux")]
    fn splice_read_fd(&self) -> Option<std::os::fd::RawFd> {
        (self.prefix.position() as usize >= self.prefix.get_ref().len())
            .then(|| self.inner.splice_read_fd()).flatten()
    }
    #[cfg(target_os = "linux")]
    fn splice_write_fd(&self) -> Option<std::os::fd::RawFd> { self.inner.splice_write_fd() }
    fn read_timeout(&self) -> io::Result<Option<std::time::Duration>> { self.inner.read_timeout() }
    fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> { self.inner.set_read_timeout(timeout) }
    fn set_timeouts(&self, read: Option<std::time::Duration>, write: Option<std::time::Duration>) -> io::Result<()> { self.inner.set_timeouts(read, write) }
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
