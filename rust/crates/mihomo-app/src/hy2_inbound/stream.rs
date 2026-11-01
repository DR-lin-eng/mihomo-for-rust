use std::io::{self, Read, Write};
use std::sync::mpsc;
use std::time::Duration;

use mihomo_core::{BoxedTcpStream, TcpStream};
use tokio::io::AsyncWriteExt;

pub(super) struct Hy2QuicStream {
    read_rx: mpsc::Receiver<io::Result<Vec<u8>>>,
    write_tx: tokio::sync::mpsc::UnboundedSender<Hy2WriteCommand>,
    pending: Vec<u8>,
    offset: usize,
    write_closed: bool,
}

struct Hy2QuicWriteClone {
    write_tx: tokio::sync::mpsc::UnboundedSender<Hy2WriteCommand>,
    write_closed: bool,
}

enum Hy2WriteCommand {
    Data(Vec<u8>),
    Close,
}

impl Hy2QuicStream {
    pub(super) fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        let (read_tx, read_rx) = mpsc::channel();
        let (write_tx, mut write_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut recv = recv;
            let mut send = send;
            let mut read_buf = vec![0_u8; 64 * 1024];
            let mut write_closed = false;
            let mut read_closed = false;
            loop {
                tokio::select! {
                    result = recv.read(&mut read_buf), if !read_closed => {
                        match result {
                            Ok(Some(read)) => {
                                let _ = read_tx.send(Ok(read_buf[..read].to_vec()));
                            }
                            Ok(None) => {
                                let _ = read_tx.send(Ok(Vec::new()));
                                read_closed = true;
                                if write_closed {
                                    break;
                                }
                            }
                            Err(err) => {
                                let _ = read_tx.send(Err(io::Error::other(err)));
                                break;
                            }
                        }
                    }
                    maybe = write_rx.recv(), if !write_closed => {
                        match maybe {
                            Some(Hy2WriteCommand::Data(data)) => {
                                if send.write_all(&data).await.is_err() {
                                    break;
                                }
                                if send.flush().await.is_err() {
                                    break;
                                }
                            }
                            Some(Hy2WriteCommand::Close) | None => {
                                write_closed = true;
                                let _ = send.finish();
                                if read_closed {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });
        Self {
            read_rx,
            write_tx,
            pending: Vec::new(),
            offset: 0,
            write_closed: false,
        }
    }
}

impl Read for Hy2QuicStream {
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
        match self.read_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(bytes)) if bytes.is_empty() => Ok(0),
            Ok(Ok(bytes)) => {
                let copied = bytes.len().min(buf.len());
                buf[..copied].copy_from_slice(&bytes[..copied]);
                if copied < bytes.len() {
                    self.pending = bytes;
                    self.offset = copied;
                }
                Ok(copied)
            }
            Ok(Err(err)) => Err(err),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(0),
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(0),
        }
    }
}

impl Write for Hy2QuicStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(Hy2WriteCommand::Data(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "hy2 stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for Hy2QuicStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Hy2QuicWriteClone {
            write_tx: self.write_tx.clone(),
            write_closed: false,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        if !self.write_closed {
            self.write_closed = true;
            let _ = self.write_tx.send(Hy2WriteCommand::Close);
        }
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown_write()
    }
}

impl Read for Hy2QuicWriteClone {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "hy2 write clone does not support reads",
        ))
    }
}

impl Write for Hy2QuicWriteClone {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(Hy2WriteCommand::Data(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "hy2 stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for Hy2QuicWriteClone {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            write_tx: self.write_tx.clone(),
            write_closed: false,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        if !self.write_closed {
            self.write_closed = true;
            let _ = self.write_tx.send(Hy2WriteCommand::Close);
        }
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown_write()
    }
}
