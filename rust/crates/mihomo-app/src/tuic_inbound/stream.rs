use std::io::{self, Read, Write};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use mihomo_core::{BoxedTcpStream, TcpStream};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc as tokio_mpsc;

pub(super) struct TuicQuicStream {
    read_rx: Receiver<io::Result<Vec<u8>>>,
    write_tx: tokio_mpsc::UnboundedSender<TuicWriteCommand>,
    pending: Vec<u8>,
    offset: usize,
    write_closed: bool,
}

struct TuicQuicWriteClone {
    write_tx: tokio_mpsc::UnboundedSender<TuicWriteCommand>,
    write_closed: bool,
}

enum TuicWriteCommand {
    Data(Vec<u8>),
    Close,
}

impl TuicQuicStream {
    pub(super) fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        let (read_tx, read_rx) = mpsc::channel();
        let (write_tx, mut write_rx) = tokio_mpsc::unbounded_channel();
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
                                #[cfg(test)]
                                eprintln!("tuic listener stream read {read} bytes");
                                let _ = read_tx.send(Ok(read_buf[..read].to_vec()));
                            }
                            Ok(None) => {
                                #[cfg(test)]
                                eprintln!("tuic listener stream read EOF");
                                let _ = read_tx.send(Ok(Vec::new()));
                                read_closed = true;
                                if write_closed {
                                    break;
                                }
                            }
                            Err(err) => {
                                #[cfg(test)]
                                eprintln!("tuic listener stream read error: {err}");
                                let _ = read_tx.send(Err(io::Error::other(err)));
                                break;
                            }
                        }
                    }
                    maybe = write_rx.recv(), if !write_closed => {
                        match maybe {
                            Some(TuicWriteCommand::Data(data)) => {
                                #[cfg(test)]
                                eprintln!("tuic listener stream write {} bytes", data.len());
                                if send.write_all(&data).await.is_err() {
                                    break;
                                }
                                if send.flush().await.is_err() {
                                    break;
                                }
                            }
                            Some(TuicWriteCommand::Close) | None => {
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

impl Read for TuicQuicStream {
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

impl Write for TuicQuicStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(TuicWriteCommand::Data(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tuic stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for TuicQuicStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(TuicQuicWriteClone {
            write_tx: self.write_tx.clone(),
            write_closed: false,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        if !self.write_closed {
            self.write_closed = true;
            let _ = self.write_tx.send(TuicWriteCommand::Close);
        }
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown_write()
    }
}

impl Read for TuicQuicWriteClone {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tuic write clone does not support reads",
        ))
    }
}

impl Write for TuicQuicWriteClone {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(TuicWriteCommand::Data(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tuic stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for TuicQuicWriteClone {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            write_tx: self.write_tx.clone(),
            write_closed: false,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        if !self.write_closed {
            self.write_closed = true;
            let _ = self.write_tx.send(TuicWriteCommand::Close);
        }
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown_write()
    }
}
