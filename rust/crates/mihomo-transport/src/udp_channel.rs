use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use mihomo_core::{BoxedTcpStream, TcpStream};
use tokio::sync::mpsc as tokio_mpsc;

pub(crate) enum UdpStreamCommand {
    Datagram { target: SocketAddr, payload: Vec<u8> },
    Close,
}

pub(crate) fn parse_udp_channel_frame(buf: &[u8]) -> io::Result<(SocketAddr, Vec<u8>)> {
    let mut cursor = std::io::Cursor::new(buf);
    let target = decode_socket_addr(&mut cursor)?;
    let mut length = [0_u8; 2];
    std::io::Read::read_exact(&mut cursor, &mut length)?;
    let length = u16::from_be_bytes(length) as usize;
    let mut payload = vec![0_u8; length];
    std::io::Read::read_exact(&mut cursor, &mut payload)?;
    Ok((target, payload))
}

pub(crate) fn encode_udp_channel_frame(source: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + 16 + 2 + 2 + payload.len());
    encode_socket_addr(source, &mut frame).expect("socket addr encoding should not fail");
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub(crate) fn encode_socket_addr(target: SocketAddr, out: &mut Vec<u8>) -> io::Result<()> {
    match target {
        SocketAddr::V4(addr) => {
            out.push(0x01);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            out.push(0x02);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    Ok(())
}

pub(crate) fn decode_socket_addr(reader: &mut dyn Read) -> io::Result<SocketAddr> {
    let mut atyp = [0_u8; 1];
    reader.read_exact(&mut atyp)?;
    match atyp[0] {
        0x01 => {
            let mut octets = [0_u8; 4];
            reader.read_exact(&mut octets)?;
            let mut port = [0_u8; 2];
            reader.read_exact(&mut port)?;
            Ok(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
                u16::from_be_bytes(port),
            ))
        }
        0x02 => {
            let mut octets = [0_u8; 16];
            reader.read_exact(&mut octets)?;
            let mut port = [0_u8; 2];
            reader.read_exact(&mut port)?;
            Ok(SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                u16::from_be_bytes(port),
            ))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected udp atyp {other}"),
        )),
    }
}

pub(crate) struct UdpChannelStream {
    read_rx: Receiver<io::Result<Vec<u8>>>,
    write_tx: tokio_mpsc::UnboundedSender<UdpStreamCommand>,
    pending: Vec<u8>,
    offset: usize,
    write_closed: bool,
    label: &'static str,
}

pub(crate) struct UdpChannelWriteClone {
    write_tx: tokio_mpsc::UnboundedSender<UdpStreamCommand>,
    write_closed: bool,
    label: &'static str,
}

impl UdpChannelStream {
    pub(crate) fn new(
        read_rx: Receiver<io::Result<Vec<u8>>>,
        write_tx: tokio_mpsc::UnboundedSender<UdpStreamCommand>,
        label: &'static str,
    ) -> Self {
        Self {
            read_rx,
            write_tx,
            pending: Vec::new(),
            offset: 0,
            write_closed: false,
            label,
        }
    }
}

impl Read for UdpChannelStream {
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
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("{} read timed out", self.label),
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(0),
        }
    }
}

impl Write for UdpChannelStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (target, payload) = parse_udp_channel_frame(buf)?;
        self.write_tx
            .send(UdpStreamCommand::Datagram { target, payload })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, format!("{} closed", self.label)))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for UdpChannelStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(UdpChannelWriteClone {
            write_tx: self.write_tx.clone(),
            write_closed: false,
            label: self.label,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        if !self.write_closed {
            self.write_closed = true;
            let _ = self.write_tx.send(UdpStreamCommand::Close);
        }
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown_write()
    }
}

impl Read for UdpChannelWriteClone {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{} write clone does not support reads", self.label),
        ))
    }
}

impl Write for UdpChannelWriteClone {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (target, payload) = parse_udp_channel_frame(buf)?;
        self.write_tx
            .send(UdpStreamCommand::Datagram { target, payload })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, format!("{} closed", self.label)))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for UdpChannelWriteClone {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            write_tx: self.write_tx.clone(),
            write_closed: false,
            label: self.label,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        if !self.write_closed {
            self.write_closed = true;
            let _ = self.write_tx.send(UdpStreamCommand::Close);
        }
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown_write()
    }
}
