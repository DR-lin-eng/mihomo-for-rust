use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use mihomo_core::{BoxedTcpStream, TcpStream};
use sha2::{Digest, Sha256};

use crate::{TransportError, TransportTarget};

const CMD_SYN: u8 = 0x01;
const CMD_PSH: u8 = 0x02;
const CMD_FIN: u8 = 0x03;
const CMD_SETTINGS: u8 = 0x04;
const CMD_ALERT: u8 = 0x05;
const CMD_SYNACK: u8 = 0x07;
const CMD_SERVER_SETTINGS: u8 = 0x0a;
const STREAM_ID: u32 = 1;
pub(crate) const UOT_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";

pub(crate) fn wrap_stream(
    mut stream: BoxedTcpStream,
    password: &str,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    write_auth_prelude(&mut *stream, password)?;
    write_frame(
        &mut *stream,
        CMD_SETTINGS,
        0,
        b"v=2\nclient=mihomo-rust\npadding-md5=",
    )?;

    write_frame(&mut *stream, CMD_SYN, STREAM_ID, &[])?;
    let mut destination = super::encode_socks5_target(target)?;
    destination.extend_from_slice(&target.port.to_be_bytes());
    write_frame(&mut *stream, CMD_PSH, STREAM_ID, &destination)?;
    stream.flush().map_err(TransportError::from)?;
    Ok(Box::new(AnyTlsStream {
        inner: stream,
        read_buf: Vec::new(),
        read_off: 0,
        finished: false,
    }))
}

pub(crate) fn open_udp_stream(
    stream: BoxedTcpStream,
    password: &str,
    destination: SocketAddr,
) -> Result<BoxedTcpStream, TransportError> {
    let mut stream = wrap_stream(stream, password, &TransportTarget::new(UOT_MAGIC_ADDRESS, 0))?;
    let request = encode_uot_request(destination);
    stream.write_all(&request).map_err(TransportError::from)?;
    stream.flush().map_err(TransportError::from)?;
    Ok(stream)
}

pub(crate) fn accept_server_stream(
    stream: BoxedTcpStream,
    password: &str,
) -> Result<(TransportTarget, BoxedTcpStream), TransportError> {
    accept_server_stream_with_password_hashes(stream, &[Sha256::digest(password.as_bytes()).into()])
        .map(|(target, _index, stream)| (target, stream))
}

pub(crate) fn accept_server_stream_with_password_hashes(
    mut stream: BoxedTcpStream,
    password_hashes: &[[u8; 32]],
) -> Result<(TransportTarget, usize, BoxedTcpStream), TransportError> {
    let mut actual_hash = [0_u8; 32];
    stream.read_exact(&mut actual_hash).map_err(TransportError::from)?;
    let matched = password_hashes
        .iter()
        .position(|hash| *hash == actual_hash)
        .ok_or_else(|| {
            TransportError::invalid_proxy_response("anytls authentication failed")
        })?;

    let mut padding_len = [0_u8; 2];
    stream
        .read_exact(&mut padding_len)
        .map_err(TransportError::from)?;
    let padding_len = u16::from_be_bytes(padding_len) as usize;
    if padding_len != 0 {
        let mut padding = vec![0_u8; padding_len];
        stream.read_exact(&mut padding).map_err(TransportError::from)?;
    }

    let (command, stream_id, payload) = read_frame(&mut *stream)?;
    if command != CMD_SETTINGS || stream_id != 0 {
        return Err(TransportError::invalid_proxy_response(
            "unexpected anytls settings frame",
        ));
    }
    if !String::from_utf8_lossy(&payload).contains("v=2") {
        return Err(TransportError::invalid_proxy_response(
            "anytls client settings missing v=2",
        ));
    }

    let (command, stream_id, payload) = read_frame(&mut *stream)?;
    if command != CMD_SYN || stream_id != STREAM_ID || !payload.is_empty() {
        return Err(TransportError::invalid_proxy_response(
            "unexpected anytls syn frame",
        ));
    }

    let (command, stream_id, payload) = read_frame(&mut *stream)?;
    if command != CMD_PSH || stream_id != STREAM_ID {
        return Err(TransportError::invalid_proxy_response(
            "unexpected anytls target frame",
        ));
    }
    let target = decode_target(&payload)?;

    write_frame(&mut *stream, CMD_SERVER_SETTINGS, 0, b"v=2")?;
    write_frame(&mut *stream, CMD_SYNACK, STREAM_ID, &[])?;
    stream.flush().map_err(TransportError::from)?;

    Ok((
        target,
        matched,
        Box::new(AnyTlsStream {
            inner: stream,
            read_buf: Vec::new(),
            read_off: 0,
            finished: false,
        }),
    ))
}

pub(crate) fn write_udp_packet(
    stream: &mut dyn Write,
    destination: SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    let packet = encode_uot_packet(destination, payload);
    stream.write_all(&packet)?;
    stream.flush()?;
    Ok(payload.len())
}

pub(crate) fn read_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(SocketAddr, Vec<u8>)> {
    let destination = read_uot_addr(stream)?;
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length)?;
    let length = u16::from_be_bytes(length) as usize;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok((destination, payload))
}

pub(crate) fn read_uot_request(stream: &mut dyn Read) -> io::Result<(bool, SocketAddr)> {
    let mut is_connect = [0_u8; 1];
    stream.read_exact(&mut is_connect)?;
    let destination = read_uot_addr(stream)?;
    Ok((is_connect[0] != 0, destination))
}

fn write_auth_prelude(stream: &mut dyn Write, password: &str) -> Result<(), TransportError> {
    let password = Sha256::digest(password.as_bytes());
    stream.write_all(password.as_slice()).map_err(TransportError::from)?;
    stream.write_all(&0_u16.to_be_bytes()).map_err(TransportError::from)?;
    Ok(())
}

fn write_frame(
    stream: &mut dyn Write,
    command: u8,
    sid: u32,
    payload: &[u8],
) -> Result<(), TransportError> {
    if payload.len() > u16::MAX as usize {
        return Err(TransportError::InvalidPlan(
            "anytls frame payload too large".to_owned(),
        ));
    }
    let mut frame = Vec::with_capacity(7 + payload.len());
    frame.push(command);
    frame.extend_from_slice(&sid.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame).map_err(TransportError::from)
}

fn read_frame(stream: &mut dyn Read) -> Result<(u8, u32, Vec<u8>), TransportError> {
    let mut header = [0_u8; 7];
    stream.read_exact(&mut header).map_err(TransportError::from)?;
    let command = header[0];
    let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let length = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).map_err(TransportError::from)?;
    Ok((command, sid, payload))
}

fn decode_target(payload: &[u8]) -> Result<TransportTarget, TransportError> {
    if payload.is_empty() {
        return Err(TransportError::invalid_proxy_response(
            "empty anytls target payload",
        ));
    }
    let atyp = payload[0];
    let mut offset = 1;
    let host = match atyp {
        0x01 => {
            if offset + 4 > payload.len() {
                return Err(TransportError::invalid_proxy_response(
                    "truncated anytls ipv4 target",
                ));
            }
            let ip = IpAddr::V4(Ipv4Addr::new(
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            ));
            offset += 4;
            ip.to_string()
        }
        0x04 => {
            if offset + 16 > payload.len() {
                return Err(TransportError::invalid_proxy_response(
                    "truncated anytls ipv6 target",
                ));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&payload[offset..offset + 16]);
            offset += 16;
            IpAddr::V6(Ipv6Addr::from(octets)).to_string()
        }
        0x03 => {
            if offset >= payload.len() {
                return Err(TransportError::invalid_proxy_response(
                    "truncated anytls domain target length",
                ));
            }
            let length = payload[offset] as usize;
            offset += 1;
            if offset + length > payload.len() {
                return Err(TransportError::invalid_proxy_response(
                    "truncated anytls domain target",
                ));
            }
            let host = String::from_utf8(payload[offset..offset + length].to_vec())
                .map_err(|err| TransportError::InvalidPlan(err.to_string()))?;
            offset += length;
            host
        }
        other => {
            return Err(TransportError::InvalidProxyResponse(format!(
                "unsupported anytls target atyp {other}"
            )))
        }
    };
    if offset + 2 > payload.len() {
        return Err(TransportError::invalid_proxy_response(
            "truncated anytls target port",
        ));
    }
    let port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    if offset + 2 != payload.len() {
        return Err(TransportError::invalid_proxy_response(
            "anytls target payload has trailing bytes",
        ));
    }
    Ok(TransportTarget::new(host, port))
}

struct AnyTlsStream {
    inner: BoxedTcpStream,
    read_buf: Vec<u8>,
    read_off: usize,
    finished: bool,
}

struct AnyTlsWriteClone {
    inner: BoxedTcpStream,
}

impl AnyTlsStream {
    fn fill_buffer(&mut self) -> io::Result<()> {
        while self.read_off == self.read_buf.len() && !self.finished {
            self.read_buf.clear();
            self.read_off = 0;

            let mut header = [0_u8; 7];
            self.inner.read_exact(&mut header)?;
            let command = header[0];
            let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
            let length = u16::from_be_bytes([header[5], header[6]]) as usize;
            let mut payload = vec![0_u8; length];
            self.inner.read_exact(&mut payload)?;

            match command {
                CMD_PSH if sid == STREAM_ID => {
                    self.read_buf = payload;
                    return Ok(());
                }
                CMD_FIN if sid == STREAM_ID => {
                    self.finished = true;
                    return Ok(());
                }
                CMD_SYNACK | CMD_SERVER_SETTINGS => continue,
                CMD_ALERT => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("anytls alert: {}", String::from_utf8_lossy(&payload)),
                    ))
                }
                _ => continue,
            }
        }
        Ok(())
    }
}

impl Read for AnyTlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.read_off == self.read_buf.len() {
            self.fill_buffer()?;
            if self.read_off == self.read_buf.len() && self.finished {
                return Ok(0);
            }
        }
        let available = &self.read_buf[self.read_off..];
        let copied = available.len().min(buf.len());
        buf[..copied].copy_from_slice(&available[..copied]);
        self.read_off += copied;
        Ok(copied)
    }
}

impl Write for AnyTlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        write_frame(&mut *self.inner, CMD_PSH, STREAM_ID, buf)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Read for AnyTlsWriteClone {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "anytls write clone is write-only",
        ))
    }
}

impl Write for AnyTlsWriteClone {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        write_frame(&mut *self.inner, CMD_PSH, STREAM_ID, buf)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for AnyTlsStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        if self.read_off != 0 || !self.read_buf.is_empty() || self.finished {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "anytls stream cannot be cloned after reads begin",
            ));
        }
        Ok(Box::new(AnyTlsWriteClone {
            inner: self.inner.try_clone_box()?,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        write_frame(&mut *self.inner, CMD_FIN, STREAM_ID, &[])
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        self.inner.flush()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown_write()?;
        self.inner.shutdown_all()
    }
}

impl TcpStream for AnyTlsWriteClone {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "anytls write clone does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        write_frame(&mut *self.inner, CMD_FIN, STREAM_ID, &[])
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        self.inner.flush()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown_write()?;
        self.inner.shutdown_all()
    }
}

fn encode_uot_request(destination: SocketAddr) -> Vec<u8> {
    let mut request = Vec::new();
    request.push(0x00);
    encode_uot_addr_into(&mut request, destination);
    request
}

fn encode_uot_packet(destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(1 + 16 + 2 + 2 + payload.len());
    encode_uot_addr_into(&mut packet, destination);
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn encode_uot_addr_into(buffer: &mut Vec<u8>, destination: SocketAddr) {
    match destination {
        SocketAddr::V4(addr) => {
            buffer.push(0x00);
            buffer.extend_from_slice(&addr.ip().octets());
            buffer.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            buffer.push(0x01);
            buffer.extend_from_slice(&addr.ip().octets());
            buffer.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
}

fn read_uot_addr(stream: &mut dyn Read) -> io::Result<SocketAddr> {
    let mut atyp = [0_u8; 1];
    stream.read_exact(&mut atyp)?;
    let host = match atyp[0] {
        0x00 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets)?;
            AnyTlsUotHost::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)))
        }
        0x01 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets)?;
            AnyTlsUotHost::Ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        0x02 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length)?;
            let mut host = vec![0_u8; length[0] as usize];
            stream.read_exact(&mut host)?;
            AnyTlsUotHost::Domain(String::from_utf8_lossy(&host).into_owned())
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported anytls uot atyp {other}"),
            ))
        }
    };
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port)?;
    let port = u16::from_be_bytes(port);
    match host {
        AnyTlsUotHost::Ip(ip) => Ok(SocketAddr::new(ip, port)),
        AnyTlsUotHost::Domain(host) => {
            let mut addrs = (host.as_str(), port).to_socket_addrs()?;
            addrs.next().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "anytls uot domain target unresolved",
                )
            })
        }
    }
}

enum AnyTlsUotHost {
    Ip(std::net::IpAddr),
    Domain(String),
}
