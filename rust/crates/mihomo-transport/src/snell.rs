use std::io::{self, Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};

use aes::Aes128;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AesGcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::ChaCha20Poly1305;
use mihomo_core::{BoxedTcpStream, TcpStream};
use rand::RngCore;

use crate::{TransportError, TransportTarget};

const SNELL_MAX_PAYLOAD_SIZE: usize = 0x3FFF;
const SNELL_TAG_SIZE: usize = 16;
const SNELL_NONCE_SIZE: usize = 12;
const SNELL_SALT_SIZE: usize = 16;

const SNELL_VERSION: u8 = 1;
const SNELL_COMMAND_TUNNEL: u8 = 0;
const SNELL_COMMAND_CONNECT: u8 = 1;
const SNELL_COMMAND_CONNECT_V2: u8 = 5;
const SNELL_COMMAND_ERROR: u8 = 2;
const SNELL_COMMAND_UDP: u8 = 6;
const SNELL_COMMAND_UDP_FORWARD: u8 = 1;

pub(crate) fn wrap_stream(
    stream: BoxedTcpStream,
    psk: &str,
    version: u8,
    obfs_mode: &str,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    if !obfs_mode.is_empty() {
        return Err(TransportError::UnsupportedFeature {
            proxy: "<snell>".to_owned(),
            feature: format!("obfs={obfs_mode}"),
        });
    }

    let crypto = SnellCrypto::new(psk.as_bytes().to_vec(), version)?;
    let mut stream = SnellStream::new(stream, crypto)?;
    write_header(&mut stream, target, version)?;
    stream.flush()?;
    Ok(Box::new(stream))
}

pub(crate) fn open_udp_stream(
    stream: BoxedTcpStream,
    psk: &str,
    version: u8,
    obfs_mode: &str,
) -> Result<BoxedTcpStream, TransportError> {
    if !obfs_mode.is_empty() {
        return Err(TransportError::UnsupportedFeature {
            proxy: "<snell>".to_owned(),
            feature: format!("obfs={obfs_mode}"),
        });
    }
    if version < 3 {
        return Err(TransportError::UnsupportedFeature {
            proxy: "<snell>".to_owned(),
            feature: format!("udp-version={version}"),
        });
    }

    let crypto = SnellCrypto::new(psk.as_bytes().to_vec(), version)?;
    let mut stream = SnellStream::new(stream, crypto)?;
    stream.write_all(&[SNELL_VERSION, SNELL_COMMAND_UDP, 0x00])?;
    stream.flush()?;
    Ok(Box::new(stream))
}

pub(crate) fn write_udp_packet(
    stream: &mut dyn Write,
    target: SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    let mut packet = Vec::new();
    packet.push(SNELL_COMMAND_UDP_FORWARD);
    match target {
        SocketAddr::V4(addr) => {
            packet.extend_from_slice(&[0x00, 0x04]);
            packet.extend_from_slice(&addr.ip().octets());
            packet.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            packet.extend_from_slice(&[0x00, 0x06]);
            packet.extend_from_slice(&addr.ip().octets());
            packet.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    packet.extend_from_slice(payload);
    stream.write_all(&packet)?;
    stream.flush()?;
    Ok(payload.len())
}

pub(crate) fn read_udp_packet(stream: &mut dyn Read) -> io::Result<(SocketAddr, Vec<u8>)> {
    let mut buf = vec![0_u8; 64 * 1024];
    let read = stream.read(&mut buf)?;
    if read < 1 + 2 + 4 + 2 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short snell udp packet",
        ));
    }
    buf.truncate(read);
    let mut offset = 0;
    if buf[offset] != SNELL_COMMAND_UDP_FORWARD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported snell udp command {}", buf[offset]),
        ));
    }
    offset += 1;
    let addr = match (buf[offset], buf[offset + 1]) {
        (0x00, 0x04) => {
            offset += 2;
            let ip = std::net::Ipv4Addr::new(
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            );
            offset += 4;
            let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            offset += 2;
            SocketAddr::new(std::net::IpAddr::V4(ip), port)
        }
        (0x00, 0x06) => {
            offset += 2;
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&buf[offset..offset + 16]);
            offset += 16;
            let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            offset += 2;
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)), port)
        }
        _ => {
            let host_len = buf[offset] as usize;
            offset += 1;
            if buf.len() < offset + host_len + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snell udp domain address truncated",
                ));
            }
            let host = String::from_utf8_lossy(&buf[offset..offset + host_len]).into_owned();
            offset += host_len;
            let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            offset += 2;
            let mut addrs = (host.as_str(), port).to_socket_addrs()?;
            addrs.next().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "snell udp domain target unresolved",
                )
            })?
        }
    };
    Ok((addr, buf[offset..].to_vec()))
}

pub(crate) fn wrap_accepted_stream(
    stream: BoxedTcpStream,
    psk: &str,
    version: u8,
) -> Result<BoxedTcpStream, TransportError> {
    Ok(Box::new(SnellAeadStream::new(
        stream,
        SnellCrypto::new(psk.as_bytes().to_vec(), version)?,
    )?))
}

#[derive(Clone)]
struct SnellCrypto {
    kind: SnellCipherKind,
    psk: Vec<u8>,
}

impl SnellCrypto {
    fn new(psk: Vec<u8>, version: u8) -> Result<Self, TransportError> {
        let kind = if version == 1 {
            SnellCipherKind::Chacha20Poly1305
        } else {
            SnellCipherKind::Aes128Gcm
        };
        Ok(Self { kind, psk })
    }

    fn make_aead(&self, salt: &[u8]) -> Result<SnellAead, TransportError> {
        self.kind.make_aead(&self.psk, salt)
    }
}

#[derive(Clone, Copy)]
enum SnellCipherKind {
    Aes128Gcm,
    Chacha20Poly1305,
}

impl SnellCipherKind {
    fn make_aead(self, psk: &[u8], salt: &[u8]) -> Result<SnellAead, TransportError> {
        let mut key = [0_u8; 32];
        let params = Params::new(8, 3, 1, Some(32))
            .map_err(|err| TransportError::InvalidPlan(err.to_string()))?;
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(psk, salt, &mut key)
            .map_err(|err| TransportError::InvalidPlan(err.to_string()))?;

        match self {
            Self::Aes128Gcm => Ok(SnellAead::Aes128(
                AesGcm::<Aes128, aes_gcm::aead::consts::U12>::new_from_slice(&key[..16])
                    .map_err(|err| TransportError::InvalidPlan(err.to_string()))?,
            )),
            Self::Chacha20Poly1305 => Ok(SnellAead::Chacha20(
                ChaCha20Poly1305::new_from_slice(&key)
                    .map_err(|err| TransportError::InvalidPlan(err.to_string()))?,
            )),
        }
    }
}

enum SnellAead {
    Aes128(AesGcm<Aes128, aes_gcm::aead::consts::U12>),
    Chacha20(ChaCha20Poly1305),
}

impl SnellAead {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        let nonce = Nonce::from_slice(nonce);
        match self {
            Self::Aes128(cipher) => cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| TransportError::InvalidProxyResponse("snell encrypt failed".to_owned())),
            Self::Chacha20(cipher) => cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| TransportError::InvalidProxyResponse("snell encrypt failed".to_owned())),
        }
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, TransportError> {
        let nonce = Nonce::from_slice(nonce);
        match self {
            Self::Aes128(cipher) => cipher.decrypt(nonce, ciphertext).map_err(|_| {
                TransportError::invalid_proxy_response("snell decrypt failed")
            }),
            Self::Chacha20(cipher) => cipher.decrypt(nonce, ciphertext).map_err(|_| {
                TransportError::invalid_proxy_response("snell decrypt failed")
            }),
        }
    }
}

#[derive(Clone)]
struct SnellSessionState {
    salt: Vec<u8>,
    nonce: [u8; SNELL_NONCE_SIZE],
}

impl SnellSessionState {
    fn new(salt: Vec<u8>) -> Self {
        Self {
            salt,
            nonce: [0_u8; SNELL_NONCE_SIZE],
        }
    }
}

struct SnellAeadStream {
    read_socket: BoxedTcpStream,
    write_socket: Option<BoxedTcpStream>,
    crypto: SnellCrypto,
    reader_state: Option<SnellSessionState>,
    writer_state: Option<SnellSessionState>,
    read_buf: Vec<u8>,
    read_off: usize,
}

impl SnellAeadStream {
    fn new(stream: BoxedTcpStream, crypto: SnellCrypto) -> Result<Self, TransportError> {
        match stream.try_clone_box() {
            Ok(write_socket) => Ok(Self {
                read_socket: stream,
                write_socket: Some(write_socket),
                crypto,
                reader_state: None,
                writer_state: None,
                read_buf: Vec::new(),
                read_off: 0,
            }),
            Err(_) => Ok(Self {
                read_socket: stream,
                write_socket: None,
                crypto,
                reader_state: None,
                writer_state: None,
                read_buf: Vec::new(),
                read_off: 0,
            }),
        }
    }

    fn write_socket(&mut self) -> &mut dyn Write {
        match self.write_socket.as_mut() {
            Some(socket) => &mut **socket,
            None => &mut *self.read_socket,
        }
    }

    fn init_reader(&mut self) -> io::Result<()> {
        if self.reader_state.is_none() {
            let mut salt = vec![0_u8; SNELL_SALT_SIZE];
            self.read_socket.read_exact(&mut salt)?;
            self.reader_state = Some(SnellSessionState::new(salt));
        }
        Ok(())
    }

    fn init_writer(&mut self) -> io::Result<()> {
        if self.writer_state.is_none() {
            let mut salt = vec![0_u8; SNELL_SALT_SIZE];
            rand::rngs::OsRng.fill_bytes(&mut salt);
            self.write_socket().write_all(&salt)?;
            self.writer_state = Some(SnellSessionState::new(salt));
        }
        Ok(())
    }

    fn load_next_chunk(&mut self) -> io::Result<bool> {
        self.init_reader()?;
        let (salt, mut nonce) = {
            let state = self.reader_state.as_ref().unwrap();
            (state.salt.clone(), state.nonce)
        };
        let aead = self.crypto.make_aead(&salt).map_err(to_io_invalid_data)?;

        let mut length_ciphertext = vec![0_u8; 2 + SNELL_TAG_SIZE];
        if !read_exact_or_initial_eof(&mut *self.read_socket, &mut length_ciphertext)? {
            return Ok(false);
        }
        let length_plaintext = aead
            .decrypt(&nonce, &length_ciphertext)
            .map_err(to_io_invalid_data)?;
        increment_nonce(&mut nonce);

        let chunk_len =
            (((length_plaintext[0] as usize) << 8) | length_plaintext[1] as usize)
                & SNELL_MAX_PAYLOAD_SIZE;
        if chunk_len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid zero-length snell chunk",
            ));
        }

        let mut payload_ciphertext = vec![0_u8; chunk_len + SNELL_TAG_SIZE];
        self.read_socket.read_exact(&mut payload_ciphertext)?;
        self.read_buf = aead
            .decrypt(&nonce, &payload_ciphertext)
            .map_err(to_io_invalid_data)?;
        increment_nonce(&mut nonce);
        self.reader_state.as_mut().unwrap().nonce = nonce;
        self.read_off = 0;
        Ok(true)
    }

    fn write_chunk(&mut self, payload: &[u8]) -> io::Result<()> {
        self.init_writer()?;
        let (salt, mut nonce) = {
            let state = self.writer_state.as_ref().unwrap();
            (state.salt.clone(), state.nonce)
        };
        let aead = self.crypto.make_aead(&salt).map_err(to_io_invalid_data)?;

        let length = [(payload.len() >> 8) as u8, payload.len() as u8];
        let encrypted_length = aead
            .encrypt(&nonce, &length)
            .map_err(to_io_invalid_data)?;
        increment_nonce(&mut nonce);
        let encrypted_payload = aead
            .encrypt(&nonce, payload)
            .map_err(to_io_invalid_data)?;
        increment_nonce(&mut nonce);

        self.write_socket().write_all(&encrypted_length)?;
        self.write_socket().write_all(&encrypted_payload)?;
        self.writer_state.as_mut().unwrap().nonce = nonce;
        Ok(())
    }
}

impl Read for SnellAeadStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.read_off == self.read_buf.len() {
            self.read_buf.clear();
            self.read_off = 0;
            if !self.load_next_chunk()? {
                return Ok(0);
            }
        }

        let read = (&self.read_buf[self.read_off..]).read(buf)?;
        self.read_off += read;
        if self.read_off == self.read_buf.len() {
            self.read_buf.clear();
            self.read_off = 0;
        }
        Ok(read)
    }
}

impl Write for SnellAeadStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut written = 0;
        while written < buf.len() {
            let chunk_len = (buf.len() - written).min(SNELL_MAX_PAYLOAD_SIZE);
            self.write_chunk(&buf[written..written + chunk_len])?;
            written += chunk_len;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_socket().flush()
    }
}

impl TcpStream for SnellAeadStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            read_socket: self.read_socket.try_clone_box()?,
            write_socket: self
                .write_socket
                .as_ref()
                .map(|socket| socket.try_clone_box())
                .transpose()?,
            crypto: self.crypto.clone(),
            reader_state: self.reader_state.clone(),
            writer_state: self.writer_state.clone(),
            read_buf: self.read_buf[self.read_off..].to_vec(),
            read_off: 0,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        match self.write_socket.as_mut() {
            Some(socket) => socket.shutdown_write(),
            None => self.read_socket.shutdown_write(),
        }
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        if let Some(write_socket) = self.write_socket.as_mut() {
            let write_result = write_socket.shutdown_all();
            let read_result = self.read_socket.shutdown_all();
            write_result.and(read_result)
        } else {
            self.read_socket.shutdown_all()
        }
    }
}

struct SnellStream {
    inner: SnellAeadStream,
    reply_checked: bool,
}

impl SnellStream {
    fn new(stream: BoxedTcpStream, crypto: SnellCrypto) -> Result<Self, TransportError> {
        Ok(Self {
            inner: SnellAeadStream::new(stream, crypto)?,
            reply_checked: false,
        })
    }

    fn ensure_reply_checked(&mut self) -> io::Result<()> {
        if self.reply_checked {
            return Ok(());
        }
        self.reply_checked = true;

        let mut command = [0_u8; 1];
        self.inner.read_exact(&mut command)?;
        match command[0] {
            SNELL_COMMAND_TUNNEL => Ok(()),
            SNELL_COMMAND_ERROR => {
                let mut code = [0_u8; 1];
                let mut msg_len = [0_u8; 1];
                self.inner.read_exact(&mut code)?;
                self.inner.read_exact(&mut msg_len)?;
                let mut msg = vec![0_u8; msg_len[0] as usize];
                self.inner.read_exact(&mut msg)?;
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "snell server reported code {}: {}",
                        code[0],
                        String::from_utf8_lossy(&msg)
                    ),
                ))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported snell reply command {other}"),
            )),
        }
    }
}

impl Read for SnellStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.ensure_reply_checked()?;
        self.inner.read(buf)
    }
}

impl Write for SnellStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for SnellStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            inner: SnellAeadStream {
                read_socket: self.inner.read_socket.try_clone_box()?,
                write_socket: self
                    .inner
                    .write_socket
                    .as_ref()
                    .map(|socket| socket.try_clone_box())
                    .transpose()?,
                crypto: self.inner.crypto.clone(),
                reader_state: self.inner.reader_state.clone(),
                writer_state: self.inner.writer_state.clone(),
                read_buf: self.inner.read_buf[self.inner.read_off..].to_vec(),
                read_off: 0,
            },
            reply_checked: self.reply_checked,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

fn write_header(
    stream: &mut SnellStream,
    target: &TransportTarget,
    version: u8,
) -> Result<(), TransportError> {
    let host = target.host.as_bytes();
    if host.len() > u8::MAX as usize {
        return Err(TransportError::InvalidPlan(
            "snell host must fit within 255 bytes".to_owned(),
        ));
    }

    let command = if version == 2 {
        SNELL_COMMAND_CONNECT_V2
    } else {
        SNELL_COMMAND_CONNECT
    };
    let mut header = Vec::with_capacity(5 + host.len());
    header.push(SNELL_VERSION);
    header.push(command);
    header.push(0x00);
    header.push(host.len() as u8);
    header.extend_from_slice(host);
    header.extend_from_slice(&target.port.to_be_bytes());
    stream.write_all(&header)?;
    Ok(())
}

fn increment_nonce(nonce: &mut [u8; SNELL_NONCE_SIZE]) {
    for byte in nonce {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}

fn read_exact_or_initial_eof(reader: &mut dyn Read, buf: &mut [u8]) -> io::Result<bool> {
    let mut offset = 0;
    while offset < buf.len() {
        let read = reader.read(&mut buf[offset..])?;
        if read == 0 {
            if offset == 0 {
                return Ok(false);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            ));
        }
        offset += read;
    }
    Ok(true)
}

fn to_io_invalid_data(error: TransportError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
