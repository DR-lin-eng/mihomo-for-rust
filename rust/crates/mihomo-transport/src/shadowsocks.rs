use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AesGcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use mihomo_core::{BoxedTcpStream, TcpStream};
use rand::RngCore;
use sha1::Sha1;

use crate::{TransportError, TransportTarget};

const SHADOWSOCKS_MAX_PAYLOAD_SIZE: usize = 0x3FFF;
const SHADOWSOCKS_INFO: &[u8] = b"ss-subkey";
const SHADOWSOCKS_TAG_SIZE: usize = 16;
const SHADOWSOCKS_NONCE_SIZE: usize = 12;

pub(crate) fn wrap_stream(
    stream: BoxedTcpStream,
    cipher: &str,
    password: &str,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let crypto = ShadowsocksCrypto::new(cipher, password)?;
    let mut stream = ShadowsocksStream::new(stream, crypto)?;
    let mut serialized_target = super::encode_socks5_target(target)?;
    serialized_target.extend_from_slice(&target.port.to_be_bytes());
    stream.write_all(&serialized_target)?;
    stream.flush()?;
    Ok(Box::new(stream))
}

pub(crate) fn encode_udp_packet(
    cipher: &str,
    password: &str,
    target: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    encode_udp_packet_for_target(cipher, password, &TransportTarget::new(target.ip().to_string(), target.port()), payload)
}

pub(crate) fn encode_udp_packet_for_target(
    cipher: &str,
    password: &str,
    target: &TransportTarget,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let crypto = ShadowsocksCrypto::new(cipher, password)?;
    let mut salt = vec![0_u8; crypto.salt_size()];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let aead = crypto.make_aead(&salt)?;
    let mut plaintext = super::encode_socks5_target(target)?;
    plaintext.extend_from_slice(&target.port.to_be_bytes());
    plaintext.extend_from_slice(payload);
    let encrypted = aead
        .encrypt(&[0_u8; SHADOWSOCKS_NONCE_SIZE], &plaintext)
        .map_err(to_io_invalid_data)
        .map_err(TransportError::from)?;
    let mut packet = salt;
    packet.extend_from_slice(&encrypted);
    Ok(packet)
}

pub(crate) fn decode_udp_packet(
    cipher: &str,
    password: &str,
    packet: &[u8],
) -> Result<(SocketAddr, Vec<u8>), TransportError> {
    let crypto = ShadowsocksCrypto::new(cipher, password)?;
    if packet.len() < crypto.salt_size() + SHADOWSOCKS_TAG_SIZE {
        return Err(TransportError::invalid_proxy_response(
            "short shadowsocks udp packet",
        ));
    }
    let (salt, ciphertext) = packet.split_at(crypto.salt_size());
    let aead = crypto.make_aead(salt)?;
    let plaintext = aead.decrypt(&[0_u8; SHADOWSOCKS_NONCE_SIZE], ciphertext)?;
    let (target, header_len) = decode_socket_addr(&plaintext)?;
    Ok((target, plaintext[header_len..].to_vec()))
}

pub(crate) fn wrap_accepted_stream(
    stream: BoxedTcpStream,
    cipher: &str,
    password: &str,
) -> Result<BoxedTcpStream, TransportError> {
    let crypto = ShadowsocksCrypto::new(cipher, password)?;
    Ok(Box::new(ShadowsocksStream::new(stream, crypto)?))
}

#[derive(Clone)]
struct ShadowsocksCrypto {
    kind: ShadowsocksCipherKind,
    master_key: Vec<u8>,
}

impl ShadowsocksCrypto {
    fn new(cipher: &str, password: &str) -> Result<Self, TransportError> {
        let kind = ShadowsocksCipherKind::parse(cipher)?;
        let master_key = shadowsocks_kdf(password, kind.key_size());
        Ok(Self { kind, master_key })
    }

    fn salt_size(&self) -> usize {
        self.kind.salt_size()
    }

    fn make_aead(&self, salt: &[u8]) -> Result<ShadowsocksAead, TransportError> {
        self.kind.make_aead(&self.master_key, salt)
    }
}

#[derive(Clone, Copy)]
enum ShadowsocksCipherKind {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    Chacha20IetfPoly1305,
}

impl ShadowsocksCipherKind {
    fn parse(cipher: &str) -> Result<Self, TransportError> {
        match cipher.to_ascii_uppercase().as_str() {
            "AEAD_AES_128_GCM" | "AES-128-GCM" => Ok(Self::Aes128Gcm),
            "AEAD_AES_192_GCM" | "AES-192-GCM" => Ok(Self::Aes192Gcm),
            "AEAD_AES_256_GCM" | "AES-256-GCM" => Ok(Self::Aes256Gcm),
            "AEAD_CHACHA20_POLY1305" | "CHACHA20-IETF-POLY1305" => {
                Ok(Self::Chacha20IetfPoly1305)
            }
            other => Err(TransportError::InvalidPlan(format!(
                "unsupported shadowsocks cipher {other}"
            ))),
        }
    }

    fn key_size(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes192Gcm => 24,
            Self::Aes256Gcm | Self::Chacha20IetfPoly1305 => 32,
        }
    }

    fn salt_size(self) -> usize {
        self.key_size().max(16)
    }

    fn make_aead(self, master_key: &[u8], salt: &[u8]) -> Result<ShadowsocksAead, TransportError> {
        let mut subkey = vec![0_u8; self.key_size()];
        Hkdf::<Sha1>::new(Some(salt), master_key)
            .expand(SHADOWSOCKS_INFO, &mut subkey)
            .map_err(|_| TransportError::InvalidPlan("invalid shadowsocks hkdf output".to_owned()))?;

        match self {
            Self::Aes128Gcm => Ok(ShadowsocksAead::Aes128(
                AesGcm::<Aes128, aes_gcm::aead::consts::U12>::new_from_slice(&subkey)
                    .map_err(|err| TransportError::InvalidPlan(err.to_string()))?,
            )),
            Self::Aes192Gcm => Ok(ShadowsocksAead::Aes192(
                AesGcm::<Aes192, aes_gcm::aead::consts::U12>::new_from_slice(&subkey)
                    .map_err(|err| TransportError::InvalidPlan(err.to_string()))?,
            )),
            Self::Aes256Gcm => Ok(ShadowsocksAead::Aes256(
                AesGcm::<Aes256, aes_gcm::aead::consts::U12>::new_from_slice(&subkey)
                    .map_err(|err| TransportError::InvalidPlan(err.to_string()))?,
            )),
            Self::Chacha20IetfPoly1305 => Ok(ShadowsocksAead::Chacha20(
                ChaCha20Poly1305::new_from_slice(&subkey)
                    .map_err(|err| TransportError::InvalidPlan(err.to_string()))?,
            )),
        }
    }
}

enum ShadowsocksAead {
    Aes128(AesGcm<Aes128, aes_gcm::aead::consts::U12>),
    Aes192(AesGcm<Aes192, aes_gcm::aead::consts::U12>),
    Aes256(AesGcm<Aes256, aes_gcm::aead::consts::U12>),
    Chacha20(ChaCha20Poly1305),
}

impl ShadowsocksAead {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        let nonce = Nonce::from_slice(nonce);
        match self {
            Self::Aes128(cipher) => cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| TransportError::InvalidProxyResponse("shadowsocks encrypt failed".to_owned())),
            Self::Aes192(cipher) => cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| TransportError::InvalidProxyResponse("shadowsocks encrypt failed".to_owned())),
            Self::Aes256(cipher) => cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| TransportError::InvalidProxyResponse("shadowsocks encrypt failed".to_owned())),
            Self::Chacha20(cipher) => cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| TransportError::InvalidProxyResponse("shadowsocks encrypt failed".to_owned())),
        }
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, TransportError> {
        let nonce = Nonce::from_slice(nonce);
        match self {
            Self::Aes128(cipher) => cipher.decrypt(nonce, ciphertext).map_err(|_| {
                TransportError::invalid_proxy_response("shadowsocks decrypt failed")
            }),
            Self::Aes192(cipher) => cipher.decrypt(nonce, ciphertext).map_err(|_| {
                TransportError::invalid_proxy_response("shadowsocks decrypt failed")
            }),
            Self::Aes256(cipher) => cipher.decrypt(nonce, ciphertext).map_err(|_| {
                TransportError::invalid_proxy_response("shadowsocks decrypt failed")
            }),
            Self::Chacha20(cipher) => cipher.decrypt(nonce, ciphertext).map_err(|_| {
                TransportError::invalid_proxy_response("shadowsocks decrypt failed")
            }),
        }
    }
}

#[derive(Clone)]
struct ShadowsocksSessionState {
    salt: Vec<u8>,
    nonce: [u8; SHADOWSOCKS_NONCE_SIZE],
}

impl ShadowsocksSessionState {
    fn new(salt: Vec<u8>) -> Self {
        Self {
            salt,
            nonce: [0_u8; SHADOWSOCKS_NONCE_SIZE],
        }
    }
}

struct ShadowsocksStream {
    read_socket: BoxedTcpStream,
    write_socket: Option<BoxedTcpStream>,
    crypto: ShadowsocksCrypto,
    reader_state: Option<ShadowsocksSessionState>,
    writer_state: Option<ShadowsocksSessionState>,
    read_buf: Vec<u8>,
    read_off: usize,
}

impl ShadowsocksStream {
    fn new(stream: BoxedTcpStream, crypto: ShadowsocksCrypto) -> Result<Self, TransportError> {
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

    fn init_reader(&mut self) -> io::Result<&mut ShadowsocksSessionState> {
        if self.reader_state.is_none() {
            let mut salt = vec![0_u8; self.crypto.salt_size()];
            self.read_socket.read_exact(&mut salt)?;
            self.reader_state = Some(ShadowsocksSessionState::new(salt));
        }
        Ok(self.reader_state.as_mut().unwrap())
    }

    fn init_writer(&mut self) -> io::Result<&mut ShadowsocksSessionState> {
        if self.writer_state.is_none() {
            let mut salt = vec![0_u8; self.crypto.salt_size()];
            rand::rngs::OsRng.fill_bytes(&mut salt);
            self.write_socket().write_all(&salt)?;
            self.writer_state = Some(ShadowsocksSessionState::new(salt));
        }
        Ok(self.writer_state.as_mut().unwrap())
    }

    fn load_next_chunk(&mut self) -> io::Result<bool> {
        self.init_reader()?;
        let (salt, mut nonce) = {
            let state = self.reader_state.as_ref().unwrap();
            (state.salt.clone(), state.nonce)
        };
        let aead = self.crypto.make_aead(&salt).map_err(to_io_invalid_data)?;

        let mut length_ciphertext = vec![0_u8; 2 + SHADOWSOCKS_TAG_SIZE];
        if !read_exact_or_initial_eof(&mut *self.read_socket, &mut length_ciphertext)? {
            return Ok(false);
        }
        let length_plaintext = aead
            .decrypt(&nonce, &length_ciphertext)
            .map_err(to_io_invalid_data)?;
        increment_nonce(&mut nonce);

        if length_plaintext.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid shadowsocks length frame",
            ));
        }
        let chunk_len =
            (((length_plaintext[0] as usize) << 8) | length_plaintext[1] as usize)
                & SHADOWSOCKS_MAX_PAYLOAD_SIZE;
        if chunk_len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid zero-length shadowsocks chunk",
            ));
        }

        let mut payload_ciphertext = vec![0_u8; chunk_len + SHADOWSOCKS_TAG_SIZE];
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

impl Read for ShadowsocksStream {
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

impl Write for ShadowsocksStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut written = 0;
        while written < buf.len() {
            let remaining = buf.len() - written;
            let chunk_len = remaining.min(SHADOWSOCKS_MAX_PAYLOAD_SIZE);
            self.write_chunk(&buf[written..written + chunk_len])?;
            written += chunk_len;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_socket().flush()
    }
}

impl TcpStream for ShadowsocksStream {
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

fn shadowsocks_kdf(password: &str, key_len: usize) -> Vec<u8> {
    let mut derived = Vec::with_capacity(key_len);
    let mut previous = Vec::new();
    while derived.len() < key_len {
        let mut hash = Md5::new();
        hash.update(&previous);
        hash.update(password.as_bytes());
        previous = hash.finalize().to_vec();
        derived.extend_from_slice(&previous);
    }
    derived.truncate(key_len);
    derived
}

fn decode_socket_addr(payload: &[u8]) -> Result<(SocketAddr, usize), TransportError> {
    let Some(atyp) = payload.first().copied() else {
        return Err(TransportError::invalid_proxy_response(
            "missing shadowsocks udp address type",
        ));
    };
    let mut offset = 1;
    let ip = match atyp {
        0x01 => {
            if payload.len() < offset + 4 + 2 {
                return Err(TransportError::invalid_proxy_response(
                    "truncated shadowsocks ipv4 address",
                ));
            }
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            ));
            offset += 4;
            ip
        }
        0x04 => {
            if payload.len() < offset + 16 + 2 {
                return Err(TransportError::invalid_proxy_response(
                    "truncated shadowsocks ipv6 address",
                ));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&payload[offset..offset + 16]);
            offset += 16;
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        0x03 => {
            let Some(length) = payload.get(offset).copied() else {
                return Err(TransportError::invalid_proxy_response(
                    "missing shadowsocks udp fqdn length",
                ));
            };
            offset += 1;
            let length = length as usize;
            if payload.len() < offset + length + 2 {
                return Err(TransportError::invalid_proxy_response(
                    "truncated shadowsocks fqdn address",
                ));
            }
            let host = String::from_utf8_lossy(&payload[offset..offset + length]).into_owned();
            offset += length;
            let port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let mut addrs = (host.as_str(), port).to_socket_addrs().map_err(TransportError::from)?;
            let addr = addrs.next().ok_or_else(|| {
                TransportError::invalid_proxy_response("shadowsocks udp fqdn target unresolved")
            })?;
            offset += 2;
            return Ok((addr, offset));
        }
        other => {
            return Err(TransportError::invalid_proxy_response(format!(
                "unsupported shadowsocks udp address type {other}"
            )))
        }
    };
    let port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    offset += 2;
    Ok((SocketAddr::new(ip, port), offset))
}

fn increment_nonce(nonce: &mut [u8; SHADOWSOCKS_NONCE_SIZE]) {
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
