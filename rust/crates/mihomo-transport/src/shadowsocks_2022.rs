//! SIP022 AEAD-2022 ("SS2022") TCP stream transport.
//!
//! Implements the 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm and
//! 2022-blake3-chacha20-poly1305 ciphers over TCP as specified by
//! <https://shadowsocks.org/doc/sip022.html>: a random session salt, an
//! encrypted fixed-length header (type, timestamp, length), an encrypted
//! variable-length header carrying the SOCKS5 target plus padding, and AEAD
//! length/payload chunk framing with a 12-byte little-endian counter nonce.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit, generic_array::GenericArray};
use aes::Aes128;
use aes::Aes256;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AesGcm, Nonce};
use base64::Engine as _;
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use mihomo_core::{BoxedTcpStream, TcpStream};
use rand::RngCore;

use crate::executor::encode_socks5_target;
use crate::{TransportError, TransportTarget};

const SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";
const TAG_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const LENGTH_CHUNK_SIZE: usize = 2;
/// Write-side payload cap: every compliant peer accepts at least this much.
const MAX_WRITE_PAYLOAD: usize = 0x3FFF;
/// Read-side payload cap: SIP022 permits lengths up to 0xFFFF.
const MAX_READ_PAYLOAD: usize = 0xFFFF;
const MAX_PADDING: usize = 900;
const TIMESTAMP_WINDOW_SECS: u64 = 30;
const REPLAY_TTL: Duration = Duration::from_secs(60);
const FIXED_HEADER_TYPE_CLIENT: u8 = 0;
const FIXED_HEADER_TYPE_SERVER: u8 = 1;
const CLIENT_PADDING_MAX: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Shadowsocks2022Cipher {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl Shadowsocks2022Cipher {
    pub(crate) fn parse(cipher: &str) -> Option<Self> {
        match cipher.trim().to_ascii_lowercase().as_str() {
            "2022-blake3-aes-128-gcm" => Some(Self::Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Some(Self::Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Some(Self::Chacha20Poly1305),
            _ => None,
        }
    }

    fn key_size(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::Chacha20Poly1305 => 32,
        }
    }

    fn name(self) -> &'static str {
        kind_name(self)
    }

    fn make_aead(self, subkey: &[u8]) -> Result<Shadowsocks2022Aead, TransportError> {
        match self {
            Self::Aes128Gcm => Ok(Shadowsocks2022Aead::Aes128(
                AesGcm::<Aes128, aes_gcm::aead::consts::U12>::new_from_slice(subkey)
                    .map_err(|err| TransportError::InvalidPlan(err.to_string()))?,
            )),
            Self::Aes256Gcm => Ok(Shadowsocks2022Aead::Aes256(
                AesGcm::<Aes256, aes_gcm::aead::consts::U12>::new_from_slice(subkey)
                    .map_err(|err| TransportError::InvalidPlan(err.to_string()))?,
            )),
            Self::Chacha20Poly1305 => Ok(Shadowsocks2022Aead::Chacha20(
                ChaCha20Poly1305::new_from_slice(subkey)
                    .map_err(|err| TransportError::InvalidPlan(err.to_string()))?,
            )),
        }
    }
}

enum Shadowsocks2022Aead {
    Aes128(AesGcm<Aes128, aes_gcm::aead::consts::U12>),
    Aes256(AesGcm<Aes256, aes_gcm::aead::consts::U12>),
    Chacha20(ChaCha20Poly1305),
    XChacha20(XChaCha20Poly1305),
}

impl Shadowsocks2022Aead {
    fn encrypt(&self, counter: u64, plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.encrypt_with_nonce(&nonce_bytes(counter), plaintext)
    }

    /// AEAD with an explicit nonce (UDP uses header-derived or random
    /// nonces rather than the TCP counter).
    fn encrypt_with_nonce(&self, nonce_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        let result = match self {
            Self::Aes128(cipher) => cipher.encrypt(Nonce::from_slice(nonce_bytes), plaintext),
            Self::Aes256(cipher) => cipher.encrypt(Nonce::from_slice(nonce_bytes), plaintext),
            Self::Chacha20(cipher) => cipher.encrypt(Nonce::from_slice(nonce_bytes), plaintext),
            Self::XChacha20(cipher) => {
                use chacha20poly1305::aead::AeadInPlace as _;
                let xnonce = chacha20poly1305::XNonce::from_slice(nonce_bytes);
                cipher.encrypt(xnonce, plaintext)
            }
        };
        result.map_err(|_| TransportError::invalid_proxy_response("ss2022 encrypt failed"))
    }

    fn decrypt_with_nonce(&self, nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, TransportError> {
        let result = match self {
            Self::Aes128(cipher) => cipher.decrypt(Nonce::from_slice(nonce_bytes), ciphertext),
            Self::Aes256(cipher) => cipher.decrypt(Nonce::from_slice(nonce_bytes), ciphertext),
            Self::Chacha20(cipher) => cipher.decrypt(Nonce::from_slice(nonce_bytes), ciphertext),
            Self::XChacha20(cipher) => {
                let xnonce = chacha20poly1305::XNonce::from_slice(nonce_bytes);
                cipher.decrypt(xnonce, ciphertext)
            }
        };
        result.map_err(|_| TransportError::invalid_proxy_response("ss2022 decrypt failed"))
    }

    fn decrypt(&self, counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.decrypt_with_nonce(&nonce_bytes(counter), ciphertext)
    }
}

#[derive(Clone)]
struct Shadowsocks2022Session {
    cipher: Shadowsocks2022Cipher,
    psk: Vec<u8>,
}

impl Shadowsocks2022Session {
    fn from_password(cipher: &str, password: &str) -> Result<Self, TransportError> {
        let Some(kind) = Shadowsocks2022Cipher::parse(cipher) else {
            return Err(TransportError::InvalidPlan(format!(
                "unsupported shadowsocks 2022 cipher {cipher}"
            )));
        };
        let psk = decode_psk(password, kind)?;
        Ok(Self { cipher: kind, psk })
    }

    fn new_aead(&self, salt: &[u8]) -> Result<Shadowsocks2022Aead, TransportError> {
        let subkey = derive_subkey(&self.psk, salt);
        self.cipher
            .make_aead(&subkey[..self.cipher.key_size()])
    }
}

/// Decodes a base64-encoded SIP022 PSK and verifies its length matches the
/// cipher. Returns the decoded key length for config-time validation.
pub(crate) fn validate_psk(cipher: &str, password: &str) -> Result<usize, TransportError> {
    let Some(kind) = Shadowsocks2022Cipher::parse(cipher) else {
        return Err(TransportError::InvalidPlan(format!(
            "unsupported shadowsocks 2022 cipher {cipher}"
        )));
    };
    let psk = decode_psk(password, kind)?;
    Ok(psk.len())
}

fn decode_psk(password: &str, kind: Shadowsocks2022Cipher) -> Result<Vec<u8>, TransportError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(password.trim().as_bytes())
        .map_err(|err| {
            TransportError::InvalidPlan(format!("shadowsocks 2022 psk is not valid base64: {err}"))
        })?;
    if decoded.len() != kind.key_size() {
        return Err(TransportError::InvalidPlan(format!(
            "shadowsocks 2022 psk must decode to {} bytes for {}, got {}",
            kind.key_size(),
            kind.name(),
            decoded.len()
        )));
    }
    Ok(decoded)
}

/// Builds the UDP AEAD for a 2022 method: AES-GCM variants derive a subkey
/// per packet; the chacha variant uses the PSK directly with XChaCha20.
fn udp_packet_aead(
    kind: Shadowsocks2022Cipher,
    psk: &[u8],
) -> Result<Shadowsocks2022Aead, TransportError> {
    match kind {
        Shadowsocks2022Cipher::Aes128Gcm | Shadowsocks2022Cipher::Aes256Gcm => {
            let subkey = derive_subkey(psk, psk);
            kind.make_aead(&subkey[..kind.key_size()])
        }
        Shadowsocks2022Cipher::Chacha20Poly1305 => Ok(Shadowsocks2022Aead::XChacha20(
            XChaCha20Poly1305::new_from_slice(psk)
                .map_err(|err| TransportError::InvalidPlan(err.to_string()))?,
        )),
    }
}

fn kind_name(kind: Shadowsocks2022Cipher) -> &'static str {
    match kind {
        Shadowsocks2022Cipher::Aes128Gcm => "2022-blake3-aes-128-gcm",
        Shadowsocks2022Cipher::Aes256Gcm => "2022-blake3-aes-256-gcm",
        Shadowsocks2022Cipher::Chacha20Poly1305 => "2022-blake3-chacha20-poly1305",
    }
}

/// `session_subkey := blake3::derive_key("shadowsocks 2022 session subkey",
/// key + salt)` per SIP022, truncated to the cipher key size.
fn derive_subkey(key: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut material = Vec::with_capacity(key.len() + salt.len());
    material.extend_from_slice(key);
    material.extend_from_slice(salt);
    let derived = blake3::derive_key(SUBKEY_CONTEXT, &material);
    derived.to_vec()
}

fn nonce_bytes(counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0_u8; NONCE_SIZE];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn timestamp_within_window(timestamp: u64) -> bool {
    unix_timestamp().abs_diff(timestamp) <= TIMESTAMP_WINDOW_SECS
}

/// Salt replay cache: SIP022 requires remembering every salt for 60 seconds
/// via a filter that must never produce false positives.
fn salt_is_fresh(salt: &[u8]) -> bool {
    static REPLAY_CACHE: OnceLock<Mutex<HashMap<Vec<u8>, Instant>>> = OnceLock::new();
    let cache = REPLAY_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match cache.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.retain(|_, inserted_at| inserted_at.elapsed() < REPLAY_TTL);
    if guard.len() >= 65536 {
        guard.clear();
    }
    let key = salt.to_vec();
    if guard.contains_key(&key) {
        return false;
    }
    guard.insert(key, Instant::now());
    true
}

fn random_salt(size: usize) -> Vec<u8> {
    let mut salt = vec![0_u8; size];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

fn random_padding() -> Vec<u8> {
    let len = rand::random::<usize>() % (CLIENT_PADDING_MAX + 1);
    let mut padding = vec![0_u8; len];
    rand::rngs::OsRng.fill_bytes(&mut padding);
    padding
}

/// Client side of a SIP022 TCP stream. The session salt and both header
/// chunks are written eagerly so targets fail fast, per the spec's single
/// socket write requirement.
pub(crate) fn wrap_stream(
    stream: BoxedTcpStream,
    cipher: &str,
    password: &str,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let session = Shadowsocks2022Session::from_password(cipher, password)?;
    let stream = Shadowsocks2022ClientStream::new(stream, session, target)?;
    Ok(Box::new(stream))
}

/// Server side of a SIP022 TCP stream. Consumes the session salt and both
/// header chunks, enforces timestamp and replay rules, and returns the
/// request target together with a stream whose first read yields the
/// initial payload carried inside the variable-length header.
pub(crate) fn accept_stream(
    stream: BoxedTcpStream,
    cipher: &str,
    password: &str,
) -> Result<(TransportTarget, BoxedTcpStream), TransportError> {
    let session = Shadowsocks2022Session::from_password(cipher, password)?;
    Shadowsocks2022ServerStream::accept(stream, session)
}

fn encode_variable_header(target: &TransportTarget) -> Result<Vec<u8>, TransportError> {
    let mut header = encode_socks5_target(target)?;
    header.extend_from_slice(&target.port.to_be_bytes());
    let padding = random_padding();
    header.extend_from_slice(&(padding.len() as u16).to_be_bytes());
    header.extend_from_slice(&padding);
    Ok(header)
}

fn decode_variable_header(
    header: &[u8],
) -> Result<(TransportTarget, usize), TransportError> {
    let mut offset = 0;
    let Some(&atyp) = header.first() else {
        return Err(TransportError::invalid_proxy_response(
            "ss2022 variable header is empty",
        ));
    };
    offset += 1;
    let host = match atyp {
        0x01 => {
            if header.len() < offset + 4 {
                return Err(TransportError::invalid_proxy_response(
                    "ss2022 truncated ipv4 target",
                ));
            }
            let host = IpAddr::V4(std::net::Ipv4Addr::new(
                header[offset],
                header[offset + 1],
                header[offset + 2],
                header[offset + 3],
            ));
            offset += 4;
            host.to_string()
        }
        0x04 => {
            if header.len() < offset + 16 {
                return Err(TransportError::invalid_proxy_response(
                    "ss2022 truncated ipv6 target",
                ));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&header[offset..offset + 16]);
            offset += 16;
            IpAddr::V6(std::net::Ipv6Addr::from(octets)).to_string()
        }
        0x03 => {
            let Some(&length) = header.get(offset) else {
                return Err(TransportError::invalid_proxy_response(
                    "ss2022 missing domain length",
                ));
            };
            offset += 1;
            if header.len() < offset + length as usize {
                return Err(TransportError::invalid_proxy_response(
                    "ss2022 truncated domain target",
                ));
            }
            let host =
                String::from_utf8_lossy(&header[offset..offset + length as usize]).into_owned();
            offset += length as usize;
            host
        }
        other => {
            return Err(TransportError::invalid_proxy_response(format!(
                "ss2022 unsupported address type {other}"
            )))
        }
    };
    if header.len() < offset + 2 {
        return Err(TransportError::invalid_proxy_response(
            "ss2022 missing target port",
        ));
    }
    let port = u16::from_be_bytes([header[offset], header[offset + 1]]);
    offset += 2;
    if header.len() < offset + 2 {
        return Err(TransportError::invalid_proxy_response(
            "ss2022 missing padding length",
        ));
    }
    let padding_len =
        ((header[offset] as usize) << 8) | header[offset + 1] as usize;
    offset += 2;
    if padding_len > MAX_PADDING || header.len() < offset + padding_len {
        return Err(TransportError::invalid_proxy_response(
            "ss2022 invalid padding section",
        ));
    }
    offset += padding_len;
    if padding_len == 0 && header.len() == offset {
        return Err(TransportError::invalid_proxy_response(
            "ss2022 request must carry padding or initial payload",
        ));
    }
    Ok((TransportTarget::new(host, port), offset))
}

fn encrypt_chunk(
    aead: &Shadowsocks2022Aead,
    counter: &mut u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let ciphertext = aead.encrypt(*counter, plaintext)?;
    *counter += 1;
    Ok(ciphertext)
}

fn write_chunked_payload(
    writer: &mut dyn Write,
    aead: &Shadowsocks2022Aead,
    counter: &mut u64,
    mut payload: &[u8],
) -> Result<(), TransportError> {
    while !payload.is_empty() {
        let chunk_len = payload.len().min(MAX_WRITE_PAYLOAD);
        let (chunk, rest) = payload.split_at(chunk_len);
        payload = rest;
        let length = [(chunk_len >> 8) as u8, chunk_len as u8];
        writer.write_all(&encrypt_chunk(aead, counter, &length)?)?;
        writer.write_all(&encrypt_chunk(aead, counter, chunk)?)?;
    }
    writer.flush()?;
    Ok(())
}

fn read_exact_or_eof(reader: &mut dyn Read, buf: &mut [u8]) -> io::Result<bool> {
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

fn read_and_decrypt(
    reader: &mut dyn Read,
    aead: &Shadowsocks2022Aead,
    counter: &mut u64,
    plaintext_len: usize,
) -> Result<Vec<u8>, TransportError> {
    let mut ciphertext = vec![0_u8; plaintext_len + TAG_SIZE];
    reader
        .read_exact(&mut ciphertext)
        .map_err(TransportError::from)?;
    let plaintext = aead.decrypt(*counter, &ciphertext)?;
    *counter += 1;
    Ok(plaintext)
}

struct Shadowsocks2022ClientStream {
    read_socket: BoxedTcpStream,
    write_socket: Option<BoxedTcpStream>,
    session: Shadowsocks2022Session,
    salt: Vec<u8>,
    write_counter: u64,
    write_aead: Option<Shadowsocks2022Aead>,
    server_salt: Option<Vec<u8>>,
    response_header_parsed: bool,
    first_payload_len: Option<usize>,
    read_counter: u64,
    read_aead: Option<Shadowsocks2022Aead>,
    read_buf: Vec<u8>,
    read_off: usize,
    read_finished: bool,
}

impl Shadowsocks2022ClientStream {
    fn new(
        stream: BoxedTcpStream,
        session: Shadowsocks2022Session,
        target: &TransportTarget,
    ) -> Result<Self, TransportError> {
        let write_socket = stream.try_clone_box().ok();
        let mut this = Self {
            read_socket: stream,
            write_socket,
            session,
            salt: Vec::new(),
            write_counter: 0,
            write_aead: None,
            server_salt: None,
            response_header_parsed: false,
            first_payload_len: None,
            read_counter: 0,
            read_aead: None,
            read_buf: Vec::new(),
            read_off: 0,
            read_finished: false,
        };
        this.write_request_header(target)?;
        Ok(this)
    }

    fn write_socket(&mut self) -> &mut dyn Write {
        match self.write_socket.as_mut() {
            Some(socket) => &mut **socket,
            None => &mut *self.read_socket,
        }
    }

    fn write_request_header(&mut self, target: &TransportTarget) -> Result<(), TransportError> {
        let salt = random_salt(self.session.cipher.key_size());
        let aead = self.session.new_aead(&salt)?;
        let header = encode_variable_header(target)?;
        let mut fixed = Vec::with_capacity(11);
        fixed.push(FIXED_HEADER_TYPE_CLIENT);
        fixed.extend_from_slice(&unix_timestamp().to_be_bytes());
        fixed.extend_from_slice(&(header.len() as u16).to_be_bytes());

        let mut prologue = salt.clone();
        prologue.extend_from_slice(&encrypt_chunk(&aead, &mut self.write_counter, &fixed)?);
        prologue.extend_from_slice(&encrypt_chunk(&aead, &mut self.write_counter, &header)?);
        self.write_socket().write_all(&prologue)?;
        self.write_socket().flush()?;
        self.salt = salt;
        self.write_aead = Some(aead);
        Ok(())
    }

    fn load_next_chunk(&mut self) -> io::Result<bool> {
        if !self.response_header_parsed {
            self.read_response_header()?;
        }
        // SIP022: the response fixed-length header doubles as the first
        // length chunk, so its payload is read directly from the header.
        let length = match self.first_payload_len.take() {
            Some(length) => length,
            None => {
                let mut length_ciphertext = vec![0_u8; LENGTH_CHUNK_SIZE + TAG_SIZE];
                if !read_exact_or_eof(&mut self.read_socket, &mut length_ciphertext)? {
                    self.read_finished = true;
                    return Ok(false);
                }
                let aead = self.read_aead.as_ref().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "ss2022 response not established")
                })?;
                let length_plaintext = aead
                    .decrypt(self.read_counter, &length_ciphertext)
                    .map_err(to_io_invalid_data)?;
                self.read_counter += 1;
                if length_plaintext.len() != LENGTH_CHUNK_SIZE {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid ss2022 length chunk",
                    ));
                }
                let length =
                    ((length_plaintext[0] as usize) << 8) | length_plaintext[1] as usize;
                if length > MAX_READ_PAYLOAD {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ss2022 payload chunk too large",
                    ));
                }
                length
            }
        };
        let mut ciphertext = vec![0_u8; length + TAG_SIZE];
        self.read_socket.read_exact(&mut ciphertext)?;
        let aead = self.read_aead.as_ref().expect("response established");
        self.read_buf = aead
            .decrypt(self.read_counter, &ciphertext)
            .map_err(to_io_invalid_data)?;
        self.read_counter += 1;
        self.read_off = 0;
        Ok(true)
    }

    fn read_response_header(&mut self) -> io::Result<()> {
        let salt_size = self.session.cipher.key_size();
        let mut server_salt = vec![0_u8; salt_size];
        self.read_socket.read_exact(&mut server_salt)?;
        let aead = self
            .session
            .new_aead(&server_salt)
            .map_err(to_io_invalid_data)?;
        let header_plaintext = read_and_decrypt(
            &mut self.read_socket,
            &aead,
            &mut self.read_counter,
            11 + salt_size,
        )
        .map_err(to_io_invalid_data)?;
        if header_plaintext[0] != FIXED_HEADER_TYPE_SERVER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ss2022 unexpected response header type",
            ));
        }
        let mut timestamp = [0_u8; 8];
        timestamp.copy_from_slice(&header_plaintext[1..9]);
        if !timestamp_within_window(u64::from_be_bytes(timestamp)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ss2022 response timestamp outside the replay window",
            ));
        }
        if header_plaintext[9..9 + salt_size] != self.salt[..] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ss2022 response request salt mismatch",
            ));
        }
        let first_payload_len = ((header_plaintext[9 + salt_size] as usize) << 8)
            | header_plaintext[10 + salt_size] as usize;
        self.server_salt = Some(server_salt);
        self.read_aead = Some(aead);
        self.response_header_parsed = true;
        self.first_payload_len = Some(first_payload_len);
        Ok(())
    }
}

impl Read for Shadowsocks2022ClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.read_off < self.read_buf.len() {
                let read = (&self.read_buf[self.read_off..]).read(buf)?;
                self.read_off += read;
                if self.read_off == self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_off = 0;
                }
                return Ok(read);
            }
            if self.read_finished {
                return Ok(0);
            }
            if !self.load_next_chunk()? {
                return Ok(0);
            }
        }
    }
}

impl Write for Shadowsocks2022ClientStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let aead = self.write_aead.as_ref().expect("request header written");
        let mut writer: &mut dyn Write = match self.write_socket.as_mut() {
            Some(socket) => &mut **socket,
            None => &mut self.read_socket,
        };
        let mut counter = self.write_counter;
        write_chunked_payload(&mut *writer, aead, &mut counter, buf).map_err(to_io_invalid_data)?;
        self.write_counter = counter;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.write_socket.as_mut() {
            Some(socket) => socket.flush(),
            None => self.read_socket.flush(),
        }
    }
}

impl TcpStream for Shadowsocks2022ClientStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            read_socket: self.read_socket.try_clone_box()?,
            write_socket: self
                .write_socket
                .as_ref()
                .map(|socket| socket.try_clone_box())
                .transpose()?,
            session: self.session.clone(),
            salt: self.salt.clone(),
            write_counter: self.write_counter,
            write_aead: Some(
                self.session
                    .new_aead(&self.salt)
                    .map_err(to_io_invalid_data)?,
            ),
            server_salt: self.server_salt.clone(),
            response_header_parsed: self.response_header_parsed,
            first_payload_len: self.first_payload_len,
            read_counter: self.read_counter,
            read_aead: match &self.server_salt {
                Some(salt) => Some(self.session.new_aead(salt).map_err(to_io_invalid_data)?),
                None => None,
            },
            read_buf: self.read_buf[self.read_off..].to_vec(),
            read_off: 0,
            read_finished: self.read_finished,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        match self.write_socket.as_mut() {
            Some(socket) => socket.shutdown_write(),
            None => self.read_socket.shutdown_write(),
        }
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        let write_result = self
            .write_socket
            .as_mut()
            .map(|socket| socket.shutdown_all());
        let read_result = self.read_socket.shutdown_all();
        match (write_result, read_result) {
            (Some(write_result), read_result) => write_result.and(read_result),
            (None, read_result) => read_result,
        }
    }
}

struct Shadowsocks2022ServerStream {
    read_socket: BoxedTcpStream,
    write_socket: Option<BoxedTcpStream>,
    session: Shadowsocks2022Session,
    client_salt: Vec<u8>,
    read_counter: u64,
    read_finished: bool,
    server_salt: Vec<u8>,
    response_header_written: bool,
    write_counter: u64,
    write_aead: Option<Shadowsocks2022Aead>,
    read_buf: Vec<u8>,
    read_off: usize,
}

impl Shadowsocks2022ServerStream {
    fn accept(
        mut stream: BoxedTcpStream,
        session: Shadowsocks2022Session,
    ) -> Result<(TransportTarget, BoxedTcpStream), TransportError> {
        let salt_size = session.cipher.key_size();
        let mut client_salt = vec![0_u8; salt_size];
        stream.read_exact(&mut client_salt)?;
        if !salt_is_fresh(&client_salt) {
            return Err(TransportError::invalid_proxy_response(
                "ss2022 request salt replay detected",
            ));
        }
        let aead = session.new_aead(&client_salt)?;
        let mut read_counter = 0_u64;
        let fixed_plaintext =
            read_and_decrypt(&mut stream, &aead, &mut read_counter, 11)?;
        if fixed_plaintext[0] != FIXED_HEADER_TYPE_CLIENT {
            return Err(TransportError::invalid_proxy_response(
                "ss2022 unexpected request header type",
            ));
        }
        let mut timestamp = [0_u8; 8];
        timestamp.copy_from_slice(&fixed_plaintext[1..9]);
        if !timestamp_within_window(u64::from_be_bytes(timestamp)) {
            return Err(TransportError::invalid_proxy_response(
                "ss2022 request timestamp outside the replay window",
            ));
        }
        let header_len = ((fixed_plaintext[9] as usize) << 8) | fixed_plaintext[10] as usize;
        if header_len == 0 || header_len > MAX_READ_PAYLOAD {
            return Err(TransportError::invalid_proxy_response(
                "ss2022 invalid variable header length",
            ));
        }
        let header = read_and_decrypt(&mut stream, &aead, &mut read_counter, header_len)?;
        let (target, payload_offset) = decode_variable_header(&header)?;
        let write_socket = stream.try_clone_box().ok();
        Ok((
            target,
            Box::new(Self {
                read_socket: stream,
                write_socket,
                session,
                client_salt,
                read_counter,
                read_finished: false,
                server_salt: Vec::new(),
                response_header_written: false,
                write_counter: 0,
                write_aead: None,
                read_buf: header[payload_offset..].to_vec(),
                read_off: 0,
            }),
        ))
    }

    fn write_socket(&mut self) -> &mut dyn Write {
        match self.write_socket.as_mut() {
            Some(socket) => &mut **socket,
            None => &mut *self.read_socket,
        }
    }

    fn load_next_chunk(&mut self) -> io::Result<bool> {
        let aead = self
            .session
            .new_aead(&self.client_salt)
            .map_err(to_io_invalid_data)?;
        let mut counter = self.read_counter;
        let Some(length) =
            read_chunk_length(&mut *self.read_socket, &aead, &mut counter)?
        else {
            self.read_finished = true;
            return Ok(false);
        };
        self.read_buf =
            read_and_decrypt(&mut self.read_socket, &aead, &mut counter, length)
                .map_err(to_io_invalid_data)?;
        self.read_counter = counter;
        self.read_off = 0;
        Ok(true)
    }
}

fn read_chunk_length(
    reader: &mut dyn Read,
    aead: &Shadowsocks2022Aead,
    counter: &mut u64,
) -> io::Result<Option<usize>> {
    let mut length_ciphertext = vec![0_u8; LENGTH_CHUNK_SIZE + TAG_SIZE];
    if !read_exact_or_eof(reader, &mut length_ciphertext)? {
        return Ok(None);
    }
    let length_plaintext = aead
        .decrypt(*counter, &length_ciphertext)
        .map_err(to_io_invalid_data)?;
    *counter += 1;
    if length_plaintext.len() != LENGTH_CHUNK_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ss2022 length chunk",
        ));
    }
    let length = ((length_plaintext[0] as usize) << 8) | length_plaintext[1] as usize;
    if length > MAX_READ_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ss2022 payload chunk too large",
        ));
    }
    Ok(Some(length))
}

impl Read for Shadowsocks2022ServerStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.read_off < self.read_buf.len() {
                let read = (&self.read_buf[self.read_off..]).read(buf)?;
                self.read_off += read;
                if self.read_off == self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_off = 0;
                }
                return Ok(read);
            }
            if self.read_finished {
                return Ok(0);
            }
            if !self.load_next_chunk()? {
                return Ok(0);
            }
        }
    }
}

impl Write for Shadowsocks2022ServerStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut writer: &mut dyn Write = match self.write_socket.as_mut() {
            Some(socket) => &mut **socket,
            None => &mut self.read_socket,
        };
        let mut counter = self.write_counter;
        if !self.response_header_written {
            let chunk_len = buf.len().min(MAX_WRITE_PAYLOAD);
            let (first_chunk, rest) = buf.split_at(chunk_len);
            let salt = random_salt(self.session.cipher.key_size());
            let aead = self
                .session
                .new_aead(&salt)
                .map_err(to_io_invalid_data)?;
            let mut fixed = Vec::with_capacity(11 + self.client_salt.len());
            fixed.push(FIXED_HEADER_TYPE_SERVER);
            fixed.extend_from_slice(&unix_timestamp().to_be_bytes());
            fixed.extend_from_slice(&self.client_salt);
            fixed.extend_from_slice(&(first_chunk.len() as u16).to_be_bytes());

            let mut prologue = salt.clone();
            prologue.extend_from_slice(
                &encrypt_chunk(&aead, &mut counter, &fixed).map_err(to_io_invalid_data)?,
            );
            prologue.extend_from_slice(
                &encrypt_chunk(&aead, &mut counter, first_chunk).map_err(to_io_invalid_data)?,
            );
            writer.write_all(&prologue)?;
            writer.flush()?;
            self.server_salt = salt;
            self.write_aead = Some(aead);
            self.response_header_written = true;
            if !rest.is_empty() {
                let aead = self.write_aead.as_ref().expect("response established");
                write_chunked_payload(&mut *writer, aead, &mut counter, rest)
                    .map_err(to_io_invalid_data)?;
            }
            self.write_counter = counter;
            return Ok(buf.len());
        }
        let aead = self.write_aead.as_ref().expect("response established");
        write_chunked_payload(&mut *writer, aead, &mut counter, buf).map_err(to_io_invalid_data)?;
        self.write_counter = counter;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.write_socket.as_mut() {
            Some(socket) => socket.flush(),
            None => self.read_socket.flush(),
        }
    }
}

impl TcpStream for Shadowsocks2022ServerStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            read_socket: self.read_socket.try_clone_box()?,
            write_socket: self
                .write_socket
                .as_ref()
                .map(|socket| socket.try_clone_box())
                .transpose()?,
            session: self.session.clone(),
            client_salt: self.client_salt.clone(),
            read_counter: self.read_counter,
            read_finished: self.read_finished,
            server_salt: self.server_salt.clone(),
            response_header_written: self.response_header_written,
            write_counter: self.write_counter,
            write_aead: if self.response_header_written {
                Some(
                    self.session
                        .new_aead(&self.server_salt)
                        .map_err(to_io_invalid_data)?,
                )
            } else {
                None
            },
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
        let write_result = self
            .write_socket
            .as_mut()
            .map(|socket| socket.shutdown_all());
        let read_result = self.read_socket.shutdown_all();
        match (write_result, read_result) {
            (Some(write_result), read_result) => write_result.and(read_result),
            (None, read_result) => read_result,
        }
    }
}

fn to_io_invalid_data(error: TransportError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

// ---------------------------------------------------------------------------
// SIP022 UDP relay (2022-blake3-aes-128-gcm / aes-256-gcm)
// ---------------------------------------------------------------------------

const UDP_SEPARATE_HEADER_SIZE: usize = 16;
const UDP_SESSION_ID_SIZE: usize = 8;
const UDP_PACKET_ID_SIZE: usize = 8;
const UDP_TYPE_CLIENT: u8 = 0;
const UDP_TYPE_SERVER: u8 = 1;

/// Server-side per-session UDP responder: keeps the response packet counter
/// for one inbound session (SIP022 requires a monotonic server packet id).
#[derive(Debug)]
pub struct Shadowsocks2022UdpResponseSession {
    session_id: [u8; UDP_SESSION_ID_SIZE],
    next_packet_id: std::sync::atomic::AtomicU64,
}

impl Shadowsocks2022UdpResponseSession {
    pub fn new(session_id: [u8; UDP_SESSION_ID_SIZE]) -> Self {
        Self {
            session_id,
            next_packet_id: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn encode_response(
        &self,
        cipher: &str,
        password: &str,
        target: &TransportTarget,
        payload: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        // Server packet ids start at 1: id 0 is reserved for client packets.
        let packet_id = self
            .next_packet_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        encode_udp_response(cipher, password, self.session_id, packet_id, target, payload)
    }
}

/// Global process-wide SIP022 UDP session registry: replay window plus the
/// shared responder (monotonic server packet counter) for each session.
#[derive(Default)]
pub struct Shadowsocks2022UdpRegistry {
    sessions: Mutex<HashMap<[u8; UDP_SESSION_ID_SIZE], UdpSessionEntry>>,
}

struct UdpSessionEntry {
    last_client_packet: Option<u64>,
    responder: Arc<Shadowsocks2022UdpResponseSession>,
}

impl Shadowsocks2022UdpRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn responder_for(&self, session_id: [u8; UDP_SESSION_ID_SIZE]) -> Arc<Shadowsocks2022UdpResponseSession> {
        let mut guard = match self.sessions.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.len() >= 65536 {
            guard.clear();
        }
        let entry = guard.entry(session_id).or_insert_with(|| UdpSessionEntry {
            last_client_packet: None,
            responder: Arc::new(Shadowsocks2022UdpResponseSession::new(session_id)),
        });
        Arc::clone(&entry.responder)
    }

    fn check_replay(
        &self,
        session_id: [u8; UDP_SESSION_ID_SIZE],
        packet_id: u64,
    ) -> Result<(), TransportError> {
        let mut guard = match self.sessions.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.len() >= 65536 {
            guard.clear();
        }
        let entry = guard.entry(session_id).or_insert_with(|| UdpSessionEntry {
            last_client_packet: None,
            responder: Arc::new(Shadowsocks2022UdpResponseSession::new(session_id)),
        });
        match entry.last_client_packet {
            // An exact repeat of the newest id is a replay; slightly older ids
            // are tolerated for reordering inside a small window.
            Some(last) if packet_id == last => Err(TransportError::invalid_proxy_response(
                "shadowsocks 2022 udp packet replay detected",
            )),
            Some(last) if packet_id < last && last - packet_id > 32 => {
                Err(TransportError::invalid_proxy_response(
                    "shadowsocks 2022 udp packet replay detected",
                ))
            }
            Some(last) if packet_id <= last => Ok(()),
            _ => {
                entry.last_client_packet = Some(entry.last_client_packet.unwrap_or(packet_id).max(packet_id));
                Ok(())
            }
        }
    }
}

/// Per-session UDP state shared between packets of one relay session.
#[derive(Clone, Debug)]
pub struct Shadowsocks2022UdpState {
    session_id: [u8; UDP_SESSION_ID_SIZE],
    packet_id: u64,
}

impl Shadowsocks2022UdpState {
    /// Creates a client-side session with a random session id.
    pub fn client() -> Self {
        let mut session_id = [0_u8; UDP_SESSION_ID_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut session_id);
        Self {
            session_id,
            packet_id: 0,
        }
    }
}

/// Encrypts one client→server SIP022 UDP packet.
///
/// Layout (all AEAD-2022 UDP variants):
/// - AES-GCM: `separate_header(16) || AEAD body`, where the separate header
///   is `AES-ECB(psk, session_id || packet_id)` and the body key is
///   `blake3_derive("shadowsocks 2022 session subkey", psk || session_id)`
///   with nonce `separate_header[4..16]`.
/// - chacha20: `xnonce(24) || XChaCha20-Poly1305(psk, xnonce)` over the same
///   plaintext layout.
/// Plaintext: `session_id(8) || packet_id(8) || type(0) || timestamp(8) ||
/// padding_len(2) || padding || ATYP+addr+port || payload`.
pub fn encode_udp_packet(
    cipher: &str,
    password: &str,
    session: &mut Shadowsocks2022UdpState,
    target: &TransportTarget,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let kind = udp_cipher_kind(cipher)?;
    let psk = decode_psk(password, kind)?;
    let session_id = session.session_id;
    let packet_id = session.packet_id;
    session.packet_id = packet_id + 1;

    let plaintext = build_udp_plain_client(
        kind,
        &psk,
        session_id,
        packet_id,
        target,
        payload,
    )?;
    let (outer, ciphertext) = seal_udp_packet(kind, &psk, session_id, packet_id, &plaintext)?;
    let mut packet = outer;
    packet.extend_from_slice(&ciphertext);
    Ok(packet)
}

/// Decrypts one client→server SIP022 UDP packet, returning its target,
/// payload and the session responder used to encrypt server→client replies.
pub fn decode_udp_packet(
    cipher: &str,
    password: &str,
    registry: &Shadowsocks2022UdpRegistry,
    packet: &[u8],
) -> Result<
    (
        TransportTarget,
        Vec<u8>,
        std::sync::Arc<Shadowsocks2022UdpResponseSession>,
    ),
    TransportError,
> {
    let kind = udp_cipher_kind(cipher)?;
    let psk = decode_psk(password, kind)?;
    let (session_id, packet_id, plaintext) = open_udp_packet(kind, &psk, packet)?;
    registry.check_replay(session_id, packet_id)?;
    let responder = registry.responder_for(session_id);

    let (target, payload) = parse_udp_plain(&plaintext, UDP_TYPE_CLIENT)?;
    Ok((target, payload, responder))
}

/// Encrypts one server→client SIP022 UDP response packet.
pub fn encode_udp_response(
    cipher: &str,
    password: &str,
    session_id: [u8; UDP_SESSION_ID_SIZE],
    packet_id: u64,
    target: &TransportTarget,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let kind = udp_cipher_kind(cipher)?;
    let psk = decode_psk(password, kind)?;
    let plaintext = build_udp_plain_server(
        kind,
        &psk,
        session_id,
        packet_id,
        target,
        payload,
    )?;
    let (outer, ciphertext) = seal_udp_packet(kind, &psk, session_id, packet_id, &plaintext)?;
    let mut packet = outer;
    packet.extend_from_slice(&ciphertext);
    Ok(packet)
}

/// Decrypts one server→client SIP022 UDP response packet (client-side).
pub fn decode_udp_response(
    cipher: &str,
    password: &str,
    packet: &[u8],
) -> Result<(TransportTarget, Vec<u8>), TransportError> {
    let kind = udp_cipher_kind(cipher)?;
    let psk = decode_psk(password, kind)?;
    let (_session_id, _packet_id, plaintext) = open_udp_packet(kind, &psk, packet)?;
    let (target, payload) = parse_udp_plain(&plaintext, UDP_TYPE_SERVER)?;
    Ok((target, payload))
}

/// Builds the decrypted plaintext body for a client request packet:
/// session_id || packet_id || type || timestamp || padding || addr || payload.
fn build_udp_plain_client(
    kind: Shadowsocks2022Cipher,
    psk: &[u8],
    session_id: [u8; UDP_SESSION_ID_SIZE],
    packet_id: u64,
    target: &TransportTarget,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let mut plain = Vec::new();
    plain.extend_from_slice(&session_id);
    plain.extend_from_slice(&packet_id.to_be_bytes());
    plain.push(UDP_TYPE_CLIENT);
    plain.extend_from_slice(&unix_timestamp().to_be_bytes());
    plain.extend_from_slice(&0_u16.to_be_bytes()); // padding length
    plain.extend_from_slice(&encode_udp_target(target)?);
    plain.extend_from_slice(payload);
    let _ = kind;
    let _ = psk;
    Ok(plain)
}

/// Builds the decrypted plaintext body for a server response packet:
/// session_id || packet_id || type || timestamp || padding || addr || payload.
fn build_udp_plain_server(
    kind: Shadowsocks2022Cipher,
    psk: &[u8],
    session_id: [u8; UDP_SESSION_ID_SIZE],
    packet_id: u64,
    target: &TransportTarget,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let mut plain = Vec::new();
    plain.extend_from_slice(&session_id);
    plain.extend_from_slice(&packet_id.to_be_bytes());
    plain.push(UDP_TYPE_SERVER);
    plain.extend_from_slice(&unix_timestamp().to_be_bytes());
    plain.extend_from_slice(&0_u16.to_be_bytes());
    plain.extend_from_slice(&encode_udp_target(target)?);
    plain.extend_from_slice(payload);
    let _ = kind;
    let _ = psk;
    Ok(plain)
}

/// Parses the decrypted plaintext: validates type, timestamp and padding,
/// then returns the target and payload.
fn parse_udp_plain(
    plaintext: &[u8],
    expected_type: u8,
) -> Result<(TransportTarget, Vec<u8>), TransportError> {
    // session_id(8) + packet_id(8) + type(1) + timestamp(8) + padding_len(2)
    if plaintext.len() < UDP_SESSION_ID_SIZE + UDP_PACKET_ID_SIZE + 1 + 8 + 2 {
        return Err(TransportError::invalid_proxy_response(
            "short shadowsocks 2022 udp body",
        ));
    }
    let mut offset = UDP_SESSION_ID_SIZE + UDP_PACKET_ID_SIZE;
    if plaintext[offset] != expected_type {
        return Err(TransportError::invalid_proxy_response(
            "unexpected shadowsocks 2022 udp type",
        ));
    }
    offset += 1;
    let mut timestamp = [0_u8; 8];
    timestamp.copy_from_slice(&plaintext[offset..offset + 8]);
    if !timestamp_within_window(u64::from_be_bytes(timestamp)) {
        return Err(TransportError::invalid_proxy_response(
            "shadowsocks 2022 udp timestamp outside the replay window",
        ));
    }
    offset += 8;
    let padding_len = u16::from_be_bytes([plaintext[offset], plaintext[offset + 1]]) as usize;
    offset += 2;
    if padding_len > MAX_PADDING || plaintext.len() < offset + padding_len {
        return Err(TransportError::invalid_proxy_response(
            "invalid shadowsocks 2022 udp padding",
        ));
    }
    offset += padding_len;
    let (target, used) = decode_udp_target(&plaintext[offset..])?;
    offset += used;
    Ok((target, plaintext[offset..].to_vec()))
}

/// Seals one UDP packet: returns the outer header (separate header for AES,
/// random XNonce for chacha) and the AEAD ciphertext.
fn seal_udp_packet(
    kind: Shadowsocks2022Cipher,
    psk: &[u8],
    session_id: [u8; UDP_SESSION_ID_SIZE],
    packet_id: u64,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), TransportError> {
    match kind {
        Shadowsocks2022Cipher::Aes128Gcm | Shadowsocks2022Cipher::Aes256Gcm => {
            // separate header: session_id || packet_id, AES-ECB with the PSK.
            let mut separate = [0_u8; UDP_SEPARATE_HEADER_SIZE];
            separate[0..8].copy_from_slice(&session_id);
            separate[8..16].copy_from_slice(&packet_id.to_be_bytes());
            aes_ecb_apply(kind, psk, &mut separate, true);
            let body_key = udp_body_key(kind, psk, &separate[0..8])?;
            let aead = kind.make_aead(&body_key[..kind.key_size()])?;
            let mut nonce = [0_u8; 12];
            nonce.copy_from_slice(separate.get(4..16).unwrap_or(&[0_u8; 12]));
            let ciphertext = aead.encrypt_with_nonce(&nonce, plaintext)?;
            Ok((separate.to_vec(), ciphertext))
        }
        Shadowsocks2022Cipher::Chacha20Poly1305 => {
            let mut xnonce = [0_u8; 24];
            rand::rngs::OsRng.fill_bytes(&mut xnonce);
            let aead = Shadowsocks2022Aead::XChacha20(
                XChaCha20Poly1305::new_from_slice(psk)
                    .map_err(|err| TransportError::InvalidPlan(err.to_string()))?,
            );
            let ciphertext = aead.encrypt_with_nonce(&xnonce, plaintext)?;
            Ok((xnonce.to_vec(), ciphertext))
        }
    }
}

/// Opens one UDP packet: returns (session_id, packet_id, plaintext).
fn open_udp_packet(
    kind: Shadowsocks2022Cipher,
    psk: &[u8],
    packet: &[u8],
) -> Result<([u8; UDP_SESSION_ID_SIZE], u64, Vec<u8>), TransportError> {
    match kind {
        Shadowsocks2022Cipher::Aes128Gcm | Shadowsocks2022Cipher::Aes256Gcm => {
            if packet.len() < UDP_SEPARATE_HEADER_SIZE + TAG_SIZE {
                return Err(TransportError::invalid_proxy_response(
                    "short shadowsocks 2022 udp packet",
                ));
            }
            let mut separate = [0_u8; UDP_SEPARATE_HEADER_SIZE];
            separate.copy_from_slice(&packet[0..UDP_SEPARATE_HEADER_SIZE]);
            // The body key and nonce derive from the ENCRYPTED header bytes
            // (the receiving side cannot decrypt the header first because
            // the key depends on it).
            let body_key = udp_body_key(kind, psk, &separate[0..8])?;
            let mut nonce = [0_u8; 12];
            nonce.copy_from_slice(separate.get(4..16).unwrap_or(&[0_u8; 12]));
            aes_ecb_apply(kind, psk, &mut separate, false);
            let session_id: [u8; UDP_SESSION_ID_SIZE] = separate[0..8]
                .try_into()
                .map_err(|_| {
                    TransportError::invalid_proxy_response("reality: bad session id")
                })?;
            let packet_id = u64::from_be_bytes(separate[8..16].try_into().unwrap());
            let aead = kind.make_aead(&body_key[..kind.key_size()])?;
            let plaintext = aead.decrypt_with_nonce(
                &nonce,
                &packet[UDP_SEPARATE_HEADER_SIZE..],
            )?;
            Ok((session_id, packet_id, plaintext))
        }
        Shadowsocks2022Cipher::Chacha20Poly1305 => {
            if packet.len() < 24 + TAG_SIZE {
                return Err(TransportError::invalid_proxy_response(
                    "short shadowsocks 2022 chacha udp packet",
                ));
            }
            let mut xnonce = [0_u8; 24];
            xnonce.copy_from_slice(&packet[0..24]);
            let aead = Shadowsocks2022Aead::XChacha20(
                XChaCha20Poly1305::new_from_slice(psk)
                    .map_err(|err| TransportError::InvalidPlan(err.to_string()))?,
            );
            let plaintext = aead.decrypt_with_nonce(&xnonce, &packet[24..])?;
            if plaintext.len() < UDP_SESSION_ID_SIZE + UDP_PACKET_ID_SIZE {
                return Err(TransportError::invalid_proxy_response(
                    "short shadowsocks 2022 chacha udp plaintext",
                ));
            }
            let session_id: [u8; UDP_SESSION_ID_SIZE] = plaintext[0..8].try_into().unwrap();
            let packet_id = u64::from_be_bytes(plaintext[8..16].try_into().unwrap());
            Ok((session_id, packet_id, plaintext))
        }
    }
}

/// Derives the AES UDP body key: blake3_derive(context, psk || session_id).
fn udp_body_key(
    kind: Shadowsocks2022Cipher,
    psk: &[u8],
    session_id_bytes: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let mut material = Vec::with_capacity(psk.len() + session_id_bytes.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(session_id_bytes);
    let derived = blake3::derive_key(SUBKEY_CONTEXT, &material);
    Ok(derived.get(0..kind.key_size()).unwrap_or(&derived).to_vec())
}

fn udp_cipher_kind(cipher: &str) -> Result<Shadowsocks2022Cipher, TransportError> {
    Shadowsocks2022Cipher::parse(cipher).ok_or_else(|| {
        TransportError::InvalidPlan(format!("unsupported shadowsocks 2022 cipher {cipher}"))
    })
}

fn aes_ecb_apply(
    kind: Shadowsocks2022Cipher,
    psk: &[u8],
    block: &mut [u8; UDP_SEPARATE_HEADER_SIZE],
    encrypt: bool,
) {
    // 16-byte block = exactly one AES block, used as ECB (per SIP022).
    let block = GenericArray::from_mut_slice(block);
    match kind {
        Shadowsocks2022Cipher::Aes128Gcm => {
            let cipher = Aes128::new(GenericArray::from_slice(psk));
            if encrypt {
                cipher.encrypt_block(block);
            } else {
                cipher.decrypt_block(block);
            }
        }
        Shadowsocks2022Cipher::Aes256Gcm => {
            let cipher = Aes256::new(GenericArray::from_slice(psk));
            if encrypt {
                cipher.encrypt_block(block);
            } else {
                cipher.decrypt_block(block);
            }
        }
        Shadowsocks2022Cipher::Chacha20Poly1305 => {
            // Rejected earlier by udp_cipher_kind().
        }
    }
}

fn encode_udp_target(target: &TransportTarget) -> Result<Vec<u8>, TransportError> {
    let mut encoded = encode_socks5_target(target)?;
    encoded.extend_from_slice(&target.port.to_be_bytes());
    Ok(encoded)
}

fn decode_udp_target(payload: &[u8]) -> Result<(TransportTarget, usize), TransportError> {
    let mut offset = 0;
    let Some(&atyp) = payload.first() else {
        return Err(TransportError::invalid_proxy_response(
            "shadowsocks 2022 udp target is empty",
        ));
    };
    offset += 1;
    let host = match atyp {
        0x01 => {
            if payload.len() < offset + 4 {
                return Err(TransportError::invalid_proxy_response(
                    "truncated shadowsocks 2022 udp ipv4 target",
                ));
            }
            let octets = &payload[offset..offset + 4];
            offset += 4;
            std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]).to_string()
        }
        0x04 => {
            if payload.len() < offset + 16 {
                return Err(TransportError::invalid_proxy_response(
                    "truncated shadowsocks 2022 udp ipv6 target",
                ));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&payload[offset..offset + 16]);
            offset += 16;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        0x03 => {
            let Some(&length) = payload.get(offset) else {
                return Err(TransportError::invalid_proxy_response(
                    "missing shadowsocks 2022 udp domain length",
                ));
            };
            offset += 1;
            let length = length as usize;
            if payload.len() < offset + length {
                return Err(TransportError::invalid_proxy_response(
                    "truncated shadowsocks 2022 udp domain target",
                ));
            }
            let host =
                String::from_utf8_lossy(&payload[offset..offset + length]).into_owned();
            offset += length;
            host
        }
        other => {
            return Err(TransportError::invalid_proxy_response(format!(
                "unsupported shadowsocks 2022 udp address type {other}"
            )))
        }
    };
    if payload.len() < offset + 2 {
        return Err(TransportError::invalid_proxy_response(
            "missing shadowsocks 2022 udp target port",
        ));
    }
    let port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    offset += 2;
    Ok((TransportTarget::new(host, port), offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    const PSK_256: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    const PSK_128: &str = "AQIDBAUGBwgJCgsMDQ4PEA==";

    #[test]
    fn udp_packet_round_trip() {
        for cipher in [
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        ] {
            let psk = if cipher.contains("128") { PSK_128 } else { PSK_256 };
            let mut state = Shadowsocks2022UdpState::client();
            let target = TransportTarget::new("example.com", 53);
            let packet = encode_udp_packet(cipher, psk, &mut state, &target, b"query")
                .unwrap_or_else(|err| panic!("[dbg] {cipher} encode failed: {err}"));
            let registry = Shadowsocks2022UdpRegistry::new();
            let (decoded_target, payload, _responder) =
                decode_udp_packet(cipher, psk, &registry, &packet)
                    .unwrap_or_else(|err| panic!("[dbg] {cipher} decode failed: {err}"));
            assert_eq!(decoded_target.authority(), "example.com:53");
            assert_eq!(payload, b"query");
        }
    }

    #[test]
    fn udp_replayed_packet_is_rejected() {
        for cipher in [
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        ] {
            let mut state = Shadowsocks2022UdpState::client();
            let target = TransportTarget::new("example.com", 53);
            let packet =
                encode_udp_packet(cipher, PSK_256, &mut state, &target, b"query").unwrap();
            let registry = Shadowsocks2022UdpRegistry::new();
            decode_udp_packet(cipher, PSK_256, &registry, &packet).unwrap();
            let err = decode_udp_packet(cipher, PSK_256, &registry, &packet).unwrap_err();
            assert!(err.to_string().contains("replay"), "{err}");
        }
    }

    #[test]
    fn udp_server_response_round_trip() {
        for cipher in [
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        ] {
            let psk = if cipher.contains("128") { PSK_128 } else { PSK_256 };
            let mut state = Shadowsocks2022UdpState::client();
            let target = TransportTarget::new("example.com", 53);
            let packet = encode_udp_packet(cipher, psk, &mut state, &target, b"query").unwrap();
            let registry = Shadowsocks2022UdpRegistry::new();
            let (_target, _payload, responder) =
                decode_udp_packet(cipher, psk, &registry, &packet).unwrap();
            let reply = responder.encode_response(cipher, psk, &target, b"answer").unwrap();
            let (reply_target, answer) = decode_udp_response(cipher, psk, &reply).unwrap();
            assert_eq!(reply_target.authority(), "example.com:53");
            assert_eq!(answer, b"answer");
        }
    }

    #[test]
    fn client_server_stream_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (target, mut server) =
                accept_stream(Box::new(stream), "2022-blake3-aes-256-gcm", PSK_256).unwrap();
            assert_eq!(target.authority(), "example.com:443");
            let mut buf = [0_u8; 4];
            server.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            server.write_all(b"pong").unwrap();
            server.flush().unwrap();
        });
        let stream = std::net::TcpStream::connect(addr).unwrap();
        let mut client = wrap_stream(
            Box::new(stream),
            "2022-blake3-aes-256-gcm",
            PSK_256,
            &TransportTarget::new("example.com", 443),
        )
        .unwrap();
        client.write_all(b"ping").unwrap();
        client.flush().unwrap();
        let mut buf = [0_u8; 4];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        worker.join().unwrap();
    }
}
