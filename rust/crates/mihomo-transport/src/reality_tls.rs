//! XTLS REALITY protocol (TLS 1.3 camouflaged proxy handshake).
//!
//! Full protocol notes live in PROGRESS.md. The module implements:
//! - REALITY ClientHello parsing and session_id seal verification.
//! - The camouflage ServerHello mirroring with a fresh key_share.
//! - A minimal RFC 8446 TLS 1.3 handshake on top of the negotiated suite.
//! - The Ed25519 proof-of-server certificate scheme.
//! - Transparent fallback relaying to the camouflage site.

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{self, Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use base64::Engine as _;
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::{Signer as _, SigningKey};
use hkdf::Hkdf;
use mihomo_core::{BoxedTcpStream, TcpStream};
use ml_kem::kem::Decapsulate as _;
use ml_kem::KeyExport as _;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};

use crate::{TransportError, TransportTarget};

const SID_LEN: usize = 32;
const RANDOM_LEN: usize = 32;
const HKDF_REALITY_INFO: &[u8] = b"REALITY";
const TAG_SIZE: usize = 16;
const RECORD_HEADER_LEN: usize = 5;
const RECORD_TYPE_HANDSHAKE: u8 = 22;
const RECORD_TYPE_CHANGE_CIPHER: u8 = 20;
const RECORD_TYPE_APPLICATION: u8 = 23;
const TLS13_VERSION: u16 = 0x0304;
const TLS12_VERSION_BYTES: [u8; 2] = [0x03, 0x03];
const GROUP_X25519: u16 = 0x001d;
const GROUP_X25519_MLKEM768: u16 = 0x11ec;
const SUITE_AES_128_GCM_SHA256: u16 = 0x1301;
const SUITE_AES_256_GCM_SHA384: u16 = 0x1302;
const SUITE_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
const HS_TYPE_CLIENT_HELLO: u8 = 1;
/// RFC 8446 §4.4.3 context strings (the NUL is part of the context).
const SERVER_CV_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify\x00";
const CLIENT_CV_CONTEXT: &[u8] = b"TLS 1.3, client CertificateVerify\x00";
/// RFC 8446 Appendix D.4 middlebox-compatibility ChangeCipherSpec record.
const DUMMY_CCS_RECORD: [u8; 6] = [RECORD_TYPE_CHANGE_CIPHER, 3, 3, 0, 1, 0x01];
const HS_TYPE_SERVER_HELLO: u8 = 2;
const HS_TYPE_CERTIFICATE: u8 = 11;
const HS_TYPE_CERTIFICATE_VERIFY: u8 = 15;
const HS_TYPE_FINISHED: u8 = 20;
const EXT_SERVER_NAME: u16 = 0;
const EXT_ALPN: u16 = 16;
const EXT_KEY_SHARE: u16 = 51;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const HS_TYPE_ENCRYPTED_EXTENSIONS: u8 = 8;
const SIG_ALG_ED25519: u16 = 0x0807;
const MLKEM_ENCAP_KEY_SIZE: usize = 1184;
const MLKEM_CIPHERTEXT_SIZE: usize = 1088;
const DEFAULT_MAX_TIME_DIFF: Duration = Duration::from_secs(60);

/// Key material for one REALITY endpoint.
#[derive(Clone, Debug)]
pub struct RealityKeys {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

/// Generates a REALITY X25519 keypair (`generate reality-keypair` parity).
pub fn generate_keypair() -> RealityKeys {
    let mut private_key = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut private_key);
    private_key[0] = private_key[0] & 248;
    private_key[31] = (private_key[31] & 127) | 64;
    let secret = XSecret::from(private_key);
    let public = XPublic::from(&secret).to_bytes();
    RealityKeys {
        private_key,
        public_key: public,
    }
}

fn x25519(private_key: &[u8; 32], peer: &[u8; 32]) -> Option<[u8; 32]> {
    let secret = XSecret::from(*private_key);
    let public = XPublic::from(*peer);
    Some(secret.diffie_hellman(&public).to_bytes())
}

type HkdfSha256 = Hkdf<Sha256>;

/// HKDF-SHA256 with the REALITY label: salt is the first 20 bytes of the
/// ClientHello random, matching the Go reference implementation.
fn reality_auth_key(shared: &[u8; 32], random: &[u8; RANDOM_LEN]) -> [u8; 32] {
    let salt = random.get(0..20).unwrap_or(&[]);
    let hk = HkdfSha256::new(Some(salt), shared);
    let mut key = [0_u8; 32];
    hk.expand(HKDF_REALITY_INFO, &mut key)
        .expect("32 byte output is valid");
    key
}

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

// ---------------------------------------------------------------------------
// Handshake message parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct ClientHelloView {
    /// The full handshake message bytes (record header excluded). The
    /// session_id seal is patched in place inside this vector.
    pub original: Vec<u8>,
    pub random: [u8; RANDOM_LEN],
    pub session_id_offset: usize,
    pub session_id_len: usize,
    /// (group, offset of share data inside `original`, share length)
    pub key_shares: Vec<(u16, usize, usize)>,
    pub server_name: String,
}

impl ClientHelloView {
    /// The dedicated X25519 share wins for the auth derivation; otherwise
    /// the trailing 32 bytes of the X25519MLKEM768 share are used.
    fn auth_peer_pub(&self) -> Option<[u8; 32]> {
        let mut mlkem_pub = None;
        for (group, offset, len) in &self.key_shares {
            if *group == GROUP_X25519 && *len == 32 {
                let mut key = [0_u8; 32];
                key.copy_from_slice(&self.original[*offset..*offset + 32]);
                return Some(key);
            }
            if *group == GROUP_X25519_MLKEM768 && *len == MLKEM_ENCAP_KEY_SIZE + 32 {
                let start = *offset + MLKEM_ENCAP_KEY_SIZE;
                let mut key = [0_u8; 32];
                key.copy_from_slice(&self.original[start..start + 32]);
                mlkem_pub = Some(key);
            }
        }
        mlkem_pub
    }

    fn patch_session_id(&mut self, ciphertext: &[u8; SID_LEN]) {
        if self.session_id_len == SID_LEN {
            self.original[self.session_id_offset..self.session_id_offset + SID_LEN]
                .copy_from_slice(ciphertext);
        }
    }
}

/// Parses a ClientHello handshake message. Only REALITY-relevant fields are
/// extracted; unknown extensions are skipped exactly like the Go reference.
pub(crate) fn parse_client_hello(hs: &[u8]) -> Option<ClientHelloView> {
    if hs.first() != Some(&HS_TYPE_CLIENT_HELLO) {
        return None;
    }
    if hs.len() < 36 {
        return None;
    }
    let body_len = handshake_message_len(hs);
    if hs.len() < body_len {
        return None;
    }
    let mut cursor = 4_usize;
    let mut random = [0_u8; RANDOM_LEN];
    random.copy_from_slice(&hs[cursor + 2..cursor + 2 + RANDOM_LEN]);
    cursor += 2 + RANDOM_LEN;
    let session_id_len = hs[cursor] as usize;
    cursor += 1;
    let session_id_offset = cursor;
    if hs.len() < cursor + session_id_len + 2 {
        return None;
    }
    cursor += session_id_len;
    let suites_len = u16::from_be_bytes([hs[cursor], hs[cursor + 1]]) as usize;
    cursor += 2 + suites_len;
    if hs.len() <= cursor {
        return None;
    }
    let compression_len = hs[cursor] as usize;
    cursor += 1 + compression_len;
    if hs.len() < cursor + 2 {
        return None;
    }
    let ext_total = u16::from_be_bytes([hs[cursor], hs[cursor + 1]]) as usize;
    cursor += 2;
    if hs.len() < cursor + ext_total {
        return None;
    }
    let mut key_shares = Vec::new();
    let mut server_name = String::new();
    let mut exts = cursor;
    let exts_end = cursor + ext_total;
    while exts + 4 <= exts_end {
        let ext_type = u16::from_be_bytes([hs[exts], hs[exts + 1]]);
        let ext_len = u16::from_be_bytes([hs[exts + 2], hs[exts + 3]]) as usize;
        if exts + 4 + ext_len > exts_end {
            return None;
        }
        let data_start = exts + 4;
        match ext_type {
            EXT_SERVER_NAME => {
                // host_name list: uint16 list len, uint8 type, uint16 len, name
                if ext_len >= 5 && hs[data_start + 2] == 0 {
                    let name_len = u16::from_be_bytes([hs[data_start + 3], hs[data_start + 4]])
                        as usize;
                    if ext_len >= 5 + name_len {
                        server_name =
                            String::from_utf8_lossy(&hs[data_start + 5..data_start + 5 + name_len])
                                .into_owned();
                    }
                }
            }
            EXT_KEY_SHARE => {
                if ext_len < 2 { return None; }
                let vector_len = u16::from_be_bytes([hs[data_start], hs[data_start+1]]) as usize;
                if vector_len + 2 != ext_len { return None; }
                let mut share = data_start + 2;
                let share_end = data_start + ext_len;
                while share + 4 <= share_end {
                    let group = u16::from_be_bytes([hs[share], hs[share + 1]]);
                    let share_len =
                        u16::from_be_bytes([hs[share + 2], hs[share + 3]]) as usize;
                    if share + 4 + share_len > share_end {
                        break;
                    }
                    key_shares.push((group, share + 4, share_len));
                    share += 4 + share_len;
                }
            }
            _ => {}
        }
        exts = data_start + ext_len;
    }
    Some(ClientHelloView {
        original: hs.to_vec(),
        random,
        session_id_offset,
        session_id_len,
        key_shares,
        server_name,
    })
}


fn array32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out.copy_from_slice(bytes.get(0..32).unwrap_or(&[0_u8; 32]));
    out
}


fn resolve_dest(dest: &str) -> io::Result<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    dest.to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "reality dest unresolved"))
}

/// Reads one plaintext TLS record, returning (type, payload).
fn read_plain_record(stream: &mut dyn Read) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0_u8; RECORD_HEADER_LEN];
    stream.read_exact(&mut header)?;
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    if header[1] != 3 || header[2] > 3 || length > 16 * 1024 + 256 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "reality: invalid TLS record header"));
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok((header[0], payload))
}

/// Accumulates bytes from the camouflage site until a well-formed TLS 1.3
/// ServerHello has been captured.
fn read_dest_server_hello(
    target: &mut std::net::TcpStream,
) -> Result<ServerHelloView, TransportError> {
    let bytes = read_server_hello_message(target)?;
    parse_server_hello(&bytes).ok_or_else(|| {
        TransportError::invalid_proxy_response(
            "reality: dest ServerHello is not TLS 1.3 with a supported share",
        )
    })
}

fn tls_alert_error(stage: &str, payload: &[u8]) -> TransportError {
    if payload.len() != 2 {
        return TransportError::invalid_proxy_response(format!("reality: malformed TLS alert {stage}"));
    }
    let name = match payload[1] {
        0 => "close_notify", 10 => "unexpected_message", 20 => "bad_record_mac",
        40 => "handshake_failure", 42 => "bad_certificate", 47 => "illegal_parameter",
        48 => "unknown_ca", 50 => "decode_error", 51 => "decrypt_error",
        70 => "protocol_version", 80 => "internal_error", 90 => "user_canceled",
        109 => "missing_extension", 110 => "unsupported_extension",
        112 => "unrecognized_name", 120 => "no_application_protocol", _ => "unknown_alert",
    };
    TransportError::invalid_proxy_response(format!(
        "reality: TLS alert {stage}: {name} ({}), level={}", payload[1], payload[0],
    ))
}

/// A handshake message can span TLS records; TCP reads need not align with
/// either boundary. Preserve each fragment until the entire ServerHello exists.
fn read_server_hello_message(stream: &mut dyn Read) -> Result<Vec<u8>, TransportError> {
    let mut message = Vec::new();
    for _ in 0..256 {
        let (record_type, payload) = read_record_skipping_ccs(stream).map_err(|err| {
            TransportError::invalid_proxy_response(format!(
                "reality: reading ServerHello ({} handshake bytes received): {err}", message.len(),
            ))
        })?;
        if record_type == 21 { return Err(tls_alert_error("before ServerHello", &payload)); }
        if record_type != RECORD_TYPE_HANDSHAKE {
            return Err(TransportError::invalid_proxy_response(format!(
                "reality: expected ServerHello handshake record, received TLS record type {record_type}",
            )));
        }
        message.extend_from_slice(&payload);
        if message.len() < 4 { continue; }
        let length = handshake_message_len(&message);
        if message[0] != HS_TYPE_SERVER_HELLO || length > 128 * 1024 {
            return Err(TransportError::invalid_proxy_response("reality: invalid ServerHello handshake"));
        }
        if message.len() >= length {
            if message.len() != length {
                return Err(TransportError::invalid_proxy_response("reality: unexpected plaintext after ServerHello"));
            }
            return Ok(message);
        }
    }
    Err(TransportError::invalid_proxy_response("reality: ServerHello exceeded fragment limit"))
}


fn handshake_message_len(hs: &[u8]) -> usize {
    4 + ((u32::from(hs[1]) << 16) | (u32::from(hs[2]) << 8) | u32::from(hs[3])) as usize
}

#[derive(Debug)]
pub(crate) struct ServerHelloView {
    /// Camouflage site ServerHello bytes; the key_share region is patched
    /// in place before the record is forwarded to the REALITY client.
    pub original: Vec<u8>,
    pub share_data: Vec<u8>,
    pub record_header: [u8; RECORD_HEADER_LEN],
    pub cipher_suite: u16,
    pub share_group: u16,
    pub share_offset: usize,
    pub share_len: usize,
}

impl ServerHelloView {
    fn patch_share(&mut self, data: &[u8]) {
        self.original[self.share_offset..self.share_offset + self.share_len]
            .copy_from_slice(data);
    }
}

/// Parses and validates the camouflage site's ServerHello. The site must
/// negotiate TLS 1.3 with an X25519 or X25519MLKEM768 key share.
pub(crate) fn parse_server_hello(hs: &[u8]) -> Option<ServerHelloView> {
    if hs.first() != Some(&HS_TYPE_SERVER_HELLO) || hs.len() < 40 {
        return None;
    }
    let body_len = handshake_message_len(hs);
    if hs.len() < body_len {
        return None;
    }
    let mut cursor = 4 + 2 + RANDOM_LEN;
    let session_id_len = hs[cursor] as usize;
    cursor += 1 + session_id_len;
    if hs.len() < cursor + 3 {
        return None;
    }
    let cipher_suite = u16::from_be_bytes([hs[cursor], hs[cursor + 1]]);
    cursor += 2;
    cursor += 1; // compression method
    if hs.len() < cursor + 2 {
        return None;
    }
    let ext_total = u16::from_be_bytes([hs[cursor], hs[cursor + 1]]) as usize;
    cursor += 2;
    if hs.len() < cursor + ext_total {
        return None;
    }
    let mut share_group = 0_u16;
    let mut share_offset = 0_usize;
    let mut share_len = 0_usize;
    let mut exts = cursor;
    let exts_end = cursor + ext_total;
    while exts + 4 <= exts_end {
        let ext_type = u16::from_be_bytes([hs[exts], hs[exts + 1]]);
        let ext_len = u16::from_be_bytes([hs[exts + 2], hs[exts + 3]]) as usize;
        if exts + 4 + ext_len > exts_end {
            return None;
        }
        if ext_type == EXT_KEY_SHARE && ext_len >= 4 {
            share_group = u16::from_be_bytes([hs[exts + 4], hs[exts + 5]]);
            share_len = u16::from_be_bytes([hs[exts + 6], hs[exts + 7]]) as usize;
            share_offset = exts + 8;
            if exts + 8 + share_len > exts_end {
                return None;
            }
        }
        if ext_type == EXT_SUPPORTED_VERSIONS {
            if ext_len != 2
                || u16::from_be_bytes([hs[exts + 4], hs[exts + 5]]) != TLS13_VERSION
            {
                return None;
            }
        }
        exts = exts + 4 + ext_len;
    }
    let share_ok = (share_group == GROUP_X25519 && share_len == 32)
        || (share_group == GROUP_X25519_MLKEM768
            && share_len == MLKEM_CIPHERTEXT_SIZE + 32);
    if share_len == 0 || !share_ok {
        return None;
    }
    Some(ServerHelloView {
        share_data: hs[share_offset..share_offset + share_len].to_vec(),
        original: hs.to_vec(),
        record_header: [RECORD_TYPE_HANDSHAKE, 3, 3, 0, 0],
        cipher_suite,
        share_group,
        share_offset,
        share_len,
    })
}

// ---------------------------------------------------------------------------
// TLS 1.3 key schedule and record layer
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
}

impl CipherSuite {
    fn from_id(id: u16) -> Option<Self> {
        match id {
            SUITE_AES_128_GCM_SHA256 => Some(Self::Aes128GcmSha256),
            SUITE_AES_256_GCM_SHA384 => Some(Self::Aes256GcmSha384),
            SUITE_CHACHA20_POLY1305_SHA256 => Some(Self::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    fn key_size(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::Chacha20Poly1305Sha256 => 32,
        }
    }
}

type HkdfSha384 = Hkdf<Sha384>;

/// HKDF-Extract per the negotiated suite (SHA-384 for the AES-256-GCM
/// suite, SHA-256 otherwise), returning the pseudo-random key.
fn hkdf_extract(suite: CipherSuite, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match suite {
        CipherSuite::Aes256GcmSha384 => HkdfSha384::extract(Some(salt), ikm).0.to_vec(),
        _ => HkdfSha256::extract(Some(salt), ikm).0.to_vec(),
    }
}

fn hkdf_expand_label(
    suite: CipherSuite,
    secret: &[u8],
    label: &str,
    context: &[u8],
    len: usize,
) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let mut hkdf_label = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    hkdf_label.extend_from_slice(&(len as u16).to_be_bytes());
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(full_label.as_bytes());
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);
    let mut out = vec![0_u8; len];
    let expanded = match suite {
        CipherSuite::Aes256GcmSha384 => match HkdfSha384::from_prk(secret) {
            Ok(hk) => hk.expand(&hkdf_label, &mut out).is_ok(),
            Err(_) => false,
        },
        _ => match HkdfSha256::from_prk(secret) {
            Ok(hk) => hk.expand(&hkdf_label, &mut out).is_ok(),
            Err(_) => false,
        },
    };
    if expanded {
        out
    } else {
        Vec::new()
    }
}

/// Incremental TLS 1.3 transcript hash. The hash function follows the
/// negotiated suite: SHA-384 for TLS_AES_256_GCM_SHA384, SHA-256 otherwise
/// (RFC 8446, Appendix B.4).
#[derive(Clone)]
enum TranscriptState {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl TranscriptState {
    fn new(suite: CipherSuite) -> Self {
        match suite {
            CipherSuite::Aes256GcmSha384 => Self::Sha384(Sha384::new()),
            _ => Self::Sha256(Sha256::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(hasher) => hasher.update(data),
            Self::Sha384(hasher) => hasher.update(data),
        }
    }

    /// Consume the state and return the transcript hash.
    fn chain(self) -> Vec<u8> {
        match self {
            Self::Sha256(hasher) => hasher.finalize().to_vec(),
            Self::Sha384(hasher) => hasher.finalize().to_vec(),
        }
    }

    /// Hash of the transcript up to this point, leaving the state usable.
    fn snapshot_hash(&self) -> Vec<u8> {
        self.clone().chain()
    }
}

/// Finished HMAC per the negotiated suite's hash.
fn hmac_suite(suite: CipherSuite, key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::Mac as _;
    match suite {
        CipherSuite::Aes256GcmSha384 => {
            let mut mac = <hmac::Hmac<Sha384> as hmac::Mac>::new_from_slice(key)
                .expect("hmac accepts any key length");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        _ => hmac_sha256(key, data),
    }
}

/// Nonce = IV XOR the 64-bit sequence number placed in the tail bytes.
fn seq_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let counter = seq.to_be_bytes();
    let mut nonce = [0_u8; 12];
    for index in 0..4 {
        nonce[index] = iv[index];
    }
    for index in 0..8 {
        nonce[index + 4] = iv[index + 4] ^ counter[index];
    }
    nonce
}

#[derive(Clone)]
enum SuiteAead {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    Chacha20(ChaCha20Poly1305),
}

impl SuiteAead {
    fn new(suite: CipherSuite, key: &[u8]) -> Option<Self> {
        Some(match suite {
            CipherSuite::Aes128GcmSha256 => {
                Self::Aes128(Aes128Gcm::new_from_slice(key).ok()?)
            }
            CipherSuite::Aes256GcmSha384 => {
                Self::Aes256(Aes256Gcm::new_from_slice(key).ok()?)
            }
            CipherSuite::Chacha20Poly1305Sha256 => {
                Self::Chacha20(ChaCha20Poly1305::new_from_slice(key).ok()?)
            }
        })
    }

    fn seal(&self, iv: &[u8; 12], seq: u64, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let nonce = seq_nonce(iv, seq);
        let mut header = aad.to_vec();
        if header.len() == 3 {
            header.extend_from_slice(&((plaintext.len() + TAG_SIZE) as u16).to_be_bytes());
        }
        let payload = aead::Payload {
            msg: plaintext,
            aad: &header,
        };
        match self {
            Self::Aes128(cipher) => cipher.encrypt(Nonce::from_slice(&nonce), payload),
            Self::Aes256(cipher) => cipher.encrypt(Nonce::from_slice(&nonce), payload),
            Self::Chacha20(cipher) => cipher.encrypt(Nonce::from_slice(&nonce), payload),
        }
        .unwrap_or_default()
    }

    fn open(&self, iv: &[u8; 12], seq: u64, ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        let nonce = seq_nonce(iv, seq);
        let mut header = aad.to_vec();
        if header.len() == 3 {
            header.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
        }
        let payload = aead::Payload {
            msg: ciphertext,
            aad: &header,
        };
        match self {
            Self::Aes128(cipher) => cipher.decrypt(Nonce::from_slice(&nonce), payload),
            Self::Aes256(cipher) => cipher.decrypt(Nonce::from_slice(&nonce), payload),
            Self::Chacha20(cipher) => cipher.decrypt(Nonce::from_slice(&nonce), payload),
        }
        .ok()
    }
}

/// TLSInnerPlaintext is content || type || zero padding (RFC 8446 §5.2).
/// Locate the type before removing padding so content ending in zero bytes is
/// preserved. REALITY's disguised ticket can be an empty application record.
fn decode_inner_plaintext(mut plaintext: Vec<u8>) -> io::Result<(u8, Vec<u8>)> {
    let type_offset = plaintext.iter().rposition(|byte| *byte != 0).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "reality: missing TLS inner content type",
        )
    })?;
    let content_type = plaintext[type_offset];
    if !matches!(content_type, 21..=23) || type_offset > 16 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reality: invalid TLS inner plaintext",
        ));
    }
    plaintext.truncate(type_offset);
    Ok((content_type, plaintext))
}

// ---------------------------------------------------------------------------
// REALITY configuration and shared helpers
// ---------------------------------------------------------------------------

/// Inbound REALITY configuration (mirrors Go `reality.Config`).
#[derive(Clone, Debug)]
pub struct RealityServerConfig {
    /// X25519 private key (base64 URL_SAFE_NO_PAD in the YAML config).
    pub private_key: [u8; 32],
    /// SNI allowlist (the ClientHello server_name must be listed here).
    pub server_names: Vec<String>,
    /// Accepted 8-byte short ids (hex strings in the YAML config).
    pub short_ids: Vec<[u8; 8]>,
    /// Camouflage site, e.g. "www.microsoft.com:443".
    pub dest: String,
    /// Maximum allowed clock difference (seconds); zero means unlimited.
    pub max_time_diff: u64,
}

impl RealityServerConfig {
    pub fn parse_private_key(value: &str) -> Result<[u8; 32], TransportError> {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value.trim().as_bytes())
            .map_err(|err| {
                TransportError::InvalidPlan(format!("reality private-key decode failed: {err}"))
            })?;
        if decoded.len() != 32 {
            return Err(TransportError::InvalidPlan(format!(
                "reality private-key must decode to 32 bytes, got {}",
                decoded.len()
            )));
        }
        let mut key = [0_u8; 32];
        key.copy_from_slice(&decoded);
        Ok(key)
    }

    pub fn parse_short_id(value: &str) -> Result<[u8; 8], TransportError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Ok([0_u8; 8]);
        }
        let decoded = hex::decode(trimmed).map_err(|err| {
            TransportError::InvalidPlan(format!("reality short-id must be hex: {err}"))
        })?;
        if decoded.len() > 8 {
            return Err(TransportError::InvalidPlan(
                "reality short-id must be at most 8 bytes".to_owned(),
            ));
        }
        let mut id = [0_u8; 8];
        id[..decoded.len()].copy_from_slice(&decoded);
        Ok(id)
    }
}

/// Outbound REALITY configuration (mirrors the client side of the config).
#[derive(Clone, Debug, Default)]
pub struct RealityClientConfig {
    /// X25519 public key of the server (base64 URL_SAFE_NO_PAD in YAML).
    pub public_key: [u8; 32],
    /// The 8-byte short id registered on the server.
    pub short_id: [u8; 8],
    /// SNI presented in the ClientHello (must be on the server allowlist).
    pub server_name: String,
    /// Enable the hybrid group only when the server supports it (Go parity).
    pub support_x25519mlkem768: bool,
    /// Empty selects the browser-compatible h2/http/1.1 default.
    pub alpn: Vec<String>,
}

pub fn parse_client_public_key(value: &str) -> Result<[u8; 32], TransportError> {
    RealityServerConfig::parse_private_key(value)
}

pub fn parse_client_short_id_for_reality(value: &str) -> Result<[u8; 8], TransportError> {
    RealityServerConfig::parse_short_id(value)
}

fn parse_client_short_id(value: &str) -> Result<[u8; 8], TransportError> {
    RealityServerConfig::parse_short_id(value)
}

fn seal_session_id(
    auth_key: &[u8; 32],
    random: &[u8; RANDOM_LEN],
    original: &[u8],
    plain: &[u8; 16],
) -> [u8; SID_LEN] {
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(random.get(20..32).unwrap_or(&[0_u8; 12]));
    let aead = Aes256Gcm::new_from_slice(auth_key).expect("256 bit key");
    let sealed = aead
        .encrypt(
            Nonce::from_slice(&nonce),
            aead::Payload {
                msg: plain,
                aad: original,
            },
        )
        .expect("seal cannot fail for valid inputs");
    let mut out = [0_u8; SID_LEN];
    out.copy_from_slice(&sealed);
    out
}

fn open_session_id(
    auth_key: &[u8; 32],
    random: &[u8; RANDOM_LEN],
    original: &[u8],
    sealed: &[u8],
) -> Option<[u8; 16]> {
    if sealed.len() != SID_LEN {
        return None;
    }
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(random.get(20..32)?);
    let aead = Aes256Gcm::new_from_slice(auth_key).ok()?;
    let plain = aead
        .decrypt(
            Nonce::from_slice(&nonce),
            aead::Payload {
                msg: sealed,
                aad: original,
            },
        )
        .ok()?;
    if plain.len() != 16 {
        return None;
    }
    let mut out = [0_u8; 16];
    out.copy_from_slice(&plain);
    Some(out)
}

// ---------------------------------------------------------------------------
// Proof-of-server certificate
// ---------------------------------------------------------------------------

/// Per-process Ed25519 signing key, matching the Go implementation's init().
fn process_signing_key() -> &'static SigningKey {
    static KEY: OnceLock<SigningKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut seed = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    })
}

/// Builds the DER of an Ed25519 self-signed certificate template whose
/// trailing 64-byte signature slot will be replaced by
/// HMAC-SHA512(AuthKey, embedded_public_key).
fn der_value(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut der = vec![tag];
    if value.len() < 128 { der.push(value.len() as u8); }
    else if value.len() < 256 { der.extend_from_slice(&[0x81, value.len() as u8]); }
    else { der.push(0x82); der.extend_from_slice(&(value.len() as u16).to_be_bytes()); }
    der.extend_from_slice(value);
    der
}

fn build_certificate_der(public_key: &[u8; 32]) -> Vec<u8> {
    let alg = der_value(0x30, &[0x06, 0x03, 0x2b, 0x65, 0x70]);
    let mut tbs = vec![0xa0, 3, 2, 1, 2, 2, 1, 1]; // v3, serial 1
    tbs.extend_from_slice(&alg);
    tbs.extend_from_slice(&[0x30, 0]); // issuer
    let mut validity = der_value(0x17, b"250101000000Z");
    validity.extend_from_slice(&der_value(0x17, b"491231235959Z"));
    tbs.extend_from_slice(&der_value(0x30, &validity));
    tbs.extend_from_slice(&[0x30, 0]); // subject
    let mut spki = alg.clone();
    let mut public_bits = vec![0];
    public_bits.extend_from_slice(public_key);
    spki.extend_from_slice(&der_value(3, &public_bits));
    tbs.extend_from_slice(&der_value(0x30, &spki));
    let mut certificate = der_value(0x30, &tbs);
    certificate.extend_from_slice(&alg);
    certificate.extend_from_slice(&der_value(3, &[0; 65]));
    der_value(0x30, &certificate)
}

fn reality_certificate_proof(auth_key: &[u8; 32], public: &[u8; 32]) -> Vec<u8> {
    use hmac::Mac as _;
    let mut mac = <hmac::Hmac<Sha512> as hmac::Mac>::new_from_slice(auth_key)
        .expect("HMAC accepts a 32-byte key");
    mac.update(public);
    mac.finalize().into_bytes().to_vec()
}

/// Builds the certificate whose signature slot carries
/// HMAC-SHA512(AuthKey, embedded Ed25519 public key).
fn reality_certificate(auth_key: &[u8; 32]) -> (Vec<u8>, SigningKey) {
    let signing = process_signing_key().clone();
    let public = signing.verifying_key().to_bytes();
    let mut der = build_certificate_der(&public);
    let mac_out = reality_certificate_proof(auth_key, &public);
    let start = der.len() - 64;
    der[start..start + 64].copy_from_slice(&mac_out);
    (der, signing)
}

// ---------------------------------------------------------------------------
// Server side (inbound listener)
// ---------------------------------------------------------------------------

fn hex_short_ids(short_ids: &[[u8; 8]]) -> BTreeSet<[u8; 8]> {
    short_ids.iter().copied().collect()
}

/// Bidirectional byte relay used for the steal fallback path.
fn relay_bidirectional(
    mut client: BoxedTcpStream,
    mut target: std::net::TcpStream,
    initial_client_to_target: &[u8],
) {
    let mut client_read = match client.try_clone_box() {
        Ok(cloned) => cloned,
        Err(_) => return,
    };
    let mut client_write = match client.try_clone_box() {
        Ok(cloned) => cloned,
        Err(_) => return,
    };
    let mut target_write = match target.try_clone() {
        Ok(stream) => stream,
        Err(_) => return,
    };
    if !initial_client_to_target.is_empty() {
        if target_write.write_all(initial_client_to_target).is_err() {
            return;
        }
    }
    std::thread::scope(|scope| {
        scope.spawn(move || {
            let _ = io::copy(&mut client_read, &mut target_write);
            let _ = target_write.shutdown(std::net::Shutdown::Write);
        });
        scope.spawn(move || {
            let _ = io::copy(&mut target, &mut client_write);
            let _ = client_write.shutdown_all();
        });
    });
}

/// Server entry point: consumes the ClientHello, validates the REALITY seal
/// and either completes the REALITY TLS 1.3 handshake (returning the plain
/// stream for the proxy layer above) or transparently relays to `dest`.
///
/// Returns `Err(TransportError::Rejected)` when the connection was relayed
/// to the camouflage site (the listener should simply drop it).
pub fn accept_stream(
    stream: BoxedTcpStream,
    config: &RealityServerConfig,
) -> Result<BoxedTcpStream, TransportError> {
    let mut stream = stream;
    // The camouflage site is dialled lazily: the success path needs it only
    // after the ClientHello arrives (to borrow its ServerHello). An empty
    // dest disables the borrow entirely (useful for loopback interop tests).
    let dest_addr = if config.dest.trim().is_empty() {
        None
    } else {
        Some(resolve_dest(&config.dest).map_err(|err| {
            TransportError::invalid_proxy_response(format!(
                "reality dest resolve failed: {err}"
            ))
        })?)
    };

    // Read the ClientHello record from the client. Real TLS 1.3 clients
    // (utls compatibility mode) emit a dummy ChangeCipherSpec record first.
    let (record_type, handshake_bytes) = read_record_skipping_ccs(&mut stream)?;
    if record_type != RECORD_TYPE_HANDSHAKE
        || handshake_bytes.first() != Some(&HS_TYPE_CLIENT_HELLO)
    {
        return Err(TransportError::invalid_proxy_response(
            "reality: first record is not a ClientHello",
        ));
    }
    let mut client_hello = match parse_client_hello(&handshake_bytes) {
        Some(parsed) => parsed,
        None => {
            return Err(TransportError::invalid_proxy_response("reality: malformed ClientHello"));
        }
    };

    // Mirror the ClientHello record to the camouflage site exactly as
    // received (the Go MirrorConn semantics): dest needs it to produce the
    // ServerHello that gets borrowed on the success path.
    let mut target = match dest_addr {
        Some(dest_addr) => {
            let mut target = std::net::TcpStream::connect(dest_addr).map_err(|err| {
                TransportError::invalid_proxy_response(format!(
                    "reality dest dial failed: {err}"
                ))
            })?;
            target
                .set_nodelay(true)
                .map_err(|err| TransportError::from(io::Error::new(io::ErrorKind::Other, err)))?;
            let mut mirrored = vec![RECORD_TYPE_HANDSHAKE, 3, 3, 0, 0];
            mirrored[3] = (handshake_bytes.len() >> 8) as u8;
            mirrored[4] = (handshake_bytes.len() & 0xff) as u8;
            mirrored.extend_from_slice(&handshake_bytes);
            target
                .write_all(&mirrored)
                .map_err(|err| TransportError::from(io::Error::new(io::ErrorKind::Other, err)))?;
            target
                .flush()
                .map_err(|err| TransportError::from(io::Error::new(io::ErrorKind::Other, err)))?;
            target
        }
        None => {
            return Err(TransportError::invalid_proxy_response(
                "reality: dest is required for the ServerHello borrow",
            ))
        }
    };

    let mut auth_failed_reason = String::from("sni not allowed");
    let mut auth_ok = config
        .server_names
        .iter()
        .any(|name| name == &client_hello.server_name);
    if !auth_ok {
        auth_failed_reason = format!("sni not allowed: {}", client_hello.server_name);
    }

    let mut auth_key = [0_u8; 32];
    if auth_ok {
        if let Some(peer_pub) = client_hello.auth_peer_pub() {
            if let Some(shared) = x25519(&config.private_key, &peer_pub) {
                auth_key = reality_auth_key(&shared, &client_hello.random);
                let sid_start = client_hello.session_id_offset;
                let sid_len = client_hello.session_id_len;
                let sealed = client_hello.original[sid_start..sid_start + sid_len].to_vec();
                // The seal AAD is the raw ClientHello with the session_id
                // zeroed (the client sealed against the placeholder hello).
                let mut aad = client_hello.original.clone();
                aad[sid_start..sid_start + sid_len].fill(0);
                match open_session_id(&auth_key, &client_hello.random, &aad, &sealed) {
                    Some(plain) => {
                        let time = u32::from_be_bytes([plain[4], plain[5], plain[6], plain[7]]);
                        let mut short_id = [0_u8; 8];
                        short_id.copy_from_slice(plain.get(8..16).unwrap_or(&[0_u8; 8]));
                        let time_diff = unix_now().abs_diff(time);
                        let short_ok = hex_short_ids(&config.short_ids).contains(&short_id);
                        let limit = if config.max_time_diff == 0 {
                            DEFAULT_MAX_TIME_DIFF
                        } else {
                            Duration::from_secs(config.max_time_diff)
                        };
                        let time_ok = config.max_time_diff == 0
                            || Duration::from_secs(time_diff as u64) <= limit;
                        if !short_ok {
                            auth_ok = false;
                            auth_failed_reason = "short id mismatch".to_owned();
                        } else if !time_ok {
                            auth_ok = false;
                            auth_failed_reason = "timestamp outside window".to_owned();
                        }
                    }
                    None => {
                        auth_ok = false;
                        auth_failed_reason = "session id seal invalid".to_owned();
                    }
                }
            } else {
                auth_ok = false;
                auth_failed_reason = "x25519 failed".to_owned();
            }
        } else {
            auth_ok = false;
            auth_failed_reason = "missing X25519 key share".to_owned();
        }
    }
    if !auth_ok {
    }

    if !auth_ok {
        // Steal fallback: feed the ClientHello into the camouflage site and
        // relay both directions until the connection ends.
        relay_bidirectional(stream, target, &client_hello.original);
        return Err(TransportError::Rejected { drop: false });
    }

    // Authenticated: read the camouflage site's ServerHello and mirror it.
    let server_hello = read_dest_server_hello(&mut target)?;
    let mut server_hello = server_hello;
    let suite = CipherSuite::from_id(server_hello.cipher_suite).ok_or_else(|| {
        TransportError::invalid_proxy_response(
            "reality: camouflage site negotiated an unsupported cipher suite",
        )
    })?;

    // Compute the TLS shared secret against the client's matching share.
    let client_share = client_hello
        .key_shares
        .iter()
        .find(|(group, _, _)| *group == server_hello.share_group)
        .map(|(_, offset, len)| client_hello.original[*offset..*offset + *len].to_vec())
        .ok_or_else(|| {
            TransportError::invalid_proxy_response(
                "reality: client is missing the selected key share",
            )
        })?;

    let mut eph_x25519_priv = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut eph_x25519_priv);
    eph_x25519_priv[0] = eph_x25519_priv[0] & 248;
    eph_x25519_priv[31] = (eph_x25519_priv[31] & 127) | 64;
    let eph_x25519_pub = XPublic::from(&XSecret::from(eph_x25519_priv)).to_bytes();

    let mut mlkem_ciphertext: Vec<u8> = Vec::new();
    let shared_key: Vec<u8> = match server_hello.share_group {
        GROUP_X25519 => {
            let peer = array32(&client_share);
            x25519(&eph_x25519_priv, &peer)
                .map(|secret| secret.to_vec())
                .ok_or_else(|| {
                    TransportError::invalid_proxy_response("reality: x25519 shared failed")
                })?
        }
        GROUP_X25519_MLKEM768 => {
            let share_slice = client_share.get(0..MLKEM_ENCAP_KEY_SIZE).ok_or_else(|| {
                TransportError::invalid_proxy_response("reality: bad mlkem share")
            })?;
            let encap = ml_kem::ml_kem_768::EncapsulationKey::new(
                &share_slice
                    .try_into()
                    .map_err(|_| {
                        TransportError::invalid_proxy_response("reality: bad mlkem share")
                    })?,
            )
            .map_err(|_| {
                TransportError::invalid_proxy_response("reality: bad mlkem share")
            })?;
            let mut message = [0_u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut message);
            let (ciphertext, mlkem_shared) = encap.encapsulate_deterministic(&message.into());
            let peer = array32(&client_share[MLKEM_ENCAP_KEY_SIZE..]);
            let x25519_shared = x25519(&eph_x25519_priv, &peer).ok_or_else(|| {
                TransportError::invalid_proxy_response("reality: x25519 shared failed")
            })?;
            let mut combined = mlkem_shared.0.to_vec();
            combined.extend_from_slice(&x25519_shared);
            mlkem_ciphertext = ciphertext.0.to_vec();
            combined
        }
        other => {
            return Err(TransportError::invalid_proxy_response(format!(
                "reality: unsupported key share group {other:#x}"
            )))
        }
    };

    // Patch the camouflage ServerHello with our own key share:
    // X25519 -> 32 bytes; X25519MLKEM768 -> ciphertext ++ our X25519 public.
    // The ciphertext is reused verbatim from the encapsulation above so the
    // client decapsulates exactly the shared secret used for the schedule.
    match server_hello.share_group {
        GROUP_X25519 => server_hello.patch_share(&eph_x25519_pub),
        GROUP_X25519_MLKEM768 => {
            let mut patched = mlkem_ciphertext.clone();
            patched.extend_from_slice(&eph_x25519_pub);
            server_hello.patch_share(&patched);
        }
        _ => {}
    }

    // Forward the patched ServerHello to the client and finish the flight.
    finish_server_handshake(
        stream,
        target,
        &client_hello.original,
        server_hello,
        suite,
        &shared_key,
        &auth_key,
    )
}

/// Completes the TLS 1.3 server flight: forwards the patched ServerHello,
/// sends EncryptedExtensions / Certificate / CertificateVerify / Finished,
/// validates the client Finished and returns the application-data stream.
fn finish_server_handshake(
    mut stream: BoxedTcpStream,
    mut target: std::net::TcpStream,
    client_hello_original: &[u8],
    server_hello: ServerHelloView,
    suite: CipherSuite,
    shared_key: &[u8],
    auth_key: &[u8; 32],
) -> Result<BoxedTcpStream, TransportError> {
    // The record header for ServerHello must carry its true length.
    let mut record_header = server_hello.record_header;
    let sh_len = server_hello.original.len();
    record_header[3] = (sh_len >> 8) as u8;
    record_header[4] = (sh_len & 0xff) as u8;

    // Incremental transcript; the hash follows the negotiated suite.
    let mut transcript = TranscriptState::new(suite);
    transcript.update(client_hello_original);
    transcript.update(&server_hello.original);
    let transcript_sh = transcript.snapshot_hash();

    // Key schedule: handshake phase.
    let empty_hash = TranscriptState::new(suite).snapshot_hash();
    let zero_secret = vec![0_u8; hkdf_extract_prk_len(suite)];
    let early_secret = hkdf_extract(suite, &zero_secret, &zero_secret);
    let derived1 = hkdf_expand_label(
        suite,
        &early_secret,
        "derived",
        &empty_hash,
        hkdf_extract_prk_len(suite),
    );
    let handshake_secret = hkdf_extract(suite, &derived1, shared_key);
    let server_hs_secret = hkdf_expand_label(
        suite,
        &handshake_secret,
        "s hs traffic",
        &transcript_sh,
        hkdf_extract_prk_len(suite),
    );
    let client_hs_secret = hkdf_expand_label(
        suite,
        &handshake_secret,
        "c hs traffic",
        &transcript_sh,
        hkdf_extract_prk_len(suite),
    );
    let server_hs_keys = traffic_keys_for(suite, &server_hs_secret).ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: key schedule failed")
    })?;
    let client_hs_keys = traffic_keys_for(suite, &client_hs_secret).ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: key schedule failed")
    })?;
    let server_hs_aead = SuiteAead::new(suite, &server_hs_keys.key).ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: cipher init failed")
    })?;
    let client_hs_aead = SuiteAead::new(suite, &client_hs_keys.key).ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: cipher init failed")
    })?;

    // Send the patched ServerHello record as captured from the site, followed
    // by the middlebox-compatibility dummy ChangeCipherSpec record.
    stream
        .write_all(&record_header)
        .map_err(TransportError::from)?;
    stream
        .write_all(&server_hello.original)
        .map_err(TransportError::from)?;
    send_dummy_ccs(&mut stream)?;

    let encrypted_extensions = {
        let mut message = vec![HS_TYPE_ENCRYPTED_EXTENSIONS, 0x00, 0x00, 0x02, 0x00, 0x00];
        message
    };
    send_encrypted_handshake(
        &mut stream,
        &server_hs_aead,
        &server_hs_keys.iv,
        0,
        &encrypted_extensions,
    )?;
    transcript.update(&encrypted_extensions);

    // Certificate: request context empty + one DER entry + empty extensions.
    let (cert_der, signing_key) = reality_certificate(auth_key);
    let entry_len = cert_der.len();
    let mut cert_message = vec![HS_TYPE_CERTIFICATE, 0, 0, 0];
    let body_len = 1 + 3 + 3 + entry_len + 2;
    cert_message[1] = (body_len >> 16) as u8;
    cert_message[2] = (body_len >> 8) as u8;
    cert_message[3] = (body_len & 0xff) as u8;
    cert_message.push(0x00); // empty request context
    cert_message.extend_from_slice(&((entry_len + 5) as u32).to_be_bytes()[1..]);
    cert_message.extend_from_slice(&(entry_len as u32).to_be_bytes()[1..]);
    cert_message.extend_from_slice(&cert_der);
    cert_message.extend_from_slice(&[0x00, 0x00]); // empty extensions

    let certificate_bytes = cert_message.clone();
    send_encrypted_handshake(
        &mut stream,
        &server_hs_aead,
        &server_hs_keys.iv,
        1,
        &certificate_bytes,
    )?;
    transcript.update(&certificate_bytes);

    // CertificateVerify: Ed25519 over the RFC 8446 signed blob (context up to
    // and including the Certificate message).
    let transcript_for_cv = transcript.snapshot_hash();
    let mut signed = Vec::with_capacity(64 + SERVER_CV_CONTEXT.len() + transcript_for_cv.len());
    signed.extend_from_slice(&[0x20_u8; 64]);
    signed.extend_from_slice(SERVER_CV_CONTEXT);
    signed.extend_from_slice(&transcript_for_cv);
    let signature = signing_key.sign(&signed).to_bytes();

    let mut cv_message = vec![HS_TYPE_CERTIFICATE_VERIFY, 0, 0, 0];
    let cv_body_len = 2 + 2 + 64;
    cv_message[1] = (cv_body_len >> 16) as u8;
    cv_message[2] = (cv_body_len >> 8) as u8;
    cv_message[3] = (cv_body_len & 0xff) as u8;
    cv_message.extend_from_slice(&SIG_ALG_ED25519.to_be_bytes());
    cv_message.extend_from_slice(&64_u16.to_be_bytes());
    cv_message.extend_from_slice(&signature);

    send_encrypted_handshake(
        &mut stream,
        &server_hs_aead,
        &server_hs_keys.iv,
        2,
        &cv_message,
    )?;
    transcript.update(&cv_message);

    // Finished: HMAC over the transcript so far with the finished key.
    let finished_key = hkdf_expand_label(
        suite,
        &server_hs_secret,
        "finished",
        &[],
        hkdf_extract_prk_len(suite),
    );
    let transcript_before_finished = transcript.snapshot_hash();
    let verify_data = hmac_suite(suite, &finished_key, &transcript_before_finished);
    let mut finished_message = vec![HS_TYPE_FINISHED, 0, 0];
    finished_message.push(verify_data.len() as u8);
    finished_message.extend_from_slice(&verify_data);
    send_encrypted_handshake(
        &mut stream,
        &server_hs_aead,
        &server_hs_keys.iv,
        3,
        &finished_message,
    )?;
    transcript.update(&finished_message);

    // Application keys (transcript through the server Finished).
    let derived2 = hkdf_expand_label(
        suite,
        &handshake_secret,
        "derived",
        &empty_hash,
        hkdf_extract_prk_len(suite),
    );
    let master_secret = hkdf_extract(suite, &derived2, &zero_secret);
    let transcript_after_server_finished = transcript.snapshot_hash();
    let server_app_secret = hkdf_expand_label(
        suite,
        &master_secret,
        "s ap traffic",
        &transcript_after_server_finished,
        hkdf_extract_prk_len(suite),
    );
    let client_app_secret = hkdf_expand_label(
        suite,
        &master_secret,
        "c ap traffic",
        &transcript_after_server_finished,
        hkdf_extract_prk_len(suite),
    );
    let server_app_keys = traffic_keys_for(suite, &server_app_secret).ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: key schedule failed")
    })?;
    let client_app_keys = traffic_keys_for(suite, &client_app_secret).ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: key schedule failed")
    })?;
    let client_app_aead = SuiteAead::new(suite, &client_app_keys.key).ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: cipher init failed")
    })?;

    // Verify the client Finished (client handshake keys) and switch to the
    // application keys for everything that follows. Skip any compatibility
    // CCS records the client emitted before its Finished.
    let (record_type, record_payload) = read_record_skipping_ccs(&mut stream)?;
    if record_type != RECORD_TYPE_APPLICATION {
        return Err(TransportError::invalid_proxy_response(
            "reality: expected encrypted client Finished",
        ));
    }
    let client_seq: u64 = 0;
    let client_finished = client_hs_aead
        .open(&client_hs_keys.iv, client_seq, &record_payload, &[
            RECORD_TYPE_APPLICATION, 3, 3,
        ])
        .ok_or_else(|| {
            TransportError::invalid_proxy_response("reality: client Finished decrypt failed")
        })?;
    let (content_type, client_finished) = decode_inner_plaintext(client_finished)?;
    if content_type != RECORD_TYPE_HANDSHAKE
        || client_finished.first() != Some(&HS_TYPE_FINISHED)
    {
        return Err(TransportError::invalid_proxy_response(
            "reality: expected Finished message",
        ));
    }
    let client_finished_key = hkdf_expand_label(
        suite,
        &client_hs_secret,
        "finished",
        &[],
        hkdf_extract_prk_len(suite),
    );
    let client_transcript = transcript.snapshot_hash();
    let expected = hmac_suite(suite, &client_finished_key, &client_transcript);
    let verify_data = client_finished.get(4..).ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: short Finished")
    })?;
    if verify_data.len() != expected.len() || !constant_time_eq(verify_data, &expected) {
        return Err(TransportError::invalid_proxy_response(
            "reality: client Finished mismatch",
        ));
    }
    // Drop the camouflage connection; the REALITY session takes over.
    drop(target);

    Ok(Box::new(RealityStream {
        read_socket: stream.try_clone_box()?,
        write_socket: Some(stream.try_clone_box()?),
        read_aead: client_app_aead,
        read_iv: client_app_keys.iv,
        read_seq: client_seq,
        read_record: Default::default(),
        write_state: Arc::new(Mutex::new(RealityWriteState {
            aead: SuiteAead::new(suite, &server_app_keys.key).ok_or_else(|| {
                TransportError::invalid_proxy_response("reality: cipher init failed")
            })?,
            iv: server_app_keys.iv,
            seq: 0,
            direct: false,
        })),
        read_direct: false,
        read_buf: Vec::new(),
        read_off: 0,
        read_finished: false,
        handshake_client_aead: Some(client_hs_aead),
        handshake_client_iv: client_hs_keys.iv,
        handshake_client_seq: client_seq,
    }))
}

fn hkdf_extract_prk_len(suite: CipherSuite) -> usize {
    match suite {
        CipherSuite::Aes256GcmSha384 => 48,
        _ => 32,
    }
}

fn traffic_keys_for(suite: CipherSuite, secret: &[u8]) -> Option<TrafficKeys> {
    let key = hkdf_expand_label(suite, secret, "key", &[], suite.key_size());
    let iv = hkdf_expand_label(suite, secret, "iv", &[], 12);
    if key.len() != suite.key_size() || iv.len() != 12 {
        return None;
    }
    Some(TrafficKeys {
        key,
        iv: iv.try_into().ok()?,
    })
}

struct TrafficKeys {
    key: Vec<u8>,
    iv: [u8; 12],
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <hmac::Hmac<Sha256> as hmac::Mac>::new_from_slice(key)
        .expect("hmac accepts any key length");
    use hmac::Mac as _;
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff = diff | (a ^ b);
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Client side (outbound proxy connection)
// ---------------------------------------------------------------------------

/// Builds the REALITY ClientHello: a compact but spec-conformant TLS 1.3
/// hello carrying both X25519MLKEM768 and X25519 key shares plus the
/// encrypted session_id seal.
fn build_client_hello(
    config: &RealityClientConfig,
    x25519_priv: &[u8; 32],
    mlkem_encap: &[u8; MLKEM_ENCAP_KEY_SIZE],
    random: &[u8; RANDOM_LEN],
) -> (Vec<u8>, [u8; 16]) {
    let mut x25519_pub = [0_u8; 32];
    x25519_pub.copy_from_slice(&XPublic::from(&XSecret::from(*x25519_priv)).to_bytes());

    // session_id plaintext: version(4) || time(4) || short_id(8), padded.
    let mut seal_plain = [0_u8; 16];
    let now = unix_now().to_be_bytes();
    seal_plain[0] = 1; // client major version marker (xray core.Version_x = 1)
    seal_plain[1] = 8;
    seal_plain[2] = 2;
    seal_plain[3] = 0;
    seal_plain[4..8].copy_from_slice(&now);
    seal_plain[8..16].copy_from_slice(&config.short_id);

    // Extensions block.
    let mut extensions = Vec::new();
    // server_name: extension_data = uint16 list_len { uint8 type, uint16 len, name }
    let sni = config.server_name.as_bytes();
    if !sni.is_empty() && sni.len() <= 255 {
        let list_len = 1 + 2 + sni.len();
        let ext_data_len = 2 + list_len;
        extensions.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        extensions.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
        extensions.extend_from_slice(&(list_len as u16).to_be_bytes());
        extensions.push(0);
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(sni);
    }
    let protocols = if config.alpn.is_empty() {
        vec!["h2".to_owned(), "http/1.1".to_owned()]
    } else { config.alpn.clone() };
    let mut names = Vec::new();
    for protocol in protocols {
        names.push(protocol.len() as u8);
        names.extend_from_slice(protocol.as_bytes());
    }
    extensions.extend_from_slice(&EXT_ALPN.to_be_bytes());
    extensions.extend_from_slice(&((names.len() + 2) as u16).to_be_bytes());
    extensions.extend_from_slice(&(names.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&names);
    let mut groups = Vec::new();
    if config.support_x25519mlkem768 {
        groups.extend_from_slice(&GROUP_X25519_MLKEM768.to_be_bytes());
    }
    groups.extend_from_slice(&GROUP_X25519.to_be_bytes());
    extensions.extend_from_slice(&EXT_SUPPORTED_GROUPS.to_be_bytes());
    extensions.extend_from_slice(&((groups.len() + 2) as u16).to_be_bytes());
    extensions.extend_from_slice(&(groups.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&groups);
    // Cover RSA-PSS and ECDSA certificate variants at camouflage sites, in
    // addition to the Ed25519 proof used by REALITY itself.
    let signature_algorithms: [u16; 9] = [
        SIG_ALG_ED25519, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    extensions.extend_from_slice(&EXT_SIGNATURE_ALGORITHMS.to_be_bytes());
    extensions.extend_from_slice(&((signature_algorithms.len() * 2 + 2) as u16).to_be_bytes());
    extensions.extend_from_slice(&((signature_algorithms.len() * 2) as u16).to_be_bytes());
    for algorithm in signature_algorithms { extensions.extend_from_slice(&algorithm.to_be_bytes()); }
    // Client supported_versions includes an 8-bit vector length.
    extensions.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
    extensions.extend_from_slice(&3_u16.to_be_bytes());
    extensions.push(2);
    extensions.extend_from_slice(&TLS13_VERSION.to_be_bytes());
    let mut shares = Vec::new();
    if config.support_x25519mlkem768 {
        shares.extend_from_slice(&GROUP_X25519_MLKEM768.to_be_bytes());
        shares.extend_from_slice(&((MLKEM_ENCAP_KEY_SIZE + 32) as u16).to_be_bytes());
        shares.extend_from_slice(mlkem_encap);
        shares.extend_from_slice(&x25519_pub);
    }
    shares.extend_from_slice(&GROUP_X25519.to_be_bytes());
    shares.extend_from_slice(&32_u16.to_be_bytes());
    shares.extend_from_slice(&x25519_pub);
    extensions.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
    extensions.extend_from_slice(&((shares.len() + 2) as u16).to_be_bytes());
    extensions.extend_from_slice(&(shares.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&shares);
    // psk_key_exchange_modes: psk_dhe_ke
    extensions.extend_from_slice(&45_u16.to_be_bytes());
    extensions.extend_from_slice(&2_u16.to_be_bytes());
    extensions.push(1);
    extensions.push(1);

    let mut body = Vec::with_capacity(2 + RANDOM_LEN + 1 + 32 + 8 + 2 + 1 + 2 + extensions.len());
    body.extend_from_slice(&TLS12_VERSION_BYTES);
    body.extend_from_slice(random);
    body.push(SID_LEN as u8);
    body.extend_from_slice(&[0_u8; SID_LEN]); // session_id placeholder
    // cipher_suites: TLS_AES_128_GCM_SHA256, TLS_CHACHA20, TLS_AES_256_GCM
    body.extend_from_slice(&6_u16.to_be_bytes());
    body.extend_from_slice(&SUITE_AES_128_GCM_SHA256.to_be_bytes());
    body.extend_from_slice(&SUITE_CHACHA20_POLY1305_SHA256.to_be_bytes());
    body.extend_from_slice(&SUITE_AES_256_GCM_SHA384.to_be_bytes());
    body.push(1); // compression methods length
    body.push(0); // null compression
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut message = vec![HS_TYPE_SERVER_HELLO_MARKER, 0, 0, 0];
    message[1] = (body.len() >> 16) as u8;
    message[2] = (body.len() >> 8) as u8;
    message[3] = (body.len() & 0xff) as u8;
    message.extend_from_slice(&body);

    // The auth seal must cover the full ClientHello with a zeroed session_id,
    // so the ciphertext is computed twice: first to derive the AAD with an
    // empty seal, then placed into the hello. The Go flow seals with the raw
    // hello (session id placeholder zeroed) as AAD, which matches this.
    (message, seal_plain)
}

const HS_TYPE_SERVER_HELLO_MARKER: u8 = 1;

/// Outbound entry point: performs the REALITY client handshake over
/// `stream` and returns the application-data stream.
pub fn wrap_stream(
    mut stream: BoxedTcpStream,
    config: &RealityClientConfig,
    _target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let protocols = if config.alpn.is_empty() { vec!["h2", "http/1.1"] }
        else { config.alpn.iter().map(String::as_str).collect() };
    if protocols.iter().any(|p| p.is_empty() || p.len() > 255)
        || protocols.iter().map(|p| p.len() + 1).sum::<usize>() > 4096 {
        return Err(TransportError::InvalidPlan("reality: invalid ALPN protocol list".to_owned()));
    }
    let mut x25519_priv = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut x25519_priv);
    let dk = if config.support_x25519mlkem768 {
        let mut seed = [0_u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Some(ml_kem::ml_kem_768::DecapsulationKey::from_seed(seed.into()))
    } else { None };
    let mlkem_encap = dk.as_ref().map(|dk| dk.encapsulation_key().to_bytes().0)
        .unwrap_or([0_u8; MLKEM_ENCAP_KEY_SIZE]);

    let mut random = [0_u8; RANDOM_LEN];
    rand::rngs::OsRng.fill_bytes(&mut random);

    let (mut hello, seal_plain) = build_client_hello(config, &x25519_priv, &mlkem_encap, &random);

    // Derive the auth key against the server's REALITY public key.
    let shared = x25519(&x25519_priv, &config.public_key).ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: x25519 with server key failed")
    })?;
    let auth_key = reality_auth_key(&shared, &random);
    let sealed = seal_session_id(&auth_key, &random, &hello, &seal_plain);

    // Patch the session_id into the hello: handshake header (4) +
    // legacy version (2) + random (32) + session-id length byte (1).
    let sid_offset = 4 + 2 + RANDOM_LEN + 1;
    hello[sid_offset..sid_offset + SID_LEN].copy_from_slice(&sealed);

    // Browsers use the permitted TLS 1.0 legacy record version for their first
    // ClientHello. Older REALITY servers check it before authenticating; the
    // ClientHello legacy_version and negotiated protocol remain TLS 1.2/1.3.
    let mut record = vec![RECORD_TYPE_HANDSHAKE, 3, 1, 0, 0];
    record[3] = (hello.len() >> 8) as u8;
    record[4] = (hello.len() & 0xff) as u8;
    record.extend_from_slice(&hello);
    stream.write_all(&record).map_err(TransportError::from)?;
    stream.flush().map_err(TransportError::from)?;

    let payload = read_server_hello_message(&mut *stream)?;
    let server_hello = parse_server_hello(&payload).ok_or_else(|| {
        TransportError::invalid_proxy_response(
            "reality: server is not a REALITY endpoint (ServerHello rejected)",
        )
    })?;
    let suite = CipherSuite::from_id(server_hello.cipher_suite).ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: unsupported server cipher suite")
    })?;

    // Compute the shared secret for the negotiated group.
    let shared_key: Vec<u8> = match server_hello.share_group {
        GROUP_X25519 => {
            let peer = array32(&server_hello.share_data);
            x25519(&x25519_priv, &peer)
                .map(|secret| secret.to_vec())
                .ok_or_else(|| {
                    TransportError::invalid_proxy_response("reality: x25519 shared failed")
                })?
        }
        GROUP_X25519_MLKEM768 => {
            let mut ciphertext = ml_kem::ml_kem_768::Ciphertext::default();
            ciphertext.clone_from_slice(&server_hello.share_data[..MLKEM_CIPHERTEXT_SIZE]);
            let dk = dk.as_ref().ok_or_else(|| TransportError::invalid_proxy_response(
                "reality: server selected an unoffered hybrid key share",
            ))?;
            let mlkem_shared = dk.decapsulate(&ciphertext);
            let server_x25519_pub = array32(
                server_hello
                    .share_data
                    .get(MLKEM_CIPHERTEXT_SIZE..MLKEM_CIPHERTEXT_SIZE + 32)
                    .unwrap_or(&[0_u8; 32]),
            );
            let x25519_shared = x25519(&x25519_priv, &server_x25519_pub).ok_or_else(|| {
                TransportError::invalid_proxy_response("reality: x25519 shared failed")
            })?;
            let mut combined = mlkem_shared.0.to_vec();
            combined.extend_from_slice(&x25519_shared);
            combined
        }
        other => {
            return Err(TransportError::invalid_proxy_response(format!(
                "reality: unsupported server share group {other:#x}"
            )))
        }
    };

    // Key schedule (handshake phase).
    let empty_hash = TranscriptState::new(suite).snapshot_hash();
    let zero_secret = vec![0_u8; hkdf_extract_prk_len(suite)];
    let early_secret = hkdf_extract(suite, &zero_secret, &zero_secret);
    let derived1 = hkdf_expand_label(
        suite,
        &early_secret,
        "derived",
        &empty_hash,
        hkdf_extract_prk_len(suite),
    );
    let handshake_secret = hkdf_extract(suite, &derived1, &shared_key);
    let client_hello_message = &record[RECORD_HEADER_LEN..];
    let mut transcript = TranscriptState::new(suite);
    transcript.update(client_hello_message);
    transcript.update(&server_hello.original);
    let transcript_sh = transcript.snapshot_hash();
    let client_hs_secret = hkdf_expand_label(
        suite,
        &handshake_secret,
        "c hs traffic",
        &transcript_sh,
        hkdf_extract_prk_len(suite),
    );
    let server_hs_secret = hkdf_expand_label(
        suite,
        &handshake_secret,
        "s hs traffic",
        &transcript_sh,
        hkdf_extract_prk_len(suite),
    );
    let client_hs_keys = traffic_keys_for(suite, &client_hs_secret).ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: key schedule failed")
    })?;
    let server_hs_keys = traffic_keys_for(suite, &server_hs_secret).ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: key schedule failed")
    })?;
    let client_hs_aead = SuiteAead::new(suite, &client_hs_keys.key).ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: cipher init failed")
    })?;
    let server_hs_aead = SuiteAead::new(suite, &server_hs_keys.key).ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: cipher init failed")
    })?;

    // Decrypt the remaining server flight: EE, Certificate, CertificateVerify,
    // Finished (each in its own record for the flows we generate; tolerate
    // multiple handshake messages inside one record via a splitter below).
    let mut pending: Vec<u8> = Vec::new();
    let mut server_seq: u64 = 0;
    let mut certificate_der: Option<Vec<u8>> = None;
    let mut cv_signature: Option<Vec<u8>> = None;
    let mut server_finished: Option<Vec<u8>> = None;
    let mut server_finished_message: Option<Vec<u8>> = None;
    // Every decrypted server handshake message in order; used to rebuild
    // the transcript for the CertificateVerify and Finished checks.
    let mut flight_messages: Vec<Vec<u8>> = Vec::new();

    while server_finished.is_none() {
        let (record_type, payload) = read_record_skipping_ccs(&mut stream).map_err(|err| {
            TransportError::invalid_proxy_response(format!("reality: reading server flight: {err}"))
        })?;
        if record_type == 21 {
            return Err(tls_alert_error("during server handshake", &payload));
        }
        if record_type != RECORD_TYPE_APPLICATION && record_type != RECORD_TYPE_HANDSHAKE {
            return Err(TransportError::invalid_proxy_response(
                "reality: unexpected record during server flight",
            ));
        }
        let opened = if record_type == RECORD_TYPE_APPLICATION {
            let plaintext = server_hs_aead
                .open(
                    &server_hs_keys.iv,
                    server_seq,
                    &payload,
                    &[RECORD_TYPE_APPLICATION, 3, 3],
                )
                .ok_or_else(|| {
                    TransportError::invalid_proxy_response("reality: server flight decrypt failed")
                })?;
            server_seq += 1;
            let (inner_type, content) = decode_inner_plaintext(plaintext)?;
            if inner_type == 21 {
                return Err(tls_alert_error("during server handshake", &content));
            }
            if inner_type != RECORD_TYPE_HANDSHAKE {
                return Err(TransportError::invalid_proxy_response(
                    "reality: server handshake record has invalid content type",
                ));
            }
            content
        } else {
            payload
        };
        // Handshake messages may be fragmented across TLS records or grouped
        // in a single one. TLS padding has already been removed above.
        pending.extend_from_slice(&opened);
        // Split handshake messages out of the decrypted stream.
        while pending.len() >= 4 {
            let msg_len = ((u32::from(pending[1]) << 16)
                | (u32::from(pending[2]) << 8)
                | u32::from(pending[3])) as usize;
            if pending.len() < 4 + msg_len {
                break;
            }
            let message: Vec<u8> = pending.drain(0..4 + msg_len).collect();
            match message[0] {
                HS_TYPE_CERTIFICATE => {
                    certificate_der = Some(parse_certificate_entry(&message)?);
                    flight_messages.push(message);
                }
                HS_TYPE_CERTIFICATE_VERIFY => {
                    let alg = u16::from_be_bytes([message[4], message[5]]);
                    if alg != SIG_ALG_ED25519 {
                        return Err(TransportError::invalid_proxy_response(
                            "reality: unexpected CertificateVerify algorithm",
                        ));
                    }
                    let sig_len = u16::from_be_bytes([message[6], message[7]]) as usize;
                    let sig = message.get(8..8 + sig_len).ok_or_else(|| {
                        TransportError::invalid_proxy_response(
                            "reality: short CertificateVerify",
                        )
                    })?;
                    cv_signature = Some(sig.to_vec());
                    flight_messages.push(message);
                }
                HS_TYPE_FINISHED => {
                    let verify = message.get(4..).ok_or_else(|| {
                        TransportError::invalid_proxy_response("reality: short Finished")
                    })?;
                    server_finished = Some(verify.to_vec());
                    server_finished_message = Some(message.clone());
                    flight_messages.push(message);
                }
                _ => {
                    flight_messages.push(message);
                }
            }
        }
    }

    // Certificate must carry the REALITY proof: parse the SPKI public key and
    // verify HMAC-SHA512(AuthKey, pub) == signature slot.
    let cert_der = certificate_der.ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: missing Certificate")
    })?;
    let (cert_pub, cert_signature) = parse_self_signed_cert(&cert_der)?;
    let expected = reality_certificate_proof(&auth_key, &cert_pub);
    let cert_sig = cert_signature.ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: certificate missing signature")
    })?;
    if !constant_time_eq(&expected, &cert_sig) {
        return Err(TransportError::invalid_proxy_response(
            "reality: server certificate proof mismatch",
        ));
    }

    // CertificateVerify: Ed25519 over spaces64 + server context + transcript.
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&cert_pub).map_err(|_| {
        TransportError::invalid_proxy_response("reality: bad certificate public key")
    })?;
    let sig = cv_signature.ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: missing CertificateVerify")
    })?;
    // The server signs over CH + SH + EE + Certificate (excluding the
    // CertificateVerify itself).
    let mut transcript_cv = TranscriptState::new(suite);
    transcript_cv.update(client_hello_message);
    transcript_cv.update(&server_hello.original);
    for message in &flight_messages {
        if message[0] == HS_TYPE_CERTIFICATE_VERIFY || message[0] == HS_TYPE_FINISHED {
            break;
        }
        transcript_cv.update(message);
    }
    let transcript_for_cv = transcript_cv.snapshot_hash();
    let mut signed = Vec::with_capacity(64 + SERVER_CV_CONTEXT.len() + transcript_for_cv.len());
    signed.extend_from_slice(&[0x20_u8; 64]);
    signed.extend_from_slice(SERVER_CV_CONTEXT);
    signed.extend_from_slice(&transcript_for_cv);
    verifying
        .verify_strict(
            &signed,
            &ed25519_dalek::Signature::from_slice(sig.as_slice()).map_err(|_| {
                TransportError::invalid_proxy_response(
                    "reality: bad CertificateVerify signature",
                )
            })?,
        )
        .map_err(|_| {
            TransportError::invalid_proxy_response(
                "reality: CertificateVerify signature invalid",
            )
        })?;

    // Server Finished: HMAC(finished_key, transcript(CH..CV)).
    let server_finished_value = server_finished.ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: missing server Finished")
    })?;
    let finished_key = hkdf_expand_label(
        suite,
        &server_hs_secret,
        "finished",
        &[],
        hkdf_extract_prk_len(suite),
    );
    let mut transcript_through_cv = TranscriptState::new(suite);
    transcript_through_cv.update(client_hello_message);
    transcript_through_cv.update(&server_hello.original);
    for message in &flight_messages {
        if message[0] == HS_TYPE_FINISHED {
            break;
        }
        transcript_through_cv.update(message);
    }
    let expected_finished = hmac_suite(
        suite,
        &finished_key,
        &transcript_through_cv.snapshot_hash(),
    );
    if !constant_time_eq(&server_finished_value, &expected_finished) {
        return Err(TransportError::invalid_proxy_response(
            "reality: server Finished mismatch",
        ));
    }

    // Send the client Finished.
    let client_finished_key = hkdf_expand_label(
        suite,
        &client_hs_secret,
        "finished",
        &[],
        hkdf_extract_prk_len(suite),
    );
    // App secrets are derived over the transcript through the server
    // Finished; the exact received message bytes keep the hash aligned.
    let server_finished_message = server_finished_message.ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: missing server Finished")
    })?;
    transcript_through_cv.update(&server_finished_message);
    let transcript_after_server_finished = transcript_through_cv.snapshot_hash();
    let client_verify = hmac_suite(
        suite,
        &client_finished_key,
        &transcript_after_server_finished,
    );
    let mut client_finished_message = vec![HS_TYPE_FINISHED, 0, 0];
    client_finished_message.push(client_verify.len() as u8);
    client_finished_message.extend_from_slice(&client_verify);
    // RFC 8446 Appendix D.4: the client's second flight is preceded by a
    // dummy ChangeCipherSpec record.
    send_dummy_ccs(&mut stream)?;
    send_encrypted_handshake(
        &mut stream,
        &client_hs_aead,
        &client_hs_keys.iv,
        0,
        &client_finished_message,
    )?;

    // Application keys.
    let derived2 = hkdf_expand_label(
        suite,
        &handshake_secret,
        "derived",
        &empty_hash,
        hkdf_extract_prk_len(suite),
    );
    let master_secret = hkdf_extract(suite, &derived2, &zero_secret);
    let client_app_secret = hkdf_expand_label(
        suite,
        &master_secret,
        "c ap traffic",
        &transcript_after_server_finished,
        hkdf_extract_prk_len(suite),
    );
    let server_app_secret = hkdf_expand_label(
        suite,
        &master_secret,
        "s ap traffic",
        &transcript_after_server_finished,
        hkdf_extract_prk_len(suite),
    );
    let client_app_keys = traffic_keys_for(suite, &client_app_secret).ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: key schedule failed")
    })?;
    let server_app_keys = traffic_keys_for(suite, &server_app_secret).ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: key schedule failed")
    })?;
    let client_app_aead = SuiteAead::new(suite, &client_app_keys.key).ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: cipher init failed")
    })?;

    let read_socket = stream.try_clone_box().map_err(|err| {
        TransportError::invalid_proxy_response(format!("reality: stream clone failed: {err}"))
    })?;
    let write_socket = stream.try_clone_box().map_err(|err| {
        TransportError::invalid_proxy_response(format!("reality: stream clone failed: {err}"))
    })?;
    // Client read direction decrypts with the SERVER traffic keys; the
    // write direction encrypts with the CLIENT traffic keys.
    let read_aead = SuiteAead::new(suite, &server_app_keys.key).ok_or_else(|| {
        TransportError::invalid_proxy_response("reality: cipher init failed")
    })?;
    Ok(Box::new(RealityStream {
        read_socket,
        write_socket: Some(write_socket),
        read_aead,
        read_iv: server_app_keys.iv,
        read_seq: 0,
        read_record: Default::default(),
        write_state: Arc::new(Mutex::new(RealityWriteState {
            aead: client_app_aead,
            iv: client_app_keys.iv,
            seq: 0,
            direct: false,
        })),
        read_direct: false,
        read_buf: Vec::new(),
        read_off: 0,
        read_finished: false,
        handshake_client_aead: None,
        handshake_client_iv: [0_u8; 12],
        handshake_client_seq: 0,
    }))
}

/// Extracts (SPKI ed25519 public key, signature slot) from our certificate
/// template DER. Positions are deterministic from the builder layout.
fn parse_self_signed_cert(der: &[u8]) -> Result<([u8; 32], Option<Vec<u8>>), TransportError> {
    let (remaining, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|_| TransportError::invalid_proxy_response("reality: invalid certificate DER"))?;
    let spki = cert.public_key();
    if !remaining.is_empty() || spki.algorithm.algorithm.to_id_string() != "1.3.101.112"
        || spki.subject_public_key.unused_bits != 0 || spki.subject_public_key.data.len() != 32
        || cert.signature_value.unused_bits != 0 || cert.signature_value.data.len() != 64 {
        return Err(TransportError::invalid_proxy_response("reality: invalid Ed25519 proof certificate"));
    }
    let mut public = [0; 32];
    public.copy_from_slice(&spki.subject_public_key.data);
    Ok((public, Some(cert.signature_value.data.to_vec())))
}

fn encrypted_extensions_len(collected: &[Vec<u8>]) -> Result<usize, TransportError> {
    collected
        .iter()
        .find(|message| message[0] == 8)
        .map(|message| message.len())
        .ok_or_else(|| {
            TransportError::invalid_proxy_response("reality: missing EncryptedExtensions")
        })
}

fn certificate_len(collected: &[Vec<u8>]) -> Result<usize, TransportError> {
    collected
        .iter()
        .find(|message| message[0] == HS_TYPE_CERTIFICATE)
        .map(|message| message.len())
        .ok_or_else(|| {
            TransportError::invalid_proxy_response("reality: missing Certificate")
        })
}

fn cv_message_bytes(collected: &[Vec<u8>]) -> Result<usize, TransportError> {
    collected
        .iter()
        .find(|message| message[0] == HS_TYPE_CERTIFICATE_VERIFY)
        .map(|message| message.len())
        .ok_or_else(|| {
            TransportError::invalid_proxy_response("reality: missing CertificateVerify")
        })
}

/// Extracts the single DER entry from a server Certificate message.
fn parse_certificate_entry(message: &[u8]) -> Result<Vec<u8>, TransportError> {
    let invalid = || TransportError::invalid_proxy_response("reality: malformed Certificate message");
    if message.first() != Some(&HS_TYPE_CERTIFICATE) || message.len() < 11 { return Err(invalid()); }
    let context_len = message[4] as usize;
    let list_offset = 5 + context_len;
    let list_len = message.get(list_offset..list_offset+3).ok_or_else(invalid)?;
    let list_len = ((list_len[0] as usize) << 16) | ((list_len[1] as usize) << 8) | list_len[2] as usize;
    let entry_offset = list_offset + 3;
    if entry_offset + list_len != message.len() || list_len < 5 { return Err(invalid()); }
    let len = message.get(entry_offset..entry_offset+3).ok_or_else(invalid)?;
    let len = ((len[0] as usize) << 16) | ((len[1] as usize) << 8) | len[2] as usize;
    let start = entry_offset + 3;
    if len + 5 > list_len { return Err(invalid()); }
    Ok(message.get(start..start+len).ok_or_else(invalid)?.to_vec())
}

fn array_ref_1088(bytes: &[u8]) -> [u8; 1088] {
    let mut out = [0_u8; 1088];
    out.copy_from_slice(bytes.get(0..1088).unwrap_or(&[0_u8; 1088]));
    out
}

/// Encrypts one handshake message (type-prefixed) as a TLS record.
fn send_encrypted_handshake(
    stream: &mut BoxedTcpStream,
    aead: &SuiteAead,
    iv: &[u8; 12],
    seq: u64,
    message: &[u8],
) -> Result<(), TransportError> {
    let mut inner = message.to_vec();
    inner.push(RECORD_TYPE_HANDSHAKE);
    let sealed = aead.seal(iv, seq, &inner, &[RECORD_TYPE_APPLICATION, 3, 3]);
    let mut header = [RECORD_TYPE_APPLICATION, 3, 3, 0, 0];
    header[3] = (sealed.len() >> 8) as u8;
    header[4] = (sealed.len() & 0xff) as u8;
    stream.write_all(&header).map_err(TransportError::from)?;
    stream.write_all(&sealed).map_err(TransportError::from)?;
    stream.flush().map_err(TransportError::from)?;
    Ok(())
}

fn send_dummy_ccs(stream: &mut BoxedTcpStream) -> Result<(), TransportError> {
    stream
        .write_all(&DUMMY_CCS_RECORD)
        .map_err(TransportError::from)?;
    stream.flush().map_err(TransportError::from)?;
    Ok(())
}

/// Reads one plaintext record, skipping middlebox-compatibility
/// ChangeCipherSpec records.
fn read_record_skipping_ccs(stream: &mut dyn Read) -> Result<(u8, Vec<u8>), TransportError> {
    loop {
        let (record_type, payload) = read_plain_record(stream)?;
        if record_type == RECORD_TYPE_CHANGE_CIPHER {
            continue;
        }
        return Ok((record_type, payload));
    }
}
// ---------------------------------------------------------------------------
// Application data stream
// ---------------------------------------------------------------------------

/// TLS 1.3 application-data stream over the REALITY session.
struct RealityStream {
    read_socket: BoxedTcpStream,
    write_socket: Option<BoxedTcpStream>,
    read_aead: SuiteAead,
    read_iv: [u8; 12],
    read_seq: u64,
    read_record: crate::tls_client::TlsRecordBuffer,
    write_state: Arc<Mutex<RealityWriteState>>,
    read_direct: bool,
    read_buf: Vec<u8>,
    read_off: usize,
    read_finished: bool,
    // Reserved for flows that defer the client Finished; unused on the
    // server side because the Finished is verified during the handshake.
    handshake_client_aead: Option<SuiteAead>,
    handshake_client_iv: [u8; 12],
    handshake_client_seq: u64,
}

struct RealityWriteState {
    aead: SuiteAead,
    iv: [u8; 12],
    seq: u64,
    direct: bool,
}

impl RealityStream {
    /// Reads one application-data record and stores its plaintext.
    /// A clean EOF (zero-byte read at a record boundary) ends the stream
    /// with Ok(false) to preserve the std::io::Read EOF semantics.
    fn load_next_record(&mut self) -> io::Result<bool> {
        let Some(record) = self.read_record.read_from(&mut *self.read_socket)? else {
            self.read_finished = true;
            return Ok(false);
        };
        if record[1..3] != TLS12_VERSION_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "reality: invalid TLS record version"));
        }
        let record_type = record[0];
        let payload = &record[RECORD_HEADER_LEN..];
        match record_type {
            RECORD_TYPE_APPLICATION => {
                let seq = self.read_seq;
                let plaintext = self
                    .read_aead
                    .open(&self.read_iv, seq, payload, &[RECORD_TYPE_APPLICATION, 3, 3])
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "reality: application record decrypt failed",
                        )
                    })?;
                self.read_seq = seq + 1;
                let (content_type, content) = decode_inner_plaintext(plaintext)?;
                match content_type {
                    RECORD_TYPE_APPLICATION => {
                        self.read_buf = content;
                        self.read_off = 0;
                    }
                    RECORD_TYPE_HANDSHAKE => {
                        // Post-handshake messages, e.g. session tickets, are
                        // TLS control traffic rather than VLESS payload.
                    }
                    21 if content.as_slice() == [1, 0] => {
                        self.read_finished = true;
                        return Ok(false);
                    }
                    21 => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "reality: TLS alert received",
                        ));
                    }
                    _ => unreachable!("inner content type was validated"),
                }
                Ok(true)
            }
            _ => {
                self.read_finished = true;
                Ok(false)
            }
        }
    }
}

impl Read for RealityStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.read_off < self.read_buf.len() {
                let read = (&self.read_buf[self.read_off..]).read(buf)?;
                self.read_off = self.read_off + read;
                if self.read_off == self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_off = 0;
                }
                return Ok(read);
            }
            if self.read_direct {
                return self.read_socket.read(buf);
            }
            if self.read_finished {
                return Ok(0);
            }
            if !self.load_next_record()? {
                return Ok(0);
            }
        }
    }
}

impl Write for RealityStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut state = self.write_state.lock().unwrap();
        if state.direct {
            return match self.write_socket.as_mut() {
                Some(socket) => socket.write(buf),
                None => self.read_socket.write(buf),
            };
        }
        let mut written = 0;
        while written < buf.len() {
            let chunk_len = (buf.len() - written).min(0x3fff);
            let chunk = &buf[written..written + chunk_len];
            let mut inner = chunk.to_vec();
            inner.push(RECORD_TYPE_APPLICATION);
            let sealed = state.aead.seal(
                &state.iv,
                state.seq,
                &inner,
                &[RECORD_TYPE_APPLICATION, 3, 3],
            );
            state.seq += 1;
            let mut header = [RECORD_TYPE_APPLICATION, 3, 3, 0, 0];
            header[3] = (sealed.len() >> 8) as u8;
            header[4] = (sealed.len() & 0xff) as u8;
            let write_socket = match self.write_socket.as_mut() {
                Some(socket) => socket,
                None => &mut self.read_socket,
            };
            write_socket.write_all(&header)?;
            write_socket.write_all(&sealed)?;
            written = written + chunk_len;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.write_socket.as_mut() {
            Some(socket) => socket.flush(),
            None => self.read_socket.flush(),
        }
    }
}

impl TcpStream for RealityStream {
    fn tcp_stats(&self)->Option<mihomo_core::TcpStats>{self.read_socket.tcp_stats()}
    fn set_timeouts(&self,read:Option<std::time::Duration>,write:Option<std::time::Duration>)->io::Result<()>{self.read_socket.set_timeouts(read,write)}

    fn supports_tls_passthrough(&self) -> bool {
        true
    }

    fn start_tls_passthrough_read(&mut self) -> io::Result<()> {
        // load_next_record reads exactly one record, so read_buf is the only
        // decrypted data to drain before reading directly from the socket.
        if !self.read_record.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "reality: passthrough requires a record boundary"));
        }
        self.read_direct = true;
        Ok(())
    }

    fn start_tls_passthrough_write(&mut self) -> io::Result<()> {
        self.flush()?;
        self.write_state.lock().unwrap().direct = true;
        Ok(())
    }

    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            read_socket: self.read_socket.try_clone_box()?,
            write_socket: self
                .write_socket
                .as_ref()
                .map(|socket| socket.try_clone_box())
                .transpose()?,
            read_aead: self.read_aead.clone(),
            read_iv: self.read_iv,
            read_seq: self.read_seq,
            read_record: self.read_record.clone(),
            write_state: Arc::clone(&self.write_state),
            read_direct: self.read_direct,
            read_buf: self.read_buf[self.read_off..].to_vec(),
            read_off: 0,
            read_finished: self.read_finished,
            handshake_client_aead: None,
            handshake_client_iv: [0_u8; 12],
            handshake_client_seq: 0,
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

/// Minimal TLS 1.3 ServerHello record (X25519 share) standing in for the
/// camouflage site; used by REALITY tests in this crate and in mihomo-app.
#[doc(hidden)]
pub(crate) fn fake_site_server_hello() -> Vec<u8> {
    fake_site_server_hello_with_suite(SUITE_AES_128_GCM_SHA256)
}

/// Same as [`fake_site_server_hello`] but negotiating an arbitrary suite, to
/// exercise the SHA-384 key schedule path.
#[doc(hidden)]
pub(crate) fn fake_site_server_hello_with_suite(suite: u16) -> Vec<u8> {
let mut share = [7_u8; 32];
share[0] = 0x01;
let mut extensions = Vec::new();
extensions.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
extensions.extend_from_slice(&2_u16.to_be_bytes());
extensions.extend_from_slice(&TLS13_VERSION.to_be_bytes());
extensions.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
extensions.extend_from_slice(&(2 + 2 + 32 as u16).to_be_bytes());
extensions.extend_from_slice(&GROUP_X25519.to_be_bytes());
extensions.extend_from_slice(&32_u16.to_be_bytes());
extensions.extend_from_slice(&share);
let mut body = Vec::new();
body.extend_from_slice(&TLS12_VERSION_BYTES);
body.extend_from_slice(&[0_u8; RANDOM_LEN]);
body.push(0); // empty session id echo
body.extend_from_slice(&suite.to_be_bytes());
body.push(0);
body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
body.extend_from_slice(&extensions);
let mut message = vec![HS_TYPE_SERVER_HELLO, 0, 0, 0];
message[1] = 0;
message[2] = (body.len() >> 8) as u8;
message[3] = (body.len() & 0xff) as u8;
message.extend_from_slice(&body);
let mut record = vec![RECORD_TYPE_HANDSHAKE, 3, 3, 0, 0];
record[3] = (message.len() >> 8) as u8;
record[4] = (message.len() & 0xff) as u8;
record.extend_from_slice(&message);
record
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::TcpListener;

    const TEST_PASSWORD: &str = "aGVsbG8td29ybGQtaXMtYS1nb29kLWRheS0tdG9kYXk";

    fn test_server_config() -> RealityServerConfig {
        let mut short_id = [0_u8; 8];
        short_id.copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        RealityServerConfig {
            private_key: RealityServerConfig::parse_private_key(TEST_PASSWORD).unwrap(),
            server_names: vec!["www.example.com".to_owned()],
            short_ids: vec![short_id],
            dest: String::new(),
            max_time_diff: 60,
        }
    }

    fn client_config_for(server: &RealityServerConfig, short_id: [u8; 8]) -> RealityClientConfig {
        let secret = XSecret::from(server.private_key);
        RealityClientConfig {
            public_key: XPublic::from(&secret).to_bytes(),
            short_id,
            server_name: "www.example.com".to_owned(),
            ..Default::default()
        }
    }


    #[test]
    fn client_hello_parses_back() {
        let mut config = client_config_for(&test_server_config(), [1, 2, 3, 4, 5, 6, 7, 8]);
        config.support_x25519mlkem768 = true;
        let mut x25519_priv = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut x25519_priv);
        let seed_array: ml_kem::Seed = [0_u8; 64].into();
        let dk = ml_kem::ml_kem_768::DecapsulationKey::from_seed(seed_array);
        let encapsulation = dk.encapsulation_key();
        let mlkem_encap = encapsulation.to_bytes().0;
        let random = [9_u8; RANDOM_LEN];
        let (hello, seal_plain) = build_client_hello(&config, &x25519_priv, &mlkem_encap, &random);
        let parsed = match parse_client_hello(&hello) {
            Some(parsed) => parsed,
            None => panic!("hello must parse (len={})", hello.len()),
        };
        assert_eq!(parsed.server_name, "www.example.com");
        assert_eq!(parsed.session_id_len, SID_LEN);
        assert_eq!(parsed.key_shares.len(), 2, "expect mlkem + x25519 shares");
        assert!(parsed.auth_peer_pub().is_some());
        let _ = seal_plain;
    }

    #[test]
    fn client_server_handshake_round_trip() {
        let server_config = test_server_config();
        let site = TcpListener::bind("127.0.0.1:0").unwrap();
        let site_addr = site.local_addr().unwrap();
        let site_worker = std::thread::spawn(move || {
            let (mut stream, _) = site.accept().unwrap();
            // Consume the mirrored ClientHello record.
            let mut header = [0_u8; RECORD_HEADER_LEN];
            stream.read_exact(&mut header).unwrap();
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut body = vec![0_u8; len];
            stream.read_exact(&mut body).unwrap();
            // Respond with a well-formed TLS 1.3 ServerHello.
            stream.write_all(&fake_site_server_hello()).unwrap();
            // Keep the socket open; the REALITY path drops it after handshake.
            std::thread::sleep(std::time::Duration::from_millis(200));
        });

        let mut server_config = test_server_config();
        server_config.dest = format!("127.0.0.1:{}", site_addr.port());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reality = accept_stream(Box::new(stream), &server_config).unwrap();
            let mut buf = [0_u8; 4];
            reality.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            reality.write_all(b"pong").unwrap();
            reality.flush().unwrap();
        });

        let raw = std::net::TcpStream::connect(addr).unwrap();
        let client_config = client_config_for(&test_server_config(), [1, 2, 3, 4, 5, 6, 7, 8]);
        let mut client = wrap_stream(
            Box::new(raw),
            &client_config,
            &TransportTarget::new("127.0.0.1", 443),
        )
        .unwrap();
        client.write_all(b"ping").unwrap();
        client.flush().unwrap();
        let mut buf = [0_u8; 4];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        worker.join().unwrap();
        site_worker.join().unwrap();
    }

    #[test]
    fn client_server_handshake_round_trip_sha384_suite() {
        // Dest sites commonly negotiate TLS_AES_256_GCM_SHA384; the whole
        // key schedule must switch to SHA-384 transcripts on both sides.
        let server_config = test_server_config();
        let site = TcpListener::bind("127.0.0.1:0").unwrap();
        let site_addr = site.local_addr().unwrap();
        let site_worker = std::thread::spawn(move || {
            let (mut stream, _) = site.accept().unwrap();
            let mut header = [0_u8; RECORD_HEADER_LEN];
            stream.read_exact(&mut header).unwrap();
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut body = vec![0_u8; len];
            stream.read_exact(&mut body).unwrap();
            stream
                .write_all(&fake_site_server_hello_with_suite(SUITE_AES_256_GCM_SHA384))
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(200));
        });

        let mut server_config = test_server_config();
        server_config.dest = format!("127.0.0.1:{}", site_addr.port());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reality = accept_stream(Box::new(stream), &server_config).unwrap();
            let mut buf = [0_u8; 4];
            reality.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            reality.write_all(b"pong").unwrap();
            reality.flush().unwrap();
        });

        let raw = std::net::TcpStream::connect(addr).unwrap();
        let client_config = client_config_for(&test_server_config(), [1, 2, 3, 4, 5, 6, 7, 8]);
        let mut client = wrap_stream(
            Box::new(raw),
            &client_config,
            &TransportTarget::new("127.0.0.1", 443),
        )
        .unwrap();
        client.write_all(b"ping").unwrap();
        client.flush().unwrap();
        let mut buf = [0_u8; 4];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        worker.join().unwrap();
        site_worker.join().unwrap();
    }

    #[test]
    fn bad_short_id_falls_back_to_steal() {
        let server_config = test_server_config();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let site = TcpListener::bind("127.0.0.1:0").unwrap();
        let site_addr = site.local_addr().unwrap();
        let site_worker = std::thread::spawn(move || {
            let (mut stream, _) = site.accept().unwrap();
            let mut buf = [0_u8; 5];
            let _ = stream.read_exact(&mut buf);
            stream
                .write_all(&[0x16, 0x03, 0x03, 0x00, 0x01, 0x00])
                .unwrap();
        });
        let mut config = server_config.clone();
        config.dest = format!("127.0.0.1:{}", site_addr.port());
        let worker = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let result = accept_stream(Box::new(stream), &config);
            assert!(result.is_err(), "bad short id must be rejected");
        });

        let raw = std::net::TcpStream::connect(addr).unwrap();
        let client_config = client_config_for(&test_server_config(), [9, 9, 9, 9, 9, 9, 9, 9]);
        let outcome = wrap_stream(
            Box::new(raw),
            &client_config,
            &TransportTarget::new("127.0.0.1", 443),
        );
        assert!(outcome.is_err(), "steal path must not look like REALITY");
        worker.join().unwrap();
        site_worker.join().unwrap();
    }
}

#[cfg(test)]
mod interop_tests;
