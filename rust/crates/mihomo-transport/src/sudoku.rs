use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, Cursor, Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;

use aes::Aes128;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AesGcm, Nonce};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use mihomo_core::{BoxedTcpStream, TcpStream};
use rand::{rngs::OsRng, rngs::StdRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

use crate::{TransportError, TransportTarget, WebsocketOptions};

use std::net::{SocketAddr, ToSocketAddrs};

const IO_BUFFER_SIZE: usize = 32 * 1024;
const KIP_MAGIC: &[u8; 3] = b"kip";
const KIP_TYPE_CLIENT_HELLO: u8 = 0x01;
const KIP_TYPE_SERVER_HELLO: u8 = 0x02;
const KIP_TYPE_OPEN_TCP: u8 = 0x10;
const KIP_TYPE_START_MUX: u8 = 0x11;
const KIP_TYPE_START_UOT: u8 = 0x12;
const RECORD_HEADER_SIZE: usize = 12;
const MAX_FRAME_BODY_SIZE: usize = 65_535;
const KIP_USER_HASH_SIZE: usize = 8;
const KIP_NONCE_SIZE: usize = 16;
const KIP_PUBKEY_SIZE: usize = 32;
const KIP_TABLE_HINT_SIZE: usize = 4;
const PROB_ONE: u64 = 1_u64 << 32;
const PACKED_PROTECTED_PREFIX_BYTES: usize = 14;

const PERM4: [[u8; 4]; 24] = [
    [0, 1, 2, 3],
    [0, 1, 3, 2],
    [0, 2, 1, 3],
    [0, 2, 3, 1],
    [0, 3, 1, 2],
    [0, 3, 2, 1],
    [1, 0, 2, 3],
    [1, 0, 3, 2],
    [1, 2, 0, 3],
    [1, 2, 3, 0],
    [1, 3, 0, 2],
    [1, 3, 2, 0],
    [2, 0, 1, 3],
    [2, 0, 3, 1],
    [2, 1, 0, 3],
    [2, 1, 3, 0],
    [2, 3, 0, 1],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [3, 0, 2, 1],
    [3, 1, 0, 2],
    [3, 1, 2, 0],
    [3, 2, 0, 1],
    [3, 2, 1, 0],
];

pub(crate) fn wrap_stream(
    mut stream: BoxedTcpStream,
    proxy: &TransportTarget,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
    http_mask_mode: &str,
    http_mask_tls: bool,
    http_mask_host: &str,
    path_root: &str,
    custom_table: &str,
    custom_tables: &[String],
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    validate_supported_options(
        table_type,
        enable_pure_downlink,
        http_mask_enabled,
        http_mask_mode,
        custom_table,
        custom_tables,
    )?;

    match normalized_http_mask_mode(http_mask_enabled, http_mask_mode) {
        Some("legacy") => write_legacy_http_mask_header(&mut *stream, target, path_root)?,
        Some("stream" | "poll" | "auto") => {
            stream = crate::sudoku_httpmask::dial_http_tunnel(
                stream,
                proxy,
                key,
                http_mask_mode,
                http_mask_tls,
                http_mask_host,
                path_root,
            )?;
        }
        Some("ws") => {
            stream = wrap_websocket_http_mask_stream(stream, proxy, key, path_root, http_mask_host)?;
        }
        Some(other) => {
            return Err(TransportError::UnsupportedFeature {
                proxy: "<sudoku>".to_owned(),
                feature: format!("http-mask-mode={other}"),
            })
        }
        None => {}
    }

    let seed = client_aead_seed(key)?;
    let choice = pick_client_tables(&seed, table_type, custom_table, custom_tables)?;
    let obfs: BoxedTcpStream = if enable_pure_downlink {
        Box::new(SudokuObfsStream::new(
            stream,
            Arc::clone(&choice.tables.uplink),
            Arc::clone(&choice.tables.downlink),
            padding_min,
            padding_max,
        ))
    } else {
        Box::new(SudokuPackedObfsStream::new(
            stream,
            Arc::clone(&choice.tables.uplink),
            Arc::clone(&choice.tables.downlink),
            padding_min,
            padding_max,
        ))
    };
    let (psk_c2s, psk_s2c) = derive_psk_directional_bases(&seed);
    let mut record = SudokuRecordStream::new(
        obfs,
        normalize_aead_method(aead_method)?,
        psk_c2s,
        psk_s2c,
    )?;
    perform_client_handshake(&mut record, &seed, key, choice.table_hint)?;

    let mut address = encode_address(&target.authority())?;
    write_kip_message(&mut record, KIP_TYPE_OPEN_TCP, &address)?;
    address.clear();
    Ok(Box::new(record))
}

fn validate_supported_options(
    table_type: &str,
    _enable_pure_downlink: bool,
    http_mask_enabled: bool,
    http_mask_mode: &str,
    _custom_table: &str,
    _custom_tables: &[String],
) -> Result<(), TransportError> {
    parse_ascii_mode(table_type)?;
    let Some(mode) = normalized_http_mask_mode(http_mask_enabled, http_mask_mode) else {
        return Ok(());
    };
    if mode != "legacy" && mode != "ws" && mode != "stream" && mode != "poll" && mode != "auto" {
        return Err(TransportError::UnsupportedFeature {
            proxy: "<sudoku>".to_owned(),
            feature: format!("http-mask-mode={mode}"),
        });
    }
    Ok(())
}

fn normalized_http_mask_mode<'a>(
    http_mask_enabled: bool,
    http_mask_mode: &'a str,
) -> Option<&'a str> {
    if !http_mask_enabled {
        return None;
    }
    let trimmed = http_mask_mode.trim();
    if trimmed.is_empty() {
        Some("legacy")
    } else {
        Some(trimmed)
    }
}

pub(crate) fn open_udp_stream(
    mut stream: BoxedTcpStream,
    proxy: &TransportTarget,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
    http_mask_mode: &str,
    http_mask_tls: bool,
    http_mask_host: &str,
    path_root: &str,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<BoxedTcpStream, TransportError> {
    validate_supported_options(
        table_type,
        enable_pure_downlink,
        http_mask_enabled,
        http_mask_mode,
        custom_table,
        custom_tables,
    )?;

    match normalized_http_mask_mode(http_mask_enabled, http_mask_mode) {
        Some("legacy") => {
            write_legacy_http_mask_header(
                &mut *stream,
                &TransportTarget::new("udp.sudoku.invalid", 0),
                path_root,
            )?;
        }
        Some("stream" | "poll" | "auto") => {
            stream = crate::sudoku_httpmask::dial_http_tunnel(
                stream,
                proxy,
                key,
                http_mask_mode,
                http_mask_tls,
                http_mask_host,
                path_root,
            )?;
        }
        Some("ws") => {
            stream = wrap_websocket_http_mask_stream(stream, proxy, key, path_root, http_mask_host)?;
        }
        Some(other) => {
            return Err(TransportError::UnsupportedFeature {
                proxy: "<sudoku>".to_owned(),
                feature: format!("http-mask-mode={other}"),
            })
        }
        None => {}
    }

    let seed = client_aead_seed(key)?;
    let choice = pick_client_tables(&seed, table_type, custom_table, custom_tables)?;
    let obfs: BoxedTcpStream = if enable_pure_downlink {
        Box::new(SudokuObfsStream::new(
            stream,
            Arc::clone(&choice.tables.uplink),
            Arc::clone(&choice.tables.downlink),
            padding_min,
            padding_max,
        ))
    } else {
        Box::new(SudokuPackedObfsStream::new(
            stream,
            Arc::clone(&choice.tables.uplink),
            Arc::clone(&choice.tables.downlink),
            padding_min,
            padding_max,
        ))
    };
    let (psk_c2s, psk_s2c) = derive_psk_directional_bases(&seed);
    let mut record = SudokuRecordStream::new(
        obfs,
        normalize_aead_method(aead_method)?,
        psk_c2s,
        psk_s2c,
    )?;
    perform_client_handshake(&mut record, &seed, key, choice.table_hint)?;
    write_kip_message(&mut record, KIP_TYPE_START_UOT, &[])?;
    Ok(Box::new(record))
}

pub(crate) fn open_multiplex_client_stream(
    mut stream: BoxedTcpStream,
    proxy: &TransportTarget,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
    http_mask_mode: &str,
    http_mask_tls: bool,
    http_mask_host: &str,
    path_root: &str,
    custom_table: &str,
    custom_tables: &[String],
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    validate_supported_options(
        table_type,
        enable_pure_downlink,
        http_mask_enabled,
        http_mask_mode,
        custom_table,
        custom_tables,
    )?;

    match normalized_http_mask_mode(http_mask_enabled, http_mask_mode) {
        Some("legacy") => write_legacy_http_mask_header(&mut *stream, target, path_root)?,
        Some("stream" | "poll" | "auto") => {
            stream = crate::sudoku_httpmask::dial_http_tunnel(
                stream,
                proxy,
                key,
                http_mask_mode,
                http_mask_tls,
                http_mask_host,
                path_root,
            )?;
        }
        Some("ws") => {
            stream = wrap_websocket_http_mask_stream(stream, proxy, key, path_root, http_mask_host)?;
        }
        Some(other) => {
            return Err(TransportError::UnsupportedFeature {
                proxy: "<sudoku>".to_owned(),
                feature: format!("http-mask-mode={other}"),
            })
        }
        None => {}
    }

    let seed = client_aead_seed(key)?;
    let choice = pick_client_tables(&seed, table_type, custom_table, custom_tables)?;
    let obfs: BoxedTcpStream = if enable_pure_downlink {
        Box::new(SudokuObfsStream::new(
            stream,
            Arc::clone(&choice.tables.uplink),
            Arc::clone(&choice.tables.downlink),
            padding_min,
            padding_max,
        ))
    } else {
        Box::new(SudokuPackedObfsStream::new(
            stream,
            Arc::clone(&choice.tables.uplink),
            Arc::clone(&choice.tables.downlink),
            padding_min,
            padding_max,
        ))
    };
    let (psk_c2s, psk_s2c) = derive_psk_directional_bases(&seed);
    let mut record = SudokuRecordStream::new(
        obfs,
        normalize_aead_method(aead_method)?,
        psk_c2s,
        psk_s2c,
    )?;
    perform_client_handshake(&mut record, &seed, key, choice.table_hint)?;
    write_kip_message(&mut record, KIP_TYPE_START_MUX, &[])?;
    Ok(Box::new(record))
}

pub(crate) fn write_udp_packet(
    stream: &mut dyn Write,
    destination: SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    let address = encode_address(&destination.to_string())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let mut header = [0_u8; 4];
    binary_write_u16(&mut header[..2], address.len() as u16);
    binary_write_u16(&mut header[2..], payload.len() as u16);
    write_all_chunks(stream, &[&header, &address, payload])?;
    Ok(payload.len())
}

pub(crate) fn read_udp_packet(
    stream: &mut dyn Read,
) -> io::Result<(SocketAddr, Vec<u8>)> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    let address_len = binary_read_u16(&header[..2]) as usize;
    let payload_len = binary_read_u16(&header[2..]) as usize;
    let mut address = vec![0_u8; address_len];
    stream.read_exact(&mut address)?;
    let destination = resolve_udp_address(&decode_address(&address)?)?;
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload)?;
    Ok((destination, payload))
}

fn perform_client_handshake(
    stream: &mut SudokuRecordStream,
    seed: &str,
    key: &str,
    table_hint: Option<u32>,
) -> Result<(), TransportError> {
    let mut ephemeral_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut ephemeral_bytes);
    let ephemeral = X25519Secret::from(ephemeral_bytes);
    let client_pub = X25519PublicKey::from(&ephemeral);
    let mut nonce = [0_u8; KIP_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    let user_hash = kip_user_hash_from_key(key);

    let mut payload = Vec::with_capacity(8 + KIP_USER_HASH_SIZE + KIP_NONCE_SIZE + KIP_PUBKEY_SIZE + 4);
    payload.extend_from_slice(&(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| TransportError::InvalidPlan(err.to_string()))?
        .as_secs() as i64)
        .to_be_bytes());
    payload.extend_from_slice(&user_hash);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(client_pub.as_bytes());
    payload.extend_from_slice(&0_u32.to_be_bytes());
    if let Some(table_hint) = table_hint {
        payload.extend_from_slice(&table_hint.to_be_bytes());
    }
    write_kip_message(stream, KIP_TYPE_CLIENT_HELLO, &payload)?;

    let server_hello = read_kip_message(stream)?;
    if server_hello.0 != KIP_TYPE_SERVER_HELLO {
        return Err(TransportError::invalid_proxy_response(format!(
            "unexpected sudoku handshake message {}",
            server_hello.0
        )));
    }
    if server_hello.1.len() != KIP_NONCE_SIZE + KIP_PUBKEY_SIZE + 4 {
        return Err(TransportError::invalid_proxy_response(
            "invalid sudoku server hello length",
        ));
    }
    let server_nonce = &server_hello.1[..KIP_NONCE_SIZE];
    if server_nonce != nonce {
        return Err(TransportError::invalid_proxy_response(
            "sudoku handshake nonce mismatch",
        ));
    }
    let mut server_pub = [0_u8; KIP_PUBKEY_SIZE];
    server_pub.copy_from_slice(&server_hello.1[KIP_NONCE_SIZE..KIP_NONCE_SIZE + KIP_PUBKEY_SIZE]);
    let shared = ephemeral.diffie_hellman(&X25519PublicKey::from(server_pub));
    let (sess_c2s, sess_s2c) =
        derive_session_directional_bases(seed, shared.as_bytes(), nonce);
    stream.rekey(sess_c2s, sess_s2c)?;
    Ok(())
}

fn normalize_aead_method(method: &str) -> Result<SudokuAeadMethod, TransportError> {
    match method.trim() {
        "" | "chacha20-poly1305" => Ok(SudokuAeadMethod::Chacha20Poly1305),
        "aes-128-gcm" => Ok(SudokuAeadMethod::Aes128Gcm),
        "none" => Ok(SudokuAeadMethod::None),
        other => Err(TransportError::UnsupportedFeature {
            proxy: "<sudoku>".to_owned(),
            feature: format!("aead-method={other}"),
        }),
    }
}

const ASCII_MODE_TOKEN_ASCII: &str = "ascii";
const ASCII_MODE_TOKEN_ENTROPY: &str = "entropy";

#[derive(Clone, Debug, Eq, PartialEq)]
struct SudokuAsciiMode {
    uplink: String,
    downlink: String,
}

fn parse_ascii_mode(mode: &str) -> Result<SudokuAsciiMode, TransportError> {
    let raw = mode.trim().to_ascii_lowercase();
    match raw.as_str() {
        "" | "entropy" | "prefer_entropy" => {
            return Ok(SudokuAsciiMode {
                uplink: ASCII_MODE_TOKEN_ENTROPY.to_owned(),
                downlink: ASCII_MODE_TOKEN_ENTROPY.to_owned(),
            })
        }
        "ascii" | "prefer_ascii" => {
            return Ok(SudokuAsciiMode {
                uplink: ASCII_MODE_TOKEN_ASCII.to_owned(),
                downlink: ASCII_MODE_TOKEN_ASCII.to_owned(),
            })
        }
        _ => {}
    }
    let Some(rest) = raw.strip_prefix("up_") else {
        return Err(TransportError::UnsupportedFeature {
            proxy: "<sudoku>".to_owned(),
            feature: format!("table-type={mode}"),
        });
    };
    let Some((up, down)) = rest.split_once("_down_") else {
        return Err(TransportError::UnsupportedFeature {
            proxy: "<sudoku>".to_owned(),
            feature: format!("table-type={mode}"),
        });
    };
    Ok(SudokuAsciiMode {
        uplink: normalize_ascii_mode_token(up, mode)?,
        downlink: normalize_ascii_mode_token(down, mode)?,
    })
}

fn normalize_ascii_mode_token(token: &str, original_mode: &str) -> Result<String, TransportError> {
    match token.trim().to_ascii_lowercase().as_str() {
        "ascii" | "prefer_ascii" => Ok(ASCII_MODE_TOKEN_ASCII.to_owned()),
        "" | "entropy" | "prefer_entropy" => Ok(ASCII_MODE_TOKEN_ENTROPY.to_owned()),
        _ => Err(TransportError::UnsupportedFeature {
            proxy: "<sudoku>".to_owned(),
            feature: format!("table-type={original_mode}"),
        }),
    }
}

fn single_direction_preference(token: &str) -> &str {
    if token == ASCII_MODE_TOKEN_ASCII {
        "prefer_ascii"
    } else {
        "prefer_entropy"
    }
}

fn custom_pattern_for_token(token: &str, custom_pattern: &str) -> String {
    if token == ASCII_MODE_TOKEN_ENTROPY {
        custom_pattern.trim().to_ascii_lowercase()
    } else {
        String::new()
    }
}

fn write_legacy_http_mask_header(
    stream: &mut dyn Write,
    target: &TransportTarget,
    path_root: &str,
) -> Result<(), TransportError> {
    let root = path_root.trim_matches('/');
    let path = if root.is_empty() {
        "/api/v1/upload"
    } else {
        return write_all_chunks(
            stream,
            &[format!(
                "POST /{root}/api/v1/upload HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.9\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nContent-Type: application/octet-stream\r\nContent-Length: 4096\r\n\r\n",
                target.host
            )
            .as_bytes()],
        )
        .map_err(TransportError::from);
    };
    write_all_chunks(
        stream,
        &[format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.9\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nContent-Type: application/octet-stream\r\nContent-Length: 4096\r\n\r\n",
            target.host
        )
        .as_bytes()],
    )
    .map_err(TransportError::from)
}

fn http_mask_ws_path(path_root: &str) -> String {
    let root = path_root.trim_matches('/');
    if root.is_empty() {
        "/ws".to_owned()
    } else {
        format!("/{root}/ws")
    }
}

fn wrap_websocket_http_mask_stream(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    key: &str,
    path_root: &str,
    http_mask_host: &str,
) -> Result<BoxedTcpStream, TransportError> {
    let mut headers = BTreeMap::new();
    headers.insert("X-Sudoku-Tunnel".to_owned(), "ws".to_owned());
    headers.insert("X-Sudoku-Version".to_owned(), "1".to_owned());
    let auth_key = client_aead_seed(key)?;
    if let Some(token) = crate::sudoku_httpmask::client_auth_token_for_ws(&auth_key) {
        headers.insert("Authorization".to_owned(), format!("Bearer {token}"));
    }
    if !http_mask_host.trim().is_empty() {
        headers.insert("Host".to_owned(), http_mask_host.trim().to_owned());
    }
    crate::websocket::wrap_stream(
        stream,
        proxy,
        &WebsocketOptions {
            path: http_mask_ws_path(path_root),
            headers,
            ..Default::default()
        },
    )
}

fn encode_custom_hint(
    value: u8,
    position: u8,
    x_bits: &[u8],
    p_bits: &[u8],
    v_bits: &[u8],
) -> u8 {
    let mut out = (1_u8 << x_bits[0]) | (1_u8 << x_bits[1]);
    if (value & 0x02) != 0 {
        out |= 1_u8 << p_bits[0];
    }
    if (value & 0x01) != 0 {
        out |= 1_u8 << p_bits[1];
    }
    for (index, bit) in v_bits.iter().enumerate() {
        if ((position >> (3 - index as u8)) & 0x01) != 0 {
            out |= 1_u8 << *bit;
        }
    }
    out
}

fn write_kip_message(
    writer: &mut dyn Write,
    message_type: u8,
    payload: &[u8],
) -> Result<(), TransportError> {
    let mut header = [0_u8; 6];
    header[..3].copy_from_slice(KIP_MAGIC);
    header[3] = message_type;
    binary_write_u16(&mut header[4..], payload.len() as u16);
    write_all_chunks(writer, &[&header, payload]).map_err(TransportError::from)
}

fn read_kip_message(reader: &mut dyn Read) -> Result<(u8, Vec<u8>), TransportError> {
    let mut header = [0_u8; 6];
    reader.read_exact(&mut header)?;
    if &header[..3] != KIP_MAGIC {
        return Err(TransportError::invalid_proxy_response(
            "invalid sudoku kip magic",
        ));
    }
    let payload_len = binary_read_u16(&header[4..]) as usize;
    let mut payload = vec![0_u8; payload_len];
    reader.read_exact(&mut payload)?;
    Ok((header[3], payload))
}

fn derive_psk_directional_bases(seed: &str) -> (Vec<u8>, Vec<u8>) {
    let sum = Sha256::digest(seed.as_bytes());
    let c2s = hkdf_expand(sum.as_slice(), b"sudoku-psk-c2s");
    let s2c = hkdf_expand(sum.as_slice(), b"sudoku-psk-s2c");
    (c2s, s2c)
}

fn derive_session_directional_bases(
    seed: &str,
    shared: &[u8],
    nonce: [u8; KIP_NONCE_SIZE],
) -> (Vec<u8>, Vec<u8>) {
    let salt = Sha256::digest(seed.as_bytes());
    let mut ikm = Vec::with_capacity(shared.len() + nonce.len());
    ikm.extend_from_slice(shared);
    ikm.extend_from_slice(&nonce);
    let prk = hkdf::Hkdf::<Sha256>::extract(Some(salt.as_slice()), &ikm).0;
    let c2s = hkdf_expand(prk.as_slice(), b"sudoku-session-c2s");
    let s2c = hkdf_expand(prk.as_slice(), b"sudoku-session-s2c");
    (c2s, s2c)
}

fn hkdf_expand(key_material: &[u8], info: &[u8]) -> Vec<u8> {
    let hkdf = hkdf::Hkdf::<Sha256>::from_prk(key_material).expect("valid hkdf prk");
    let mut out = vec![0_u8; 32];
    hkdf.expand(info, &mut out).expect("valid hkdf expand");
    out
}

fn kip_user_hash_from_key(key: &str) -> [u8; KIP_USER_HASH_SIZE] {
    let mut out = [0_u8; KIP_USER_HASH_SIZE];
    let digest = if let Ok(bytes) = hex::decode(key.trim()) {
        Sha256::digest(bytes)
    } else {
        Sha256::digest(key.as_bytes())
    };
    out.copy_from_slice(&digest[..KIP_USER_HASH_SIZE]);
    out
}

pub(crate) fn client_aead_seed(key: &str) -> Result<String, TransportError> {
    let key = key.trim();
    if key.is_empty() {
        return Err(TransportError::InvalidPlan(
            "sudoku transport requires key".to_owned(),
        ));
    }
    let Ok(bytes) = hex::decode(key) else {
        return Ok(key.to_owned());
    };
    if bytes.len() == 32 {
        let mut point_bytes = [0_u8; 32];
        point_bytes.copy_from_slice(&bytes);
        if let Some(point) = CompressedEdwardsY(point_bytes).decompress() {
            return Ok(hex::encode(point.compress().to_bytes()));
        }
        if let Some(scalar) = Option::<Scalar>::from(Scalar::from_canonical_bytes(point_bytes)) {
            let public = EdwardsPoint::mul_base(&scalar);
            return Ok(hex::encode(public.compress().to_bytes()));
        }
    }
    if bytes.len() == 64 {
        let mut r_bytes = [0_u8; 32];
        let mut k_bytes = [0_u8; 32];
        r_bytes.copy_from_slice(&bytes[..32]);
        k_bytes.copy_from_slice(&bytes[32..]);
        let Some(r) = Option::<Scalar>::from(Scalar::from_canonical_bytes(r_bytes)) else {
            return Ok(key.to_owned());
        };
        let Some(k) = Option::<Scalar>::from(Scalar::from_canonical_bytes(k_bytes)) else {
            return Ok(key.to_owned());
        };
        let public = EdwardsPoint::mul_base(&(r + k));
        return Ok(hex::encode(public.compress().to_bytes()));
    }
    Ok(key.to_owned())
}

fn encode_address(raw_addr: &str) -> Result<Vec<u8>, TransportError> {
    let (host, port) = split_host_port(raw_addr)?;
    let mut out = Vec::new();
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(addr) => {
                out.push(0x01);
                out.extend_from_slice(&addr.octets());
            }
            std::net::IpAddr::V6(addr) => {
                out.push(0x04);
                out.extend_from_slice(&addr.octets());
            }
        }
    } else {
        if host.len() > 255 {
            return Err(TransportError::InvalidPlan("sudoku domain too long".to_owned()));
        }
        out.push(0x03);
        out.push(host.len() as u8);
        out.extend_from_slice(host.as_bytes());
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

fn decode_address(payload: &[u8]) -> io::Result<String> {
    let mut reader = io::Cursor::new(payload);
    let mut atyp = [0_u8; 1];
    reader.read_exact(&mut atyp)?;
    match atyp[0] {
        0x01 => {
            let mut ip = [0_u8; 4];
            reader.read_exact(&mut ip)?;
            let mut port = [0_u8; 2];
            reader.read_exact(&mut port)?;
            Ok(SocketAddr::new(std::net::IpAddr::V4(ip.into()), binary_read_u16(&port)).to_string())
        }
        0x04 => {
            let mut ip = [0_u8; 16];
            reader.read_exact(&mut ip)?;
            let mut port = [0_u8; 2];
            reader.read_exact(&mut port)?;
            Ok(SocketAddr::new(std::net::IpAddr::V6(ip.into()), binary_read_u16(&port)).to_string())
        }
        0x03 => {
            let mut len = [0_u8; 1];
            reader.read_exact(&mut len)?;
            let mut host = vec![0_u8; len[0] as usize];
            reader.read_exact(&mut host)?;
            let mut port = [0_u8; 2];
            reader.read_exact(&mut port)?;
            Ok(format!("{}:{}", String::from_utf8_lossy(&host), binary_read_u16(&port)))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported sudoku address type {other}"),
        )),
    }
}

fn split_host_port(raw: &str) -> Result<(String, u16), TransportError> {
    if let Some(rest) = raw.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return Err(TransportError::InvalidPlan(format!(
                "invalid sudoku target address {raw}"
            )));
        };
        let port = port
            .parse()
            .map_err(|_| TransportError::InvalidPlan(format!("invalid sudoku port in {raw}")))?;
        return Ok((host.to_owned(), port));
    }
    let Some((host, port)) = raw.rsplit_once(':') else {
        return Err(TransportError::InvalidPlan(format!(
            "invalid sudoku target address {raw}"
        )));
    };
    let port = port
        .parse()
        .map_err(|_| TransportError::InvalidPlan(format!("invalid sudoku port in {raw}")))?;
    Ok((host.to_owned(), port))
}

fn resolve_udp_address(raw: &str) -> io::Result<SocketAddr> {
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let (host, port) = split_host_port(raw)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    let mut addrs = (host.as_str(), port).to_socket_addrs()?;
    addrs.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "sudoku udp domain target unresolved",
        )
    })
}

fn write_all_chunks(writer: &mut dyn Write, chunks: &[&[u8]]) -> io::Result<()> {
    for chunk in chunks {
        writer.write_all(chunk)?;
    }
    writer.flush()
}

fn binary_write_u16(dst: &mut [u8], value: u16) {
    dst[0] = (value >> 8) as u8;
    dst[1] = value as u8;
}

fn binary_write_u32(dst: &mut [u8], value: u32) {
    dst[0] = (value >> 24) as u8;
    dst[1] = (value >> 16) as u8;
    dst[2] = (value >> 8) as u8;
    dst[3] = value as u8;
}

fn binary_write_u64(dst: &mut [u8], value: u64) {
    dst.copy_from_slice(&value.to_be_bytes());
}

fn binary_read_u16(src: &[u8]) -> u16 {
    u16::from_be_bytes([src[0], src[1]])
}

fn binary_read_u32(src: &[u8]) -> u32 {
    u32::from_be_bytes([src[0], src[1], src[2], src[3]])
}

fn binary_read_u64(src: &[u8]) -> u64 {
    u64::from_be_bytes(src[..8].try_into().expect("u64 slice"))
}

struct SudokuTable {
    layout: SudokuLayout,
    encode_table: Vec<Vec<[u8; 4]>>,
    decode_map: HashMap<u32, u8>,
    padding_pool: Vec<u8>,
}

#[derive(Clone)]
struct SudokuTables {
    uplink: Arc<SudokuTable>,
    downlink: Arc<SudokuTable>,
    hint: u32,
    uplink_ascii: bool,
}

impl SudokuTables {
    fn new(key: &str, table_type: &str, custom_table: &str) -> Result<Self, TransportError> {
        let mode = parse_ascii_mode(table_type)?;
        let uplink_pattern = custom_pattern_for_token(&mode.uplink, custom_table);
        let downlink_pattern = custom_pattern_for_token(&mode.downlink, custom_table);
        let uplink = Arc::new(SudokuTable::new_single(
            key,
            single_direction_preference(&mode.uplink),
            &uplink_pattern,
        )?);
        let downlink = if mode.uplink == mode.downlink && uplink_pattern == downlink_pattern {
            Arc::clone(&uplink)
        } else {
            Arc::new(SudokuTable::new_single(
                key,
                single_direction_preference(&mode.downlink),
                &downlink_pattern,
            )?)
        };
        Ok(Self {
            uplink,
            downlink,
            hint: table_hint_fingerprint(
                key,
                canonical_ascii_mode(&mode),
                &uplink_pattern,
                &downlink_pattern,
            ),
            uplink_ascii: mode.uplink == ASCII_MODE_TOKEN_ASCII,
        })
    }
}

struct SudokuTableChoice {
    tables: SudokuTables,
    table_hint: Option<u32>,
}

fn pick_client_tables(
    key: &str,
    table_type: &str,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<SudokuTableChoice, TransportError> {
    let candidates = build_client_table_candidates(key, table_type, custom_table, custom_tables)?;
    if candidates.is_empty() {
        return Err(TransportError::InvalidPlan(
            "sudoku transport requires at least one table".to_owned(),
        ));
    }
    if candidates.len() == 1 {
        return Ok(SudokuTableChoice {
            tables: candidates[0].clone(),
            table_hint: None,
        });
    }
    let mut random = [0_u8; 1];
    OsRng.fill_bytes(&mut random);
    let selected = candidates[random[0] as usize % candidates.len()].clone();
    Ok(SudokuTableChoice {
        table_hint: Some(selected.hint),
        tables: selected,
    })
}

fn build_client_table_candidates(
    key: &str,
    table_type: &str,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<Vec<SudokuTables>, TransportError> {
    let patterns = normalized_custom_patterns(custom_table, custom_tables);
    patterns
        .iter()
        .map(|pattern| SudokuTables::new(key, table_type, pattern))
        .collect()
}

fn build_server_table_candidates(
    key: &str,
    table_type: &str,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<Vec<SudokuTables>, TransportError> {
    let mode = parse_ascii_mode(table_type)?;
    let mut patterns = normalized_custom_patterns(custom_table, custom_tables);
    if mode.uplink == ASCII_MODE_TOKEN_ENTROPY
        && patterns.iter().any(|pattern| !pattern.trim().is_empty())
        && patterns
            .first()
            .map(|pattern| !pattern.trim().is_empty())
            .unwrap_or(false)
    {
        patterns.insert(0, String::new());
    }
    patterns
        .iter()
        .map(|pattern| SudokuTables::new(key, table_type, pattern))
        .collect()
}

fn normalized_custom_patterns(custom_table: &str, custom_tables: &[String]) -> Vec<String> {
    if !custom_tables.is_empty() {
        return custom_tables
            .iter()
            .map(|pattern| pattern.trim().to_owned())
            .collect();
    }
    let custom_table = custom_table.trim();
    if custom_table.is_empty() {
        vec![String::new()]
    } else {
        vec![custom_table.to_owned()]
    }
}

fn canonical_ascii_mode(mode: &SudokuAsciiMode) -> String {
    if mode.uplink == ASCII_MODE_TOKEN_ASCII && mode.downlink == ASCII_MODE_TOKEN_ASCII {
        "prefer_ascii".to_owned()
    } else if mode.uplink == ASCII_MODE_TOKEN_ENTROPY && mode.downlink == ASCII_MODE_TOKEN_ENTROPY {
        "prefer_entropy".to_owned()
    } else {
        format!("up_{}_down_{}", mode.uplink, mode.downlink)
    }
}

fn table_hint_fingerprint(
    key: &str,
    mode: String,
    uplink_pattern: &str,
    downlink_pattern: &str,
) -> u32 {
    let mut payload = Vec::new();
    let uplink_pattern = uplink_pattern.trim().to_ascii_lowercase();
    let downlink_pattern = downlink_pattern.trim().to_ascii_lowercase();
    for part in [
        "sudoku-table-hint",
        key,
        mode.as_str(),
        uplink_pattern.as_str(),
        downlink_pattern.as_str(),
    ] {
        if !payload.is_empty() {
            payload.push(0);
        }
        payload.extend_from_slice(part.as_bytes());
    }
    let sum = Sha256::digest(&payload);
    u32::from_be_bytes([sum[0], sum[1], sum[2], sum[3]])
}

impl SudokuTable {
    fn new_single(key: &str, preference: &str, custom_pattern: &str) -> Result<Self, TransportError> {
        let layout = SudokuLayout::for_preference(preference, custom_pattern)?;
        let mut encode_table = vec![Vec::new(); 256];
        let mut decode_map = HashMap::new();
        let all_grids = generate_all_grids();
        let mut grids = all_grids.clone();
        let seed = {
            let digest = Sha256::digest(key.as_bytes());
            let mut bytes = [0_u8; 8];
            bytes.copy_from_slice(&digest[..8]);
            u64::from_be_bytes(bytes)
        };
        let mut rng = StdRng::seed_from_u64(seed);
        shuffle_grids(&mut grids, &mut rng);
        let combinations = generate_combinations();

        for byte_val in 0_u16..=255 {
            let target = &grids[byte_val as usize];
            for positions in &combinations {
                let mut raw_parts = [(0_u8, 0_u8); 4];
                for (index, position) in positions.iter().enumerate() {
                    raw_parts[index] = (target[*position] - 1, *position as u8);
                }
                if !is_unique_match(&all_grids, &raw_parts) {
                    continue;
                }
                let mut hints = [0_u8; 4];
                for (index, (value, position)) in raw_parts.iter().enumerate() {
                    hints[index] = layout.hint_byte(*value, *position);
                }
                encode_table[byte_val as usize].push(hints);
                decode_map.insert(pack_hints_to_key(hints), byte_val as u8);
            }
        }

        Ok(Self {
            padding_pool: layout.padding_pool.clone(),
            layout,
            encode_table,
            decode_map,
        })
    }
}

#[derive(Clone)]
struct SudokuLayout {
    hint_table: [bool; 256],
    encode_hint: [[u8; 16]; 4],
    encode_group: [u8; 64],
    decode_group: [u8; 256],
    group_valid: [bool; 256],
    pad_marker: u8,
    padding_pool: Vec<u8>,
}

impl SudokuLayout {
    fn for_preference(preference: &str, custom_pattern: &str) -> Result<Self, TransportError> {
        match preference.trim().to_ascii_lowercase().as_str() {
            "ascii" | "prefer_ascii" => Ok(Self::ascii_layout()),
            "" | "entropy" | "prefer_entropy" => {
                if custom_pattern.trim().is_empty() {
                    Ok(Self::entropy_layout())
                } else {
                    Self::custom_layout(custom_pattern)
                }
            }
            other => Err(TransportError::UnsupportedFeature {
                proxy: "<sudoku>".to_owned(),
                feature: format!("table-type={other}"),
            }),
        }
    }

    fn ascii_layout() -> Self {
        let mut hint_table = [false; 256];
        let mut encode_hint = [[0_u8; 16]; 4];
        for value in 0..4 {
            for position in 0..16 {
                let mut byte = 0x40 | ((value as u8) << 4) | position as u8;
                if byte == 0x7f {
                    byte = b'\n';
                }
                encode_hint[value][position] = byte;
            }
        }
        for byte in 0_u8..=255 {
            if (byte & 0x40) == 0x40 {
                hint_table[byte as usize] = true;
            }
        }
        hint_table[b'\n' as usize] = true;
        let mut encode_group = [0_u8; 64];
        let mut decode_group = [0_u8; 256];
        let mut group_valid = [false; 256];
        for group in 0..64_u8 {
            let mut byte = 0x40 | group;
            if byte == 0x7f {
                byte = b'\n';
            }
            encode_group[group as usize] = byte;
            decode_group[byte as usize] = group;
            group_valid[byte as usize] = true;
        }
        let padding_pool = (0..32).map(|index| 0x20_u8 + index).collect();
        Self {
            hint_table,
            encode_hint,
            encode_group,
            decode_group,
            group_valid,
            pad_marker: 0x3f,
            padding_pool,
        }
    }

    fn entropy_layout() -> Self {
        let mut hint_table = [false; 256];
        let mut encode_hint = [[0_u8; 16]; 4];
        for value in 0..4 {
            for position in 0..16 {
                encode_hint[value][position] = ((value as u8) << 5) | position as u8;
            }
        }
        for byte in 0_u8..=255 {
            if (byte & 0x90) == 0 {
                hint_table[byte as usize] = true;
            }
        }
        let mut encode_group = [0_u8; 64];
        let mut decode_group = [0_u8; 256];
        let mut group_valid = [false; 256];
        for group in 0..64_u8 {
            let byte = ((group & 0x30) << 1) | (group & 0x0f);
            encode_group[group as usize] = byte;
            decode_group[byte as usize] = group;
            group_valid[byte as usize] = true;
        }
        let mut padding_pool = Vec::with_capacity(16);
        for index in 0..8 {
            padding_pool.push(0x80_u8 + index);
            padding_pool.push(0x10_u8 + index);
        }
        Self {
            hint_table,
            encode_hint,
            encode_group,
            decode_group,
            group_valid,
            pad_marker: 0x80,
            padding_pool,
        }
    }

    fn custom_layout(pattern: &str) -> Result<Self, TransportError> {
        let cleaned = pattern
            .trim()
            .replace(' ', "")
            .to_ascii_lowercase();
        if cleaned.len() != 8 {
            return Err(TransportError::InvalidPlan(format!(
                "custom table must have 8 symbols, got {}",
                cleaned.len()
            )));
        }

        let mut x_bits = Vec::new();
        let mut p_bits = Vec::new();
        let mut v_bits = Vec::new();
        for (index, ch) in cleaned.chars().enumerate() {
            let bit = 7_u8
                .checked_sub(index as u8)
                .expect("custom table bit index");
            match ch {
                'x' => x_bits.push(bit),
                'p' => p_bits.push(bit),
                'v' => v_bits.push(bit),
                other => {
                    return Err(TransportError::InvalidPlan(format!(
                        "invalid char {other:?} in custom table"
                    )))
                }
            }
        }
        if x_bits.len() != 2 || p_bits.len() != 2 || v_bits.len() != 4 {
            return Err(TransportError::InvalidPlan(
                "custom table must contain exactly 2 x, 2 p, 4 v".to_owned(),
            ));
        }

        let mut x_mask = 0_u8;
        for bit in &x_bits {
            x_mask |= 1_u8 << *bit;
        }

        let mut encode_hint = [[0_u8; 16]; 4];
        for value in 0..4 {
            for position in 0..16 {
                encode_hint[value][position] =
                    encode_custom_hint(value as u8, position as u8, &x_bits, &p_bits, &v_bits);
            }
        }

        let mut hint_table = [false; 256];
        for byte in 0_u8..=255 {
            if (byte & x_mask) == x_mask {
                hint_table[byte as usize] = true;
            }
        }
        let mut encode_group = [0_u8; 64];
        let mut decode_group = [0_u8; 256];
        let mut group_valid = [false; 256];
        for group in 0..64_u8 {
            let value = (group >> 4) & 0x03;
            let position = group & 0x0f;
            let byte = encode_custom_hint(value, position, &x_bits, &p_bits, &v_bits);
            encode_group[group as usize] = byte;
            decode_group[byte as usize] = group;
            group_valid[byte as usize] = true;
        }

        let mut padding_pool = Vec::new();
        for drop_index in 0..x_bits.len() {
            for value in 0..4 {
                for position in 0..16 {
                    let mut byte =
                        encode_custom_hint(value as u8, position as u8, &x_bits, &p_bits, &v_bits);
                    byte &= !(1_u8 << x_bits[drop_index]);
                    if byte.count_ones() >= 5 {
                        padding_pool.push(byte);
                    }
                }
            }
        }
        padding_pool.sort_unstable();
        padding_pool.dedup();
        if padding_pool.is_empty() {
            return Err(TransportError::InvalidPlan(
                "custom table produced empty padding pool".to_owned(),
            ));
        }

        Ok(Self {
            hint_table,
            encode_hint,
            encode_group,
            decode_group,
            group_valid,
            pad_marker: padding_pool[0],
            padding_pool,
        })
    }

    fn hint_byte(&self, value: u8, position: u8) -> u8 {
        self.encode_hint[value as usize][position as usize]
    }

    fn group_byte(&self, group: u8) -> u8 {
        self.encode_group[group as usize]
    }

    fn decode_group(&self, byte: u8) -> Option<u8> {
        if !self.group_valid[byte as usize] {
            return None;
        }
        Some(self.decode_group[byte as usize])
    }
}

struct SudokuObfsStream {
    read_socket: BoxedTcpStream,
    write_socket: Option<BoxedTcpStream>,
    write_table: Arc<SudokuTable>,
    read_table: Arc<SudokuTable>,
    read_buf: [u8; IO_BUFFER_SIZE],
    pending: VecDeque<u8>,
    hint_buf: [u8; 4],
    hint_count: usize,
    rng: StdRng,
    padding_threshold: u64,
}

impl SudokuObfsStream {
    fn new(
        inner: BoxedTcpStream,
        write_table: Arc<SudokuTable>,
        read_table: Arc<SudokuTable>,
        padding_min: i32,
        padding_max: i32,
    ) -> Self {
        let write_socket = inner.try_clone_box().ok();
        let mut seed = [0_u8; 32];
        OsRng.fill_bytes(&mut seed);
        let rng = StdRng::from_seed(seed);
        let padding_threshold = pick_padding_threshold(&rng, padding_min, padding_max);
        Self {
            read_socket: inner,
            write_socket,
            write_table,
            read_table,
            read_buf: [0_u8; IO_BUFFER_SIZE],
            pending: VecDeque::new(),
            hint_buf: [0_u8; 4],
            hint_count: 0,
            rng,
            padding_threshold,
        }
    }

    fn write_socket(&mut self) -> &mut dyn Write {
        match self.write_socket.as_mut() {
            Some(socket) => &mut **socket,
            None => &mut *self.read_socket,
        }
    }

    fn decode_chunk(&mut self, chunk: &[u8]) -> Result<(), TransportError> {
        for byte in chunk {
            if !self.read_table.layout.hint_table[*byte as usize] {
                continue;
            }
            self.hint_buf[self.hint_count] = *byte;
            self.hint_count += 1;
            if self.hint_count == 4 {
                let key = pack_hints_to_key(self.hint_buf);
                let Some(value) = self.read_table.decode_map.get(&key).copied() else {
                    return Err(TransportError::invalid_proxy_response(
                        "sudoku decode map miss",
                    ));
                };
                self.pending.push_back(value);
                self.hint_count = 0;
            }
        }
        Ok(())
    }
}

impl Read for SudokuObfsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(read) = drain_pending_bytes(buf, &mut self.pending) {
            return Ok(read);
        }
        loop {
            let read = self.read_socket.read(&mut self.read_buf)?;
            if read == 0 {
                return Ok(0);
            }
            let chunk = self.read_buf[..read].to_vec();
            self.decode_chunk(&chunk)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            if let Some(decoded) = drain_pending_bytes(buf, &mut self.pending) {
                return Ok(decoded);
            }
        }
    }
}

impl Write for SudokuObfsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let encoded = encode_sudoku_payload(
            &self.write_table,
            &mut self.rng,
            self.padding_threshold,
            buf,
        );
        self.write_socket().write_all(&encoded)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_socket().flush()
    }
}

impl TcpStream for SudokuObfsStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            read_socket: self.read_socket.try_clone_box()?,
            write_socket: self
                .write_socket
                .as_ref()
                .map(|socket| socket.try_clone_box())
                .transpose()?,
            write_table: Arc::clone(&self.write_table),
            read_table: Arc::clone(&self.read_table),
            read_buf: [0_u8; IO_BUFFER_SIZE],
            pending: self.pending.clone(),
            hint_buf: self.hint_buf,
            hint_count: self.hint_count,
            rng: self.rng.clone(),
            padding_threshold: self.padding_threshold,
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

struct SudokuPackedObfsStream {
    inner: BoxedTcpStream,
    write_table: Arc<SudokuTable>,
    read_table: Arc<SudokuTable>,
    reader: io::BufReader<BoxedTcpStream>,
    pending: VecDeque<u8>,
    raw_buf: [u8; IO_BUFFER_SIZE],
    rng: StdRng,
    padding_threshold: u64,
    write_bit_buf: u64,
    write_bit_count: usize,
    read_bit_buf: u64,
    read_bit_count: usize,
    write_pad_marker: u8,
    write_pad_pool: Vec<u8>,
    read_pad_marker: u8,
}

impl SudokuPackedObfsStream {
    fn new(
        inner: BoxedTcpStream,
        write_table: Arc<SudokuTable>,
        read_table: Arc<SudokuTable>,
        padding_min: i32,
        padding_max: i32,
    ) -> Self {
        let mut seed = [0_u8; 32];
        OsRng.fill_bytes(&mut seed);
        let rng = StdRng::from_seed(seed);
        let padding_threshold = pick_padding_threshold(&rng, padding_min, padding_max);
        let reader_inner = inner.try_clone_box().expect("packed sudoku stream should clone underlay");
        let write_pad_marker = write_table.layout.pad_marker;
        let mut write_pad_pool = write_table.layout.padding_pool.clone();
        write_pad_pool.retain(|byte| *byte != write_pad_marker);
        if write_pad_pool.is_empty() {
            write_pad_pool.push(write_pad_marker);
        }
        let read_pad_marker = read_table.layout.pad_marker;
        Self {
            inner,
            write_table,
            read_table,
            reader: io::BufReader::with_capacity(IO_BUFFER_SIZE, reader_inner),
            pending: VecDeque::new(),
            raw_buf: [0_u8; IO_BUFFER_SIZE],
            rng,
            padding_threshold,
            write_bit_buf: 0,
            write_bit_count: 0,
            read_bit_buf: 0,
            read_bit_count: 0,
            write_pad_marker,
            write_pad_pool,
            read_pad_marker,
        }
    }

    fn maybe_add_padding(&mut self, out: &mut Vec<u8>) {
        if should_pad(&mut self.rng, self.padding_threshold) {
            let index = (self.rng.next_u32() as usize) % self.write_pad_pool.len();
            out.push(self.write_pad_pool[index]);
        }
    }

    fn append_group(&mut self, out: &mut Vec<u8>, group: u8) {
        self.maybe_add_padding(out);
        out.push(self.write_table.layout.group_byte(group & 0x3f));
    }

    fn append_forced_padding(&mut self, out: &mut Vec<u8>) {
        let index = (self.rng.next_u32() as usize) % self.write_pad_pool.len();
        out.push(self.write_pad_pool[index]);
    }

    fn next_prefix_gap(&mut self) -> usize {
        1 + (self.rng.next_u32() as usize % 2)
    }

    fn write_protected_prefix(&mut self, out: &mut Vec<u8>, payload: &[u8]) -> usize {
        if payload.is_empty() {
            return 0;
        }
        let limit = payload.len().min(PACKED_PROTECTED_PREFIX_BYTES);
        for _ in 0..(1 + (self.rng.next_u32() as usize % 2)) {
            self.append_forced_padding(out);
        }

        let mut gap = self.next_prefix_gap();
        let mut effective = 0;
        for byte in &payload[..limit] {
            self.write_bit_buf = (self.write_bit_buf << 8) | u64::from(*byte);
            self.write_bit_count += 8;
            while self.write_bit_count >= 6 {
                self.write_bit_count -= 6;
                let group = ((self.write_bit_buf >> self.write_bit_count) & 0x3f) as u8;
                if self.write_bit_count == 0 {
                    self.write_bit_buf = 0;
                } else {
                    self.write_bit_buf &= (1_u64 << self.write_bit_count) - 1;
                }
                self.append_group(out, group);
            }
            effective += 1;
            if effective >= gap {
                self.append_forced_padding(out);
                effective = 0;
                gap = self.next_prefix_gap();
            }
        }
        limit
    }

    fn decode_chunk(&mut self, chunk: &[u8]) -> Result<(), TransportError> {
        for byte in chunk {
            if !self.read_table.layout.hint_table[*byte as usize] {
                if *byte == self.read_pad_marker {
                    self.read_bit_buf = 0;
                    self.read_bit_count = 0;
                }
                continue;
            }
            let group = self
                .read_table
                .layout
                .decode_group(*byte)
                .ok_or_else(|| TransportError::invalid_proxy_response("sudoku packed decode map miss"))?;
            self.read_bit_buf = (self.read_bit_buf << 6) | u64::from(group);
            self.read_bit_count += 6;
            if self.read_bit_count >= 8 {
                self.read_bit_count -= 8;
                let value = ((self.read_bit_buf >> self.read_bit_count) & 0xff) as u8;
                self.pending.push_back(value);
                if self.read_bit_count == 0 {
                    self.read_bit_buf = 0;
                } else {
                    self.read_bit_buf &= (1_u64 << self.read_bit_count) - 1;
                }
            }
        }
        Ok(())
    }
}

impl Read for SudokuPackedObfsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(read) = drain_pending_bytes(buf, &mut self.pending) {
            return Ok(read);
        }
        loop {
            let read = self.reader.read(&mut self.raw_buf)?;
            if read == 0 {
                self.read_bit_buf = 0;
                self.read_bit_count = 0;
                return Ok(0);
            }
            let chunk = self.raw_buf[..read].to_vec();
            self.decode_chunk(&chunk)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            if let Some(decoded) = drain_pending_bytes(buf, &mut self.pending) {
                return Ok(decoded);
            }
        }
    }
}

impl Write for SudokuPackedObfsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut out = Vec::with_capacity(buf.len() * 2);
        let prefix_len = self.write_protected_prefix(&mut out, buf);
        let mut index = prefix_len;

        while self.write_bit_count > 0 && index < buf.len() {
            self.write_bit_buf = (self.write_bit_buf << 8) | u64::from(buf[index]);
            self.write_bit_count += 8;
            index += 1;
            while self.write_bit_count >= 6 {
                self.write_bit_count -= 6;
                let group = ((self.write_bit_buf >> self.write_bit_count) & 0x3f) as u8;
                if self.write_bit_count == 0 {
                    self.write_bit_buf = 0;
                } else {
                    self.write_bit_buf &= (1_u64 << self.write_bit_count) - 1;
                }
                self.append_group(&mut out, group);
            }
        }

        while index + 2 < buf.len() {
            let b1 = buf[index];
            let b2 = buf[index + 1];
            let b3 = buf[index + 2];
            index += 3;

            self.append_group(&mut out, (b1 >> 2) & 0x3f);
            self.append_group(&mut out, ((b1 & 0x03) << 4) | ((b2 >> 4) & 0x0f));
            self.append_group(&mut out, ((b2 & 0x0f) << 2) | ((b3 >> 6) & 0x03));
            self.append_group(&mut out, b3 & 0x3f);
        }

        while index < buf.len() {
            self.write_bit_buf = (self.write_bit_buf << 8) | u64::from(buf[index]);
            self.write_bit_count += 8;
            index += 1;
            while self.write_bit_count >= 6 {
                self.write_bit_count -= 6;
                let group = ((self.write_bit_buf >> self.write_bit_count) & 0x3f) as u8;
                if self.write_bit_count == 0 {
                    self.write_bit_buf = 0;
                } else {
                    self.write_bit_buf &= (1_u64 << self.write_bit_count) - 1;
                }
                self.append_group(&mut out, group);
            }
        }

        if self.write_bit_count > 0 {
            let group = ((self.write_bit_buf << (6 - self.write_bit_count)) & 0x3f) as u8;
            self.write_bit_buf = 0;
            self.write_bit_count = 0;
            self.append_group(&mut out, group);
            out.push(self.write_pad_marker);
        }

        self.maybe_add_padding(&mut out);
        self.inner.write_all(&out)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for SudokuPackedObfsStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sudoku packed obfs stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

struct ProbeTcpStream {
    inner: Cursor<Vec<u8>>,
}

impl Read for ProbeTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for ProbeTcpStream {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "probe stream is read-only"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for ProbeTcpStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "probe stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ReplayTcpStream {
    prefix: Cursor<Vec<u8>>,
    inner: BoxedTcpStream,
}

impl Read for ReplayTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.prefix.read(buf)?;
        if read != 0 {
            return Ok(read);
        }
        self.inner.read(buf)
    }
}

impl Write for ReplayTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for ReplayTcpStream {
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

#[derive(Clone)]
struct SharedRawStream {
    state: Arc<Mutex<SharedRawStreamState>>,
}

struct SharedRawStreamState {
    inner: BoxedTcpStream,
    recorded: Vec<u8>,
}

impl SharedRawStream {
    fn new(inner: BoxedTcpStream) -> Self {
        Self {
            state: Arc::new(Mutex::new(SharedRawStreamState {
                inner,
                recorded: Vec::new(),
            })),
        }
    }

    fn replay_stream(&self) -> BoxedTcpStream {
        let prefix = self
            .state
            .lock()
            .expect("shared raw stream mutex poisoned")
            .recorded
            .clone();
        Box::new(SharedReplayTcpStream {
            prefix: Cursor::new(prefix),
            shared: self.clone(),
        })
    }
}

impl Read for SharedRawStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut state = self.state.lock().expect("shared raw stream mutex poisoned");
        let read = state.inner.read(buf)?;
        if read != 0 {
            state.recorded.extend_from_slice(&buf[..read]);
        }
        Ok(read)
    }
}

impl Write for SharedRawStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.state.lock().expect("shared raw stream mutex poisoned");
        state.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.state.lock().expect("shared raw stream mutex poisoned");
        state.inner.flush()
    }
}

impl TcpStream for SharedRawStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "shared raw stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        let mut state = self.state.lock().expect("shared raw stream mutex poisoned");
        state.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        let mut state = self.state.lock().expect("shared raw stream mutex poisoned");
        state.inner.shutdown_all()
    }
}

struct SharedReplayTcpStream {
    prefix: Cursor<Vec<u8>>,
    shared: SharedRawStream,
}

impl Read for SharedReplayTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.prefix.read(buf)?;
        if read != 0 {
            return Ok(read);
        }
        self.shared.read(buf)
    }
}

impl Write for SharedReplayTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.shared.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.shared.flush()
    }
}

impl TcpStream for SharedReplayTcpStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "shared replay stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.shared.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shared.shutdown_all()
    }
}

const SUDOKU_MUX_FRAME_OPEN: u8 = 0x01;
const SUDOKU_MUX_FRAME_DATA: u8 = 0x02;
const SUDOKU_MUX_FRAME_CLOSE: u8 = 0x03;
const SUDOKU_MUX_FRAME_RESET: u8 = 0x04;
const SUDOKU_MUX_HEADER_SIZE: usize = 9;
const SUDOKU_MUX_MAX_FRAME_SIZE: usize = 256 * 1024;
const SUDOKU_MUX_MAX_DATA_PAYLOAD: usize = 32 * 1024;

struct SudokuMuxAcceptEvent {
    stream: SudokuMuxStream,
    payload: Vec<u8>,
}

struct SudokuMuxSessionState {
    closed: bool,
    close_err: Option<io::ErrorKind>,
    streams: HashMap<u32, std::sync::mpsc::Sender<SudokuMuxStreamEvent>>,
}

struct SudokuMuxWriterState {
    inner: BoxedTcpStream,
}

enum SudokuMuxStreamEvent {
    Data(Vec<u8>),
    Close,
}

struct SudokuMuxSession {
    state: Arc<Mutex<SudokuMuxSessionState>>,
    #[cfg(test)]
    writer: Arc<Mutex<SudokuMuxWriterState>>,
    accept_rx: std::sync::mpsc::Receiver<SudokuMuxAcceptEvent>,
}

#[derive(Clone)]
pub struct SudokuMultiplexServer {
    session: Arc<SudokuMuxSession>,
}

pub(crate) struct SudokuMuxStream {
    writer: Arc<Mutex<SudokuMuxWriterState>>,
    stream_id: u32,
    events: std::sync::mpsc::Receiver<SudokuMuxStreamEvent>,
    read_buf: Cursor<Vec<u8>>,
    read_closed: bool,
    write_closed: bool,
}

#[cfg(test)]
pub(crate) struct SudokuMultiplexClient {
    session: Arc<SudokuMuxSession>,
    next_stream_id: u32,
}

impl SudokuMuxSession {
    fn new(inner: BoxedTcpStream) -> io::Result<Arc<Self>> {
        let (accept_tx, accept_rx) = std::sync::mpsc::channel();
        let reader = inner.try_clone_box()?;
        let state = Arc::new(Mutex::new(SudokuMuxSessionState {
            closed: false,
            close_err: None,
            streams: HashMap::new(),
        }));
        let writer = Arc::new(Mutex::new(SudokuMuxWriterState { inner }));
        let read_state = Arc::clone(&state);
        let read_writer = Arc::clone(&writer);
        thread::spawn(move || sudoku_mux_read_loop(reader, read_state, read_writer, accept_tx));
        Ok(Arc::new(Self {
            state,
            #[cfg(test)]
            writer,
            accept_rx,
        }))
    }

    fn accept_stream(&self) -> io::Result<(SudokuMuxStream, Vec<u8>)> {
        match self.accept_rx.recv() {
            Ok(event) => Ok((event.stream, event.payload)),
            Err(_) => {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| io::Error::other("sudoku mux session mutex poisoned"))?;
                Err(io::Error::new(
                    state.close_err.unwrap_or(io::ErrorKind::BrokenPipe),
                    "sudoku mux session closed",
                ))
            }
        }
    }
}

impl SudokuMultiplexServer {
    pub(crate) fn new(stream: BoxedTcpStream) -> io::Result<Self> {
        Ok(Self {
            session: SudokuMuxSession::new(stream)?,
        })
    }

    pub fn accept_tcp(&self) -> io::Result<(BoxedTcpStream, String)> {
        let (stream, payload) = self.session.accept_stream()?;
        let target = decode_address(&payload)?;
        Ok((Box::new(stream), target))
    }
}

#[cfg(test)]
impl SudokuMultiplexClient {
    pub(crate) fn new(stream: BoxedTcpStream) -> io::Result<Self> {
        Ok(Self {
            session: SudokuMuxSession::new(stream)?,
            next_stream_id: 1,
        })
    }

    pub(crate) fn open_tcp(&mut self, target: &str) -> io::Result<BoxedTcpStream> {
        let stream_id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(1).max(1);
        let payload = encode_address(target)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        let (event_tx, event_rx) = std::sync::mpsc::channel();
        {
            let mut guard = self
                .session
                .state
                .lock()
                .map_err(|_| io::Error::other("sudoku mux client mutex poisoned"))?;
            guard.streams.insert(stream_id, event_tx);
        }
        sudoku_mux_send_frame(&self.session, SUDOKU_MUX_FRAME_OPEN, stream_id, &payload)?;
        Ok(Box::new(SudokuMuxStream {
            writer: Arc::clone(&self.session.writer),
            stream_id,
            events: event_rx,
            read_buf: Cursor::new(Vec::new()),
            read_closed: false,
            write_closed: false,
        }))
    }
}

fn sudoku_mux_read_loop(
    mut reader: BoxedTcpStream,
    state: Arc<Mutex<SudokuMuxSessionState>>,
    writer: Arc<Mutex<SudokuMuxWriterState>>,
    accept_tx: std::sync::mpsc::Sender<SudokuMuxAcceptEvent>,
) {
    loop {
        let mut header = [0_u8; SUDOKU_MUX_HEADER_SIZE];
        if let Err(err) = reader.read_exact(&mut header) {
            close_sudoku_mux_session(&state, err.kind());
            return;
        }

        let frame_type = header[0];
        let stream_id = u32::from_be_bytes(header[1..5].try_into().expect("sudoku mux stream id"));
        let payload_len =
            u32::from_be_bytes(header[5..9].try_into().expect("sudoku mux payload len")) as usize;
        if payload_len > SUDOKU_MUX_MAX_FRAME_SIZE {
            close_sudoku_mux_session(&state, io::ErrorKind::InvalidData);
            return;
        }

        let mut payload = vec![0_u8; payload_len];
        if payload_len != 0 {
            if let Err(err) = reader.read_exact(&mut payload) {
                close_sudoku_mux_session(&state, err.kind());
                return;
            }
        }

        match frame_type {
            SUDOKU_MUX_FRAME_OPEN => {
                let (event_tx, event_rx) = std::sync::mpsc::channel();
                {
                    let mut guard = match state.lock() {
                        Ok(guard) => guard,
                        Err(_) => return,
                    };
                    guard.streams.insert(stream_id, event_tx);
                }
                let stream = SudokuMuxStream {
                    writer: Arc::clone(&writer),
                    stream_id,
                    events: event_rx,
                    read_buf: Cursor::new(Vec::new()),
                    read_closed: false,
                    write_closed: false,
                };
                if accept_tx
                    .send(SudokuMuxAcceptEvent { stream, payload })
                    .is_err()
                {
                    close_sudoku_mux_session(&state, io::ErrorKind::BrokenPipe);
                    return;
                }
            }
            SUDOKU_MUX_FRAME_DATA => {
                if let Some(sender) = sudoku_mux_stream_sender(&state, stream_id) {
                    let _ = sender.send(SudokuMuxStreamEvent::Data(payload));
                }
            }
            SUDOKU_MUX_FRAME_CLOSE | SUDOKU_MUX_FRAME_RESET => {
                if let Some(sender) = sudoku_mux_take_stream_sender(&state, stream_id) {
                    let _ = sender.send(SudokuMuxStreamEvent::Close);
                }
            }
            _ => {
                close_sudoku_mux_session(&state, io::ErrorKind::InvalidData);
                return;
            }
        }
    }
}

fn sudoku_mux_stream_sender(
    state: &Arc<Mutex<SudokuMuxSessionState>>,
    stream_id: u32,
) -> Option<std::sync::mpsc::Sender<SudokuMuxStreamEvent>> {
    let guard = state.lock().ok()?;
    guard.streams.get(&stream_id).cloned()
}

fn sudoku_mux_take_stream_sender(
    state: &Arc<Mutex<SudokuMuxSessionState>>,
    stream_id: u32,
) -> Option<std::sync::mpsc::Sender<SudokuMuxStreamEvent>> {
    let mut guard = state.lock().ok()?;
    guard.streams.remove(&stream_id)
}

fn close_sudoku_mux_session(state: &Arc<Mutex<SudokuMuxSessionState>>, kind: io::ErrorKind) {
    let streams = {
        let mut guard = match state.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        if guard.closed {
            return;
        }
        guard.closed = true;
        guard.close_err = Some(kind);
        std::mem::take(&mut guard.streams)
    };
    for (_, sender) in streams {
        let _ = sender.send(SudokuMuxStreamEvent::Close);
    }
}

#[cfg(test)]
fn sudoku_mux_send_frame(
    session: &Arc<SudokuMuxSession>,
    frame_type: u8,
    stream_id: u32,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > SUDOKU_MUX_MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sudoku mux payload too large",
        ));
    }
    let mut header = [0_u8; SUDOKU_MUX_HEADER_SIZE];
    header[0] = frame_type;
    header[1..5].copy_from_slice(&stream_id.to_be_bytes());
    header[5..9].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    let mut guard = session
        .writer
        .lock()
        .map_err(|_| io::Error::other("sudoku mux session mutex poisoned"))?;
    guard.inner.write_all(&header)?;
    guard.inner.write_all(payload)?;
    guard.inner.flush()
}

fn sudoku_mux_send_frame_with_writer(
    writer: &Arc<Mutex<SudokuMuxWriterState>>,
    frame_type: u8,
    stream_id: u32,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > SUDOKU_MUX_MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sudoku mux payload too large",
        ));
    }
    let mut header = [0_u8; SUDOKU_MUX_HEADER_SIZE];
    header[0] = frame_type;
    header[1..5].copy_from_slice(&stream_id.to_be_bytes());
    header[5..9].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    let mut guard = writer
        .lock()
        .map_err(|_| io::Error::other("sudoku mux session mutex poisoned"))?;
    guard.inner.write_all(&header)?;
    guard.inner.write_all(payload)?;
    guard.inner.flush()
}

impl Read for SudokuMuxStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let remaining = self.read_buf.get_ref().len() as u64 - self.read_buf.position();
            if remaining != 0 {
                return self.read_buf.read(buf);
            }
            if self.read_closed {
                return Ok(0);
            }
            match self.events.recv() {
                Ok(SudokuMuxStreamEvent::Data(payload)) => {
                    self.read_buf = Cursor::new(payload);
                }
                Ok(SudokuMuxStreamEvent::Close) | Err(_) => {
                    self.read_closed = true;
                    return Ok(0);
                }
            }
        }
    }
}

impl Write for SudokuMuxStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.write_closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sudoku mux stream closed",
            ));
        }
        let mut written = 0usize;
        while written < buf.len() {
            let end = (written + SUDOKU_MUX_MAX_DATA_PAYLOAD).min(buf.len());
            sudoku_mux_send_frame_with_writer(
                &self.writer,
                SUDOKU_MUX_FRAME_DATA,
                self.stream_id,
                &buf[written..end],
            )?;
            written = end;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TcpStream for SudokuMuxStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sudoku mux stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        if self.write_closed {
            return Ok(());
        }
        sudoku_mux_send_frame_with_writer(&self.writer, SUDOKU_MUX_FRAME_CLOSE, self.stream_id, &[])?;
        self.write_closed = true;
        Ok(())
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.shutdown_write()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SudokuAeadMethod {
    None,
    Aes128Gcm,
    Chacha20Poly1305,
}

enum RecordCipher {
    Aes128(AesGcm<Aes128, aes_gcm::aead::consts::U12>),
    Chacha20(chacha20poly1305::ChaCha20Poly1305),
}

impl RecordCipher {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, TransportError> {
        let nonce = Nonce::from_slice(nonce);
        match self {
            Self::Aes128(cipher) => cipher
                .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
                .map_err(|_| TransportError::invalid_proxy_response("sudoku record encrypt failed")),
            Self::Chacha20(cipher) => cipher
                .encrypt(
                    chacha20poly1305::Nonce::from_slice(nonce),
                    chacha20poly1305::aead::Payload { msg: plaintext, aad },
                )
                .map_err(|_| TransportError::invalid_proxy_response("sudoku record encrypt failed")),
        }
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, TransportError> {
        match self {
            Self::Aes128(cipher) => cipher
                .decrypt(
                    Nonce::from_slice(nonce),
                    aes_gcm::aead::Payload { msg: ciphertext, aad },
                )
                .map_err(|_| TransportError::invalid_proxy_response("sudoku record decrypt failed")),
            Self::Chacha20(cipher) => cipher
                .decrypt(
                    chacha20poly1305::Nonce::from_slice(nonce),
                    chacha20poly1305::aead::Payload { msg: ciphertext, aad },
                )
                .map_err(|_| TransportError::invalid_proxy_response("sudoku record decrypt failed")),
        }
    }

    fn overhead(&self) -> usize {
        match self {
            Self::Aes128(_) | Self::Chacha20(_) => 16,
        }
    }
}

struct SudokuRecordStream {
    read_socket: BoxedTcpStream,
    write_socket: Option<BoxedTcpStream>,
    method: SudokuAeadMethod,
    base_send: Vec<u8>,
    base_recv: Vec<u8>,
    send_cipher: Option<RecordCipher>,
    recv_cipher: Option<RecordCipher>,
    send_cipher_epoch: u32,
    recv_cipher_epoch: u32,
    send_epoch: u32,
    send_seq: u64,
    send_bytes: i64,
    send_epoch_updates: u32,
    recv_epoch: u32,
    recv_seq: u64,
    recv_initialized: bool,
    read_plaintext: VecDeque<u8>,
}

impl SudokuRecordStream {
    fn new(
        inner: BoxedTcpStream,
        method: SudokuAeadMethod,
        base_send: Vec<u8>,
        base_recv: Vec<u8>,
    ) -> Result<Self, TransportError> {
        let write_socket = inner.try_clone_box().ok();
        let (send_epoch, send_seq) = random_record_counters()?;
        Ok(Self {
            read_socket: inner,
            write_socket,
            method,
            base_send,
            base_recv,
            send_cipher: None,
            recv_cipher: None,
            send_cipher_epoch: 0,
            recv_cipher_epoch: 0,
            send_epoch,
            send_seq,
            send_bytes: 0,
            send_epoch_updates: 0,
            recv_epoch: 0,
            recv_seq: 0,
            recv_initialized: false,
            read_plaintext: VecDeque::new(),
        })
    }

    fn write_socket(&mut self) -> &mut dyn Write {
        match self.write_socket.as_mut() {
            Some(socket) => &mut **socket,
            None => &mut *self.read_socket,
        }
    }

    fn rekey(&mut self, base_send: Vec<u8>, base_recv: Vec<u8>) -> Result<(), TransportError> {
        let (send_epoch, send_seq) = random_record_counters()?;
        self.base_send = base_send;
        self.base_recv = base_recv;
        self.send_cipher = None;
        self.recv_cipher = None;
        self.send_cipher_epoch = 0;
        self.recv_cipher_epoch = 0;
        self.send_epoch = send_epoch;
        self.send_seq = send_seq;
        self.send_bytes = 0;
        self.send_epoch_updates = 0;
        self.recv_epoch = 0;
        self.recv_seq = 0;
        self.recv_initialized = false;
        self.read_plaintext.clear();
        Ok(())
    }

    fn cipher_for_send(&mut self) -> Result<Option<&RecordCipher>, TransportError> {
        if self.method == SudokuAeadMethod::None {
            return Ok(None);
        }
        if self.send_cipher.is_none() || self.send_cipher_epoch != self.send_epoch {
            self.send_cipher = Some(new_record_cipher(
                self.method,
                &derive_epoch_key(&self.base_send, self.send_epoch, self.method),
            )?);
            self.send_cipher_epoch = self.send_epoch;
        }
        Ok(self.send_cipher.as_ref())
    }

    fn cipher_for_recv(&mut self, epoch: u32) -> Result<Option<&RecordCipher>, TransportError> {
        if self.method == SudokuAeadMethod::None {
            return Ok(None);
        }
        if self.recv_cipher.is_none() || self.recv_cipher_epoch != epoch {
            self.recv_cipher = Some(new_record_cipher(
                self.method,
                &derive_epoch_key(&self.base_recv, epoch, self.method),
            )?);
            self.recv_cipher_epoch = epoch;
        }
        Ok(self.recv_cipher.as_ref())
    }

    fn maybe_bump_send_epoch(&mut self, added_plaintext: usize) -> Result<(), TransportError> {
        if self.method == SudokuAeadMethod::None {
            return Ok(());
        }
        const KEY_UPDATE_AFTER_BYTES: i64 = 32 << 20;
        self.send_bytes += added_plaintext as i64;
        let threshold = KEY_UPDATE_AFTER_BYTES * i64::from(self.send_epoch_updates + 1);
        if self.send_bytes < threshold {
            return Ok(());
        }
        self.send_epoch = self.send_epoch.wrapping_add(1);
        self.send_epoch_updates = self.send_epoch_updates.wrapping_add(1);
        self.send_seq = random_nonzero_u64()?;
        Ok(())
    }

    fn validate_recv_position(&self, epoch: u32, seq: u64) -> Result<(), TransportError> {
        if !self.recv_initialized {
            return Ok(());
        }
        if epoch < self.recv_epoch {
            return Err(TransportError::invalid_proxy_response(
                "sudoku replayed epoch",
            ));
        }
        if epoch == self.recv_epoch && seq != self.recv_seq {
            return Err(TransportError::invalid_proxy_response(
                "sudoku out of order record",
            ));
        }
        if epoch > self.recv_epoch && epoch - self.recv_epoch > 8 {
            return Err(TransportError::invalid_proxy_response(
                "sudoku epoch jump too large",
            ));
        }
        Ok(())
    }

    fn mark_recv_position(&mut self, epoch: u32, seq: u64) {
        self.recv_epoch = epoch;
        self.recv_seq = seq.wrapping_add(1);
        self.recv_initialized = true;
    }
}

impl Read for SudokuRecordStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(read) = drain_pending_bytes(buf, &mut self.read_plaintext) {
            return Ok(read);
        }
        if self.method == SudokuAeadMethod::None {
            return self.read_socket.read(buf);
        }

        let mut length = [0_u8; 2];
        let read = self.read_socket.read(&mut length[..1])?;
        if read == 0 {
            return Ok(0);
        }
        self.read_socket.read_exact(&mut length[1..])?;
        let body_len = binary_read_u16(&length) as usize;
        if body_len < RECORD_HEADER_SIZE || body_len > MAX_FRAME_BODY_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid sudoku record body length",
            ));
        }
        let mut body = vec![0_u8; body_len];
        self.read_socket.read_exact(&mut body)?;
        let header = &body[..RECORD_HEADER_SIZE];
        let ciphertext = &body[RECORD_HEADER_SIZE..];
        let epoch = binary_read_u32(&header[..4]);
        let seq = binary_read_u64(&header[4..]);
        self.validate_recv_position(epoch, seq)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        let cipher = self
            .cipher_for_recv(epoch)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        let plaintext = cipher
            .expect("cipher for recv")
            .decrypt(header, ciphertext, header)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        self.mark_recv_position(epoch, seq);
        self.read_plaintext.extend(plaintext);
        drain_pending_bytes(buf, &mut self.read_plaintext)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "empty sudoku record"))
    }
}

impl Write for SudokuRecordStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.method == SudokuAeadMethod::None {
            return self.write_socket().write(buf);
        }
        let mut total = 0;
        while total < buf.len() {
            let send_epoch = self.send_epoch;
            let send_seq = self.send_seq;
            let overhead = {
                let cipher = self
                    .cipher_for_send()
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
                cipher.expect("cipher for send").overhead()
            };
            let max_plain = MAX_FRAME_BODY_SIZE - RECORD_HEADER_SIZE - overhead;
            let end = (total + max_plain).min(buf.len());
            let chunk = &buf[total..end];
            let mut header = [0_u8; RECORD_HEADER_SIZE];
            binary_write_u32(&mut header[..4], send_epoch);
            binary_write_u64(&mut header[4..], send_seq);
            let ciphertext = {
                let cipher = self
                    .cipher_for_send()
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
                cipher
                    .expect("cipher for send")
                    .encrypt(&header, chunk, &header)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?
            };
            self.send_seq = send_seq.wrapping_add(1);
            let body_len = RECORD_HEADER_SIZE + ciphertext.len();
            let mut length = [0_u8; 2];
            binary_write_u16(&mut length, body_len as u16);
            write_all_chunks(self.write_socket(), &[&length, &header, &ciphertext])?;
            total = end;
            self.maybe_bump_send_epoch(chunk.len())
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_socket().flush()
    }
}

impl TcpStream for SudokuRecordStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(Self {
            read_socket: self.read_socket.try_clone_box()?,
            write_socket: self
                .write_socket
                .as_ref()
                .map(|socket| socket.try_clone_box())
                .transpose()?,
            method: self.method,
            base_send: self.base_send.clone(),
            base_recv: self.base_recv.clone(),
            send_cipher: None,
            recv_cipher: None,
            send_cipher_epoch: self.send_cipher_epoch,
            recv_cipher_epoch: self.recv_cipher_epoch,
            send_epoch: self.send_epoch,
            send_seq: self.send_seq,
            send_bytes: self.send_bytes,
            send_epoch_updates: self.send_epoch_updates,
            recv_epoch: self.recv_epoch,
            recv_seq: self.recv_seq,
            recv_initialized: self.recv_initialized,
            read_plaintext: self.read_plaintext.clone(),
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

fn new_record_cipher(
    method: SudokuAeadMethod,
    key: &[u8],
) -> Result<RecordCipher, TransportError> {
    match method {
        SudokuAeadMethod::None => Err(TransportError::InvalidPlan(
            "sudoku none cipher should not build aead".to_owned(),
        )),
        SudokuAeadMethod::Aes128Gcm => Ok(RecordCipher::Aes128(
            AesGcm::<Aes128, aes_gcm::aead::consts::U12>::new_from_slice(&key[..16])
                .map_err(|err| TransportError::InvalidPlan(err.to_string()))?,
        )),
        SudokuAeadMethod::Chacha20Poly1305 => Ok(RecordCipher::Chacha20(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key[..32])
                .map_err(|err| TransportError::InvalidPlan(err.to_string()))?,
        )),
    }
}

fn derive_epoch_key(base: &[u8], epoch: u32, method: SudokuAeadMethod) -> Vec<u8> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(base).expect("valid hmac key");
    mac.update(b"sudoku-record:");
    match method {
        SudokuAeadMethod::None => mac.update(b"none"),
        SudokuAeadMethod::Aes128Gcm => mac.update(b"aes-128-gcm"),
        SudokuAeadMethod::Chacha20Poly1305 => mac.update(b"chacha20-poly1305"),
    }
    mac.update(&epoch.to_be_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn random_record_counters() -> Result<(u32, u64), TransportError> {
    Ok((random_nonzero_u32()?, random_nonzero_u64()?))
}

fn random_nonzero_u32() -> Result<u32, TransportError> {
    loop {
        let value = OsRng.next_u32();
        if value != 0 && value != u32::MAX {
            return Ok(value);
        }
    }
}

fn random_nonzero_u64() -> Result<u64, TransportError> {
    loop {
        let value = OsRng.next_u64();
        if value != 0 && value != u64::MAX {
            return Ok(value);
        }
    }
}

fn pick_padding_threshold(rng: &StdRng, padding_min: i32, padding_max: i32) -> u64 {
    let mut local = rng.clone();
    let mut min = padding_min.clamp(0, 100) as u64 * PROB_ONE / 100;
    let mut max = padding_max.clamp(0, 100) as u64 * PROB_ONE / 100;
    if max < min {
        std::mem::swap(&mut min, &mut max);
    }
    if max == min {
        return min;
    }
    min + (u64::from(local.next_u32()) * (max - min) >> 32)
}

fn should_pad(rng: &mut StdRng, threshold: u64) -> bool {
    if threshold == 0 {
        return false;
    }
    if threshold >= PROB_ONE {
        return true;
    }
    u64::from(rng.next_u32()) < threshold
}

fn encode_sudoku_payload(
    table: &SudokuTable,
    rng: &mut StdRng,
    padding_threshold: u64,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() * 6 + 1);
    for byte in payload {
        if should_pad(rng, padding_threshold) {
            out.push(table.padding_pool[(rng.next_u32() as usize) % table.padding_pool.len()]);
        }
        let puzzles = &table.encode_table[*byte as usize];
        let puzzle = puzzles[(rng.next_u32() as usize) % puzzles.len()];
        let permutation = PERM4[(rng.next_u32() as usize) % PERM4.len()];
        for index in permutation {
            if should_pad(rng, padding_threshold) {
                out.push(table.padding_pool[(rng.next_u32() as usize) % table.padding_pool.len()]);
            }
            out.push(puzzle[index as usize]);
        }
    }
    if should_pad(rng, padding_threshold) {
        out.push(table.padding_pool[(rng.next_u32() as usize) % table.padding_pool.len()]);
    }
    out
}

fn drain_pending_bytes(buf: &mut [u8], pending: &mut VecDeque<u8>) -> Option<usize> {
    if pending.is_empty() {
        return None;
    }
    let mut read = 0;
    while read < buf.len() {
        let Some(byte) = pending.pop_front() else {
            break;
        };
        buf[read] = byte;
        read += 1;
    }
    Some(read)
}

type Grid = [u8; 16];

fn generate_all_grids() -> Vec<Grid> {
    let mut grids = Vec::new();
    let mut grid = [0_u8; 16];
    backtrack_grid(0, &mut grid, &mut grids);
    grids
}

fn backtrack_grid(index: usize, grid: &mut Grid, grids: &mut Vec<Grid>) {
    if index == 16 {
        grids.push(*grid);
        return;
    }
    let row = index / 4;
    let col = index % 4;
    let box_row = (row / 2) * 2;
    let box_col = (col / 2) * 2;
    'candidate: for number in 1..=4_u8 {
        for i in 0..4 {
            if grid[row * 4 + i] == number || grid[i * 4 + col] == number {
                continue 'candidate;
            }
        }
        for r in 0..2 {
            for c in 0..2 {
                if grid[(box_row + r) * 4 + (box_col + c)] == number {
                    continue 'candidate;
                }
            }
        }
        grid[index] = number;
        backtrack_grid(index + 1, grid, grids);
        grid[index] = 0;
    }
}

fn shuffle_grids(grids: &mut [Grid], rng: &mut StdRng) {
    let len = grids.len();
    for i in (1..len).rev() {
        let j = (rng.next_u32() as usize) % (i + 1);
        grids.swap(i, j);
    }
}

fn generate_combinations() -> Vec<[usize; 4]> {
    let mut combinations = Vec::new();
    let mut current = Vec::new();
    combine_positions(0, 4, &mut current, &mut combinations);
    combinations
}

fn combine_positions(
    start: usize,
    remaining: usize,
    current: &mut Vec<usize>,
    out: &mut Vec<[usize; 4]>,
) {
    if remaining == 0 {
        out.push([current[0], current[1], current[2], current[3]]);
        return;
    }
    for index in start..=(16 - remaining) {
        current.push(index);
        combine_positions(index + 1, remaining - 1, current, out);
        current.pop();
    }
}

fn is_unique_match(grids: &[Grid], parts: &[(u8, u8); 4]) -> bool {
    let mut matches = 0;
    for grid in grids {
        if parts
            .iter()
            .all(|(value, position)| grid[*position as usize] == value + 1)
        {
            matches += 1;
            if matches > 1 {
                return false;
            }
        }
    }
    matches == 1
}

fn pack_hints_to_key(mut hints: [u8; 4]) -> u32 {
    hints.sort_unstable();
    (u32::from(hints[0]) << 24)
        | (u32::from(hints[1]) << 16)
        | (u32::from(hints[2]) << 8)
        | u32::from(hints[3])
}

pub(crate) enum SudokuServerSession {
    Tcp { target: String, stream: BoxedTcpStream },
    Multiplex { stream: BoxedTcpStream },
    Udp { stream: BoxedTcpStream },
}

pub(crate) enum SudokuServerAcceptOutcome {
    Session(SudokuServerSession),
    Suspicious(BoxedTcpStream),
}

pub(crate) fn accept_server_stream_for_tests(
    stream: BoxedTcpStream,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
) -> Result<SudokuServerSession, TransportError> {
    accept_server_stream_for_tests_with_custom(
        stream,
        key,
        aead_method,
        table_type,
        padding_min,
        padding_max,
        enable_pure_downlink,
        http_mask_enabled,
        "",
    )
}

pub(crate) fn accept_server_stream_for_tests_with_custom(
    stream: BoxedTcpStream,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
    custom_table: &str,
) -> Result<SudokuServerSession, TransportError> {
    accept_server_stream_for_tests_with_custom_tables(
        stream,
        key,
        aead_method,
        table_type,
        padding_min,
        padding_max,
        enable_pure_downlink,
        http_mask_enabled,
        custom_table,
        &[],
    )
}

pub(crate) fn accept_server_stream_for_tests_with_custom_tables(
    mut stream: BoxedTcpStream,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<SudokuServerSession, TransportError> {
    if http_mask_enabled {
        consume_legacy_http_mask_header(&mut *stream)?;
    }
    let seed = client_aead_seed(key)?;
    let candidates = build_server_table_candidates(&seed, table_type, custom_table, custom_tables)?;
    let (tables, stream) = select_server_tables(
        stream,
        &seed,
        aead_method,
        &candidates,
        padding_min,
        padding_max,
    )?;
    let obfs: BoxedTcpStream = if enable_pure_downlink {
        Box::new(SudokuObfsStream::new(
            stream,
            Arc::clone(&tables.downlink),
            Arc::clone(&tables.uplink),
            padding_min,
            padding_max,
        ))
    } else {
        Box::new(SudokuPackedObfsStream::new(
            stream,
            Arc::clone(&tables.downlink),
            Arc::clone(&tables.uplink),
            padding_min,
            padding_max,
        ))
    };
    let (psk_c2s, psk_s2c) = derive_psk_directional_bases(&seed);
    let mut record = SudokuRecordStream::new(
        obfs,
        normalize_aead_method(aead_method)?,
        psk_s2c,
        psk_c2s,
    )?;

    let client_hello = read_kip_message(&mut record)?;
    if client_hello.0 != KIP_TYPE_CLIENT_HELLO {
        return Err(TransportError::invalid_proxy_response(
            "unexpected sudoku client hello type",
        ));
    }
    let client_hello = decode_client_hello(&client_hello.1)?;
    let nonce = client_hello.nonce;
    let client_pub = client_hello.client_pub;

    let mut server_secret_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut server_secret_bytes);
    let server_secret = X25519Secret::from(server_secret_bytes);
    let server_pub = X25519PublicKey::from(&server_secret);
    let session_shared = server_secret.diffie_hellman(&X25519PublicKey::from(client_pub));

    let mut server_hello = Vec::with_capacity(KIP_NONCE_SIZE + KIP_PUBKEY_SIZE + 4);
    server_hello.extend_from_slice(&nonce);
    server_hello.extend_from_slice(server_pub.as_bytes());
    server_hello.extend_from_slice(&0_u32.to_be_bytes());
    write_kip_message(&mut record, KIP_TYPE_SERVER_HELLO, &server_hello)?;
    let (sess_c2s, sess_s2c) =
        derive_session_directional_bases(&seed, session_shared.as_bytes(), nonce);
    record.rekey(sess_s2c, sess_c2s)?;

    let session = read_kip_message(&mut record)?;
    match session.0 {
        KIP_TYPE_OPEN_TCP => Ok(SudokuServerSession::Tcp {
            target: decode_address(&session.1).map_err(TransportError::from)?,
            stream: Box::new(record),
        }),
        KIP_TYPE_START_MUX => Ok(SudokuServerSession::Multiplex {
            stream: Box::new(record),
        }),
        KIP_TYPE_START_UOT => Ok(SudokuServerSession::Udp {
            stream: Box::new(record),
        }),
        other => Err(TransportError::invalid_proxy_response(format!(
            "unexpected sudoku session type {other}"
        ))),
    }
}

struct DecodedClientHello {
    nonce: [u8; KIP_NONCE_SIZE],
    client_pub: [u8; KIP_PUBKEY_SIZE],
    table_hint: Option<u32>,
}

fn decode_client_hello(payload: &[u8]) -> Result<DecodedClientHello, TransportError> {
    let min_len = 8 + KIP_USER_HASH_SIZE + KIP_NONCE_SIZE + KIP_PUBKEY_SIZE + 4;
    if payload.len() < min_len {
        return Err(TransportError::invalid_proxy_response(
            "invalid sudoku client hello length",
        ));
    }
    let mut nonce = [0_u8; KIP_NONCE_SIZE];
    nonce.copy_from_slice(
        &payload[8 + KIP_USER_HASH_SIZE..8 + KIP_USER_HASH_SIZE + KIP_NONCE_SIZE],
    );
    let mut client_pub = [0_u8; KIP_PUBKEY_SIZE];
    client_pub.copy_from_slice(
        &payload[8 + KIP_USER_HASH_SIZE + KIP_NONCE_SIZE
            ..8 + KIP_USER_HASH_SIZE + KIP_NONCE_SIZE + KIP_PUBKEY_SIZE],
    );
    let table_hint = if payload.len() >= min_len + KIP_TABLE_HINT_SIZE {
        Some(u32::from_be_bytes(
            payload[min_len..min_len + KIP_TABLE_HINT_SIZE]
                .try_into()
                .expect("table hint length"),
        ))
    } else {
        None
    };
    Ok(DecodedClientHello {
        nonce,
        client_pub,
        table_hint,
    })
}

fn probe_client_hello_with_tables(
    probe: &[u8],
    seed: &str,
    aead_method: &str,
    tables: &SudokuTables,
    padding_min: i32,
    padding_max: i32,
) -> Result<DecodedClientHello, TransportError> {
    let obfs = SudokuObfsStream::new(
        Box::new(ProbeTcpStream {
            inner: Cursor::new(probe.to_vec()),
        }),
        Arc::clone(&tables.downlink),
        Arc::clone(&tables.uplink),
        padding_min,
        padding_max,
    );
    let (psk_c2s, psk_s2c) = derive_psk_directional_bases(seed);
    let mut record = SudokuRecordStream::new(
        Box::new(obfs),
        normalize_aead_method(aead_method)?,
        psk_s2c,
        psk_c2s,
    )?;
    let client_hello = read_kip_message(&mut record)?;
    if client_hello.0 != KIP_TYPE_CLIENT_HELLO {
        return Err(TransportError::invalid_proxy_response(
            "unexpected sudoku client hello type",
        ));
    }
    decode_client_hello(&client_hello.1)
}

fn select_server_tables(
    mut stream: BoxedTcpStream,
    seed: &str,
    aead_method: &str,
    candidates: &[SudokuTables],
    padding_min: i32,
    padding_max: i32,
) -> Result<(SudokuTables, BoxedTcpStream), TransportError> {
    if candidates.is_empty() {
        return Err(TransportError::InvalidPlan(
            "no sudoku table candidates".to_owned(),
        ));
    }
    if candidates.len() == 1 {
        return Ok((candidates[0].clone(), stream));
    }

    let mut active = (0..candidates.len()).collect::<Vec<_>>();
    let mut probe = Vec::new();
    let mut buf = [0_u8; 4096];
    while probe.len() < 64 * 1024 {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            return Err(TransportError::invalid_proxy_response(
                "sudoku handshake probe reached eof",
            ));
        }
        probe.extend_from_slice(&buf[..read]);

        let mut next = Vec::new();
        for index in &active {
            match probe_client_hello_with_tables(
                &probe,
                seed,
                aead_method,
                &candidates[*index],
                padding_min,
                padding_max,
            ) {
                Ok(hello) => {
                    let resolved = if let Some(hint) = hello.table_hint {
                        let resolved = candidates
                            .iter()
                            .find(|candidate| candidate.hint == hint)
                            .ok_or_else(|| {
                                TransportError::invalid_proxy_response(format!(
                                    "unknown sudoku table hint {hint}"
                                ))
                            })?
                            .clone();
                        if resolved.hint != candidates[*index].hint
                            && (!resolved.uplink_ascii || !candidates[*index].uplink_ascii)
                        {
                            return Err(TransportError::invalid_proxy_response(format!(
                                "sudoku table hint {hint} mismatches probed uplink table"
                            )));
                        }
                        resolved
                    } else {
                        candidates[*index].clone()
                    };
                    return Ok((
                        resolved,
                        Box::new(ReplayTcpStream {
                            prefix: Cursor::new(probe),
                            inner: stream,
                        }),
                    ));
                }
                Err(TransportError::Io { kind, .. })
                    if matches!(kind, io::ErrorKind::UnexpectedEof | io::ErrorKind::WouldBlock) =>
                {
                    next.push(*index);
                }
                Err(TransportError::Io { kind, .. }) if kind == io::ErrorKind::BrokenPipe => {
                    next.push(*index);
                }
                Err(_) => {}
            }
        }
        active = next;
        if active.is_empty() {
            break;
        }
    }

    Err(TransportError::invalid_proxy_response(
        "sudoku handshake table selection failed",
    ))
}

pub(crate) fn accept_server_stream_for_tests_with_custom_tables_allow_suspicious(
    stream: BoxedTcpStream,
    key: &str,
    aead_method: &str,
    table_type: &str,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    http_mask_enabled: bool,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<SudokuServerAcceptOutcome, TransportError> {
    let shared = SharedRawStream::new(stream);
    let mut stream: BoxedTcpStream = Box::new(shared.clone());
    if http_mask_enabled {
        consume_legacy_http_mask_header(&mut *stream)?;
    }
    let seed = client_aead_seed(key)?;
    let candidates = build_server_table_candidates(&seed, table_type, custom_table, custom_tables)?;
    let (tables, stream) = match select_server_tables_allow_suspicious(
        stream,
        &seed,
        aead_method,
        &candidates,
        padding_min,
        padding_max,
    ) {
        Ok(value) => value,
        Err(_) => return Ok(SudokuServerAcceptOutcome::Suspicious(shared.replay_stream())),
    };
    let obfs: BoxedTcpStream = if enable_pure_downlink {
        Box::new(SudokuObfsStream::new(
            stream,
            Arc::clone(&tables.downlink),
            Arc::clone(&tables.uplink),
            padding_min,
            padding_max,
        ))
    } else {
        Box::new(SudokuPackedObfsStream::new(
            stream,
            Arc::clone(&tables.downlink),
            Arc::clone(&tables.uplink),
            padding_min,
            padding_max,
        ))
    };
    let (psk_c2s, psk_s2c) = derive_psk_directional_bases(&seed);
    let mut record = SudokuRecordStream::new(
        obfs,
        normalize_aead_method(aead_method)?,
        psk_s2c,
        psk_c2s,
    )?;

    let client_hello = match read_kip_message(&mut record) {
        Ok(message) => message,
        Err(_) => return Ok(SudokuServerAcceptOutcome::Suspicious(shared.replay_stream())),
    };
    if client_hello.0 != KIP_TYPE_CLIENT_HELLO {
        return Ok(SudokuServerAcceptOutcome::Suspicious(shared.replay_stream()));
    }
    let client_hello = match decode_client_hello(&client_hello.1) {
        Ok(hello) => hello,
        Err(_) => return Ok(SudokuServerAcceptOutcome::Suspicious(shared.replay_stream())),
    };
    let nonce = client_hello.nonce;
    let client_pub = client_hello.client_pub;

    let mut server_secret_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut server_secret_bytes);
    let server_secret = X25519Secret::from(server_secret_bytes);
    let server_pub = X25519PublicKey::from(&server_secret);
    let session_shared = server_secret.diffie_hellman(&X25519PublicKey::from(client_pub));

    let mut server_hello = Vec::with_capacity(KIP_NONCE_SIZE + KIP_PUBKEY_SIZE + 4);
    server_hello.extend_from_slice(&nonce);
    server_hello.extend_from_slice(server_pub.as_bytes());
    server_hello.extend_from_slice(&0_u32.to_be_bytes());
    if write_kip_message(&mut record, KIP_TYPE_SERVER_HELLO, &server_hello).is_err() {
        return Ok(SudokuServerAcceptOutcome::Suspicious(shared.replay_stream()));
    }
    let (sess_c2s, sess_s2c) =
        derive_session_directional_bases(&seed, session_shared.as_bytes(), nonce);
    if record.rekey(sess_s2c, sess_c2s).is_err() {
        return Ok(SudokuServerAcceptOutcome::Suspicious(shared.replay_stream()));
    }

    let session = match read_kip_message(&mut record) {
        Ok(message) => message,
        Err(_) => return Ok(SudokuServerAcceptOutcome::Suspicious(shared.replay_stream())),
    };
    match session.0 {
        KIP_TYPE_OPEN_TCP => Ok(SudokuServerAcceptOutcome::Session(
            SudokuServerSession::Tcp {
                target: match decode_address(&session.1) {
                    Ok(target) => target,
                    Err(_) => return Ok(SudokuServerAcceptOutcome::Suspicious(shared.replay_stream())),
                },
                stream: Box::new(record),
            },
        )),
        KIP_TYPE_START_MUX => Ok(SudokuServerAcceptOutcome::Session(
            SudokuServerSession::Multiplex {
                stream: Box::new(record),
            },
        )),
        KIP_TYPE_START_UOT => Ok(SudokuServerAcceptOutcome::Session(
            SudokuServerSession::Udp {
                stream: Box::new(record),
            },
        )),
        other => Err(TransportError::invalid_proxy_response(format!(
            "unexpected sudoku session type {other}"
        ))),
    }
}

fn select_server_tables_allow_suspicious(
    mut stream: BoxedTcpStream,
    seed: &str,
    aead_method: &str,
    candidates: &[SudokuTables],
    padding_min: i32,
    padding_max: i32,
) -> Result<(SudokuTables, BoxedTcpStream), BoxedTcpStream> {
    if candidates.is_empty() {
        return Err(stream);
    }
    if candidates.len() == 1 {
        return Ok((candidates[0].clone(), stream));
    }

    let mut active = (0..candidates.len()).collect::<Vec<_>>();
    let mut probe = Vec::new();
    let mut buf = [0_u8; 4096];
    while probe.len() < 64 * 1024 {
        let read = match stream.read(&mut buf) {
            Ok(read) => read,
            Err(_) => break,
        };
        if read == 0 {
            break;
        }
        probe.extend_from_slice(&buf[..read]);

        let mut next = Vec::new();
        for index in &active {
            match probe_client_hello_with_tables(
                &probe,
                seed,
                aead_method,
                &candidates[*index],
                padding_min,
                padding_max,
            ) {
                Ok(hello) => {
                    let resolved = if let Some(hint) = hello.table_hint {
                        match candidates.iter().find(|candidate| candidate.hint == hint) {
                            Some(candidate) => candidate.clone(),
                            None => candidates[*index].clone(),
                        }
                    } else {
                        candidates[*index].clone()
                    };
                    return Ok((
                        resolved,
                        Box::new(ReplayTcpStream {
                            prefix: Cursor::new(probe),
                            inner: stream,
                        }),
                    ));
                }
                Err(TransportError::Io { kind, .. })
                    if matches!(kind, io::ErrorKind::UnexpectedEof | io::ErrorKind::WouldBlock) =>
                {
                    next.push(*index);
                }
                Err(TransportError::Io { kind, .. }) if kind == io::ErrorKind::BrokenPipe => {
                    next.push(*index);
                }
                Err(_) => {}
            }
        }
        active = next;
        if active.is_empty() {
            break;
        }
    }

    Err(Box::new(ReplayTcpStream {
        prefix: Cursor::new(probe),
        inner: stream,
    }))
}

fn consume_legacy_http_mask_header(reader: &mut dyn Read) -> Result<(), TransportError> {
    let mut last = [0_u8; 4];
    let mut filled = 0_usize;
    loop {
        let mut byte = [0_u8; 1];
        reader.read_exact(&mut byte)?;
        if filled < 4 {
            last[filled] = byte[0];
            filled += 1;
        } else {
            last.rotate_left(1);
            last[3] = byte[0];
        }
        if filled == 4 && last == *b"\r\n\r\n" {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use sha1::{Digest, Sha1};
    use mihomo_core::BoxedTcpStream;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use crate::{
        SocketOptions, SystemTcpDialer, TcpTransportExecutor, TransportAction, TransportHop,
        TransportPlan, TransportPlanRunner, TransportTarget,
    };

    use super::{
        accept_server_stream_for_tests, accept_server_stream_for_tests_with_custom,
        accept_server_stream_for_tests_with_custom_tables,
        accept_server_stream_for_tests_with_custom_tables_allow_suspicious, open_udp_stream,
        open_multiplex_client_stream, read_udp_packet, wrap_stream, write_udp_packet,
        SudokuMultiplexClient, SudokuMultiplexServer, SudokuServerAcceptOutcome,
        SudokuServerSession,
    };

    struct ServerWebsocketStream {
        inner: BoxedTcpStream,
        pending: Vec<u8>,
        offset: usize,
    }

    impl ServerWebsocketStream {
        fn new(inner: BoxedTcpStream) -> Self {
            Self {
                inner,
                pending: Vec::new(),
                offset: 0,
            }
        }

        fn read_frame(&mut self) -> std::io::Result<Option<Vec<u8>>> {
            let mut header = [0_u8; 2];
            self.inner.read_exact(&mut header)?;
            let fin = header[0] & 0x80 != 0;
            let opcode = header[0] & 0x0f;
            let masked = header[1] & 0x80 != 0;
            let mut len = u64::from(header[1] & 0x7f);
            if len == 126 {
                let mut ext = [0_u8; 2];
                self.inner.read_exact(&mut ext)?;
                len = u64::from(u16::from_be_bytes(ext));
            } else if len == 127 {
                let mut ext = [0_u8; 8];
                self.inner.read_exact(&mut ext)?;
                len = u64::from_be_bytes(ext);
            }
            let mask = if masked {
                let mut mask = [0_u8; 4];
                self.inner.read_exact(&mut mask)?;
                Some(mask)
            } else {
                None
            };
            let mut payload = vec![0_u8; len as usize];
            self.inner.read_exact(&mut payload)?;
            if let Some(mask) = mask {
                for (index, byte) in payload.iter_mut().enumerate() {
                    *byte ^= mask[index % 4];
                }
            }
            match opcode {
                0x1 | 0x2 => {
                    assert!(fin, "fragmented websocket frames are unsupported");
                    Ok(Some(payload))
                }
                0x8 => Ok(None),
                0x9 => {
                    self.write_frame(0xA, &payload)?;
                    Ok(Some(Vec::new()))
                }
                0xA => Ok(Some(Vec::new())),
                other => panic!("unexpected websocket opcode {other}"),
            }
        }

        fn write_frame(&mut self, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
            let mut header = Vec::with_capacity(10);
            header.push(0x80 | (opcode & 0x0f));
            if payload.len() < 126 {
                header.push(payload.len() as u8);
            } else if payload.len() < 65_536 {
                header.push(126);
                header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            } else {
                header.push(127);
                header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
            }
            self.inner.write_all(&header)?;
            self.inner.write_all(payload)?;
            self.inner.flush()
        }
    }

    impl Read for ServerWebsocketStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
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
            loop {
                let Some(frame) = self.read_frame()? else {
                    return Ok(0);
                };
                if frame.is_empty() {
                    continue;
                }
                let copied = frame.len().min(buf.len());
                buf[..copied].copy_from_slice(&frame[..copied]);
                if copied < frame.len() {
                    self.pending = frame;
                    self.offset = copied;
                }
                return Ok(copied);
            }
        }
    }

    impl Write for ServerWebsocketStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.write_frame(0x2, buf)?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    impl mihomo_core::TcpStream for ServerWebsocketStream {
        fn try_clone_box(&self) -> std::io::Result<BoxedTcpStream> {
            Ok(Box::new(Self::new(self.inner.try_clone_box()?)))
        }

        fn shutdown_write(&mut self) -> std::io::Result<()> {
            self.inner.shutdown_write()
        }

        fn shutdown_all(&mut self) -> std::io::Result<()> {
            self.inner.shutdown_all()
        }
    }

    fn websocket_accept_key(key: &str) -> String {
        let mut sha1 = Sha1::new();
        sha1.update(key.as_bytes());
        sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        base64::engine::general_purpose::STANDARD.encode(sha1.finalize())
    }

    fn read_http_headers(stream: &mut dyn Read) -> String {
        let mut buf = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            stream.read_exact(&mut byte).unwrap();
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8(buf).unwrap()
    }

    fn accept_websocket_test_stream(mut stream: BoxedTcpStream) -> (String, BoxedTcpStream) {
        let request = read_http_headers(&mut *stream);
        let key = request
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("Sec-WebSocket-Key") {
                    Some(value.trim().to_owned())
                } else {
                    None
                }
            })
            .expect("missing Sec-WebSocket-Key");
        let accept = websocket_accept_key(&key);
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
        (request, Box::new(ServerWebsocketStream::new(stream)))
    }

    #[test]
    fn sudoku_tcp_stream_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuServerSession::Tcp { target, mut stream } = session else {
                panic!("expected tcp session");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-sudoku".into(),
            selected_path: vec!["edge-sudoku".into()],
            leaf_name: "edge-sudoku".into(),
            hops: vec![TransportHop {
                name: "edge-sudoku".into(),
                action: TransportAction::SudokuConnect {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    key: "secret-seed".into(),
                    aead_method: "chacha20-poly1305".into(),
                    table_type: "prefer_entropy".into(),
                    padding_min: 10,
                    padding_max: 30,
                    enable_pure_downlink: true,
                    http_mask_enabled: false,
                    http_mask_mode: String::new(),
                    http_mask_tls: false,
                    http_mask_host: String::new(),
                    path_root: String::new(),
                    custom_table: String::new(),
                    custom_tables: Vec::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-sudoku");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_udp_stream_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "aes-128-gcm",
                "prefer_ascii",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuServerSession::Udp { mut stream } = session else {
                panic!("expected udp session");
            };
            let (target, payload) = read_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
            assert_eq!(payload, b"via-sudoku");
            write_udp_packet(&mut *stream, target, b"sudoku-ok").unwrap();
            stream.shutdown_write().unwrap();
        });

        let mut client = open_udp_stream(
            Box::new(std::net::TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "aes-128-gcm",
            "prefer_ascii",
            10,
            30,
            true,
            false,
            "",
            false,
            "",
            "",
            "",
            &[],
        )
        .unwrap();
        write_udp_packet(&mut *client, "127.0.0.1:5353".parse().unwrap(), b"via-sudoku").unwrap();
        let (target, payload) = read_udp_packet(&mut *client).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(payload, b"sudoku-ok");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_packed_downlink_tcp_stream_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "chacha20-poly1305",
                "up_ascii_down_entropy",
                10,
                30,
                false,
                false,
            )
            .unwrap();
            let SudokuServerSession::Tcp { target, mut stream } = session else {
                panic!("expected tcp session");
            };
            assert_eq!(target, "packed.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-packed").unwrap();
            stream.shutdown_write().unwrap();
        });

        let mut stream = wrap_stream(
            Box::new(std::net::TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "chacha20-poly1305",
            "up_ascii_down_entropy",
            10,
            30,
            false,
            false,
            "",
            false,
            "",
            "",
            "",
            &[],
            &TransportTarget::new("packed.example.com", 443),
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-packed");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_packed_downlink_udp_stream_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "chacha20-poly1305",
                "up_ascii_down_entropy",
                10,
                30,
                false,
                false,
            )
            .unwrap();
            let SudokuServerSession::Udp { mut stream } = session else {
                panic!("expected udp session");
            };
            let (target, payload) = read_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
            assert_eq!(payload, b"via-packed-sudoku");
            write_udp_packet(&mut *stream, target, b"packed-sudoku-ok").unwrap();
            stream.shutdown_write().unwrap();
        });

        let mut client = open_udp_stream(
            Box::new(std::net::TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "chacha20-poly1305",
            "up_ascii_down_entropy",
            10,
            30,
            false,
            false,
            "",
            false,
            "",
            "",
            "",
            &[],
        )
        .unwrap();
        write_udp_packet(
            &mut *client,
            "127.0.0.1:5353".parse().unwrap(),
            b"via-packed-sudoku",
        )
        .unwrap();
        let (target, payload) = read_udp_packet(&mut *client).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(payload, b"packed-sudoku-ok");
        worker.join().unwrap();
    }


    #[test]
    fn sudoku_udp_packet_supports_fqdn_targets() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&13_u16.to_be_bytes());
        packet.extend_from_slice(&4_u16.to_be_bytes());
        packet.push(0x03);
        packet.push(9);
        packet.extend_from_slice(b"localhost");
        packet.extend_from_slice(&5353_u16.to_be_bytes());
        packet.extend_from_slice(b"dns!");

        let (target, payload) = read_udp_packet(&mut std::io::Cursor::new(packet)).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(payload, b"dns!");
    }

    #[test]
    fn sudoku_supports_legacy_http_mask_header() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                true,
            )
            .unwrap();
            let SudokuServerSession::Tcp { mut stream, .. } = session else {
                panic!("expected tcp session");
            };
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").unwrap();
            stream.shutdown_write().unwrap();
        });

        let mut stream = wrap_stream(
            Box::new(std::net::TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            true,
            "",
            false,
            "",
            "mask",
            "",
            &[],
            &TransportTarget::new("mask.example.com", 443),
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_supports_websocket_http_mask_header() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.contains("GET /mask/ws HTTP/1.1\r\n"));
            assert!(request.contains("Host: cdn.example.com:8443\r\n"));
            assert!(request.contains("X-Sudoku-Tunnel: ws\r\n"));
            assert!(request.contains("X-Sudoku-Version: 1\r\n"));
            let session = accept_server_stream_for_tests(
                stream,
                "secret-seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuServerSession::Tcp { mut stream, .. } = session else {
                panic!("expected tcp session");
            };
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").unwrap();
            stream.shutdown_write().unwrap();
        });

        let mut stream = wrap_stream(
            Box::new(std::net::TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            true,
            "ws",
            false,
            "cdn.example.com:8443",
            "mask",
            "",
            &[],
            &TransportTarget::new("mask.example.com", 443),
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_ignores_http_mask_mode_when_disabled() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuServerSession::Tcp { mut stream, .. } = session else {
                panic!("expected tcp session");
            };
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").unwrap();
            stream.shutdown_write().unwrap();
        });

        let mut stream = wrap_stream(
            Box::new(std::net::TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            false,
            "ws",
            false,
            "",
            "mask",
            "",
            &[],
            &TransportTarget::new("mask.example.com", 443),
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_supports_directional_table_modes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "seed",
                "chacha20-poly1305",
                "up_ascii_down_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuServerSession::Tcp { target, mut stream } = session else {
                panic!("expected tcp session");
            };
            assert_eq!(target, "directional.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").unwrap();
            stream.shutdown_write().unwrap();
        });

        let mut stream = wrap_stream(
            Box::new(std::net::TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "seed",
            "chacha20-poly1305",
            "up_ascii_down_entropy",
            10,
            30,
            true,
            false,
            "",
            false,
            "",
            "",
            "",
            &[],
            &TransportTarget::new("directional.example.com", 443),
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_supports_single_custom_table() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let session = accept_server_stream_for_tests_with_custom(
                Box::new(stream),
                "seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
                "xpxvvpvv",
            )
            .unwrap();
            let SudokuServerSession::Tcp { target, mut stream } = session else {
                panic!("expected tcp session");
            };
            assert_eq!(target, "custom.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").unwrap();
            stream.shutdown_write().unwrap();
        });

        let mut stream = wrap_stream(
            Box::new(std::net::TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            false,
            "",
            false,
            "",
            "xpxvvpvv",
            "",
            &[],
            &TransportTarget::new("custom.example.com", 443),
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_supports_custom_table_rotation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let session = accept_server_stream_for_tests_with_custom_tables(
                Box::new(stream),
                "seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
                "",
                &["xpxvvpvv".to_owned(), "vxpvxvvp".to_owned()],
            )
            .unwrap();
            let SudokuServerSession::Tcp { target, mut stream } = session else {
                panic!("expected tcp session");
            };
            assert_eq!(target, "rotation.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").unwrap();
            stream.shutdown_write().unwrap();
        });

        let mut stream = wrap_stream(
            Box::new(std::net::TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            false,
            "",
            false,
            "",
            "",
            "",
            &["xpxvvpvv".to_owned(), "vxpvxvvp".to_owned()],
            &TransportTarget::new("rotation.example.com", 443),
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong");
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_multiplex_streams_round_trip_multiple_targets() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let session = accept_server_stream_for_tests(
                Box::new(stream),
                "secret-seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
            )
            .unwrap();
            let SudokuServerSession::Multiplex { stream } = session else {
                panic!("expected multiplex session");
            };
            let server = SudokuMultiplexServer::new(stream).unwrap();

            let (mut stream_a, target_a) = server.accept_tcp().unwrap();
            assert_eq!(target_a, "example.com:80");
            let mut payload_a = [0_u8; 6];
            stream_a.read_exact(&mut payload_a).unwrap();
            assert_eq!(&payload_a, b"helloA");
            stream_a.write_all(b"replyA").unwrap();
            stream_a.shutdown_write().unwrap();

            let (mut stream_b, target_b) = server.accept_tcp().unwrap();
            assert_eq!(target_b, "example.org:81");
            let mut payload_b = [0_u8; 6];
            stream_b.read_exact(&mut payload_b).unwrap();
            assert_eq!(&payload_b, b"helloB");
            stream_b.write_all(b"replyB").unwrap();
            stream_b.shutdown_write().unwrap();
        });

        let stream = open_multiplex_client_stream(
            Box::new(std::net::TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "secret-seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            false,
            "",
            false,
            "",
            "",
            "",
            &[],
            &TransportTarget::new("placeholder.invalid", 0),
        )
        .unwrap();
        let mut client = SudokuMultiplexClient::new(stream).unwrap();

        let mut stream_a = client.open_tcp("example.com:80").unwrap();
        stream_a.write_all(b"helloA").unwrap();
        stream_a.shutdown_write().unwrap();
        let mut reply_a = Vec::new();
        stream_a.read_to_end(&mut reply_a).unwrap();
        assert_eq!(reply_a, b"replyA");

        let mut stream_b = client.open_tcp("example.org:81").unwrap();
        stream_b.write_all(b"helloB").unwrap();
        stream_b.shutdown_write().unwrap();
        let mut reply_b = Vec::new();
        stream_b.read_to_end(&mut reply_b).unwrap();
        assert_eq!(reply_b, b"replyB");

        worker.join().unwrap();
    }

    #[test]
    fn sudoku_allow_suspicious_replays_non_protocol_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let accepted = accept_server_stream_for_tests_with_custom_tables_allow_suspicious(
                Box::new(stream),
                "secret-seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
                "",
                &[],
            )
            .unwrap();
            let SudokuServerAcceptOutcome::Suspicious(mut suspicious) = accepted else {
                panic!("expected suspicious replay stream");
            };
            let mut payload = Vec::new();
            suspicious.read_to_end(&mut payload).unwrap();
            assert_eq!(payload, b"PING /raw-fallback");
        });

        let mut client = std::net::TcpStream::connect(addr).unwrap();
        client.write_all(b"PING /raw-fallback").unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn sudoku_supports_custom_table_rotation_for_udp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let session = accept_server_stream_for_tests_with_custom_tables(
                Box::new(stream),
                "seed",
                "chacha20-poly1305",
                "prefer_entropy",
                10,
                30,
                true,
                false,
                "",
                &["xpxvvpvv".to_owned(), "vxpvxvvp".to_owned()],
            )
            .unwrap();
            let SudokuServerSession::Udp { mut stream } = session else {
                panic!("expected udp session");
            };
            let (target, payload) = read_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
            assert_eq!(payload, b"via-rot");
            write_udp_packet(&mut *stream, target, b"rot-ok").unwrap();
            stream.shutdown_write().unwrap();
        });

        let mut client = open_udp_stream(
            Box::new(std::net::TcpStream::connect(addr).unwrap()),
            &TransportTarget::new("127.0.0.1", addr.port()),
            "seed",
            "chacha20-poly1305",
            "prefer_entropy",
            10,
            30,
            true,
            false,
            "",
            false,
            "",
            "",
            "",
            &["xpxvvpvv".to_owned(), "vxpvxvvp".to_owned()],
        )
        .unwrap();
        write_udp_packet(&mut *client, "127.0.0.1:5353".parse().unwrap(), b"via-rot").unwrap();
        let (target, payload) = read_udp_packet(&mut *client).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(payload, b"rot-ok");
        worker.join().unwrap();
    }
}
