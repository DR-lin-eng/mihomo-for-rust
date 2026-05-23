use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
use aes::Aes128;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use cfb_mode::cipher::KeyIvInit;
use crc32fast::hash as crc32_hash;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use mihomo_core::{BoxedTcpStream, TcpStream};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use sha3::{
    digest::{ExtendableOutput, XofReader},
    Shake128,
};
use uuid::Uuid;

use crate::{packetaddr_magic_target, TransportError, TransportTarget};

const VERSION: u8 = 1;
const OPTION_CHUNK_STREAM: u8 = 0x01;
const SECURITY_LEGACY: u8 = 0x01;
const SECURITY_AES128_GCM: u8 = 0x03;
const SECURITY_CHACHA20_POLY1305: u8 = 0x04;
const SECURITY_NONE: u8 = 0x05;
const COMMAND_TCP: u8 = 0x01;
const COMMAND_UDP: u8 = 0x02;
const COMMAND_MUX: u8 = 0x03;
const OPTION_CHUNK_MASKING: u8 = 0x04;
const OPTION_GLOBAL_PADDING: u8 = 0x08;
const OPTION_AUTHENTICATED_LENGTH: u8 = 0x10;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;
const CHUNK_SIZE: usize = 1 << 14;
const MAX_SIZE: usize = 17 * 1024;
const MAX_PADDING_SIZE: u16 = 64;
const XUDP_STATUS_NEW: u8 = 0x01;
const XUDP_STATUS_KEEP: u8 = 0x02;
const XUDP_STATUS_END: u8 = 0x03;
const XUDP_STATUS_KEEPALIVE: u8 = 0x04;
const XUDP_OPTION_DATA: u8 = 0x01;
const XUDP_NETWORK_UDP: u8 = 0x02;
const VMESS_MUX_TARGET: &str = "v1.mux.cool:666";
const CMD_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const KDF_SALT_AUTH_ID_ENCRYPTION_KEY: &[u8] = b"AES Auth ID Encryption";
const KDF_SALT_AEAD_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_SALT_AEAD_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";
const KDF_SALT_VMESS_AEAD_KDF: &[u8] = b"VMess AEAD KDF";
const KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_IV: &[u8] = b"VMess Header AEAD Nonce";
const KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const LEGACY_ALTER_ID_SALT: &[u8] = b"16167dc8-16b6-4e6d-b8bb-65dd68113a81";

pub(crate) fn wrap_stream(
    mut stream: BoxedTcpStream,
    uuid: &str,
    alter_id: u16,
    cipher: &str,
    global_padding: bool,
    authenticated_length: bool,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let security = Security::from_cipher(cipher)?;
    let state = ClientHandshakeState::new(
        uuid,
        alter_id,
        security,
        COMMAND_TCP,
        global_padding,
        authenticated_length,
        target,
    )?;
    stream.write_all(&state.request).map_err(TransportError::from)?;
    stream.flush().map_err(TransportError::from)?;
    Ok(Box::new(VmessClientStream {
        inner: stream,
        security,
        req_body_key: state.req_body_key,
        req_body_iv: state.req_body_iv,
        resp_body_key: state.resp_body_key,
        resp_body_iv: state.resp_body_iv,
        resp_v: state.resp_v,
        response_received: false,
        legacy_protocol: state.legacy_protocol,
        read_state: ReadState::default(),
        write_state: WriteState::default(),
        chunk_stream: state.chunk_stream,
        chunk_masking: state.chunk_masking,
        global_padding: state.global_padding,
        authenticated_length: state.authenticated_length,
    }))
}

pub(crate) fn open_udp_stream(
    mut stream: BoxedTcpStream,
    uuid: &str,
    alter_id: u16,
    cipher: &str,
    global_padding: bool,
    authenticated_length: bool,
    target: std::net::SocketAddr,
) -> Result<BoxedTcpStream, TransportError> {
    let security = Security::from_cipher(cipher)?;
    let target = TransportTarget::new(target.ip().to_string(), target.port());
    let state = ClientHandshakeState::new(
        uuid,
        alter_id,
        security,
        COMMAND_UDP,
        global_padding,
        authenticated_length,
        &target,
    )?;
    stream.write_all(&state.request).map_err(TransportError::from)?;
    stream.flush().map_err(TransportError::from)?;
    Ok(Box::new(VmessClientStream {
        inner: stream,
        security,
        req_body_key: state.req_body_key,
        req_body_iv: state.req_body_iv,
        resp_body_key: state.resp_body_key,
        resp_body_iv: state.resp_body_iv,
        resp_v: state.resp_v,
        response_received: false,
        legacy_protocol: state.legacy_protocol,
        read_state: ReadState::default(),
        write_state: WriteState::default(),
        chunk_stream: state.chunk_stream,
        chunk_masking: state.chunk_masking,
        global_padding: state.global_padding,
        authenticated_length: state.authenticated_length,
    }))
}

pub(crate) fn open_packetaddr_udp_stream(
    mut stream: BoxedTcpStream,
    uuid: &str,
    alter_id: u16,
    cipher: &str,
    global_padding: bool,
    authenticated_length: bool,
) -> Result<BoxedTcpStream, TransportError> {
    let security = Security::from_cipher(cipher)?;
    let target = packetaddr_magic_target();
    let state = ClientHandshakeState::new(
        uuid,
        alter_id,
        security,
        COMMAND_UDP,
        global_padding,
        authenticated_length,
        &target,
    )?;
    stream.write_all(&state.request).map_err(TransportError::from)?;
    stream.flush().map_err(TransportError::from)?;
    Ok(Box::new(VmessClientStream {
        inner: stream,
        security,
        req_body_key: state.req_body_key,
        req_body_iv: state.req_body_iv,
        resp_body_key: state.resp_body_key,
        resp_body_iv: state.resp_body_iv,
        resp_v: state.resp_v,
        response_received: false,
        legacy_protocol: state.legacy_protocol,
        read_state: ReadState::default(),
        write_state: WriteState::default(),
        chunk_stream: state.chunk_stream,
        chunk_masking: state.chunk_masking,
        global_padding: state.global_padding,
        authenticated_length: state.authenticated_length,
    }))
}

pub(crate) fn open_xudp_stream(
    mut stream: BoxedTcpStream,
    uuid: &str,
    alter_id: u16,
    cipher: &str,
    global_padding: bool,
    authenticated_length: bool,
) -> Result<BoxedTcpStream, TransportError> {
    let security = Security::from_cipher(cipher)?;
    let state = ClientHandshakeState::new(
        uuid,
        alter_id,
        security,
        COMMAND_MUX,
        global_padding,
        authenticated_length,
        &TransportTarget::new("0.0.0.0", 0),
    )?;
    stream.write_all(&state.request).map_err(TransportError::from)?;
    stream.flush().map_err(TransportError::from)?;
    Ok(Box::new(VmessClientStream {
        inner: stream,
        security,
        req_body_key: state.req_body_key,
        req_body_iv: state.req_body_iv,
        resp_body_key: state.resp_body_key,
        resp_body_iv: state.resp_body_iv,
        resp_v: state.resp_v,
        response_received: false,
        legacy_protocol: state.legacy_protocol,
        read_state: ReadState::default(),
        write_state: WriteState::default(),
        chunk_stream: state.chunk_stream,
        chunk_masking: state.chunk_masking,
        global_padding: state.global_padding,
        authenticated_length: state.authenticated_length,
    }))
}

pub(crate) fn write_udp_packet(stream: &mut dyn Write, payload: &[u8]) -> io::Result<usize> {
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(payload.len())
}

pub(crate) fn read_udp_packet(stream: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut payload = vec![0_u8; CHUNK_SIZE];
    let read = stream.read(&mut payload)?;
    payload.truncate(read);
    Ok(payload)
}

pub(crate) fn write_xudp_packet(
    stream: &mut dyn Write,
    target: SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    let target = encode_xudp_addr(target)?;
    let header_len = 5 + target.len();
    if header_len > u16::MAX as usize || payload.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "vmess xudp packet too large",
        ));
    }
    stream.write_all(&(header_len as u16).to_be_bytes())?;
    stream.write_all(&[0, 0, XUDP_STATUS_NEW, XUDP_OPTION_DATA, XUDP_NETWORK_UDP])?;
    stream.write_all(&target)?;
    stream.write_all(&(payload.len() as u16).to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(payload.len())
}

pub(crate) fn read_xudp_packet(stream: &mut dyn Read) -> io::Result<(SocketAddr, Vec<u8>)> {
    loop {
        let mut header_len = [0_u8; 2];
        stream.read_exact(&mut header_len)?;
        let header_len = u16::from_be_bytes(header_len) as usize;
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header)?;
        match header[2] {
            XUDP_STATUS_NEW | XUDP_STATUS_KEEP => {}
            XUDP_STATUS_END => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "vmess xudp stream closed",
                ))
            }
            XUDP_STATUS_KEEPALIVE => {
                if header_len < 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vmess xudp keepalive header too short",
                    ));
                }
                let mut discard = vec![0_u8; header_len.saturating_sub(2)];
                if !discard.is_empty() {
                    stream.read_exact(&mut discard)?;
                }
                continue;
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected vmess xudp status {other}"),
                ))
            }
        }
        if header[3] & 0x02 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "vmess xudp remote closed",
            ));
        }
        let mut remaining = vec![0_u8; header_len.saturating_sub(2)];
        if !remaining.is_empty() {
            stream.read_exact(&mut remaining)?;
        }
        if header[3] & XUDP_OPTION_DATA == 0 {
            continue;
        }
        if header_len < 5 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vmess xudp header too short",
            ));
        }
        if remaining.first().copied() != Some(XUDP_NETWORK_UDP) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected vmess xudp network type",
            ));
        }
        let (target, consumed) = decode_xudp_addr(&remaining[1..])?;
        if 1 + consumed + 2 != remaining.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vmess xudp payload length trailer is malformed",
            ));
        }
        let payload_len =
            u16::from_be_bytes([remaining[1 + consumed], remaining[1 + consumed + 1]]) as usize;
        let mut payload = vec![0_u8; payload_len];
        stream.read_exact(&mut payload)?;
        return Ok((target, payload));
    }
}

pub(crate) enum VmessAcceptedStream {
    Tcp { target: String, stream: BoxedTcpStream },
    Udp { target: String, stream: BoxedTcpStream },
    Xudp { target: String, stream: BoxedTcpStream },
}

fn accept_server_stream_with_security(
    stream: BoxedTcpStream,
    uuid: &str,
    security: Security,
) -> Result<VmessAcceptedStream, TransportError> {
    let parsed = parse_client_request(stream, uuid)?;
    if parsed.security != security {
        return Err(TransportError::invalid_proxy_response(
            "vmess security mismatch",
        ));
    }
    let stream: BoxedTcpStream = Box::new(VmessServerStream {
        inner: parsed.inner,
        security: parsed.security,
        req_body_key: parsed.req_body_key,
        req_body_iv: parsed.req_body_iv,
        resp_body_key: parsed.resp_body_key,
        resp_body_iv: parsed.resp_body_iv,
        resp_v: parsed.resp_v,
        response_sent: false,
        legacy_protocol: parsed.legacy_protocol,
        read_state: ReadState::default(),
        write_state: WriteState::default(),
        chunk_stream: parsed.chunk_stream,
        chunk_masking: parsed.chunk_masking,
        global_padding: parsed.global_padding,
        authenticated_length: parsed.authenticated_length,
    });
    if parsed.command == COMMAND_UDP {
        Ok(VmessAcceptedStream::Udp {
            target: parsed.target,
            stream,
        })
    } else if parsed.command == COMMAND_MUX {
        Ok(VmessAcceptedStream::Xudp {
            target: parsed.target,
            stream,
        })
    } else {
        Ok(VmessAcceptedStream::Tcp {
            target: parsed.target,
            stream,
        })
    }
}

pub(crate) fn accept_server_stream(
    stream: BoxedTcpStream,
    uuid: &str,
) -> Result<VmessAcceptedStream, TransportError> {
    let parsed = parse_client_request(stream, uuid)?;
    let stream: BoxedTcpStream = Box::new(VmessServerStream {
        inner: parsed.inner,
        security: parsed.security,
        req_body_key: parsed.req_body_key,
        req_body_iv: parsed.req_body_iv,
        resp_body_key: parsed.resp_body_key,
        resp_body_iv: parsed.resp_body_iv,
        resp_v: parsed.resp_v,
        response_sent: false,
        legacy_protocol: parsed.legacy_protocol,
        read_state: ReadState::default(),
        write_state: WriteState::default(),
        chunk_stream: parsed.chunk_stream,
        chunk_masking: parsed.chunk_masking,
        global_padding: parsed.global_padding,
        authenticated_length: parsed.authenticated_length,
    });
    if parsed.command == COMMAND_UDP {
        Ok(VmessAcceptedStream::Udp {
            target: parsed.target,
            stream,
        })
    } else if parsed.command == COMMAND_MUX {
        Ok(VmessAcceptedStream::Xudp {
            target: parsed.target,
            stream,
        })
    } else {
        Ok(VmessAcceptedStream::Tcp {
            target: parsed.target,
            stream,
        })
    }
}

pub(crate) fn accept_server_stream_for_tests(
    stream: BoxedTcpStream,
    uuid: &str,
    cipher: &str,
) -> Result<VmessAcceptedStream, TransportError> {
    let security = Security::from_cipher(cipher)?;
    accept_server_stream_with_security(stream, uuid, security)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Security {
    Legacy,
    None,
    Aes128Gcm,
    Chacha20Poly1305,
}

impl Security {
    fn from_cipher(cipher: &str) -> Result<Self, TransportError> {
        match cipher.trim() {
            "" | "auto" => Ok(if matches!(
                std::env::consts::ARCH,
                "amd64" | "arm64" | "s390x" | "x86_64" | "aarch64"
            ) {
                Self::Aes128Gcm
            } else {
                Self::Chacha20Poly1305
            }),
            "none" | "zero" => Ok(Self::None),
            "aes-128-cfb" => Ok(Self::Legacy),
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "chacha20-poly1305" => Ok(Self::Chacha20Poly1305),
            other => Err(TransportError::UnsupportedFeature {
                proxy: "<vmess>".to_owned(),
                feature: format!("cipher={other}"),
            }),
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::Legacy => SECURITY_LEGACY,
            Self::None => SECURITY_NONE,
            Self::Aes128Gcm => SECURITY_AES128_GCM,
            Self::Chacha20Poly1305 => SECURITY_CHACHA20_POLY1305,
        }
    }
}

struct ClientHandshakeState {
    request: Vec<u8>,
    req_body_key: [u8; 16],
    req_body_iv: [u8; 16],
    resp_body_key: [u8; 16],
    resp_body_iv: [u8; 16],
    resp_v: u8,
    legacy_protocol: bool,
    chunk_stream: bool,
    chunk_masking: bool,
    global_padding: bool,
    authenticated_length: bool,
}

impl ClientHandshakeState {
    fn new(
        uuid: &str,
        alter_id: u16,
        security: Security,
        command: u8,
        global_padding: bool,
        authenticated_length: bool,
        target: &TransportTarget,
    ) -> Result<Self, TransportError> {
        let uuid = Uuid::parse_str(uuid).map_err(|err| {
            TransportError::InvalidPlan(format!("invalid vmess uuid {uuid:?}: {err}"))
        })?;
        let cmd_key = derive_cmd_key(&uuid);

        let mut req_body_iv = [0_u8; 16];
        let mut req_body_key = [0_u8; 16];
        OsRng.fill_bytes(&mut req_body_iv);
        OsRng.fill_bytes(&mut req_body_key);
        let mut resp_v = [0_u8; 1];
        OsRng.fill_bytes(&mut resp_v);
        let resp_v = resp_v[0];

        let legacy_protocol = alter_id > 0;
        let resp_body_key = if legacy_protocol {
            md5_16(&req_body_key)
        } else {
            first_16_sha256(&req_body_key)
        };
        let resp_body_iv = if legacy_protocol {
            md5_16(&req_body_iv)
        } else {
            first_16_sha256(&req_body_iv)
        };

        let request_payload = build_request_payload(
            &req_body_iv,
            &req_body_key,
            resp_v,
            security,
            command,
            global_padding,
            authenticated_length,
            target,
        )?;
        let request = if legacy_protocol {
            seal_vmess_legacy_header(cmd_key, derive_alter_key(&uuid), &request_payload)?
        } else {
            seal_vmess_aead_header(cmd_key, &request_payload)?
        };
        let (chunk_stream, chunk_masking, global_padding, authenticated_length) =
            request_chunk_mode(security, command, global_padding, authenticated_length);

        Ok(Self {
            request,
            req_body_key,
            req_body_iv,
            resp_body_key,
            resp_body_iv,
            resp_v,
            legacy_protocol,
            chunk_stream,
            chunk_masking,
            global_padding,
            authenticated_length,
        })
    }
}

struct ParsedClientRequest {
    inner: BoxedTcpStream,
    security: Security,
    command: u8,
    target: String,
    req_body_key: [u8; 16],
    req_body_iv: [u8; 16],
    resp_body_key: [u8; 16],
    resp_body_iv: [u8; 16],
    resp_v: u8,
    legacy_protocol: bool,
    chunk_stream: bool,
    chunk_masking: bool,
    global_padding: bool,
    authenticated_length: bool,
}

fn parse_client_request(
    mut stream: BoxedTcpStream,
    uuid: &str,
) -> Result<ParsedClientRequest, TransportError> {
    let uuid = Uuid::parse_str(uuid).map_err(|err| {
        TransportError::InvalidPlan(format!("invalid vmess uuid {uuid:?}: {err}"))
    })?;
    let cmd_key = derive_cmd_key(&uuid);
    let mut auth_id = [0_u8; 16];
    stream.read_exact(&mut auth_id).map_err(TransportError::from)?;
    let legacy_parse =
        try_open_vmess_legacy_header(&mut *stream, cmd_key, derive_alter_key(&uuid), &auth_id, 5)?;
    let (payload, legacy_protocol) = if let Some(payload) = legacy_parse {
        (payload, true)
    } else {
        (
            open_vmess_aead_header_with_auth_id(&mut *stream, cmd_key, auth_id)?,
            false,
        )
    };
    if payload.len() < 1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 4 {
        return Err(TransportError::invalid_proxy_response(
            "vmess request header too short",
        ));
    }
    let checksum_index = payload
        .len()
        .checked_sub(4)
        .ok_or_else(|| TransportError::invalid_proxy_response("missing vmess checksum"))?;
    let expected = fnv1a32(&payload[..checksum_index]);
    let actual = u32::from_be_bytes(payload[checksum_index..].try_into().unwrap());
    if expected != actual {
        return Err(TransportError::invalid_proxy_response(
            "vmess request checksum mismatch",
        ));
    }
    if payload[0] != VERSION {
        return Err(TransportError::invalid_proxy_response(format!(
            "unexpected vmess request version {}",
            payload[0]
        )));
    }
    let mut req_body_iv = [0_u8; 16];
    req_body_iv.copy_from_slice(&payload[1..17]);
    let mut req_body_key = [0_u8; 16];
    req_body_key.copy_from_slice(&payload[17..33]);
    let resp_v = payload[33];
    let option = payload[34];
    let padding_len = (payload[35] >> 4) as usize;
    let security = match payload[35] & 0x0f {
        SECURITY_NONE => Security::None,
        SECURITY_LEGACY => Security::Legacy,
        SECURITY_AES128_GCM => Security::Aes128Gcm,
        SECURITY_CHACHA20_POLY1305 => Security::Chacha20Poly1305,
        other => {
            return Err(TransportError::invalid_proxy_response(format!(
                "unsupported vmess security {other}"
            )))
        }
    };
    let command = payload[37];
    let (target, offset) = if command == COMMAND_MUX {
        (VMESS_MUX_TARGET.to_owned(), 38)
    } else {
        let port = u16::from_be_bytes([payload[38], payload[39]]);
        let mut offset = 40;
        let atyp = payload[offset];
        offset += 1;
        let host = match atyp {
            ATYP_IPV4 => {
                let octets: [u8; 4] = payload[offset..offset + 4].try_into().unwrap();
                offset += 4;
                std::net::Ipv4Addr::from(octets).to_string()
            }
            ATYP_IPV6 => {
                let octets: [u8; 16] = payload[offset..offset + 16].try_into().unwrap();
                offset += 16;
                std::net::Ipv6Addr::from(octets).to_string()
            }
            ATYP_DOMAIN => {
                let len = payload[offset] as usize;
                offset += 1;
                let host =
                    String::from_utf8(payload[offset..offset + len].to_vec()).map_err(|err| {
                        TransportError::invalid_proxy_response(format!(
                            "invalid vmess domain: {err}"
                        ))
                    })?;
                offset += len;
                host
            }
            other => {
                return Err(TransportError::invalid_proxy_response(format!(
                    "unsupported vmess atyp {other}"
                )))
            }
        };
        (format!("{host}:{port}"), offset)
    };
    if offset + padding_len != checksum_index {
        return Err(TransportError::invalid_proxy_response(
            "vmess request padding length mismatch",
        ));
    }

    let resp_body_key = if legacy_protocol {
        md5_16(&req_body_key)
    } else {
        first_16_sha256(&req_body_key)
    };
    let resp_body_iv = if legacy_protocol {
        md5_16(&req_body_iv)
    } else {
        first_16_sha256(&req_body_iv)
    };

    Ok(ParsedClientRequest {
        inner: stream,
        security,
        command,
        target,
        req_body_key,
        req_body_iv,
        resp_body_key,
        resp_body_iv,
        resp_v,
        legacy_protocol,
        chunk_stream: option & OPTION_CHUNK_STREAM != 0,
        chunk_masking: option & OPTION_CHUNK_MASKING != 0,
        global_padding: option & OPTION_GLOBAL_PADDING != 0,
        authenticated_length: option & OPTION_AUTHENTICATED_LENGTH != 0,
    })
}

struct VmessClientStream {
    inner: BoxedTcpStream,
    security: Security,
    req_body_key: [u8; 16],
    req_body_iv: [u8; 16],
    resp_body_key: [u8; 16],
    resp_body_iv: [u8; 16],
    resp_v: u8,
    response_received: bool,
    legacy_protocol: bool,
    read_state: ReadState,
    write_state: WriteState,
    chunk_stream: bool,
    chunk_masking: bool,
    global_padding: bool,
    authenticated_length: bool,
}

impl VmessClientStream {
    fn ensure_response_received(&mut self) -> io::Result<()> {
        if self.response_received {
            return Ok(());
        }
        if self.legacy_protocol {
            if matches!(self.security, Security::Legacy) {
                let mut header = [0_u8; 4];
                self.inner.read_exact(&mut header)?;
                let key = self.resp_body_key;
                let iv = self.resp_body_iv;
                let decryptor = self.read_state.legacy_cipher.get_or_insert_with(|| {
                    new_aes_cfb_decryptor(&key, &iv)
                });
                decryptor.xor(&mut header);
                if header[0] != self.resp_v {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected legacy vmess response header",
                    ));
                }
            } else {
                recv_response_header_legacy(
                    &mut *self.inner,
                    &self.resp_body_key,
                    &self.resp_body_iv,
                    self.resp_v,
                )
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            }
        } else {
            recv_response_header(
                &mut *self.inner,
                &self.resp_body_key,
                &self.resp_body_iv,
                self.resp_v,
            )
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        }
        self.response_received = true;
        Ok(())
    }
}

impl Read for VmessClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.ensure_response_received()?;
        read_body_into(
            &mut *self.inner,
            self.security,
            &self.req_body_key,
            &self.req_body_iv,
            &self.resp_body_key,
            &self.resp_body_iv,
            self.chunk_stream,
            self.chunk_masking,
            self.global_padding,
            self.authenticated_length,
            &mut self.read_state,
            buf,
        )
    }
}

impl Write for VmessClientStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        write_body_chunk(
            &mut *self.inner,
            self.security,
            &self.req_body_key,
            &self.req_body_iv,
            &self.req_body_key,
            &self.req_body_iv,
            self.chunk_stream,
            self.chunk_masking,
            self.global_padding,
            self.authenticated_length,
            &mut self.write_state,
            buf,
        )
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for VmessClientStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "vmess stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
}

struct VmessServerStream {
    inner: BoxedTcpStream,
    security: Security,
    req_body_key: [u8; 16],
    req_body_iv: [u8; 16],
    resp_body_key: [u8; 16],
    resp_body_iv: [u8; 16],
    resp_v: u8,
    response_sent: bool,
    legacy_protocol: bool,
    read_state: ReadState,
    write_state: WriteState,
    chunk_stream: bool,
    chunk_masking: bool,
    global_padding: bool,
    authenticated_length: bool,
}

struct VmessServerWriteClone {
    inner: BoxedTcpStream,
    security: Security,
    req_body_key: [u8; 16],
    req_body_iv: [u8; 16],
    resp_body_key: [u8; 16],
    resp_body_iv: [u8; 16],
    resp_v: u8,
    response_sent: bool,
    legacy_protocol: bool,
    write_state: WriteState,
    chunk_stream: bool,
    chunk_masking: bool,
    global_padding: bool,
    authenticated_length: bool,
}

impl VmessServerStream {
    fn ensure_response_sent(&mut self) -> io::Result<()> {
        if self.response_sent {
            return Ok(());
        }
        if self.legacy_protocol {
            if matches!(self.security, Security::Legacy) {
                let key = self.resp_body_key;
                let iv = self.resp_body_iv;
                let encryptor = self.write_state.legacy_cipher.get_or_insert_with(|| {
                    new_aes_cfb_encryptor(&key, &iv)
                });
                let mut header = [self.resp_v, 0, 0, 0];
                encryptor.xor(&mut header);
                self.inner.write_all(&header)?;
                self.inner.flush()?;
            } else {
                send_response_header_legacy(
                    &mut *self.inner,
                    &self.resp_body_key,
                    &self.resp_body_iv,
                    self.resp_v,
                )
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
            }
        } else {
            send_response_header(
                &mut *self.inner,
                &self.resp_body_key,
                &self.resp_body_iv,
                self.resp_v,
            )
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        }
        self.response_sent = true;
        Ok(())
    }
}

impl VmessServerWriteClone {
    fn ensure_response_sent(&mut self) -> io::Result<()> {
        if self.response_sent {
            return Ok(());
        }
        if self.legacy_protocol {
            if matches!(self.security, Security::Legacy) {
                let key = self.resp_body_key;
                let iv = self.resp_body_iv;
                let encryptor = self.write_state.legacy_cipher.get_or_insert_with(|| {
                    new_aes_cfb_encryptor(&key, &iv)
                });
                let mut header = [self.resp_v, 0, 0, 0];
                encryptor.xor(&mut header);
                self.inner.write_all(&header)?;
                self.inner.flush()?;
            } else {
                send_response_header_legacy(
                    &mut *self.inner,
                    &self.resp_body_key,
                    &self.resp_body_iv,
                    self.resp_v,
                )
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
            }
        } else {
            send_response_header(
                &mut *self.inner,
                &self.resp_body_key,
                &self.resp_body_iv,
                self.resp_v,
            )
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        }
        self.response_sent = true;
        Ok(())
    }
}

impl Read for VmessServerStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        read_body_into(
            &mut *self.inner,
            self.security,
            &self.req_body_key,
            &self.req_body_iv,
            &self.req_body_key,
            &self.req_body_iv,
            self.chunk_stream,
            self.chunk_masking,
            self.global_padding,
            self.authenticated_length,
            &mut self.read_state,
            buf,
        )
    }
}

impl Write for VmessServerStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.ensure_response_sent()?;
        write_body_chunk(
            &mut *self.inner,
            self.security,
            &self.req_body_key,
            &self.req_body_iv,
            &self.resp_body_key,
            &self.resp_body_iv,
            self.chunk_stream,
            self.chunk_masking,
            self.global_padding,
            self.authenticated_length,
            &mut self.write_state,
            buf,
        )
    }

    fn flush(&mut self) -> io::Result<()> {
        self.ensure_response_sent()?;
        self.inner.flush()
    }
}

impl Read for VmessServerWriteClone {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "vmess server write clone is write-only",
        ))
    }
}

impl Write for VmessServerWriteClone {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.ensure_response_sent()?;
        write_body_chunk(
            &mut *self.inner,
            self.security,
            &self.req_body_key,
            &self.req_body_iv,
            &self.resp_body_key,
            &self.resp_body_iv,
            self.chunk_stream,
            self.chunk_masking,
            self.global_padding,
            self.authenticated_length,
            &mut self.write_state,
            buf,
        )
    }

    fn flush(&mut self) -> io::Result<()> {
        self.ensure_response_sent()?;
        self.inner.flush()
    }
}

impl TcpStream for VmessServerStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        if self.response_sent
            || self.write_state.write_count != 0
            || self.write_state.length_mask.is_some()
            || self.write_state.legacy_cipher.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "vmess stream cannot be cloned after writes begin",
            ));
        }
        Ok(Box::new(VmessServerWriteClone {
            inner: self.inner.try_clone_box()?,
            security: self.security,
            req_body_key: self.req_body_key,
            req_body_iv: self.req_body_iv,
            resp_body_key: self.resp_body_key,
            resp_body_iv: self.resp_body_iv,
            resp_v: self.resp_v,
            response_sent: self.response_sent,
            legacy_protocol: self.legacy_protocol,
            write_state: WriteState::default(),
            chunk_stream: self.chunk_stream,
            chunk_masking: self.chunk_masking,
            global_padding: self.global_padding,
            authenticated_length: self.authenticated_length,
        }))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.ensure_response_sent()?;
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.ensure_response_sent()?;
        self.inner.shutdown_all()
    }
}

impl TcpStream for VmessServerWriteClone {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "vmess server write clone does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.ensure_response_sent()?;
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.ensure_response_sent()?;
        self.inner.shutdown_all()
    }
}

#[derive(Default)]
struct ReadState {
    pending: Vec<u8>,
    offset: usize,
    read_count: u16,
    length_mask: Option<Box<dyn XofReader + Send>>,
    legacy_cipher: Option<AesCfbState>,
}

#[derive(Default)]
struct WriteState {
    write_count: u16,
    length_mask: Option<Box<dyn XofReader + Send>>,
    legacy_cipher: Option<AesCfbState>,
}

fn read_body_into(
    stream: &mut dyn Read,
    security: Security,
    length_key: &[u8; 16],
    length_iv: &[u8; 16],
    key: &[u8; 16],
    iv: &[u8; 16],
    chunk_stream: bool,
    chunk_masking: bool,
    global_padding: bool,
    authenticated_length: bool,
    state: &mut ReadState,
    buf: &mut [u8],
) -> io::Result<usize> {
    if matches!(security, Security::Legacy) && !chunk_stream {
        let read = stream.read(buf)?;
        if read == 0 {
            return Ok(0);
        }
        let decryptor = state
            .legacy_cipher
            .get_or_insert_with(|| new_aes_cfb_decryptor(key, iv));
        decryptor.xor(&mut buf[..read]);
        return Ok(read);
    }
    if !chunk_stream {
        return stream.read(buf);
    }
    if state.offset < state.pending.len() {
        let available = &state.pending[state.offset..];
        let copied = available.len().min(buf.len());
        buf[..copied].copy_from_slice(&available[..copied]);
        state.offset += copied;
        if state.offset == state.pending.len() {
            state.pending.clear();
            state.offset = 0;
        }
        return Ok(copied);
    }

    let data = read_next_body_chunk(
        stream,
        security,
        length_key,
        length_iv,
        key,
        iv,
        chunk_masking,
        global_padding,
        authenticated_length,
        state,
    )?;
    let copied = data.len().min(buf.len());
    buf[..copied].copy_from_slice(&data[..copied]);
    if copied < data.len() {
        state.pending = data;
        state.offset = copied;
    }
    Ok(copied)
}

fn read_legacy_body_chunk(
    stream: &mut dyn Read,
    key: &[u8; 16],
    iv: &[u8; 16],
    chunk_masking: bool,
    global_padding: bool,
    state: &mut ReadState,
) -> io::Result<Option<Vec<u8>>> {
    let decryptor = state
        .legacy_cipher
        .get_or_insert_with(|| new_aes_cfb_decryptor(key, iv));
    let mut len_buf = [0_u8; 2];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
            ) =>
        {
            return Ok(None);
        }
        Err(err) => return Err(err),
    }
    decryptor.xor(&mut len_buf);
    let padding_len = if global_padding {
        next_padding_len(&mut state.length_mask, iv)
    } else {
        0
    };
    let mut total_len = u16::from_be_bytes(len_buf) as usize;
    if chunk_masking {
        let reader = ensure_length_mask(&mut state.length_mask, iv);
        total_len ^= next_hash_u16(reader) as usize;
    }
    if total_len == 0 {
        return Ok(None);
    }
    if padding_len > total_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad vmess legacy chunk length: length={total_len}, padding={padding_len}"),
        ));
    }
    let mut chunk = vec![0_u8; total_len];
    stream.read_exact(&mut chunk)?;
    decryptor.xor(&mut chunk);
    let data_len = total_len - padding_len;
    if data_len < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vmess legacy chunk is too short for checksum",
        ));
    }
    let expected = u32::from_be_bytes(chunk[..4].try_into().unwrap());
    let payload = &chunk[4..data_len];
    if fnv1a32(payload) != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vmess legacy chunk checksum mismatch",
        ));
    }
    Ok(Some(payload.to_vec()))
}

fn read_next_body_chunk(
    stream: &mut dyn Read,
    security: Security,
    length_key: &[u8; 16],
    length_iv: &[u8; 16],
    key: &[u8; 16],
    iv: &[u8; 16],
    chunk_masking: bool,
    global_padding: bool,
    authenticated_length: bool,
    state: &mut ReadState,
) -> io::Result<Vec<u8>> {
    if matches!(security, Security::Legacy) {
        return match read_legacy_body_chunk(stream, key, iv, chunk_masking, global_padding, state)?
        {
            Some(data) => Ok(data),
            None => Ok(Vec::new()),
        };
    }
    let (size, padding_len) = match read_next_chunk_length(
        stream,
        security,
        length_key,
        length_iv,
        iv,
        chunk_masking,
        global_padding,
        authenticated_length,
        state,
    )? {
        Some(value) => value,
        None => return Ok(Vec::new()),
    };
    if size > MAX_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vmess chunk exceeds maximum size",
        ));
    }
    let mut chunk = vec![0_u8; size];
    stream.read_exact(&mut chunk)?;
    let data = match security {
        Security::None => chunk,
        Security::Aes128Gcm => {
            let cipher = Aes128Gcm::new_from_slice(key).unwrap();
            let nonce = nonce_from(iv, state.read_count);
            cipher
                .decrypt(Nonce::from_slice(&nonce), chunk.as_ref())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "vmess aes body decrypt failed"))?
        }
        Security::Chacha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(&expand_chacha_key(key)).unwrap();
            let nonce = nonce_from(iv, state.read_count);
            cipher
                .decrypt(chacha20poly1305::Nonce::from_slice(&nonce), chunk.as_ref())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "vmess chacha body decrypt failed"))?
        }
        Security::Legacy => unreachable!("legacy vmess body is handled separately"),
    };
    if padding_len != 0 {
        let mut discard = vec![0_u8; padding_len];
        stream.read_exact(&mut discard)?;
    }
    state.read_count = state.read_count.wrapping_add(1);
    Ok(data)
}

fn write_body_chunk(
    stream: &mut dyn Write,
    security: Security,
    length_key: &[u8; 16],
    length_iv: &[u8; 16],
    key: &[u8; 16],
    iv: &[u8; 16],
    chunk_stream: bool,
    chunk_masking: bool,
    global_padding: bool,
    authenticated_length: bool,
    state: &mut WriteState,
    payload: &[u8],
) -> io::Result<usize> {
    if matches!(security, Security::Legacy) && !chunk_stream {
        if payload.is_empty() {
            return Ok(0);
        }
        let encryptor = state
            .legacy_cipher
            .get_or_insert_with(|| new_aes_cfb_encryptor(key, iv));
        let mut encoded = payload.to_vec();
        encryptor.xor(&mut encoded);
        stream.write_all(&encoded)?;
        stream.flush()?;
        return Ok(payload.len());
    }
    if !chunk_stream {
        stream.write_all(payload)?;
        stream.flush()?;
        return Ok(payload.len());
    }
    if matches!(security, Security::Legacy) {
        let encryptor = state
            .legacy_cipher
            .get_or_insert_with(|| new_aes_cfb_encryptor(key, iv));
        let mut written = 0;
        while written < payload.len() {
            let end = (written + 15_000).min(payload.len());
            let chunk = &payload[written..end];
            let padding_len = if global_padding {
                next_padding_len(&mut state.length_mask, iv)
            } else {
                0
            };
            let total_len = 4_usize
                .checked_add(chunk.len())
                .and_then(|len| len.checked_add(padding_len))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "vmess legacy chunk length overflow")
                })?;
            if total_len > u16::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "vmess legacy encoded chunk too large",
                ));
            }
            let mut encoded_len = total_len as u16;
            if chunk_masking {
                let reader = ensure_length_mask(&mut state.length_mask, iv);
                encoded_len ^= next_hash_u16(reader);
            }
            let mut len_buf = encoded_len.to_be_bytes();
            encryptor.xor(&mut len_buf);
            stream.write_all(&len_buf)?;

            let mut body = Vec::with_capacity(total_len);
            body.extend_from_slice(&fnv1a32(chunk).to_be_bytes());
            body.extend_from_slice(chunk);
            if padding_len != 0 {
                let mut padding = vec![0_u8; padding_len];
                OsRng.fill_bytes(&mut padding);
                body.extend_from_slice(&padding);
            }
            encryptor.xor(&mut body);
            stream.write_all(&body)?;
            written = end;
        }
        stream.flush()?;
        return Ok(payload.len());
    }
    let mut written = 0;
    while written < payload.len() {
        let end = (written + CHUNK_SIZE).min(payload.len());
        let chunk = &payload[written..end];
        let encoded = match security {
            Security::None => chunk.to_vec(),
            Security::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(key).unwrap();
                let nonce = nonce_from(iv, state.write_count);
                cipher
                    .encrypt(Nonce::from_slice(&nonce), chunk)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "vmess aes body encrypt failed"))?
            }
            Security::Chacha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&expand_chacha_key(key)).unwrap();
                let nonce = nonce_from(iv, state.write_count);
                cipher
                    .encrypt(chacha20poly1305::Nonce::from_slice(&nonce), chunk)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "vmess chacha body encrypt failed"))?
            }
            Security::Legacy => unreachable!("legacy vmess body is handled separately"),
        };
        let padding_len = if global_padding {
            next_padding_len(&mut state.length_mask, iv)
        } else {
            0
        };
        write_chunk_length(
            stream,
            security,
            length_key,
            length_iv,
            iv,
            chunk_masking,
            authenticated_length,
            state.write_count,
            &mut state.length_mask,
            encoded.len(),
            padding_len,
        )?;
        stream.write_all(&encoded)?;
        if padding_len != 0 {
            let mut padding = vec![0_u8; padding_len];
            OsRng.fill_bytes(&mut padding);
            stream.write_all(&padding)?;
        }
        written = end;
        state.write_count = state.write_count.wrapping_add(1);
    }
    stream.flush()?;
    Ok(payload.len())
}

fn recv_response_header(
    stream: &mut dyn Read,
    resp_body_key: &[u8; 16],
    resp_body_iv: &[u8; 16],
    expected_resp_v: u8,
) -> Result<(), TransportError> {
    let len_key = kdf(resp_body_key, &[KDF_SALT_AEAD_RESP_HEADER_LEN_KEY]);
    let len_iv = kdf(resp_body_iv, &[KDF_SALT_AEAD_RESP_HEADER_LEN_IV]);
    let payload_key = kdf(resp_body_key, &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY]);
    let payload_iv = kdf(resp_body_iv, &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV]);

    let mut enc_len = [0_u8; 18];
    stream.read_exact(&mut enc_len).map_err(TransportError::from)?;
    let len_cipher = Aes128Gcm::new_from_slice(&len_key[..16]).unwrap();
    let plain_len = len_cipher
        .decrypt(Nonce::from_slice(&len_iv[..12]), enc_len.as_ref())
        .map_err(|_| TransportError::invalid_proxy_response("vmess response length decrypt failed"))?;
    let header_len = u16::from_be_bytes([plain_len[0], plain_len[1]]) as usize;

    let mut enc_header = vec![0_u8; header_len + 16];
    stream
        .read_exact(&mut enc_header)
        .map_err(TransportError::from)?;
    let payload_cipher = Aes128Gcm::new_from_slice(&payload_key[..16]).unwrap();
    let header = payload_cipher
        .decrypt(Nonce::from_slice(&payload_iv[..12]), enc_header.as_ref())
        .map_err(|_| TransportError::invalid_proxy_response("vmess response header decrypt failed"))?;
    if header.len() < 4 || header[0] != expected_resp_v {
        return Err(TransportError::invalid_proxy_response(
            "unexpected vmess response header",
        ));
    }
    if header[2] != 0 {
        return Err(TransportError::invalid_proxy_response(
            "vmess dynamic port response is unsupported",
        ));
    }
    Ok(())
}

fn recv_response_header_legacy(
    stream: &mut dyn Read,
    resp_body_key: &[u8; 16],
    resp_body_iv: &[u8; 16],
    expected_resp_v: u8,
) -> Result<(), TransportError> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).map_err(TransportError::from)?;
    let mut decryptor = new_aes_cfb_decryptor(resp_body_key, resp_body_iv);
    decryptor.xor(&mut header);
    if header[0] != expected_resp_v {
        return Err(TransportError::invalid_proxy_response(
            "unexpected legacy vmess response header",
        ));
    }
    Ok(())
}

fn send_response_header(
    stream: &mut dyn Write,
    resp_body_key: &[u8; 16],
    resp_body_iv: &[u8; 16],
    resp_v: u8,
) -> Result<(), TransportError> {
    let header = [resp_v, 0, 0, 0];
    let len_key = kdf(resp_body_key, &[KDF_SALT_AEAD_RESP_HEADER_LEN_KEY]);
    let len_iv = kdf(resp_body_iv, &[KDF_SALT_AEAD_RESP_HEADER_LEN_IV]);
    let payload_key = kdf(resp_body_key, &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY]);
    let payload_iv = kdf(resp_body_iv, &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV]);

    let len_cipher = Aes128Gcm::new_from_slice(&len_key[..16]).unwrap();
    let payload_cipher = Aes128Gcm::new_from_slice(&payload_key[..16]).unwrap();
    let plain_len = (header.len() as u16).to_be_bytes();
    let enc_len = len_cipher
        .encrypt(Nonce::from_slice(&len_iv[..12]), plain_len.as_ref())
        .map_err(|_| TransportError::InvalidPlan("vmess response length encrypt failed".to_owned()))?;
    let enc_header = payload_cipher
        .encrypt(Nonce::from_slice(&payload_iv[..12]), header.as_ref())
        .map_err(|_| TransportError::InvalidPlan("vmess response header encrypt failed".to_owned()))?;
    stream.write_all(&enc_len).map_err(TransportError::from)?;
    stream.write_all(&enc_header).map_err(TransportError::from)?;
    stream.flush().map_err(TransportError::from)
}

fn send_response_header_legacy(
    stream: &mut dyn Write,
    resp_body_key: &[u8; 16],
    resp_body_iv: &[u8; 16],
    resp_v: u8,
) -> Result<(), TransportError> {
    let mut header = [resp_v, 0, 0, 0];
    let mut encryptor = new_aes_cfb_encryptor(resp_body_key, resp_body_iv);
    encryptor.xor(&mut header);
    stream.write_all(&header).map_err(TransportError::from)?;
    stream.flush().map_err(TransportError::from)
}

fn build_request_payload(
    req_body_iv: &[u8; 16],
    req_body_key: &[u8; 16],
    resp_v: u8,
    security: Security,
    command: u8,
    global_padding: bool,
    authenticated_length: bool,
    target: &TransportTarget,
) -> Result<Vec<u8>, TransportError> {
    let mut payload = Vec::new();
    payload.push(VERSION);
    payload.extend_from_slice(req_body_iv);
    payload.extend_from_slice(req_body_key);
    payload.push(resp_v);
    let (chunk_stream, chunk_masking, global_padding, authenticated_length) =
        request_chunk_mode(security, command, global_padding, authenticated_length);
    let mut option = 0_u8;
    if chunk_stream {
        option |= OPTION_CHUNK_STREAM;
    }
    if chunk_masking {
        option |= OPTION_CHUNK_MASKING;
    }
    if global_padding {
        option |= OPTION_GLOBAL_PADDING;
    }
    if authenticated_length {
        option |= OPTION_AUTHENTICATED_LENGTH;
    }
    payload.push(option);

    let mut padding_len = [0_u8; 1];
    OsRng.fill_bytes(&mut padding_len);
    let padding_len = (padding_len[0] & 0x0f) as usize;
    payload.push(((padding_len as u8) << 4) | security.code());
    payload.push(0);
    payload.push(command);
    if command != COMMAND_MUX {
        payload.extend_from_slice(&target.port.to_be_bytes());
        encode_target_into(&mut payload, target)?;
    }
    if padding_len != 0 {
        let mut padding = vec![0_u8; padding_len];
        OsRng.fill_bytes(&mut padding);
        payload.extend_from_slice(&padding);
    }
    payload.extend_from_slice(&fnv1a32(&payload).to_be_bytes());
    Ok(payload)
}

fn request_chunk_mode(
    security: Security,
    command: u8,
    global_padding: bool,
    authenticated_length: bool,
) -> (bool, bool, bool, bool) {
    match security {
        Security::Legacy => (true, false, false, false),
        Security::None => (command == COMMAND_UDP, false, false, false),
        Security::Aes128Gcm | Security::Chacha20Poly1305 => (
            true,
            !authenticated_length,
            global_padding,
            authenticated_length,
        ),
    }
}

enum AesCfbState {
    Encrypt(cfb_mode::BufEncryptor<Aes128>),
    Decrypt(cfb_mode::BufDecryptor<Aes128>),
}

impl AesCfbState {
    fn xor(&mut self, data: &mut [u8]) {
        match self {
            Self::Encrypt(cipher) => cipher.encrypt(data),
            Self::Decrypt(cipher) => cipher.decrypt(data),
        }
    }
}

fn new_aes_cfb_encryptor(key: &[u8; 16], iv: &[u8; 16]) -> AesCfbState {
    AesCfbState::Encrypt(cfb_mode::BufEncryptor::<Aes128>::new(key.into(), iv.into()))
}

fn new_aes_cfb_decryptor(key: &[u8; 16], iv: &[u8; 16]) -> AesCfbState {
    AesCfbState::Decrypt(cfb_mode::BufDecryptor::<Aes128>::new(key.into(), iv.into()))
}

fn shake_reader(seed: &[u8; 16]) -> Box<dyn XofReader + Send> {
    let mut shake = Shake128::default();
    sha3::digest::Update::update(&mut shake, seed);
    Box::new(shake.finalize_xof())
}

fn ensure_length_mask<'a>(
    reader: &'a mut Option<Box<dyn XofReader + Send>>,
    seed: &[u8; 16],
) -> &'a mut dyn XofReader {
    if reader.is_none() {
        *reader = Some(shake_reader(seed));
    }
    reader.as_deref_mut().unwrap()
}

fn next_hash_u16(reader: &mut dyn XofReader) -> u16 {
    let mut buf = [0_u8; 2];
    reader.read(&mut buf);
    u16::from_be_bytes(buf)
}

fn next_padding_len(reader: &mut Option<Box<dyn XofReader + Send>>, seed: &[u8; 16]) -> usize {
    let reader = ensure_length_mask(reader, seed);
    (next_hash_u16(reader) % MAX_PADDING_SIZE) as usize
}

fn read_next_chunk_length(
    stream: &mut dyn Read,
    security: Security,
    length_key: &[u8; 16],
    length_iv: &[u8; 16],
    mask_seed: &[u8; 16],
    chunk_masking: bool,
    global_padding: bool,
    authenticated_length: bool,
    state: &mut ReadState,
) -> io::Result<Option<(usize, usize)>> {
    let padding_len = if global_padding {
        next_padding_len(&mut state.length_mask, mask_seed)
    } else {
        0
    };
    let mut size = if authenticated_length {
        let mut enc_len = [0_u8; 18];
        match stream.read_exact(&mut enc_len) {
            Ok(()) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                ) =>
            {
                return Ok(None);
            }
            Err(err) => return Err(err),
        }
        let len_cipher = match security {
            Security::Aes128Gcm => Aes128Gcm::new_from_slice(&kdf(length_key, &[b"auth_len"])[..16])
                .unwrap()
                .decrypt(Nonce::from_slice(&nonce_from(length_iv, state.read_count)), enc_len.as_ref())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "vmess auth length decrypt failed"))?,
            Security::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(
                &expand_chacha_key(&kdf(length_key, &[b"auth_len"])[..16].try_into().unwrap()),
            )
            .unwrap()
            .decrypt(
                chacha20poly1305::Nonce::from_slice(&nonce_from(length_iv, state.read_count)),
                enc_len.as_ref(),
            )
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "vmess auth length decrypt failed"))?,
            Security::None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "authenticated length is unavailable for vmess none security",
                ))
            }
            Security::Legacy => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "authenticated length is unavailable for vmess legacy security",
                ))
            }
        };
        u16::from_be_bytes([len_cipher[0], len_cipher[1]]) as usize + 16
    } else {
        let mut len_buf = [0_u8; 2];
        match stream.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                ) =>
            {
                return Ok(None);
            }
            Err(err) => return Err(err),
        }
        let mut size = u16::from_be_bytes(len_buf);
        if chunk_masking {
            let reader = ensure_length_mask(&mut state.length_mask, mask_seed);
            size ^= next_hash_u16(reader);
        }
        size as usize
    };
    if padding_len > size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad vmess chunk length: length={size}, padding={padding_len}"),
        ));
    }
    size -= padding_len;
    Ok(Some((size, padding_len)))
}

fn write_chunk_length(
    stream: &mut dyn Write,
    security: Security,
    length_key: &[u8; 16],
    length_iv: &[u8; 16],
    mask_seed: &[u8; 16],
    chunk_masking: bool,
    authenticated_length: bool,
    count: u16,
    reader: &mut Option<Box<dyn XofReader + Send>>,
    encoded_len: usize,
    padding_len: usize,
) -> io::Result<()> {
    let total_len = encoded_len
        .checked_add(padding_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "vmess chunk length overflow"))?;
    if authenticated_length {
        if total_len < 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vmess authenticated chunk length underflow",
            ));
        }
        let plain_len = ((total_len - 16) as u16).to_be_bytes();
        let nonce = nonce_from(length_iv, count);
        let enc_len = match security {
            Security::Aes128Gcm => Aes128Gcm::new_from_slice(&kdf(length_key, &[b"auth_len"])[..16])
                .unwrap()
                .encrypt(Nonce::from_slice(&nonce), plain_len.as_ref())
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "vmess auth length encrypt failed"))?,
            Security::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(
                &expand_chacha_key(&kdf(length_key, &[b"auth_len"])[..16].try_into().unwrap()),
            )
            .unwrap()
            .encrypt(chacha20poly1305::Nonce::from_slice(&nonce), plain_len.as_ref())
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "vmess auth length encrypt failed"))?,
            Security::None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "authenticated length is unavailable for vmess none security",
                ))
            }
            Security::Legacy => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "authenticated length is unavailable for vmess legacy security",
                ))
            }
        };
        stream.write_all(&enc_len)?;
        return Ok(());
    }

    if total_len > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "vmess encoded chunk too large",
        ));
    }
    let mut size = total_len as u16;
    if chunk_masking {
        let reader = ensure_length_mask(reader, mask_seed);
        size ^= next_hash_u16(reader);
    }
    stream.write_all(&size.to_be_bytes())
}

fn encode_target_into(buffer: &mut Vec<u8>, target: &TransportTarget) -> Result<(), TransportError> {
    if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(addr) => {
                buffer.push(ATYP_IPV4);
                buffer.extend_from_slice(&addr.octets());
            }
            std::net::IpAddr::V6(addr) => {
                buffer.push(ATYP_IPV6);
                buffer.extend_from_slice(&addr.octets());
            }
        }
        return Ok(());
    }
    let host = target.host.as_bytes();
    if host.len() > u8::MAX as usize {
        return Err(TransportError::InvalidPlan(
            "vmess domain target must fit within 255 bytes".to_owned(),
        ));
    }
    buffer.push(ATYP_DOMAIN);
    buffer.push(host.len() as u8);
    buffer.extend_from_slice(host);
    Ok(())
}

fn encode_xudp_addr(target: SocketAddr) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&target.port().to_be_bytes());
    match target.ip() {
        IpAddr::V4(addr) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&addr.octets());
        }
        IpAddr::V6(addr) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&addr.octets());
        }
    }
    Ok(out)
}

fn decode_xudp_addr(payload: &[u8]) -> io::Result<(SocketAddr, usize)> {
    if payload.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "vmess xudp address too short",
        ));
    }
    let port = u16::from_be_bytes([payload[0], payload[1]]);
    match payload[2] {
        ATYP_IPV4 => {
            if payload.len() < 7 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "vmess xudp ipv4 address truncated",
                ));
            }
            Ok((
                SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::new(
                        payload[3], payload[4], payload[5], payload[6],
                    )),
                    port,
                ),
                7,
            ))
        }
        ATYP_IPV6 => {
            if payload.len() < 19 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "vmess xudp ipv6 address truncated",
                ));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&payload[3..19]);
            Ok((
                SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::from(octets)), port),
                19,
            ))
        }
        ATYP_DOMAIN => {
            if payload.len() < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "vmess xudp domain length missing",
                ));
            }
            let length = payload[3] as usize;
            if payload.len() < 4 + length {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "vmess xudp domain address truncated",
                ));
            }
            let host = String::from_utf8_lossy(&payload[4..4 + length]).into_owned();
            let mut addrs = (host.as_str(), port).to_socket_addrs()?;
            let addr = addrs.next().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "vmess xudp domain target unresolved",
                )
            })?;
            Ok((addr, 4 + length))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported vmess xudp atyp {other}"),
        )),
    }
}

fn seal_vmess_aead_header(cmd_key: [u8; 16], data: &[u8]) -> Result<Vec<u8>, TransportError> {
    let auth_id = create_auth_id(&cmd_key)?;
    let mut connection_nonce = [0_u8; 8];
    OsRng.fill_bytes(&mut connection_nonce);

    let len_key = kdf(
        &cmd_key,
        &[KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY, &auth_id, &connection_nonce],
    );
    let len_iv = kdf(
        &cmd_key,
        &[KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV, &auth_id, &connection_nonce],
    );
    let payload_key = kdf(
        &cmd_key,
        &[KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_KEY, &auth_id, &connection_nonce],
    );
    let payload_iv = kdf(
        &cmd_key,
        &[KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_IV, &auth_id, &connection_nonce],
    );

    let len_cipher = Aes128Gcm::new_from_slice(&len_key[..16]).unwrap();
    let payload_cipher = Aes128Gcm::new_from_slice(&payload_key[..16]).unwrap();
    let enc_len = len_cipher
        .encrypt(
            Nonce::from_slice(&len_iv[..12]),
            aes_gcm::aead::Payload {
                msg: (data.len() as u16).to_be_bytes().as_ref(),
                aad: &auth_id,
            },
        )
        .map_err(|_| TransportError::InvalidPlan("vmess header length encrypt failed".to_owned()))?;
    let enc_payload = payload_cipher
        .encrypt(Nonce::from_slice(&payload_iv[..12]), aes_gcm::aead::Payload { msg: data, aad: &auth_id })
        .map_err(|_| TransportError::InvalidPlan("vmess header encrypt failed".to_owned()))?;

    let mut out = Vec::with_capacity(16 + enc_len.len() + 8 + enc_payload.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&enc_len);
    out.extend_from_slice(&connection_nonce);
    out.extend_from_slice(&enc_payload);
    Ok(out)
}

fn open_vmess_aead_header_with_auth_id(
    stream: &mut dyn Read,
    cmd_key: [u8; 16],
    auth_id: [u8; 16],
) -> Result<Vec<u8>, TransportError> {
    let mut enc_len = [0_u8; 18];
    stream.read_exact(&mut enc_len).map_err(TransportError::from)?;
    let mut connection_nonce = [0_u8; 8];
    stream
        .read_exact(&mut connection_nonce)
        .map_err(TransportError::from)?;

    let len_key = kdf(
        &cmd_key,
        &[KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY, &auth_id, &connection_nonce],
    );
    let len_iv = kdf(
        &cmd_key,
        &[KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV, &auth_id, &connection_nonce],
    );
    let payload_key = kdf(
        &cmd_key,
        &[KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_KEY, &auth_id, &connection_nonce],
    );
    let payload_iv = kdf(
        &cmd_key,
        &[KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_IV, &auth_id, &connection_nonce],
    );

    let len_cipher = Aes128Gcm::new_from_slice(&len_key[..16]).unwrap();
    let plain_len = len_cipher
        .decrypt(Nonce::from_slice(&len_iv[..12]), aes_gcm::aead::Payload { msg: enc_len.as_ref(), aad: &auth_id })
        .map_err(|_| TransportError::invalid_proxy_response("vmess request length decrypt failed"))?;
    let header_len = u16::from_be_bytes([plain_len[0], plain_len[1]]) as usize;

    let mut enc_payload = vec![0_u8; header_len + 16];
    stream
        .read_exact(&mut enc_payload)
        .map_err(TransportError::from)?;
    let payload_cipher = Aes128Gcm::new_from_slice(&payload_key[..16]).unwrap();
    payload_cipher
        .decrypt(Nonce::from_slice(&payload_iv[..12]), aes_gcm::aead::Payload { msg: enc_payload.as_ref(), aad: &auth_id })
        .map_err(|_| TransportError::invalid_proxy_response("vmess request header decrypt failed"))
}

fn try_open_vmess_legacy_header(
    stream: &mut dyn Read,
    cmd_key: [u8; 16],
    alter_key: [u8; 16],
    auth_id: &[u8; 16],
    skew_secs: i64,
) -> Result<Option<Vec<u8>>, TransportError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| TransportError::InvalidPlan(err.to_string()))?
        .as_secs() as i64;
    let mut tried = Vec::new();
    for delta in 0..=skew_secs {
        for candidate in [now - delta, now + delta] {
            if tried.contains(&candidate) {
                continue;
            }
            tried.push(candidate);
            if build_legacy_auth_id(&alter_key, candidate as u64) != *auth_id {
                continue;
            }
            let iv = legacy_time_hash(candidate as u64);
            let mut decryptor = new_aes_cfb_decryptor(&cmd_key, &iv);
            let mut prefix = [0_u8; 38];
            stream.read_exact(&mut prefix).map_err(TransportError::from)?;
            decryptor.xor(&mut prefix);
            let command = prefix[37];
            let padding_len = (prefix[35] >> 4) as usize;
            let mut payload = prefix.to_vec();
            if command != COMMAND_MUX {
                let mut port_and_atyp = [0_u8; 3];
                stream
                    .read_exact(&mut port_and_atyp)
                    .map_err(TransportError::from)?;
                decryptor.xor(&mut port_and_atyp);
                let atyp = port_and_atyp[2];
                payload.extend_from_slice(&port_and_atyp);
                let addr_len = match atyp {
                    ATYP_IPV4 => 4,
                    ATYP_IPV6 => 16,
                    ATYP_DOMAIN => {
                        let mut len = [0_u8; 1];
                        stream.read_exact(&mut len).map_err(TransportError::from)?;
                        decryptor.xor(&mut len);
                        payload.extend_from_slice(&len);
                        len[0] as usize
                    }
                    other => {
                        return Err(TransportError::invalid_proxy_response(format!(
                            "unsupported vmess legacy atyp {other}"
                        )))
                    }
                };
                let mut addr = vec![0_u8; addr_len];
                stream.read_exact(&mut addr).map_err(TransportError::from)?;
                decryptor.xor(&mut addr);
                payload.extend_from_slice(&addr);
            }
            if padding_len != 0 {
                let mut padding = vec![0_u8; padding_len];
                stream
                    .read_exact(&mut padding)
                    .map_err(TransportError::from)?;
                decryptor.xor(&mut padding);
                payload.extend_from_slice(&padding);
            }
            let mut checksum = [0_u8; 4];
            stream
                .read_exact(&mut checksum)
                .map_err(TransportError::from)?;
            decryptor.xor(&mut checksum);
            payload.extend_from_slice(&checksum);
            return Ok(Some(payload));
        }
    }
    Ok(None)
}

fn create_auth_id(cmd_key: &[u8; 16]) -> Result<[u8; 16], TransportError> {
    let mut plain = [0_u8; 16];
    plain[..8].copy_from_slice(&(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| TransportError::InvalidPlan(err.to_string()))?
        .as_secs() as i64)
        .to_be_bytes());
    OsRng.fill_bytes(&mut plain[8..12]);
    let crc = crc32_hash(&plain[..12]);
    plain[12..].copy_from_slice(&crc.to_be_bytes());

    let key = kdf(cmd_key, &[KDF_SALT_AUTH_ID_ENCRYPTION_KEY]);
    let cipher = Aes128::new_from_slice(&key[..16]).unwrap();
    let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(&plain);
    cipher.encrypt_block(&mut block);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&block);
    Ok(out)
}

fn seal_vmess_legacy_header(
    cmd_key: [u8; 16],
    alter_key: [u8; 16],
    data: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| TransportError::InvalidPlan(err.to_string()))?
        .as_secs();
    let auth_id = build_legacy_auth_id(&alter_key, timestamp);
    let iv = legacy_time_hash(timestamp);
    let mut encrypted = data.to_vec();
    let mut encryptor = new_aes_cfb_encryptor(&cmd_key, &iv);
    encryptor.xor(&mut encrypted);
    let mut out = Vec::with_capacity(16 + encrypted.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&encrypted);
    Ok(out)
}

fn build_legacy_auth_id(alter_key: &[u8; 16], timestamp: u64) -> [u8; 16] {
    let mut mac = <Hmac<Md5> as Mac>::new_from_slice(alter_key).unwrap();
    mac.update(&(timestamp as i64).to_be_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut out = [0_u8; 16];
    out.copy_from_slice(&bytes);
    out
}

fn legacy_time_hash(timestamp: u64) -> [u8; 16] {
    let ts = (timestamp as i64).to_be_bytes();
    let mut hash = Md5::new();
    hash.update(ts);
    hash.update(ts);
    hash.update(ts);
    hash.update(ts);
    let digest = hash.finalize();
    let mut out = [0_u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn derive_cmd_key(uuid: &Uuid) -> [u8; 16] {
    let mut hash = Md5::new();
    hash.update(uuid.as_bytes());
    hash.update(CMD_KEY_SALT);
    let digest = hash.finalize();
    let mut out = [0_u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn derive_alter_key(uuid: &Uuid) -> [u8; 16] {
    let mut current = *uuid;
    loop {
        let mut hash = Md5::new();
        hash.update(current.as_bytes());
        hash.update(LEGACY_ALTER_ID_SALT);
        let digest = hash.finalize();
        let mut next = [0_u8; 16];
        next.copy_from_slice(&digest[..16]);
        if next != *uuid.as_bytes() {
            return next;
        }
        current = Uuid::from_bytes(next);
    }
}

fn first_16_sha256(input: &[u8; 16]) -> [u8; 16] {
    let digest = Sha256::digest(input);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn md5_16(input: &[u8; 16]) -> [u8; 16] {
    let digest = Md5::digest(input);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn expand_chacha_key(key16: &[u8; 16]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    let mut hash = Md5::new();
    hash.update(key16);
    let digest = hash.finalize();
    out[..16].copy_from_slice(&digest[..16]);
    let mut hash = Md5::new();
    hash.update(&out[..16]);
    let digest = hash.finalize();
    out[16..].copy_from_slice(&digest[..16]);
    out
}

fn nonce_from(iv: &[u8; 16], count: u16) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..2].copy_from_slice(&count.to_be_bytes());
    nonce[2..].copy_from_slice(&iv[2..12]);
    nonce
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5_u32;
    for byte in data {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn kdf(key: &[u8], path: &[&[u8]]) -> Vec<u8> {
    fn nested(level: usize, path: &[&[u8]], data: &[u8]) -> [u8; 32] {
        if level == path.len() {
            let digest = Sha256::digest(data);
            let mut out = [0_u8; 32];
            out.copy_from_slice(&digest);
            return out;
        }
        hmac_with(level, path, data)
    }

    fn hmac_with(level: usize, path: &[&[u8]], data: &[u8]) -> [u8; 32] {
        let mut key_bytes = path[level].to_vec();
        if key_bytes.len() > 64 {
            key_bytes = nested(level + 1, path, &key_bytes).to_vec();
        }
        key_bytes.resize(64, 0);
        let mut inner = vec![0_u8; 64 + data.len()];
        let mut outer = [0_u8; 64];
        for (index, key) in key_bytes.iter().enumerate().take(64) {
            inner[index] = *key ^ 0x36;
            outer[index] = *key ^ 0x5c;
        }
        inner[64..].copy_from_slice(data);
        let inner_sum = nested(level + 1, path, &inner);
        let mut outer_input = Vec::with_capacity(64 + inner_sum.len());
        outer_input.extend_from_slice(&outer);
        outer_input.extend_from_slice(&inner_sum);
        nested(level + 1, path, &outer_input)
    }

    let mut full_path = Vec::with_capacity(path.len() + 1);
    full_path.extend(path.iter().rev().copied());
    full_path.push(KDF_SALT_VMESS_AEAD_KDF);
    nested(0, &full_path, key).to_vec()
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use crate::{
        SocketOptions, SystemTcpDialer, TcpTransportExecutor, TransportAction, TransportHop,
        TransportPlan, TransportPlanRunner, TransportTarget,
    };

    use super::{
        accept_server_stream_for_tests, open_udp_stream, open_xudp_stream, read_udp_packet,
        read_xudp_packet, write_udp_packet, write_xudp_packet,
        VmessAcceptedStream, VMESS_MUX_TARGET,
    };

    #[test]
    fn vmess_tcp_stream_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let accepted =
                accept_server_stream_for_tests(
                    Box::new(stream),
                    "b831381d-6324-4d53-ad4f-8cda48b30811",
                    "none",
                )
                    .unwrap();
            let VmessAcceptedStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: String::new(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions::default(),
                    h2: crate::Http2Options::default(),
                    http: crate::HttpStreamOptions::default(),
                    xhttp: crate::XHttpOptions::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: crate::TlsOptions::default(),
                    alpn: Vec::new(),
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
        assert_eq!(reply, b"pong-vmess");
        worker.join().unwrap();
    }

    #[test]
    fn vmess_legacy_alter_id_tcp_stream_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let accepted = accept_server_stream_for_tests(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "legacy.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-legacy").unwrap();
            stream.shutdown_write().unwrap();
        });
        let plan = TransportPlan {
            requested: "edge-vmess-legacy".into(),
            selected_path: vec!["edge-vmess-legacy".into()],
            leaf_name: "edge-vmess-legacy".into(),
            hops: vec![TransportHop {
                name: "edge-vmess-legacy".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 16,
                    cipher: "none".into(),
                    udp: false,
                    network: String::new(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions::default(),
                    h2: crate::Http2Options::default(),
                    http: crate::HttpStreamOptions::default(),
                    xhttp: crate::XHttpOptions::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: crate::TlsOptions::default(),
                    alpn: Vec::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("legacy.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-legacy");
        worker.join().unwrap();
    }

    #[test]
    fn vmess_legacy_alter_id_udp_stream_round_trip_preserves_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let accepted = accept_server_stream_for_tests(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, "127.0.0.1:5353");
            let payload = read_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess");
            write_udp_packet(&mut *stream, b"legacy-ok").unwrap();
            stream.shutdown_write().unwrap();
        });

        let mut stream = open_udp_stream(
            Box::new(std::net::TcpStream::connect(addr).unwrap()),
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            16,
            "none",
            false,
            false,
            "127.0.0.1:5353".parse().unwrap(),
        )
        .unwrap();
        write_udp_packet(&mut *stream, b"via-vmess").unwrap();
        let payload = read_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"legacy-ok");
        worker.join().unwrap();
    }

    #[test]
    fn vmess_legacy_security_tcp_stream_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let accepted = accept_server_stream_for_tests(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "aes-128-cfb",
            )
            .unwrap();
            let VmessAcceptedStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "legacy-body.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-cfb").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-vmess-legacy-body".into(),
            selected_path: vec!["edge-vmess-legacy-body".into()],
            leaf_name: "edge-vmess-legacy-body".into(),
            hops: vec![TransportHop {
                name: "edge-vmess-legacy-body".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "aes-128-cfb".into(),
                    udp: false,
                    network: String::new(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions::default(),
                    h2: crate::Http2Options::default(),
                    http: crate::HttpStreamOptions::default(),
                    xhttp: crate::XHttpOptions::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: crate::TlsOptions::default(),
                    alpn: Vec::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("legacy-body.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-cfb");
        worker.join().unwrap();
    }

    #[test]
    fn vmess_legacy_security_over_legacy_alter_id_udp_stream_round_trip_preserves_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let accepted = accept_server_stream_for_tests(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "aes-128-cfb",
            )
            .unwrap();
            let VmessAcceptedStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, "127.0.0.1:5353");
            let payload = read_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess-cfb");
            write_udp_packet(&mut *stream, b"legacy-cfb-ok").unwrap();
            stream.shutdown_write().unwrap();
        });

        let mut stream = open_udp_stream(
            Box::new(std::net::TcpStream::connect(addr).unwrap()),
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            16,
            "aes-128-cfb",
            false,
            false,
            "127.0.0.1:5353".parse().unwrap(),
        )
        .unwrap();
        write_udp_packet(&mut *stream, b"via-vmess-cfb").unwrap();
        let payload = read_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"legacy-cfb-ok");
        worker.join().unwrap();
    }

    #[test]
    fn vmess_udp_stream_round_trip_preserves_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let accepted = accept_server_stream_for_tests(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, "127.0.0.1:5353");
            let payload = read_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess");
            write_udp_packet(&mut *stream, b"vmess-ok").unwrap();
            stream.shutdown_write().unwrap();
        });

        let mut stream = open_udp_stream(
            Box::new(std::net::TcpStream::connect(addr).unwrap()),
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
            "127.0.0.1:5353".parse().unwrap(),
        )
        .unwrap();
        write_udp_packet(&mut *stream, b"via-vmess").unwrap();
        let payload = read_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"vmess-ok");
        worker.join().unwrap();
    }

    #[test]
    fn vmess_tcp_stream_round_trip_supports_authenticated_length_and_global_padding() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let accepted = accept_server_stream_for_tests(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "aes-128-gcm",
            )
            .unwrap();
            let VmessAcceptedStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-vmess".into(),
            selected_path: vec!["edge-vmess".into()],
            leaf_name: "edge-vmess".into(),
            hops: vec![TransportHop {
                name: "edge-vmess".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "aes-128-gcm".into(),
                    udp: false,
                    network: String::new(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions::default(),
                    h2: crate::Http2Options::default(),
                    http: crate::HttpStreamOptions::default(),
                    xhttp: crate::XHttpOptions::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: true,
                    authenticated_length: true,
                    tls: crate::TlsOptions::default(),
                    alpn: Vec::new(),
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
        assert_eq!(reply, b"pong-vmess");
        worker.join().unwrap();
    }

    #[test]
    fn vmess_server_tcp_stream_supports_prewrite_clone_for_response_path() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let accepted = accept_server_stream_for_tests(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "clone.example.com:443");
            let mut writer = stream.try_clone_box().unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            writer.write_all(b"pong-clone").unwrap();
            writer.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-vmess-clone".into(),
            selected_path: vec!["edge-vmess-clone".into()],
            leaf_name: "edge-vmess-clone".into(),
            hops: vec![TransportHop {
                name: "edge-vmess-clone".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: String::new(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions::default(),
                    h2: crate::Http2Options::default(),
                    http: crate::HttpStreamOptions::default(),
                    xhttp: crate::XHttpOptions::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: crate::TlsOptions::default(),
                    alpn: Vec::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("clone.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-clone");
        worker.join().unwrap();
    }

    #[test]
    fn vmess_udp_stream_round_trip_supports_authenticated_length_and_global_padding() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let accepted = accept_server_stream_for_tests(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "aes-128-gcm",
            )
            .unwrap();
            let VmessAcceptedStream::Udp { target, mut stream } = accepted else {
                panic!("expected vmess udp stream");
            };
            assert_eq!(target, "127.0.0.1:5353");
            let payload = read_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"via-vmess");
            write_udp_packet(&mut *stream, b"vmess-ok").unwrap();
            stream.shutdown_write().unwrap();
        });

        let mut stream = open_udp_stream(
            Box::new(std::net::TcpStream::connect(addr).unwrap()),
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "aes-128-gcm",
            true,
            true,
            "127.0.0.1:5353".parse().unwrap(),
        )
        .unwrap();
        write_udp_packet(&mut *stream, b"via-vmess").unwrap();
        let payload = read_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"vmess-ok");
        worker.join().unwrap();
    }

    #[test]
    fn vmess_xudp_stream_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let accepted = accept_server_stream_for_tests(
                Box::new(stream),
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "aes-128-gcm",
            )
            .unwrap();
            let VmessAcceptedStream::Xudp { target, mut stream } = accepted else {
                panic!("expected vmess xudp stream");
            };
            assert_eq!(target, VMESS_MUX_TARGET);
            let (target, payload) = read_xudp_packet(&mut *stream).unwrap();
            assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
            assert_eq!(payload, b"via-vmess");
            write_xudp_packet(&mut *stream, target, b"vmess-ok").unwrap();
            stream.shutdown_write().unwrap();
        });

        let mut stream = open_xudp_stream(
            Box::new(std::net::TcpStream::connect(addr).unwrap()),
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "aes-128-gcm",
            false,
            false,
        )
        .unwrap();
        write_xudp_packet(&mut *stream, "127.0.0.1:5353".parse().unwrap(), b"via-vmess").unwrap();
        let (target, payload) = read_xudp_packet(&mut *stream).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(payload, b"vmess-ok");
        worker.join().unwrap();
    }

    #[test]
    fn vmess_xudp_reader_skips_keepalive_and_no_data_frames() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&2_u16.to_be_bytes());
        stream.extend_from_slice(&[0, 0, 0x04, 0x00]);
        stream.extend_from_slice(&2_u16.to_be_bytes());
        stream.extend_from_slice(&[0, 0, 0x02, 0x00]);
        stream.extend_from_slice(&12_u16.to_be_bytes());
        stream.extend_from_slice(&[0, 0, 0x01, 0x01]);
        stream.extend_from_slice(&[0x02, 0x14, 0xE9, 0x01, 127, 0, 0, 1]);
        stream.extend_from_slice(&3_u16.to_be_bytes());
        stream.extend_from_slice(b"ok!");

        let (target, payload) = read_xudp_packet(&mut std::io::Cursor::new(stream)).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(payload, b"ok!");
    }

    #[test]
    fn vmess_xudp_reader_supports_domain_targets() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&18_u16.to_be_bytes());
        stream.extend_from_slice(&[0, 0, 0x01, 0x01]);
        stream.extend_from_slice(&[0x02, 0x14, 0xE9, 0x02, 0x09]);
        stream.extend_from_slice(b"localhost");
        stream.extend_from_slice(&3_u16.to_be_bytes());
        stream.extend_from_slice(b"dns");

        let (target, payload) = read_xudp_packet(&mut std::io::Cursor::new(stream)).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(payload, b"dns");
    }
}
