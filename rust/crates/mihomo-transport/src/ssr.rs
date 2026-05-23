use std::io::{self, Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};

use aes::{Aes128, Aes192, Aes256};
use cfb_mode::cipher::KeyIvInit;
use md5::{Digest, Md5};
use mihomo_core::BoxedTcpStream;
use mihomo_core::TcpStream;
use rand::RngCore;

use crate::{ssr_http_obfs, TransportError, TransportTarget};

pub(crate) fn wrap_stream(
    stream: BoxedTcpStream,
    proxy: &TransportTarget,
    cipher: &str,
    password: &str,
    obfs: &str,
    obfs_param: &str,
    protocol: &str,
    protocol_param: &str,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    let kind = validate_supported_options(proxy, cipher, obfs, obfs_param, protocol, protocol_param)?;
    let obfs = obfs.trim();
    let mut stream = match obfs {
        "http_simple" => ssr_http_obfs::wrap_stream(
            stream,
            ssr_http_obfs::SsrHttpObfsOptions {
                host: proxy.host.clone(),
                port: proxy.port,
                param: obfs_param.to_owned(),
                iv_size: kind.iv_size(),
                post: false,
            },
        ),
        "http_post" => ssr_http_obfs::wrap_stream(
            stream,
            ssr_http_obfs::SsrHttpObfsOptions {
                host: proxy.host.clone(),
                port: proxy.port,
                param: obfs_param.to_owned(),
                iv_size: kind.iv_size(),
                post: true,
            },
        ),
        _ => stream,
    };
    if matches!(kind, SsrCipherKind::None) {
        let mut destination = super::encode_socks5_target(target)?;
        destination.extend_from_slice(&target.port.to_be_bytes());
        stream.write_all(&destination).map_err(TransportError::from)?;
        stream.flush().map_err(TransportError::from)?;
        return Ok(stream);
    }
    let crypto = SsrCrypto::new(kind, password)?;
    let mut stream = SsrStream::new(stream, crypto)?;
    let mut destination = super::encode_socks5_target(target)?;
    destination.extend_from_slice(&target.port.to_be_bytes());
    stream.write_all(&destination).map_err(TransportError::from)?;
    stream.flush().map_err(TransportError::from)?;
    Ok(Box::new(stream))
}

pub(crate) fn wrap_accepted_stream(
    stream: BoxedTcpStream,
    cipher: &str,
    password: &str,
) -> Result<BoxedTcpStream, TransportError> {
    let kind = SsrCipherKind::parse(cipher)?;
    if matches!(kind, SsrCipherKind::None) {
        return Ok(stream);
    }
    Ok(Box::new(SsrStream::new(stream, SsrCrypto::new(kind, password)?)?))
}

pub(crate) fn encode_udp_packet(
    cipher: &str,
    password: &str,
    destination: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let target = TransportTarget::new(destination.ip().to_string(), destination.port());
    let kind = SsrCipherKind::parse(cipher)?;
    let mut packet = super::encode_socks5_target(&target)?;
    packet.extend_from_slice(&target.port.to_be_bytes());
    packet.extend_from_slice(payload);
    if matches!(kind, SsrCipherKind::None) {
        return Ok(packet);
    }
    let crypto = SsrCrypto::new(kind, password)?;
    let mut iv = [0_u8; SSR_IV_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    let mut cipher_state = crypto.encryptor(&iv);
    let mut encrypted = packet;
    cipher_state.xor(&mut encrypted);
    let mut framed = iv.to_vec();
    framed.extend_from_slice(&encrypted);
    Ok(framed)
}

pub(crate) fn decode_udp_packet(
    cipher: &str,
    password: &str,
    payload: &[u8],
) -> io::Result<(SocketAddr, Vec<u8>)> {
    let kind = SsrCipherKind::parse(cipher).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    let decrypted = if matches!(kind, SsrCipherKind::None) {
        payload.to_vec()
    } else {
        if payload.len() < SSR_IV_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ssr udp packet too short for iv",
            ));
        }
        let (iv, ciphertext) = payload.split_at(SSR_IV_SIZE);
        let crypto =
            SsrCrypto::new(kind, password).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        let mut cipher_state = crypto.decryptor(iv.try_into().unwrap());
        let mut decrypted = ciphertext.to_vec();
        cipher_state.xor(&mut decrypted);
        decrypted
    };
    decode_udp_packet_plain(&decrypted)
}

fn decode_udp_packet_plain(payload: &[u8]) -> io::Result<(SocketAddr, Vec<u8>)> {
    if payload.len() < 1 + 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ssr udp packet too short",
        ));
    }
    let atyp = payload[0];
    let (ip, offset) = match atyp {
        0x01 => {
            if payload.len() < 1 + 4 + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ssr udp ipv4 packet truncated",
                ));
            }
            (
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    payload[1], payload[2], payload[3], payload[4],
                )),
                5,
            )
        }
        0x04 => {
            if payload.len() < 1 + 16 + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ssr udp ipv6 packet truncated",
                ));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&payload[1..17]);
            (
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                17,
            )
        }
        0x03 => {
            let length = *payload
                .get(1)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ssr udp fqdn length missing"))?
                as usize;
            if payload.len() < 1 + 1 + length + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ssr udp fqdn packet truncated",
                ));
            }
            let host = String::from_utf8_lossy(&payload[2..2 + length]).into_owned();
            let port = u16::from_be_bytes([payload[2 + length], payload[2 + length + 1]]);
            let mut addrs = (host.as_str(), port).to_socket_addrs()?;
            let addr = addrs.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "ssr udp fqdn target unresolved")
            })?;
            return Ok((addr, payload[2 + length + 2..].to_vec()));
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported ssr udp atyp {other}"),
            ))
        }
    };
    let port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    Ok((
        SocketAddr::new(ip, port),
        payload[offset + 2..].to_vec(),
    ))
}

fn validate_supported_options(
    proxy: &TransportTarget,
    cipher: &str,
    obfs: &str,
    obfs_param: &str,
    protocol: &str,
    protocol_param: &str,
) -> Result<SsrCipherKind, TransportError> {
    let kind = SsrCipherKind::parse(cipher).map_err(|_| TransportError::UnsupportedFeature {
        proxy: proxy.authority(),
        feature: format!("cipher={}", cipher.trim()),
    })?;
    let obfs = obfs.trim();
    if !obfs.is_empty() && obfs != "plain" && obfs != "http_simple" && obfs != "http_post" {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("obfs={obfs}"),
        });
    }
    if obfs != "plain" && obfs != "http_simple" && obfs != "http_post" && !obfs_param.trim().is_empty() {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: "obfs-param".to_owned(),
        });
    }
    let protocol = protocol.trim();
    if !protocol.is_empty() && protocol != "origin" {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: format!("protocol={protocol}"),
        });
    }
    if protocol != "origin" && !protocol_param.trim().is_empty() {
        return Err(TransportError::UnsupportedFeature {
            proxy: proxy.authority(),
            feature: "protocol-param".to_owned(),
        });
    }
    Ok(kind)
}

const SSR_IV_SIZE: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SsrCipherKind {
    None,
    Aes128Cfb,
    Aes192Cfb,
    Aes256Cfb,
}

impl SsrCipherKind {
    fn parse(cipher: &str) -> Result<Self, TransportError> {
        match cipher.trim().to_ascii_lowercase().as_str() {
            "" | "dummy" | "none" => Ok(Self::None),
            "aes-128-cfb" => Ok(Self::Aes128Cfb),
            "aes-192-cfb" => Ok(Self::Aes192Cfb),
            "aes-256-cfb" => Ok(Self::Aes256Cfb),
            other => Err(TransportError::InvalidPlan(format!(
                "unsupported ssr cipher {other}"
            ))),
        }
    }

    fn key_size(self) -> usize {
        match self {
            Self::None => 0,
            Self::Aes128Cfb => 16,
            Self::Aes192Cfb => 24,
            Self::Aes256Cfb => 32,
        }
    }

    fn iv_size(self) -> usize {
        match self {
            Self::None => 0,
            Self::Aes128Cfb | Self::Aes192Cfb | Self::Aes256Cfb => SSR_IV_SIZE,
        }
    }
}

#[derive(Clone)]
struct SsrCrypto {
    kind: SsrCipherKind,
    key: Vec<u8>,
}

impl SsrCrypto {
    fn new(kind: SsrCipherKind, password: &str) -> Result<Self, TransportError> {
        let key = ssr_kdf(password, kind.key_size());
        Ok(Self { kind, key })
    }

    fn encryptor(&self, iv: &[u8; SSR_IV_SIZE]) -> SsrCipherState {
        match self.kind {
            SsrCipherKind::None => SsrCipherState::None,
            SsrCipherKind::Aes128Cfb => SsrCipherState::Encrypt128(
                cfb_mode::BufEncryptor::<Aes128>::new((&self.key[..16]).into(), iv.into()),
            ),
            SsrCipherKind::Aes192Cfb => SsrCipherState::Encrypt192(
                cfb_mode::BufEncryptor::<Aes192>::new((&self.key[..24]).into(), iv.into()),
            ),
            SsrCipherKind::Aes256Cfb => SsrCipherState::Encrypt256(
                cfb_mode::BufEncryptor::<Aes256>::new((&self.key[..32]).into(), iv.into()),
            ),
        }
    }

    fn decryptor(&self, iv: &[u8; SSR_IV_SIZE]) -> SsrCipherState {
        match self.kind {
            SsrCipherKind::None => SsrCipherState::None,
            SsrCipherKind::Aes128Cfb => SsrCipherState::Decrypt128(
                cfb_mode::BufDecryptor::<Aes128>::new((&self.key[..16]).into(), iv.into()),
            ),
            SsrCipherKind::Aes192Cfb => SsrCipherState::Decrypt192(
                cfb_mode::BufDecryptor::<Aes192>::new((&self.key[..24]).into(), iv.into()),
            ),
            SsrCipherKind::Aes256Cfb => SsrCipherState::Decrypt256(
                cfb_mode::BufDecryptor::<Aes256>::new((&self.key[..32]).into(), iv.into()),
            ),
        }
    }
}

#[derive(Clone)]
enum SsrCipherState {
    None,
    Encrypt128(cfb_mode::BufEncryptor<Aes128>),
    Decrypt128(cfb_mode::BufDecryptor<Aes128>),
    Encrypt192(cfb_mode::BufEncryptor<Aes192>),
    Decrypt192(cfb_mode::BufDecryptor<Aes192>),
    Encrypt256(cfb_mode::BufEncryptor<Aes256>),
    Decrypt256(cfb_mode::BufDecryptor<Aes256>),
}

impl SsrCipherState {
    fn xor(&mut self, data: &mut [u8]) {
        match self {
            Self::None => {}
            Self::Encrypt128(cipher) => cipher.encrypt(data),
            Self::Decrypt128(cipher) => cipher.decrypt(data),
            Self::Encrypt192(cipher) => cipher.encrypt(data),
            Self::Decrypt192(cipher) => cipher.decrypt(data),
            Self::Encrypt256(cipher) => cipher.encrypt(data),
            Self::Decrypt256(cipher) => cipher.decrypt(data),
        }
    }
}

struct SsrStream {
    read_socket: BoxedTcpStream,
    write_socket: Option<BoxedTcpStream>,
    crypto: SsrCrypto,
    reader_state: Option<SsrCipherState>,
    writer_state: Option<SsrCipherState>,
    read_buf: Vec<u8>,
    read_off: usize,
}

impl SsrStream {
    fn new(stream: BoxedTcpStream, crypto: SsrCrypto) -> Result<Self, TransportError> {
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

    fn init_reader(&mut self) -> io::Result<&mut SsrCipherState> {
        if self.reader_state.is_none() {
            let mut iv = [0_u8; SSR_IV_SIZE];
            self.read_socket.read_exact(&mut iv)?;
            self.reader_state = Some(self.crypto.decryptor(&iv));
        }
        Ok(self.reader_state.as_mut().unwrap())
    }

    fn init_writer(&mut self) -> io::Result<&mut SsrCipherState> {
        if self.writer_state.is_none() {
            let mut iv = [0_u8; SSR_IV_SIZE];
            rand::rngs::OsRng.fill_bytes(&mut iv);
            self.write_socket().write_all(&iv)?;
            self.writer_state = Some(self.crypto.encryptor(&iv));
        }
        Ok(self.writer_state.as_mut().unwrap())
    }
}

impl Read for SsrStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.read_off < self.read_buf.len() {
            let available = &self.read_buf[self.read_off..];
            let copied = available.len().min(buf.len());
            buf[..copied].copy_from_slice(&available[..copied]);
            self.read_off += copied;
            if self.read_off == self.read_buf.len() {
                self.read_buf.clear();
                self.read_off = 0;
            }
            return Ok(copied);
        }
        self.init_reader()?;
        let mut chunk = vec![0_u8; buf.len().max(16 * 1024)];
        let read = self.read_socket.read(&mut chunk)?;
        if read == 0 {
            return Ok(0);
        }
        chunk.truncate(read);
        self.reader_state.as_mut().unwrap().xor(&mut chunk);
        let copied = chunk.len().min(buf.len());
        buf[..copied].copy_from_slice(&chunk[..copied]);
        if copied < chunk.len() {
            self.read_buf = chunk;
            self.read_off = copied;
        }
        Ok(copied)
    }
}

impl Write for SsrStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut encrypted = buf.to_vec();
        self.init_writer()?.xor(&mut encrypted);
        self.write_socket().write_all(&encrypted)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_socket().flush()
    }
}

impl TcpStream for SsrStream {
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

fn ssr_kdf(password: &str, key_len: usize) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::thread;

    use crate::{
        accept_ssr_http_obfs_test_stream, SocketOptions, SystemTcpDialer, TcpTransportExecutor,
        TransportAction, TransportHop, TransportPlan, TransportPlanRunner, TransportTarget,
    };

    use super::{decode_udp_packet, encode_udp_packet, wrap_accepted_stream, wrap_stream};

    #[test]
    fn ssr_tcp_stream_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let target = read_target(&mut stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ssr").unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ssr".into(),
            selected_path: vec!["edge-ssr".into()],
            leaf_name: "edge-ssr".into(),
            hops: vec![TransportHop {
                name: "edge-ssr".into(),
                action: TransportAction::SsrConnect {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    password: "secret".into(),
                    cipher: "dummy".into(),
                    obfs: "plain".into(),
                    obfs_param: String::new(),
                    protocol: "origin".into(),
                    protocol_param: String::new(),
                    udp: true,
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
        assert_eq!(reply, b"pong-ssr");
        worker.join().unwrap();
    }

    #[test]
    fn ssr_tcp_stream_round_trip_preserves_target_and_payload_with_ignored_params() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let target = read_target(&mut stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ssr-params").unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ssr-params".into(),
            selected_path: vec!["edge-ssr-params".into()],
            leaf_name: "edge-ssr-params".into(),
            hops: vec![TransportHop {
                name: "edge-ssr-params".into(),
                action: TransportAction::SsrConnect {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    password: "secret".into(),
                    cipher: "dummy".into(),
                    obfs: "plain".into(),
                    obfs_param: "ignored-host".into(),
                    protocol: "origin".into(),
                    protocol_param: "ignored-user".into(),
                    udp: true,
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
        assert_eq!(reply, b"pong-ssr-params");
        worker.join().unwrap();
    }

    #[test]
    fn ssr_tcp_stream_round_trip_preserves_target_and_payload_with_http_simple_obfs() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) = accept_ssr_http_obfs_test_stream(Box::new(stream)).unwrap();
            assert!(request.starts_with("GET /%"));
            assert!(request.contains("\r\nHost: obfs.example.com"));
            let mut stream = wrap_accepted_stream(stream, "aes-128-cfb", "secret").unwrap();
            let target = read_target(&mut *stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ssr-http-obfs").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ssr-http-obfs".into(),
            selected_path: vec!["edge-ssr-http-obfs".into()],
            leaf_name: "edge-ssr-http-obfs".into(),
            hops: vec![TransportHop {
                name: "edge-ssr-http-obfs".into(),
                action: TransportAction::SsrConnect {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    password: "secret".into(),
                    cipher: "aes-128-cfb".into(),
                    obfs: "http_simple".into(),
                    obfs_param: "obfs.example.com".into(),
                    protocol: "origin".into(),
                    protocol_param: String::new(),
                    udp: true,
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
        assert_eq!(reply, b"pong-ssr-http-obfs");
        worker.join().unwrap();
    }

    #[test]
    fn ssr_tcp_stream_round_trip_preserves_target_and_payload_with_http_post_obfs() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) = accept_ssr_http_obfs_test_stream(Box::new(stream)).unwrap();
            assert!(request.starts_with("POST /%"));
            assert!(request.contains("\r\nHost: obfs.example.com"));
            assert!(request.contains("Content-Type: multipart/form-data; boundary=----ssrhttpobfsboundary"));
            let mut stream = wrap_accepted_stream(stream, "aes-128-cfb", "secret").unwrap();
            let target = read_target(&mut *stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ssr-http-post").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ssr-http-post".into(),
            selected_path: vec!["edge-ssr-http-post".into()],
            leaf_name: "edge-ssr-http-post".into(),
            hops: vec![TransportHop {
                name: "edge-ssr-http-post".into(),
                action: TransportAction::SsrConnect {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    password: "secret".into(),
                    cipher: "aes-128-cfb".into(),
                    obfs: "http_post".into(),
                    obfs_param: "obfs.example.com".into(),
                    protocol: "origin".into(),
                    protocol_param: String::new(),
                    udp: true,
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
        assert_eq!(reply, b"pong-ssr-http-post");
        worker.join().unwrap();
    }

    #[test]
    fn ssr_tcp_stream_round_trip_preserves_target_and_payload_with_aes_128_cfb() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = wrap_accepted_stream(Box::new(stream), "aes-128-cfb", "secret").unwrap();
            let target = read_target(&mut *stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ssr-cfb").unwrap();
            stream.flush().unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ssr-cfb".into(),
            selected_path: vec!["edge-ssr-cfb".into()],
            leaf_name: "edge-ssr-cfb".into(),
            hops: vec![TransportHop {
                name: "edge-ssr-cfb".into(),
                action: TransportAction::SsrConnect {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    password: "secret".into(),
                    cipher: "aes-128-cfb".into(),
                    obfs: "plain".into(),
                    obfs_param: String::new(),
                    protocol: "origin".into(),
                    protocol_param: String::new(),
                    udp: true,
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
        assert_eq!(reply, b"pong-ssr-cfb");
        worker.join().unwrap();
    }

    #[test]
    fn ssr_udp_packet_round_trip_preserves_target_and_payload() {
        let destination: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let packet = encode_udp_packet("dummy", "secret", destination, b"via-ssr").unwrap();
        let (decoded_destination, payload) = decode_udp_packet("dummy", "secret", &packet).unwrap();
        assert_eq!(decoded_destination, destination);
        assert_eq!(payload, b"via-ssr");
    }

    #[test]
    fn ssr_udp_packet_round_trip_preserves_target_and_payload_with_aes_128_cfb() {
        let destination: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let packet = encode_udp_packet("aes-128-cfb", "secret", destination, b"via-ssr-cfb").unwrap();
        let (decoded_destination, payload) =
            decode_udp_packet("aes-128-cfb", "secret", &packet).unwrap();
        assert_eq!(decoded_destination, destination);
        assert_eq!(payload, b"via-ssr-cfb");
    }

    #[test]
    fn ssr_tcp_stream_round_trip_preserves_target_and_payload_with_aes_256_cfb() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = wrap_accepted_stream(Box::new(stream), "aes-256-cfb", "secret").unwrap();
            let target = read_target(&mut *stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ssr-cfb-256").unwrap();
            stream.flush().unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ssr-cfb-256".into(),
            selected_path: vec!["edge-ssr-cfb-256".into()],
            leaf_name: "edge-ssr-cfb-256".into(),
            hops: vec![TransportHop {
                name: "edge-ssr-cfb-256".into(),
                action: TransportAction::SsrConnect {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    password: "secret".into(),
                    cipher: "aes-256-cfb".into(),
                    obfs: "plain".into(),
                    obfs_param: String::new(),
                    protocol: "origin".into(),
                    protocol_param: String::new(),
                    udp: true,
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
        assert_eq!(reply, b"pong-ssr-cfb-256");
        worker.join().unwrap();
    }

    #[test]
    fn ssr_tcp_stream_round_trip_preserves_target_and_payload_with_aes_192_cfb() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = wrap_accepted_stream(Box::new(stream), "aes-192-cfb", "secret").unwrap();
            let target = read_target(&mut *stream);
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ssr-cfb-192").unwrap();
            stream.flush().unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ssr-cfb-192".into(),
            selected_path: vec!["edge-ssr-cfb-192".into()],
            leaf_name: "edge-ssr-cfb-192".into(),
            hops: vec![TransportHop {
                name: "edge-ssr-cfb-192".into(),
                action: TransportAction::SsrConnect {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    password: "secret".into(),
                    cipher: "aes-192-cfb".into(),
                    obfs: "plain".into(),
                    obfs_param: String::new(),
                    protocol: "origin".into(),
                    protocol_param: String::new(),
                    udp: true,
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
        assert_eq!(reply, b"pong-ssr-cfb-192");
        worker.join().unwrap();
    }

    #[test]
    fn ssr_udp_packet_round_trip_preserves_target_and_payload_with_aes_256_cfb() {
        let destination: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let packet = encode_udp_packet("aes-256-cfb", "secret", destination, b"via-ssr-cfb-256").unwrap();
        let (decoded_destination, payload) =
            decode_udp_packet("aes-256-cfb", "secret", &packet).unwrap();
        assert_eq!(decoded_destination, destination);
        assert_eq!(payload, b"via-ssr-cfb-256");
    }

    #[test]
    fn ssr_udp_packet_round_trip_preserves_target_and_payload_with_aes_192_cfb() {
        let destination: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let packet = encode_udp_packet("aes-192-cfb", "secret", destination, b"via-ssr-cfb-192").unwrap();
        let (decoded_destination, payload) =
            decode_udp_packet("aes-192-cfb", "secret", &packet).unwrap();
        assert_eq!(decoded_destination, destination);
        assert_eq!(payload, b"via-ssr-cfb-192");
    }

    #[test]
    fn ssr_udp_packet_supports_fqdn_targets() {
        let mut packet = vec![0x03, 0x09];
        packet.extend_from_slice(b"localhost");
        packet.extend_from_slice(&5353_u16.to_be_bytes());
        packet.extend_from_slice(b"via-domain");
        let (decoded_destination, payload) = decode_udp_packet("dummy", "secret", &packet).unwrap();
        assert_eq!(decoded_destination.port(), 5353);
        assert!(decoded_destination.ip().is_loopback());
        assert_eq!(payload, b"via-domain");
    }

    #[test]
    fn ssr_rejects_unsupported_cipher() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = Box::new(std::net::TcpStream::connect(addr).unwrap());
        let result = wrap_stream(
            stream,
            &TransportTarget::new("127.0.0.1", addr.port()),
            "aes-128-gcm",
            "secret",
            "plain",
            "",
            "origin",
            "",
            &TransportTarget::new("example.com", 443),
        );
        let err = match result {
            Ok(_) => panic!("expected unsupported cipher error"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("cipher=aes-128-gcm"));
    }

    fn read_target(stream: &mut dyn Read) -> String {
        let mut atyp = [0_u8; 1];
        stream.read_exact(&mut atyp).unwrap();
        let host = match atyp[0] {
            0x01 => {
                let mut addr = [0_u8; 4];
                stream.read_exact(&mut addr).unwrap();
                std::net::Ipv4Addr::from(addr).to_string()
            }
            0x04 => {
                let mut addr = [0_u8; 16];
                stream.read_exact(&mut addr).unwrap();
                std::net::Ipv6Addr::from(addr).to_string()
            }
            0x03 => {
                let mut len = [0_u8; 1];
                stream.read_exact(&mut len).unwrap();
                let mut host = vec![0_u8; len[0] as usize];
                stream.read_exact(&mut host).unwrap();
                String::from_utf8(host).unwrap()
            }
            other => panic!("unexpected ssr atyp {other}"),
        };
        let mut port = [0_u8; 2];
        stream.read_exact(&mut port).unwrap();
        format!("{host}:{}", u16::from_be_bytes(port))
    }
}
