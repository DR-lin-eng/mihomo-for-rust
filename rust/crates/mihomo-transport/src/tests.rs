    use std::any::Any;
    use std::collections::{BTreeMap, VecDeque};
    use std::io::{self, Cursor, Read, Write};
    use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
    use std::sync::{Arc, Mutex};
    use std::thread;

    use base64::Engine as _;
    use rcgen::{generate_simple_self_signed, KeyPair};
    use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection, StreamOwned};
    use sha1::{Digest as Sha1Digest, Sha1};
    use sha2::{Sha224, Sha256};
    use smoltcp::wire::{
        IpAddress as SmolIpAddress, IpProtocol as SmolIpProtocol,
        Ipv4Address as SmolIpv4Address, Ipv4Packet as SmolIpv4Packet,
        Ipv4Repr as SmolIpv4Repr, TcpControl as SmolTcpControl,
        TcpPacket as SmolTcpPacket, TcpRepr as SmolTcpRepr,
        TcpSeqNumber as SmolTcpSeqNumber,
    };
    use tokio_wireguard::{
        config::{Config as WgConfig, Interface as WgInterface, Peer as WgPeer},
        x25519, TcpListener as WgTcpListener, UdpSocket as WgUdpSocket,
    };
    use uuid::Uuid;

    use super::{
        accept_grpc_test_stream, accept_h2_test_stream, accept_h2_tls_test_stream,
        accept_shadowsocks_test_stream, accept_simple_obfs_http_test_stream,
        accept_sudoku_test_stream,
        accept_smux_test_stream, accept_v2ray_plugin_mux_test_stream,
        accept_vmess_test_stream, decode_shadowsocks_udp_packet,
        encode_shadowsocks_udp_packet, encode_shadowsocks_udp_packet_for_target,
        open_masque_udp_stream,
        open_anytls_udp_stream, open_gost_relay_udp_stream,
        open_trojan_udp_stream, prepend_bytes, read_anytls_udp_packet,
        register_test_root_certificate,
        read_masque_udp_packet,
        read_gost_relay_udp_packet, read_snell_udp_packet, read_trojan_udp_packet, shadowsocks,
        snell, wrap_grpc_tls_proxy_stream, wrap_tls_proxy_stream, write_anytls_udp_packet, write_gost_relay_udp_packet,
        write_masque_udp_packet,
        write_snell_udp_packet, write_trojan_udp_packet, BasicAuth, RecordingTransportRunner,
        MasqueConnectOptions, SocketOptions, SystemTcpDialer, TcpDialPurpose, TcpDialer, TcpTransportExecutor,
        TlsOptions, TransportAction, TransportFamily, TransportHop, TransportPlan,
        TransportPlanRunner, TransportTarget, TrojanShadowsocksOptions, wrap_smux_stream,
        SudokuAcceptedTestStream,
        VmessAcceptedTestStream, SUPPORTED_TRANSPORTS,
        WebsocketOptions,
    };
    use crate::{
        accept_simple_obfs_tls_test_stream, simple_obfs, GrpcOptions, Http2Options,
        HttpStreamOptions, XHttpOptions, vision,
    };
    use mihomo_core::{BoxedTcpStream, Metadata, TcpStream as _};

    fn assert_loopback_5353(target: std::net::SocketAddr) {
        assert_eq!(target.port(), 5353);
        assert!(target.ip().is_loopback(), "expected loopback target, got {target}");
    }

    #[derive(Default)]
    struct ScriptedState {
        reader: Cursor<Vec<u8>>,
        writes: Vec<u8>,
    }

    #[derive(Clone)]
    struct ScriptedStreamHandle(Arc<Mutex<ScriptedState>>);

    impl ScriptedStreamHandle {
        fn new(readable: Vec<u8>) -> Self {
            Self(Arc::new(Mutex::new(ScriptedState {
                reader: Cursor::new(readable),
                writes: Vec::new(),
            })))
        }

        fn stream(&self) -> ScriptedStream {
            ScriptedStream(Arc::clone(&self.0))
        }

        fn writes(&self) -> Vec<u8> {
            self.0.lock().unwrap().writes.clone()
        }
    }

    struct ScriptedStream(Arc<Mutex<ScriptedState>>);

    impl Read for ScriptedStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.lock().unwrap().reader.read(buf)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().writes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl mihomo_core::TcpStream for ScriptedStream {
        fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
            Ok(Box::new(ScriptedStream(Arc::clone(&self.0))))
        }
    }

    struct ServerWebsocketStream {
        inner: BoxedTcpStream,
        pending: Vec<u8>,
        offset: usize,
    }

    struct TestRustlsServerStream(StreamOwned<ServerConnection, std::net::TcpStream>);

    impl ServerWebsocketStream {
        fn new(inner: BoxedTcpStream) -> Self {
            Self {
                inner,
                pending: Vec::new(),
                offset: 0,
            }
        }

        fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
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

        fn write_frame(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
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
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.write_frame(0x2, buf)?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    impl mihomo_core::TcpStream for ServerWebsocketStream {
        fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
            Ok(Box::new(Self::new(self.inner.try_clone_box()?)))
        }

        fn shutdown_write(&mut self) -> io::Result<()> {
            self.inner.shutdown_write()
        }

        fn shutdown_all(&mut self) -> io::Result<()> {
            self.inner.shutdown_all()
        }
    }

    impl Read for TestRustlsServerStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for TestRustlsServerStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    impl mihomo_core::TcpStream for TestRustlsServerStream {
        fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "test rustls server stream does not support cloning",
            ))
        }

        fn shutdown_write(&mut self) -> io::Result<()> {
            self.0.sock.shutdown(std::net::Shutdown::Write)
        }

        fn shutdown_all(&mut self) -> io::Result<()> {
            self.0.sock.shutdown(std::net::Shutdown::Both)
        }
    }

    struct FakeDialer {
        expected: VecDeque<(String, ScriptedStreamHandle)>,
        calls: Vec<String>,
    }

    impl FakeDialer {
        fn new() -> Self {
            Self {
                expected: VecDeque::new(),
                calls: Vec::new(),
            }
        }

        fn push_connection(
            &mut self,
            authority: impl Into<String>,
            readable: Vec<u8>,
        ) -> ScriptedStreamHandle {
            let handle = ScriptedStreamHandle::new(readable);
            self.expected
                .push_back((authority.into(), handle.clone()));
            handle
        }
    }

    impl TcpDialer for FakeDialer {
        fn connect(
            &mut self,
            target: &TransportTarget,
            _socket: &SocketOptions,
            _purpose: TcpDialPurpose,
        ) -> Result<mihomo_core::BoxedTcpStream, super::TransportError> {
            self.calls.push(target.authority());
            let Some((expected, handle)) = self.expected.pop_front() else {
                return Err(super::TransportError::InvalidPlan(
                    "unexpected dial attempt".to_owned(),
                ));
            };
            if expected != target.authority() {
                return Err(super::TransportError::InvalidPlan(format!(
                    "expected dial {expected} but got {}",
                    target.authority()
                )));
            }
            Ok(Box::new(handle.stream()))
        }
    }

    struct TestStunServer {
        addr: std::net::SocketAddr,
        shutdown_tx: std::sync::mpsc::Sender<()>,
        thread: Option<thread::JoinHandle<()>>,
    }

    struct MasqueTestTcpSession {
        client_ip: Ipv4Addr,
        client_port: u16,
        server_ip: Ipv4Addr,
        server_port: u16,
        server_seq: u32,
        next_ack: u32,
        syn_acked: bool,
        pong_sent: bool,
    }

    impl TestStunServer {
        fn start() -> Self {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let addr = socket.local_addr().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_millis(100)))
                .unwrap();
            let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
            let thread = thread::spawn(move || {
                let mut socket = socket;
                let mut buf = [0_u8; 1500];
                loop {
                    if shutdown_rx.try_recv().is_ok() {
                        break;
                    }
                    match socket.recv_from(&mut buf) {
                        Ok((read, from)) => {
                            if read < 20 {
                                continue;
                            }
                            let txid = &buf[8..20];
                            let mut response = vec![0_u8; 32];
                            response[0..2].copy_from_slice(&0x0101_u16.to_be_bytes());
                            response[2..4].copy_from_slice(&12_u16.to_be_bytes());
                            response[4..8].copy_from_slice(&0x2112_A442_u32.to_be_bytes());
                            response[8..20].copy_from_slice(txid);
                            response[20..22].copy_from_slice(&0x0020_u16.to_be_bytes());
                            response[22..24].copy_from_slice(&8_u16.to_be_bytes());
                            response[24] = 0;
                            response[25] = 0x01;
                            let port = from.port() ^ 0x2112;
                            response[26..28].copy_from_slice(&port.to_be_bytes());
                            if let std::net::IpAddr::V4(ip) = from.ip() {
                                let cookie = 0x2112_A442_u32.to_be_bytes();
                                let octets = ip.octets();
                                response[28] = octets[0] ^ cookie[0];
                                response[29] = octets[1] ^ cookie[1];
                                response[30] = octets[2] ^ cookie[2];
                                response[31] = octets[3] ^ cookie[3];
                                let _ = socket.send_to(&response, from);
                            }
                        }
                        Err(err)
                            if matches!(
                                err.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) => {}
                        Err(_) => break,
                    }
                }
            });
            Self {
                addr,
                shutdown_tx,
                thread: Some(thread),
            }
        }

        fn shutdown(mut self) {
            let _ = self.shutdown_tx.send(());
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct ParsedGostRelayRequest {
        command: u8,
        username: Option<String>,
        password: Option<String>,
        target: Option<TransportTarget>,
        network: u16,
    }

    fn parse_gost_relay_request(frame: &[u8]) -> ParsedGostRelayRequest {
        assert!(frame.len() >= 4);
        assert_eq!(frame[0], 0x01);
        let command = frame[1];
        let feature_len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
        assert_eq!(frame.len(), feature_len + 4);

        let mut offset = 4;
        let mut username = None;
        let mut password = None;
        let mut target = None;
        let mut network = u16::MAX;
        while offset < frame.len() {
            let feature_type = frame[offset];
            let payload_len = u16::from_be_bytes([frame[offset + 1], frame[offset + 2]]) as usize;
            offset += 3;
            let payload = &frame[offset..offset + payload_len];
            offset += payload_len;

            match feature_type {
                0x01 => {
                    let user_len = payload[0] as usize;
                    let user_end = 1 + user_len;
                    username = Some(String::from_utf8(payload[1..user_end].to_vec()).unwrap());
                    let pass_len = payload[user_end] as usize;
                    let pass_start = user_end + 1;
                    password = Some(
                        String::from_utf8(payload[pass_start..pass_start + pass_len].to_vec())
                            .unwrap(),
                    );
                }
                0x02 => {
                    let atyp = payload[0];
                    let mut payload_offset = 1;
                    let host = match atyp {
                        0x01 => {
                            let ip = std::net::Ipv4Addr::new(
                                payload[payload_offset],
                                payload[payload_offset + 1],
                                payload[payload_offset + 2],
                                payload[payload_offset + 3],
                            );
                            payload_offset += 4;
                            ip.to_string()
                        }
                        0x04 => {
                            let mut octets = [0_u8; 16];
                            octets.copy_from_slice(&payload[payload_offset..payload_offset + 16]);
                            payload_offset += 16;
                            std::net::Ipv6Addr::from(octets).to_string()
                        }
                        0x03 => {
                            let len = payload[payload_offset] as usize;
                            payload_offset += 1;
                            let host = String::from_utf8(
                                payload[payload_offset..payload_offset + len].to_vec(),
                            )
                            .unwrap();
                            payload_offset += len;
                            host
                        }
                        other => panic!("unexpected gost relay atyp {other}"),
                    };
                    let port = u16::from_be_bytes([
                        payload[payload_offset],
                        payload[payload_offset + 1],
                    ]);
                    target = Some(TransportTarget::new(host, port));
                }
                0x04 => {
                    network = u16::from_be_bytes([payload[0], payload[1]]);
                }
                other => panic!("unexpected gost relay feature {other}"),
            }
        }

        ParsedGostRelayRequest {
            command,
            username,
            password,
            target,
            network,
        }
    }

    fn read_gost_relay_request_frame(stream: &mut dyn Read) -> Vec<u8> {
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).unwrap();
        let feature_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        let mut frame = header.to_vec();
        let mut features = vec![0_u8; feature_len];
        stream.read_exact(&mut features).unwrap();
        frame.extend_from_slice(&features);
        frame
    }

    fn read_shadowsocks_target(stream: &mut dyn Read) -> TransportTarget {
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
            other => panic!("unexpected shadowsocks atyp {other}"),
        };
        let mut port = [0_u8; 2];
        stream.read_exact(&mut port).unwrap();
        TransportTarget::new(host, u16::from_be_bytes(port))
    }

    fn read_snell_target(stream: &mut dyn Read, expected_version: u8) -> TransportTarget {
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(header[0], 1);
        assert_eq!(
            header[1],
            if expected_version == 2 { 5 } else { 1 }
        );
        assert_eq!(header[2], 0);
        let host_len = header[3] as usize;
        let mut host = vec![0_u8; host_len];
        stream.read_exact(&mut host).unwrap();
        let mut port = [0_u8; 2];
        stream.read_exact(&mut port).unwrap();
        TransportTarget::new(String::from_utf8(host).unwrap(), u16::from_be_bytes(port))
    }

    fn read_trojan_request(stream: &mut dyn Read) -> (String, u8, TransportTarget) {
        let mut password = [0_u8; 56];
        stream.read_exact(&mut password).unwrap();
        let mut crlf = [0_u8; 2];
        stream.read_exact(&mut crlf).unwrap();
        assert_eq!(&crlf, b"\r\n");
        let mut command = [0_u8; 1];
        stream.read_exact(&mut command).unwrap();
        let target = read_shadowsocks_target(stream);
        stream.read_exact(&mut crlf).unwrap();
        assert_eq!(&crlf, b"\r\n");
        (
            String::from_utf8(password.to_vec()).unwrap(),
            command[0],
            target,
        )
    }


    fn read_http_headers(stream: &mut dyn Read) -> String {
        read_http_headers_with_tail(stream).0
    }

    fn read_http_headers_with_tail(stream: &mut dyn Read) -> (String, Vec<u8>) {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read != 0, "http headers ended before terminator");
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                let header_end = position + 4;
                let request = String::from_utf8(buffer[..header_end].to_vec()).unwrap();
                let tail = buffer[header_end..].to_vec();
                return (request, tail);
            }
        }
    }

    fn send_http_response(stream: &mut dyn Write, status: &str, body: &[u8]) {
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        if !body.is_empty() {
            stream.write_all(body).unwrap();
        }
        stream.flush().unwrap();
    }

    fn websocket_accept_key(key: &str) -> String {
        let mut sha1 = Sha1::new();
        sha1.update(key.as_bytes());
        sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        base64::engine::general_purpose::STANDARD.encode(sha1.finalize())
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

    fn build_tls_server_config_with_pem() -> (Arc<ServerConfig>, String) {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let cert_pem = cert.cert.pem();
        let key_der = cert.key_pair.serialize_der();
        (
            Arc::new(
                ServerConfig::builder()
                    .with_safe_defaults()
                    .with_no_client_auth()
                    .with_single_cert(vec![Certificate(cert_der)], PrivateKey(key_der))
                    .unwrap(),
            ),
            cert_pem,
        )
    }

    fn build_tls_server_config_with_pem_and_public_key() -> (Arc<ServerConfig>, String, String) {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let cert_pem = cert.cert.pem();
        let public_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(cert.key_pair.public_key_der());
        let key_der = cert.key_pair.serialize_der();
        (
            Arc::new(
                ServerConfig::builder()
                    .with_safe_defaults()
                    .with_no_client_auth()
                    .with_single_cert(vec![Certificate(cert_der)], PrivateKey(key_der))
                    .unwrap(),
            ),
            cert_pem,
            public_key_b64,
        )
    }

    fn build_tls_server_config() -> Arc<ServerConfig> {
        build_tls_server_config_with_pem().0
    }

    fn build_tls_server_config_with_fingerprint() -> (Arc<ServerConfig>, String) {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();
        let fingerprint = hex::encode(Sha256::digest(&cert_der));
        (
            Arc::new(
                ServerConfig::builder()
                    .with_safe_defaults()
                    .with_no_client_auth()
                    .with_single_cert(vec![Certificate(cert_der)], PrivateKey(key_der))
                    .unwrap(),
            ),
            fingerprint,
        )
    }

    fn build_masque_key_material() -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let private_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(key.serialize_der());
        let public_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(key.public_key_der());
        (private_key_b64, public_key_b64)
    }

    struct TransportWireGuardServer {
        addr: SocketAddr,
        client_private_key: String,
        server_public_key: String,
        shutdown_tx: tokio::sync::oneshot::Sender<()>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl TransportWireGuardServer {
        fn start() -> Self {
            let (server_private, server_public) = x25519::keypair();
            let (client_private, client_public) = x25519::keypair();
            let endpoint_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let endpoint_addr = endpoint_socket.local_addr().unwrap();
            drop(endpoint_socket);
            let (tx, rx) = std::sync::mpsc::channel();
            let thread = thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let server_config = WgConfig {
                        interface: WgInterface {
                            address: "100.64.0.1/32".parse().unwrap(),
                            private_key: server_private,
                            listen_port: Some(endpoint_addr.port()),
                            mtu: Some(1380),
                        },
                        peers: vec![WgPeer {
                            endpoint: None,
                            allowed_ips: vec!["100.64.0.0/24".parse().unwrap()],
                            public_key: client_public,
                            persistent_keepalive: Some(15),
                        }],
                    };

                    let tcp_listener = WgTcpListener::bind("100.64.0.1:8080", server_config)
                        .await
                        .unwrap();
                    let udp_socket =
                        WgUdpSocket::bind("100.64.0.1:5353", tcp_listener.interface().clone())
                            .await
                            .unwrap();

                    let client_private_key = base64::engine::general_purpose::STANDARD
                        .encode(client_private.to_bytes());
                    let server_public_key = base64::engine::general_purpose::STANDARD
                        .encode(server_public.to_bytes());
                    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
                    tx.send((endpoint_addr, client_private_key, server_public_key, shutdown_tx))
                        .unwrap();
                    loop {
                        tokio::select! {
                            _ = &mut shutdown_rx => break,
                            accept = tcp_listener.accept() => {
                                let Ok((mut stream, _peer)) = accept else { break };
                                tokio::spawn(async move {
                                    let mut payload = [0_u8; 4];
                                    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
                                        .await
                                        .unwrap();
                                    assert_eq!(&payload, b"ping");
                                    tokio::io::AsyncWriteExt::write_all(&mut stream, b"pong-wireguard")
                                        .await
                                        .unwrap();
                                    tokio::io::AsyncWriteExt::shutdown(&mut stream).await.unwrap();
                                });
                            }
                            recv = async {
                                let mut buf = Vec::with_capacity(2048);
                                udp_socket.recv_from(&mut buf).await.map(|(read, peer)| (buf, read, peer))
                            } => {
                                let Ok((buf, read, peer)) = recv else { break };
                                if &buf[..read] == b"via-wireguard" {
                                    udp_socket.send_to(b"wireguard-ok", peer).await.unwrap();
                                    continue;
                                }
                                let query_id = u16::from_be_bytes([buf[0], buf[1]]);
                                let query =
                                    mihomo_dns::build_dns_query_for_tests("edge.example.com", mihomo_dns::DnsRecordType::A, query_id)
                                        .unwrap();
                                assert_eq!(&buf[..read], query);
                                let mut response = Vec::new();
                                response.extend_from_slice(&query_id.to_be_bytes());
                                response.extend_from_slice(&0x8180_u16.to_be_bytes());
                                response.extend_from_slice(&1_u16.to_be_bytes());
                                response.extend_from_slice(&1_u16.to_be_bytes());
                                response.extend_from_slice(&0_u16.to_be_bytes());
                                response.extend_from_slice(&0_u16.to_be_bytes());
                                response.extend_from_slice(&buf[12..read]);
                                response.extend_from_slice(&0xC00C_u16.to_be_bytes());
                                response.extend_from_slice(&1_u16.to_be_bytes());
                                response.extend_from_slice(&1_u16.to_be_bytes());
                                response.extend_from_slice(&60_u32.to_be_bytes());
                                response.extend_from_slice(&4_u16.to_be_bytes());
                                response.extend_from_slice(&[100, 64, 0, 1]);
                                udp_socket.send_to(&response, peer).await.unwrap();
                            }
                        }
                    }
                });
            });
            let (addr, client_private_key, server_public_key, shutdown_tx) = rx.recv().unwrap();
            Self {
                addr,
                client_private_key,
                server_public_key,
                shutdown_tx,
                thread: Some(thread),
            }
        }

        fn shutdown(mut self) {
            let _ = self.shutdown_tx.send(());
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    fn encode_h2_varint(value: u64, dst: &mut Vec<u8>) {
        match value {
            0..=63 => dst.push(value as u8),
            64..=16383 => {
                let encoded = 0x4000 | value as u16;
                dst.extend_from_slice(&encoded.to_be_bytes());
            }
            16384..=1_073_741_823 => {
                let encoded = 0x8000_0000 | value as u32;
                dst.extend_from_slice(&encoded.to_be_bytes());
            }
            _ => {
                let encoded = 0xC000_0000_0000_0000 | value;
                dst.extend_from_slice(&encoded.to_be_bytes());
            }
        }
    }

    fn decode_h2_varint(stream: &mut dyn Read) -> u64 {
        let mut first = [0_u8; 1];
        stream.read_exact(&mut first).unwrap();
        match first[0] >> 6 {
            0 => (first[0] & 0x3f) as u64,
            1 => {
                let mut rest = [0_u8; 1];
                stream.read_exact(&mut rest).unwrap();
                u16::from_be_bytes([first[0], rest[0]]) as u64 & 0x3fff
            }
            2 => {
                let mut rest = [0_u8; 3];
                stream.read_exact(&mut rest).unwrap();
                u32::from_be_bytes([first[0], rest[0], rest[1], rest[2]]) as u64 & 0x3fff_ffff
            }
            _ => {
                let mut rest = [0_u8; 7];
                stream.read_exact(&mut rest).unwrap();
                u64::from_be_bytes([
                    first[0], rest[0], rest[1], rest[2], rest[3], rest[4], rest[5], rest[6],
                ]) & 0x3fff_ffff_ffff_ffff
            }
        }
    }

    fn read_h2_capsule(stream: &mut dyn Read) -> (u64, Vec<u8>) {
        let capsule_type = decode_h2_varint(stream);
        let payload_len = decode_h2_varint(stream) as usize;
        let mut payload = vec![0_u8; payload_len];
        stream.read_exact(&mut payload).unwrap();
        (capsule_type, payload)
    }

    fn write_h2_capsule(stream: &mut dyn Write, capsule_type: u64, payload: &[u8]) {
        let mut frame = Vec::new();
        encode_h2_varint(capsule_type, &mut frame);
        encode_h2_varint(payload.len() as u64, &mut frame);
        frame.extend_from_slice(payload);
        stream.write_all(&frame).unwrap();
        stream.flush().unwrap();
    }

    fn build_masque_test_tcp_packet(
        session: &MasqueTestTcpSession,
        control: SmolTcpControl,
        ack_number: Option<u32>,
        seq_number: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let src_ip = SmolIpv4Address::from(session.server_ip);
        let dst_ip = SmolIpv4Address::from(session.client_ip);
        let ip_repr = SmolIpv4Repr {
            src_addr: src_ip,
            dst_addr: dst_ip,
            next_header: SmolIpProtocol::Tcp,
            payload_len: 20 + payload.len(),
            hop_limit: 64,
        };
        let tcp_repr = SmolTcpRepr {
            src_port: session.server_port,
            dst_port: session.client_port,
            control,
            seq_number: SmolTcpSeqNumber(seq_number as i32),
            ack_number: ack_number.map(|value| SmolTcpSeqNumber(value as i32)),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload,
        };
        let mut bytes = vec![0_u8; ip_repr.buffer_len() + tcp_repr.buffer_len()];
        {
            let mut ipv4_packet = SmolIpv4Packet::new_unchecked(&mut bytes);
            ip_repr.emit(
                &mut ipv4_packet,
                &smoltcp::phy::ChecksumCapabilities::default(),
            );
        }
        {
            let mut tcp_packet =
                SmolTcpPacket::new_unchecked(&mut bytes[ip_repr.buffer_len()..]);
            tcp_repr.emit(
                &mut tcp_packet,
                &SmolIpAddress::Ipv4(src_ip),
                &SmolIpAddress::Ipv4(dst_ip),
                &smoltcp::phy::ChecksumCapabilities::default(),
            );
        }
        bytes
    }

    fn read_anytls_auth_prelude(stream: &mut dyn Read) -> (Vec<u8>, u16) {
        let mut password = vec![0_u8; 32];
        stream.read_exact(&mut password).unwrap();
        let mut padding_len = [0_u8; 2];
        stream.read_exact(&mut padding_len).unwrap();
        let padding_len = u16::from_be_bytes(padding_len);
        if padding_len > 0 {
            let mut padding = vec![0_u8; padding_len as usize];
            stream.read_exact(&mut padding).unwrap();
        }
        (password, padding_len)
    }

    fn read_anytls_frame(stream: &mut dyn Read) -> (u8, u32, Vec<u8>) {
        let mut header = [0_u8; 7];
        stream.read_exact(&mut header).unwrap();
        let command = header[0];
        let stream_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let length = u16::from_be_bytes([header[5], header[6]]) as usize;
        let mut payload = vec![0_u8; length];
        stream.read_exact(&mut payload).unwrap();
        (command, stream_id, payload)
    }

    fn write_anytls_frame(stream: &mut dyn Write, command: u8, stream_id: u32, payload: &[u8]) {
        stream.write_all(&[command]).unwrap();
        stream.write_all(&stream_id.to_be_bytes()).unwrap();
        stream
            .write_all(&(payload.len() as u16).to_be_bytes())
            .unwrap();
        stream.write_all(payload).unwrap();
    }

    fn read_anytls_uot_request(payload: &[u8]) -> (bool, std::net::SocketAddr) {
        let mut cursor = io::Cursor::new(payload);
        let mut is_connect = [0_u8; 1];
        cursor.read_exact(&mut is_connect).unwrap();
        let mut atyp = [0_u8; 1];
        cursor.read_exact(&mut atyp).unwrap();
        let target = match atyp[0] {
            0x00 => {
                let mut octets = [0_u8; 4];
                cursor.read_exact(&mut octets).unwrap();
                let mut port = [0_u8; 2];
                cursor.read_exact(&mut port).unwrap();
                std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
                    u16::from_be_bytes(port),
                )
            }
            0x01 => {
                let mut octets = [0_u8; 16];
                cursor.read_exact(&mut octets).unwrap();
                let mut port = [0_u8; 2];
                cursor.read_exact(&mut port).unwrap();
                std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                    u16::from_be_bytes(port),
                )
            }
            0x02 => {
                let mut len = [0_u8; 1];
                cursor.read_exact(&mut len).unwrap();
                let mut host = vec![0_u8; len[0] as usize];
                cursor.read_exact(&mut host).unwrap();
                let mut port = [0_u8; 2];
                cursor.read_exact(&mut port).unwrap();
                let host = String::from_utf8_lossy(&host).into_owned();
                (host.as_str(), u16::from_be_bytes(port))
                    .to_socket_addrs()
                    .unwrap()
                    .next()
                    .unwrap()
            }
            other => panic!("unexpected anytls uot atyp {other}"),
        };
        (is_connect[0] != 0, target)
    }

    fn read_anytls_uot_packet(payload: &[u8]) -> (std::net::SocketAddr, Vec<u8>) {
        let mut cursor = io::Cursor::new(payload);
        let mut atyp = [0_u8; 1];
        cursor.read_exact(&mut atyp).unwrap();
        let target = match atyp[0] {
            0x00 => {
                let mut octets = [0_u8; 4];
                cursor.read_exact(&mut octets).unwrap();
                let mut port = [0_u8; 2];
                cursor.read_exact(&mut port).unwrap();
                std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
                    u16::from_be_bytes(port),
                )
            }
            0x01 => {
                let mut octets = [0_u8; 16];
                cursor.read_exact(&mut octets).unwrap();
                let mut port = [0_u8; 2];
                cursor.read_exact(&mut port).unwrap();
                std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                    u16::from_be_bytes(port),
                )
            }
            0x02 => {
                let mut len = [0_u8; 1];
                cursor.read_exact(&mut len).unwrap();
                let mut host = vec![0_u8; len[0] as usize];
                cursor.read_exact(&mut host).unwrap();
                let mut port = [0_u8; 2];
                cursor.read_exact(&mut port).unwrap();
                let host = String::from_utf8_lossy(&host).into_owned();
                (host.as_str(), u16::from_be_bytes(port))
                    .to_socket_addrs()
                    .unwrap()
                    .next()
                    .unwrap()
            }
            other => panic!("unexpected anytls uot packet atyp {other}"),
        };
        let mut length = [0_u8; 2];
        cursor.read_exact(&mut length).unwrap();
        let length = u16::from_be_bytes(length) as usize;
        let mut packet = vec![0_u8; length];
        cursor.read_exact(&mut packet).unwrap();
        (target, packet)
    }

    #[test]
    fn inventory_tracks_transport_dirs() {
        assert!(SUPPORTED_TRANSPORTS.len() >= 20);
        assert!(SUPPORTED_TRANSPORTS.contains(&TransportFamily::Sudoku));
        assert!(SUPPORTED_TRANSPORTS.contains(&TransportFamily::TrustTunnel));
        assert!(SUPPORTED_TRANSPORTS.contains(&TransportFamily::XHttp));
        assert!(SUPPORTED_TRANSPORTS.contains(&TransportFamily::ShadowSocks));
    }

    #[test]
    fn target_from_metadata_prefers_host_when_available() {
        let metadata = Metadata {
            host: Some("example.com".into()),
            dst_port: Some(443),
            ..Metadata::default()
        };
        let target = TransportTarget::from_metadata(&metadata).unwrap();
        assert_eq!(target.authority(), "example.com:443");
    }

    #[test]
    fn recording_runner_keeps_hop_order_and_summary() {
        let plan = TransportPlan {
            requested: "proxy".into(),
            selected_path: vec!["proxy".into()],
            leaf_name: "proxy".into(),
            hops: vec![
                TransportHop {
                    name: "outer".into(),
                    action: TransportAction::Direct {
                        socket: SocketOptions::default(),
                        target: TransportTarget::new("proxy.example", 443),
                    },
                },
                TransportHop {
                    name: "leaf".into(),
                    action: TransportAction::Direct {
                        socket: SocketOptions::default(),
                        target: TransportTarget::new("final.example", 8443),
                    },
                },
            ],
        };
        let mut runner = RecordingTransportRunner::default();
        let steps = runner.run_plan(&plan).unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].name, "outer");
        assert_eq!(steps[0].summary, "direct->proxy.example:443");
        assert_eq!(steps[1].summary, "direct->final.example:8443");
        assert_eq!(runner.steps(), steps.as_slice());
    }

    #[test]
    fn tcp_executor_runs_http_connect_handshake() {
        let mut dialer = FakeDialer::new();
        let handle = dialer.push_connection(
            "proxy.example.com:8080",
            b"HTTP/1.1 200 Connection Established\r\n\r\nserver-data".to_vec(),
        );
        let plan = TransportPlan {
            requested: "http-hop".into(),
            selected_path: vec!["http-hop".into()],
            leaf_name: "http-hop".into(),
            hops: vec![TransportHop {
                name: "http-hop".into(),
                action: TransportAction::HttpConnect {
                    proxy: TransportTarget::new("proxy.example.com", 8080),
                    auth: Some(BasicAuth {
                        username: "user".into(),
                        password: "pass".into(),
                    }),
                    tls: TlsOptions::default(),
                    headers: BTreeMap::from([("User-Agent".into(), "mihomo-rust".into())]),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(dialer);
        let mut stream = executor.run_plan(&plan).unwrap();

        let written = String::from_utf8(handle.writes()).unwrap();
        assert!(written.starts_with("CONNECT final.example.com:443 HTTP/1.1\r\n"));
        assert!(written.contains("Host: final.example.com:443\r\n"));
        assert!(written.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
        assert!(written.contains("User-Agent: mihomo-rust\r\n"));
        assert_eq!(executor.dialer().calls, vec!["proxy.example.com:8080"]);
        let mut remainder = Vec::new();
        stream.read_to_end(&mut remainder).unwrap();
        assert_eq!(remainder, b"server-data".to_vec());
    }

    #[test]
    fn tcp_executor_runs_http_connect_handshake_over_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let request = read_http_headers(&mut stream);
            assert!(request.starts_with("CONNECT final.example.com:443 HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nserver-data")
                .unwrap();
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "http-hop".into(),
            selected_path: vec!["http-hop".into()],
            leaf_name: "http-hop".into(),
            hops: vec![TransportHop {
                name: "http-hop".into(),
                action: TransportAction::HttpConnect {
                    proxy: TransportTarget::new("localhost", listen_addr.port()),
                    auth: None,
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    headers: BTreeMap::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        let mut remainder = Vec::new();
        stream.read_to_end(&mut remainder).unwrap();
        assert_eq!(remainder, b"server-data".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_socks5_auth_and_connect_handshake() {
        let mut dialer = FakeDialer::new();
        let handle = dialer.push_connection(
            "proxy.example.com:1080",
            vec![
                0x05, 0x02, // method selection
                0x01, 0x00, // auth success
                0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90, // connect reply
            ],
        );
        let plan = TransportPlan {
            requested: "socks-hop".into(),
            selected_path: vec!["socks-hop".into()],
            leaf_name: "socks-hop".into(),
            hops: vec![TransportHop {
                name: "socks-hop".into(),
                action: TransportAction::Socks5Connect {
                    proxy: TransportTarget::new("proxy.example.com", 1080),
                    auth: Some(BasicAuth {
                        username: "user".into(),
                        password: "pass".into(),
                    }),
                    tls: TlsOptions::default(),
                    udp: false,
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(dialer);
        executor.run_plan(&plan).unwrap();

        let writes = handle.writes();
        assert_eq!(&writes[0..4], &[0x05, 0x02, 0x00, 0x02]);
        assert_eq!(writes[4], 0x01);
        assert_eq!(writes[5], 4);
        assert_eq!(&writes[6..10], b"user");
        assert_eq!(writes[10], 4);
        assert_eq!(&writes[11..15], b"pass");
        assert_eq!(&writes[15..19], &[0x05, 0x01, 0x00, 0x03]);
        assert_eq!(writes[19] as usize, "example.com".len());
        assert_eq!(&writes[20..31], b"example.com");
        assert_eq!(&writes[31..33], &443_u16.to_be_bytes());
    }

    #[test]
    fn tcp_executor_runs_gost_relay_handshake() {
        let mut dialer = FakeDialer::new();
        let handle = dialer.push_connection("relay.example.com:8443", vec![0x01, 0x00, 0x00, 0x00]);
        let plan = TransportPlan {
            requested: "relay-hop".into(),
            selected_path: vec!["relay-hop".into()],
            leaf_name: "relay-hop".into(),
            hops: vec![TransportHop {
                name: "relay-hop".into(),
                action: TransportAction::GostRelay {
                    proxy: TransportTarget::new("relay.example.com", 8443),
                    auth: Some(BasicAuth {
                        username: "relay-user".into(),
                        password: "relay-pass".into(),
                    }),
                    forward: false,
                    tls: TlsOptions::default(),
                    mux: false,
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(dialer);
        executor.run_plan(&plan).unwrap();

        let request = parse_gost_relay_request(&handle.writes());
        assert_eq!(request.command, 0x01);
        assert_eq!(request.username.as_deref(), Some("relay-user"));
        assert_eq!(request.password.as_deref(), Some("relay-pass"));
        assert_eq!(
            request.target,
            Some(TransportTarget::new("final.example.com", 443))
        );
        assert_eq!(request.network, 0x0000);
        assert_eq!(executor.dialer().calls, vec!["relay.example.com:8443"]);
    }

    #[test]
    fn tcp_executor_runs_gost_relay_handshake_over_mux() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = accept_smux_test_stream(Box::new(stream)).unwrap();
            let request = parse_gost_relay_request(&read_gost_relay_request_frame(&mut *stream));
            assert_eq!(request.command, 0x01);
            assert_eq!(
                request.target,
                Some(TransportTarget::new("final.example.com", 443))
            );
            stream.write_all(&[0x01, 0x00, 0x00, 0x00]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "relay-hop-mux".into(),
            selected_path: vec!["relay-hop-mux".into()],
            leaf_name: "relay-hop-mux".into(),
            hops: vec![TransportHop {
                name: "relay-hop-mux".into(),
                action: TransportAction::GostRelay {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    auth: None,
                    forward: false,
                    tls: TlsOptions::default(),
                    mux: true,
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
        assert_eq!(reply, b"pong");
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_sudoku_websocket_http_mask_over_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tls_config, cert_pem) = build_tls_server_config_with_pem();
        register_test_root_certificate(&cert_pem).unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.contains("GET /mask/ws HTTP/1.1\r\n"));
            assert!(request.contains("Host: localhost:8443\r\n"));
            assert!(request.contains("X-Sudoku-Tunnel: ws\r\n"));
            assert!(request.contains("X-Sudoku-Version: 1\r\n"));
            let session = accept_sudoku_test_stream(
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
            let SudokuAcceptedTestStream::Tcp { target, mut stream } = session else {
                panic!("expected sudoku tcp session");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-sudoku-wss").unwrap();
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
                    http_mask_enabled: true,
                    http_mask_mode: "ws".into(),
                    http_mask_tls: true,
                    http_mask_host: "localhost:8443".into(),
                    path_root: "mask".into(),
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
        assert_eq!(reply, b"pong-sudoku-wss");
        worker.join().unwrap();
    }

    #[test]
    fn gost_relay_udp_stream_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = parse_gost_relay_request(&read_gost_relay_request_frame(&mut stream));
            assert_eq!(request.command, 0x81);
            assert_eq!(
                request.target,
                Some(TransportTarget::new("127.0.0.1", 5353))
            );
            assert_eq!(request.network, 0x0001);
            stream.write_all(&[0x01, 0x00, 0x00, 0x00]).unwrap();

            let payload = read_gost_relay_udp_packet(&mut stream).unwrap();
            assert_eq!(payload, b"udp-ping".to_vec());
            write_gost_relay_udp_packet(&mut stream, b"udp-pong").unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let auth = Some(BasicAuth {
            username: "user".into(),
            password: "pass".into(),
        });
        let mut stream = open_gost_relay_udp_stream(
            Box::new(stream),
            auth,
            false,
            "127.0.0.1:5353".parse().unwrap(),
        )
        .unwrap();
        write_gost_relay_udp_packet(&mut *stream, b"udp-ping").unwrap();
        let payload = read_gost_relay_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"udp-pong".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn gost_relay_udp_stream_round_trip_preserves_target_and_payload_over_mux() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = accept_smux_test_stream(Box::new(stream)).unwrap();
            let request = parse_gost_relay_request(&read_gost_relay_request_frame(&mut *stream));
            assert_eq!(request.command, 0x81);
            assert_eq!(
                request.target,
                Some(TransportTarget::new("127.0.0.1", 5353))
            );
            assert_eq!(request.network, 0x0001);
            stream.write_all(&[0x01, 0x00, 0x00, 0x00]).unwrap();

            let payload = read_gost_relay_udp_packet(&mut *stream).unwrap();
            assert_eq!(payload, b"udp-ping".to_vec());
            write_gost_relay_udp_packet(&mut *stream, b"udp-pong").unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let auth = Some(BasicAuth {
            username: "user".into(),
            password: "pass".into(),
        });
        let stream = wrap_smux_stream(Box::new(stream)).unwrap();
        let mut stream = open_gost_relay_udp_stream(
            stream,
            auth,
            false,
            "127.0.0.1:5353".parse().unwrap(),
        )
        .unwrap();
        write_gost_relay_udp_packet(&mut *stream, b"udp-ping").unwrap();
        let payload = read_gost_relay_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"udp-pong".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_shadowsocks_handshake_over_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream =
                shadowsocks::wrap_accepted_stream(Box::new(stream), "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target(&mut *stream);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss").unwrap();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ss".into(),
            selected_path: vec!["edge-ss".into()],
            leaf_name: "edge-ss".into(),
            hops: vec![TransportHop {
                name: "edge-ss".into(),
                action: TransportAction::ShadowsocksConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    cipher: "chacha20-ietf-poly1305".into(),
                    password: "secret".into(),
                    plugin: String::new(),
                    plugin_mode: String::new(),
                    plugin_host: String::new(),
                    websocket: WebsocketOptions::default(),
                    tls: TlsOptions::default(),
                    mux: false,
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
        assert_eq!(reply, b"pong-ss".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_anytls_handshake_over_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (password, padding_len) = read_anytls_auth_prelude(&mut stream);
            assert_eq!(padding_len, 0);
            assert_eq!(password, Sha256::digest(b"secret").to_vec());

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x04);
            assert_eq!(stream_id, 0);
            assert!(String::from_utf8(payload).unwrap().contains("v=2"));

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x01);
            assert_eq!(stream_id, 1);
            assert!(payload.is_empty());

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            let mut payload_reader = io::Cursor::new(payload);
            let target = read_shadowsocks_target(&mut payload_reader);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));

            write_anytls_frame(&mut stream, 0x0a, 0, b"v=2");
            write_anytls_frame(&mut stream, 0x07, 1, &[]);

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            assert_eq!(payload, b"ping".to_vec());

            write_anytls_frame(&mut stream, 0x02, 1, b"pong-anytls");
            write_anytls_frame(&mut stream, 0x03, 1, &[]);
            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x03);
            assert_eq!(stream_id, 1);
            assert!(payload.is_empty());
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-anytls".into(),
            selected_path: vec!["edge-anytls".into()],
            leaf_name: "edge-anytls".into(),
            hops: vec![TransportHop {
                name: "edge-anytls".into(),
                action: TransportAction::AnyTlsConnect {
                    proxy: TransportTarget::new("localhost", listen_addr.port()),
                    password: "secret".into(),
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into(), "http/1.1".into()],
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
        assert_eq!(reply, b"pong-anytls".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn anytls_udp_stream_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (password, padding_len) = read_anytls_auth_prelude(&mut stream);
            assert_eq!(padding_len, 0);
            assert_eq!(password, Sha256::digest(b"secret").to_vec());

            let (command, stream_id, _payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x04);
            assert_eq!(stream_id, 0);

            let (command, stream_id, _payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x01);
            assert_eq!(stream_id, 1);

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            let mut payload_reader = io::Cursor::new(payload);
            let target = read_shadowsocks_target(&mut payload_reader);
            assert_eq!(target, TransportTarget::new("sp.v2.udp-over-tcp.arpa", 0));

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            let (is_connect, destination) = read_anytls_uot_request(&payload);
            assert!(!is_connect);
            assert_eq!(destination, "127.0.0.1:5353".parse().unwrap());

            let (command, stream_id, payload) = read_anytls_frame(&mut stream);
            assert_eq!(command, 0x02);
            assert_eq!(stream_id, 1);
            let (target, packet) = read_anytls_uot_packet(&payload);
            assert_eq!(target, "127.0.0.1:5353".parse::<std::net::SocketAddr>().unwrap());
            assert_eq!(packet, b"udp-ping".to_vec());

            write_anytls_frame(&mut stream, 0x0a, 0, b"v=2");
            write_anytls_frame(&mut stream, 0x07, 1, &[]);
            let mut response = Vec::new();
            response.push(0x00);
            response.extend_from_slice(&[127, 0, 0, 1]);
            response.extend_from_slice(&5353_u16.to_be_bytes());
            response.extend_from_slice(&(8_u16).to_be_bytes());
            response.extend_from_slice(b"udp-pong");
            write_anytls_frame(&mut stream, 0x02, 1, &response);
            stream.flush().unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let stream = wrap_tls_proxy_stream(
            Box::new(stream),
            TransportTarget::new("localhost", listen_addr.port()),
            &TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &["h2".into(), "http/1.1".into()],
        )
        .unwrap();
        let mut stream = open_anytls_udp_stream(Box::new(stream), "secret", "127.0.0.1:5353".parse().unwrap()).unwrap();
        write_anytls_udp_packet(&mut *stream, "127.0.0.1:5353".parse().unwrap(), b"udp-ping").unwrap();
        let (target, payload) = read_anytls_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse::<std::net::SocketAddr>().unwrap());
        assert_eq!(payload, b"udp-pong".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn anytls_udp_packet_supports_fqdn_targets() {
        let mut packet = Vec::new();
        packet.push(0x02);
        packet.push(9);
        packet.extend_from_slice(b"localhost");
        packet.extend_from_slice(&5353_u16.to_be_bytes());
        packet.extend_from_slice(&4_u16.to_be_bytes());
        packet.extend_from_slice(b"dns!");

        let (target, payload) = read_anytls_udp_packet(&mut std::io::Cursor::new(packet)).unwrap();
        assert_loopback_5353(target);
        assert_eq!(payload, b"dns!");
    }

    #[test]
    fn tcp_executor_runs_shadowsocks_v2ray_plugin_over_websocket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /shadow HTTP/1.1\r\n"));
            assert!(request.contains("\r\nHost: ws.example.com\r\n"));
            assert!(request.contains("\r\nX-Proxy: enabled\r\n"));

            let mut stream =
                accept_shadowsocks_test_stream(stream, "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target(&mut *stream);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss-ws").unwrap();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ss".into(),
            selected_path: vec!["edge-ss".into()],
            leaf_name: "edge-ss".into(),
            hops: vec![TransportHop {
                name: "edge-ss".into(),
                action: TransportAction::ShadowsocksConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    cipher: "chacha20-ietf-poly1305".into(),
                    password: "secret".into(),
                    plugin: "v2ray-plugin".into(),
                    plugin_mode: "websocket".into(),
                    plugin_host: "ws.example.com".into(),
                    websocket: WebsocketOptions {
                        path: "/shadow".into(),
                        headers: BTreeMap::from([
                            ("Host".into(), "ws.example.com".into()),
                            ("X-Proxy".into(), "enabled".into()),
                        ]),
                        ..WebsocketOptions::default()
                    },
                    tls: TlsOptions::default(),
                    mux: false,
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
        assert_eq!(reply, b"pong-ss-ws".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_shadowsocks_gost_plugin_over_websocket_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /shadow-tls HTTP/1.1\r\n"));
            assert!(request.contains("\r\nHost: localhost\r\n"));

            let mut stream =
                accept_shadowsocks_test_stream(stream, "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target(&mut *stream);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss-wss").unwrap();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ss".into(),
            selected_path: vec!["edge-ss".into()],
            leaf_name: "edge-ss".into(),
            hops: vec![TransportHop {
                name: "edge-ss".into(),
                action: TransportAction::ShadowsocksConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    cipher: "chacha20-ietf-poly1305".into(),
                    password: "secret".into(),
                    plugin: "gost-plugin".into(),
                    plugin_mode: "websocket".into(),
                    plugin_host: "localhost".into(),
                    websocket: WebsocketOptions {
                        path: "/shadow-tls".into(),
                        headers: BTreeMap::from([("Host".into(), "localhost".into())]),
                        ..WebsocketOptions::default()
                    },
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    mux: false,
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
        assert_eq!(reply, b"pong-ss-wss".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_shadowsocks_obfs_http_over_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let stream = accept_simple_obfs_http_test_stream(Box::new(stream));
            let mut stream =
                accept_shadowsocks_test_stream(stream, "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target(&mut *stream);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss-obfs").unwrap();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ss".into(),
            selected_path: vec!["edge-ss".into()],
            leaf_name: "edge-ss".into(),
            hops: vec![TransportHop {
                name: "edge-ss".into(),
                action: TransportAction::ShadowsocksConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    cipher: "chacha20-ietf-poly1305".into(),
                    password: "secret".into(),
                    plugin: "obfs".into(),
                    plugin_mode: "http".into(),
                    plugin_host: "bing.com".into(),
                    websocket: WebsocketOptions::default(),
                    tls: TlsOptions::default(),
                    mux: false,
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
        assert_eq!(reply, b"pong-ss-obfs".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_shadowsocks_obfs_tls_over_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let stream = accept_simple_obfs_tls_test_stream(Box::new(stream));
            let mut stream =
                accept_shadowsocks_test_stream(stream, "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target(&mut *stream);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss-obfs-tls").unwrap();
            stream.flush().unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ss".into(),
            selected_path: vec!["edge-ss".into()],
            leaf_name: "edge-ss".into(),
            hops: vec![TransportHop {
                name: "edge-ss".into(),
                action: TransportAction::ShadowsocksConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    cipher: "chacha20-ietf-poly1305".into(),
                    password: "secret".into(),
                    plugin: "obfs".into(),
                    plugin_mode: "tls".into(),
                    plugin_host: "bing.com".into(),
                    websocket: WebsocketOptions::default(),
                    tls: TlsOptions::default(),
                    mux: false,
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
        assert_eq!(reply, b"pong-ss-obfs-tls".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_shadowsocks_v2ray_plugin_mux_over_websocket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /shadow-mux HTTP/1.1\r\n"));
            assert!(request.contains("\r\nHost: ws.example.com\r\n"));

            let stream = accept_v2ray_plugin_mux_test_stream(stream).unwrap();
            let mut stream =
                accept_shadowsocks_test_stream(stream, "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target(&mut *stream);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss-mux").unwrap();
            stream.flush().unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ss".into(),
            selected_path: vec!["edge-ss".into()],
            leaf_name: "edge-ss".into(),
            hops: vec![TransportHop {
                name: "edge-ss".into(),
                action: TransportAction::ShadowsocksConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    cipher: "chacha20-ietf-poly1305".into(),
                    password: "secret".into(),
                    plugin: "v2ray-plugin".into(),
                    plugin_mode: "websocket".into(),
                    plugin_host: "ws.example.com".into(),
                    websocket: WebsocketOptions {
                        path: "/shadow-mux".into(),
                        headers: BTreeMap::from([("Host".into(), "ws.example.com".into())]),
                        ..WebsocketOptions::default()
                    },
                    tls: TlsOptions::default(),
                    mux: true,
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
        assert_eq!(reply, b"pong-ss-mux".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_shadowsocks_gost_plugin_mux_over_websocket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /shadow-gost-mux HTTP/1.1\r\n"));
            assert!(request.contains("\r\nHost: ws.example.com\r\n"));

            let stream = accept_smux_test_stream(stream).unwrap();
            let mut stream =
                accept_shadowsocks_test_stream(stream, "chacha20-ietf-poly1305", "secret")
                    .unwrap();
            let target = read_shadowsocks_target(&mut *stream);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-ss-gost-mux").unwrap();
            stream.flush().unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-ss".into(),
            selected_path: vec!["edge-ss".into()],
            leaf_name: "edge-ss".into(),
            hops: vec![TransportHop {
                name: "edge-ss".into(),
                action: TransportAction::ShadowsocksConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    cipher: "chacha20-ietf-poly1305".into(),
                    password: "secret".into(),
                    plugin: "gost-plugin".into(),
                    plugin_mode: "websocket".into(),
                    plugin_host: "ws.example.com".into(),
                    websocket: WebsocketOptions {
                        path: "/shadow-gost-mux".into(),
                        headers: BTreeMap::from([("Host".into(), "ws.example.com".into())]),
                        ..WebsocketOptions::default()
                    },
                    tls: TlsOptions::default(),
                    mux: true,
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
        assert_eq!(reply, b"pong-ss-gost-mux".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_snell_handshake_over_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = snell::wrap_accepted_stream(Box::new(stream), "secret-psk", 3).unwrap();
            let target = read_snell_target(&mut *stream, 3);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(&[0x00]).unwrap();
            stream.write_all(b"pong-snell").unwrap();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-snell".into(),
            selected_path: vec!["edge-snell".into()],
            leaf_name: "edge-snell".into(),
            hops: vec![TransportHop {
                name: "edge-snell".into(),
                action: TransportAction::SnellConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    psk: "secret-psk".into(),
                    version: 3,
                    obfs_mode: String::new(),
                    obfs_host: String::new(),
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
        assert_eq!(reply, b"pong-snell".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_snell_v2_handshake_over_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = snell::wrap_accepted_stream(Box::new(stream), "secret-psk", 2).unwrap();
            let target = read_snell_target(&mut *stream, 2);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(&[0x00]).unwrap();
            stream.write_all(b"pong-snell-v2").unwrap();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-snell-v2".into(),
            selected_path: vec!["edge-snell-v2".into()],
            leaf_name: "edge-snell-v2".into(),
            hops: vec![TransportHop {
                name: "edge-snell-v2".into(),
                action: TransportAction::SnellConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    psk: "secret-psk".into(),
                    version: 2,
                    obfs_mode: String::new(),
                    obfs_host: String::new(),
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
        assert_eq!(reply, b"pong-snell-v2".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_snell_http_obfs_handshake_over_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let stream = accept_simple_obfs_http_test_stream(Box::new(stream));
            let mut stream = snell::wrap_accepted_stream(stream, "secret-psk", 3).unwrap();
            let target = read_snell_target(&mut *stream, 3);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(&[0x00]).unwrap();
            stream.write_all(b"pong-snell-obfs").unwrap();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-snell".into(),
            selected_path: vec!["edge-snell".into()],
            leaf_name: "edge-snell".into(),
            hops: vec![TransportHop {
                name: "edge-snell".into(),
                action: TransportAction::SnellConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    psk: "secret-psk".into(),
                    version: 3,
                    obfs_mode: "http".into(),
                    obfs_host: "bing.com".into(),
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
        assert_eq!(reply, b"pong-snell-obfs".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_snell_tls_obfs_handshake_over_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let stream = accept_simple_obfs_tls_test_stream(Box::new(stream));
            let mut stream = snell::wrap_accepted_stream(stream, "secret-psk", 3).unwrap();
            let target = read_snell_target(&mut *stream, 3);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(&[0x00]).unwrap();
            stream.write_all(b"pong-snell-obfs-tls").unwrap();
            stream.flush().unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-snell".into(),
            selected_path: vec!["edge-snell".into()],
            leaf_name: "edge-snell".into(),
            hops: vec![TransportHop {
                name: "edge-snell".into(),
                action: TransportAction::SnellConnect {
                    proxy: TransportTarget::new("127.0.0.1", listen_addr.port()),
                    psk: "secret-psk".into(),
                    version: 3,
                    obfs_mode: "tls".into(),
                    obfs_host: "bing.com".into(),
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
        assert_eq!(reply, b"pong-snell-obfs-tls".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_trojan_handshake_over_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (password, command, target) = read_trojan_request(&mut stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x01);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-trojan").unwrap();
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-trojan".into(),
            selected_path: vec!["edge-trojan".into()],
            leaf_name: "edge-trojan".into(),
            hops: vec![TransportHop {
                name: "edge-trojan".into(),
                action: TransportAction::TrojanConnect {
                    proxy: TransportTarget::new("localhost", listen_addr.port()),
                    password: "secret".into(),
                    shadowsocks: TrojanShadowsocksOptions::default(),
                    network: String::new(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions::default(),
                    h2: crate::Http2Options::default(),
                    http: crate::HttpStreamOptions::default(),
                    xhttp: crate::XHttpOptions::default(),
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into(), "http/1.1".into()],
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
        assert_eq!(reply, b"pong-trojan".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_trojan_handshake_over_tls_with_shadowsocks_stream_cipher() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let mut stream =
                accept_shadowsocks_test_stream(Box::new(stream), "aes-128-gcm", "inner").unwrap();
            let (password, command, target) = read_trojan_request(&mut *stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x01);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-trojan-ss").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-trojan".into(),
            selected_path: vec!["edge-trojan".into()],
            leaf_name: "edge-trojan".into(),
            hops: vec![TransportHop {
                name: "edge-trojan".into(),
                action: TransportAction::TrojanConnect {
                    proxy: TransportTarget::new("localhost", listen_addr.port()),
                    password: "secret".into(),
                    shadowsocks: TrojanShadowsocksOptions {
                        enabled: true,
                        method: "aes-128-gcm".into(),
                        password: "inner".into(),
                    },
                    network: String::new(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions::default(),
                    h2: crate::Http2Options::default(),
                    http: crate::HttpStreamOptions::default(),
                    xhttp: crate::XHttpOptions::default(),
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into(), "http/1.1".into()],
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = [0_u8; b"pong-trojan-ss".len()];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply[..], b"pong-trojan-ss");
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_trojan_handshake_over_grpc_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, format!("localhost:{}", listen_addr.port()));
            assert_eq!(request.path, "/GunService/Tun");
            let mut stream = accept_grpc_test_stream(stream);
            let (password, command, target) = read_trojan_request(&mut *stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x01);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-trojan-grpc").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-trojan".into(),
            selected_path: vec!["edge-trojan".into()],
            leaf_name: "edge-trojan".into(),
            hops: vec![TransportHop {
                name: "edge-trojan".into(),
                action: TransportAction::TrojanConnect {
                    proxy: TransportTarget::new("localhost", listen_addr.port()),
                    password: "secret".into(),
                    shadowsocks: TrojanShadowsocksOptions::default(),
                    network: "grpc".into(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions::default(),
                    h2: crate::Http2Options::default(),
                    http: crate::HttpStreamOptions::default(),
                    xhttp: crate::XHttpOptions::default(),
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into(), "http/1.1".into()],
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
        assert_eq!(reply, b"pong-trojan-grpc".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_trojan_handshake_over_h2_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "PUT");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/trh2");
            let (password, command, target) = read_trojan_request(&mut *stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x01);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-trojan-h2").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-trojan".into(),
            selected_path: vec!["edge-trojan".into()],
            leaf_name: "edge-trojan".into(),
            hops: vec![TransportHop {
                name: "edge-trojan".into(),
                action: TransportAction::TrojanConnect {
                    proxy: TransportTarget::new("localhost", listen_addr.port()),
                    password: "secret".into(),
                    shadowsocks: TrojanShadowsocksOptions::default(),
                    network: "h2".into(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions::default(),
                    h2: crate::Http2Options {
                        host: vec!["localhost".into()],
                        path: "/trh2".into(),
                    },
                    http: crate::HttpStreamOptions::default(),
                    xhttp: crate::XHttpOptions::default(),
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into(), "http/1.1".into()],
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
        assert_eq!(reply, b"pong-trojan-h2".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_trojan_handshake_over_xhttp_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/trx/");
            let (password, command, target) = read_trojan_request(&mut *stream);
            let expected_password = Sha224::digest(b"secret")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(password, expected_password);
            assert_eq!(command, 0x01);
            assert_eq!(target, TransportTarget::new("final.example.com", 443));
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-trojan-xhttp").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-trojan".into(),
            selected_path: vec!["edge-trojan".into()],
            leaf_name: "edge-trojan".into(),
            hops: vec![TransportHop {
                name: "edge-trojan".into(),
                action: TransportAction::TrojanConnect {
                    proxy: TransportTarget::new("localhost", listen_addr.port()),
                    password: "secret".into(),
                    shadowsocks: TrojanShadowsocksOptions::default(),
                    network: "xhttp".into(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions::default(),
                    h2: crate::Http2Options::default(),
                    http: crate::HttpStreamOptions::default(),
                    xhttp: crate::XHttpOptions {
                        host: "localhost".into(),
                        path: "/trx".into(),
                        mode: "stream-one".into(),
                        ..Default::default()
                    },
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: vec!["h2".into(), "http/1.1".into()],
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
        assert_eq!(reply, b"pong-trojan-xhttp".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn trojan_udp_stream_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let (_password, command, target) = read_trojan_request(&mut stream);
            assert_eq!(command, 0x03);
            assert_eq!(target, TransportTarget::new("127.0.0.1", 5353));
            let (packet_target, payload) = read_trojan_udp_packet(&mut stream).unwrap();
            assert_eq!(packet_target, "127.0.0.1:5353".parse().unwrap());
            assert_eq!(payload, b"udp-ping".to_vec());
            write_trojan_udp_packet(&mut stream, "127.0.0.1:5353".parse().unwrap(), b"udp-pong")
                .unwrap();
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let mut stream = open_trojan_udp_stream(
            Box::new(stream),
            "secret",
            &TrojanShadowsocksOptions::default(),
            TransportTarget::new("localhost", listen_addr.port()),
            TransportTarget::new("127.0.0.1", 5353),
            &tls,
            &[],
        )
        .unwrap();
        write_trojan_udp_packet(&mut *stream, "127.0.0.1:5353".parse().unwrap(), b"udp-ping")
            .unwrap();
        let (target, payload) = read_trojan_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse::<std::net::SocketAddr>().unwrap());
        assert_eq!(payload, b"udp-pong".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn trojan_udp_packet_supports_fqdn_targets() {
        let mut packet = Vec::new();
        packet.push(0x03);
        packet.push(9);
        packet.extend_from_slice(b"localhost");
        packet.extend_from_slice(&5353_u16.to_be_bytes());
        packet.extend_from_slice(&4_u16.to_be_bytes());
        packet.extend_from_slice(b"\r\n");
        packet.extend_from_slice(b"dns!");

        let (target, payload) = read_trojan_udp_packet(&mut std::io::Cursor::new(packet)).unwrap();
        assert_loopback_5353(target);
        assert_eq!(payload, b"dns!");
    }

    #[test]
    fn trojan_udp_stream_round_trip_with_shadowsocks_stream_cipher_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let mut stream =
                accept_shadowsocks_test_stream(Box::new(stream), "aes-128-gcm", "inner").unwrap();
            let (_password, command, target) = read_trojan_request(&mut *stream);
            assert_eq!(command, 0x03);
            assert_eq!(target, TransportTarget::new("127.0.0.1", 5353));
            let (packet_target, payload) = read_trojan_udp_packet(&mut *stream).unwrap();
            assert_eq!(packet_target, "127.0.0.1:5353".parse().unwrap());
            assert_eq!(payload, b"udp-ping".to_vec());
            write_trojan_udp_packet(&mut *stream, "127.0.0.1:5353".parse().unwrap(), b"udp-pong")
                .unwrap();
            stream.shutdown_write().unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let mut stream = open_trojan_udp_stream(
            Box::new(stream),
            "secret",
            &TrojanShadowsocksOptions {
                enabled: true,
                method: "aes-128-gcm".into(),
                password: "inner".into(),
            },
            TransportTarget::new("localhost", listen_addr.port()),
            TransportTarget::new("127.0.0.1", 5353),
            &tls,
            &[],
        )
        .unwrap();
        write_trojan_udp_packet(&mut *stream, "127.0.0.1:5353".parse().unwrap(), b"udp-ping")
            .unwrap();
        let (target, payload) = read_trojan_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse::<std::net::SocketAddr>().unwrap());
        assert_eq!(payload, b"udp-pong".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn trojan_udp_stream_over_grpc_tls_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, format!("localhost:{}", listen_addr.port()));
            assert_eq!(request.path, "/GunService/Tun");
            let mut stream = accept_grpc_test_stream(stream);
            let (_password, command, target) = read_trojan_request(&mut *stream);
            assert_eq!(command, 0x03);
            assert_eq!(target, TransportTarget::new("127.0.0.1", 5353));
            let (packet_target, payload) = read_trojan_udp_packet(&mut *stream).unwrap();
            assert_eq!(packet_target, "127.0.0.1:5353".parse().unwrap());
            assert_eq!(payload, b"udp-ping".to_vec());
            write_trojan_udp_packet(&mut *stream, "127.0.0.1:5353".parse().unwrap(), b"udp-pong")
                .unwrap();
            stream.shutdown_write().unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let grpc = crate::GrpcOptions::default();
        let stream = wrap_grpc_tls_proxy_stream(
            Box::new(stream),
            TransportTarget::new("localhost", listen_addr.port()),
            &tls,
            &grpc,
        )
        .unwrap();
        let mut stream = open_trojan_udp_stream(
            stream,
            "secret",
            &TrojanShadowsocksOptions::default(),
            TransportTarget::new("localhost", listen_addr.port()),
            TransportTarget::new("127.0.0.1", 5353),
            &TlsOptions::default(),
            &[],
        )
        .unwrap();
        write_trojan_udp_packet(&mut *stream, "127.0.0.1:5353".parse().unwrap(), b"udp-ping")
            .unwrap();
        let (target, payload) = read_trojan_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse::<std::net::SocketAddr>().unwrap());
        assert_eq!(payload, b"udp-pong".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn shadowsocks_udp_packet_round_trip_preserves_target_and_payload() {
        let target: std::net::SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let packet = encode_shadowsocks_udp_packet(
            "chacha20-ietf-poly1305",
            "secret",
            target,
            b"udp-ping",
        )
        .unwrap();
        let (decoded_target, decoded_payload) =
            decode_shadowsocks_udp_packet("chacha20-ietf-poly1305", "secret", &packet).unwrap();
        assert_eq!(decoded_target, target);
        assert_eq!(decoded_payload, b"udp-ping".to_vec());
    }

    #[test]
    fn shadowsocks_udp_packet_supports_fqdn_targets() {
        let packet = encode_shadowsocks_udp_packet_for_target(
            "chacha20-ietf-poly1305",
            "secret",
            &TransportTarget::new("localhost", 5353),
            b"udp-fqdn",
        )
        .unwrap();
        let (decoded_target, decoded_payload) =
            decode_shadowsocks_udp_packet("chacha20-ietf-poly1305", "secret", &packet).unwrap();
        assert_loopback_5353(decoded_target);
        assert_eq!(decoded_payload, b"udp-fqdn".to_vec());
    }

    #[test]
    fn snell_udp_packet_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = snell::wrap_accepted_stream(Box::new(stream), "secret-psk", 3).unwrap();
            let mut header = [0_u8; 3];
            stream.read_exact(&mut header).unwrap();
            assert_eq!(header, [1, 6, 0]);
            let (target, payload) = read_snell_udp_packet(&mut *stream).unwrap();
            assert_eq!(target, "127.0.0.1:5353".parse::<std::net::SocketAddr>().unwrap());
            assert_eq!(payload, b"udp-ping".to_vec());
            stream.write_all(&[0x00]).unwrap();
            write_snell_udp_packet(
                &mut *stream,
                "127.0.0.1:5353".parse().unwrap(),
                b"udp-pong",
            )
            .unwrap();
            stream.flush().unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let mut stream =
            super::wrap_snell_udp_stream(Box::new(stream), "secret-psk", 3, "", "", 443)
                .unwrap();
        write_snell_udp_packet(&mut *stream, "127.0.0.1:5353".parse().unwrap(), b"udp-ping").unwrap();
        let (target, payload) = read_snell_udp_packet(&mut *stream).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse::<std::net::SocketAddr>().unwrap());
        assert_eq!(payload, b"udp-pong".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn snell_udp_packet_supports_fqdn_targets() {
        let mut packet = Vec::new();
        packet.push(0x01);
        packet.push(0x09);
        packet.extend_from_slice(b"localhost");
        packet.extend_from_slice(&5353_u16.to_be_bytes());
        packet.extend_from_slice(b"dns!");

        let (target, payload) = read_snell_udp_packet(&mut std::io::Cursor::new(packet)).unwrap();
        assert_loopback_5353(target);
        assert_eq!(payload, b"dns!");
    }

    #[test]
    fn simple_obfs_tls_round_trip_preserves_payloads() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = accept_simple_obfs_tls_test_stream(Box::new(stream));
            let mut first = [0_u8; 5];
            stream.read_exact(&mut first).unwrap();
            assert_eq!(&first, b"hello");
            stream.write_all(b"world").unwrap();
            stream.flush().unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let mut stream = simple_obfs::wrap_tls_stream(Box::new(stream), "bing.com");
        stream.write_all(b"hello").unwrap();
        stream.flush().unwrap();
        let mut reply = [0_u8; 5];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"world");
        worker.join().unwrap();
    }

    #[test]
    fn wrap_tls_proxy_stream_accepts_matching_fingerprint() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let (tls_config, fingerprint) = build_tls_server_config_with_fingerprint();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").unwrap();
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint,
            certificate: String::new(),
            private_key: String::new(),
        };
        let mut stream = wrap_tls_proxy_stream(
            Box::new(stream),
            TransportTarget::new("localhost", listen_addr.port()),
            &tls,
            &[],
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn wrap_tls_proxy_stream_rejects_mismatched_fingerprint() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let (tls_config, _) = build_tls_server_config_with_fingerprint();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let mut discard = [0_u8; 64];
            let _ = stream.read(&mut discard);
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: "00".repeat(32),
            certificate: String::new(),
            private_key: String::new(),
        };
        let err = match wrap_tls_proxy_stream(
            Box::new(stream),
            TransportTarget::new("localhost", listen_addr.port()),
            &tls,
            &[],
        ) {
            Ok(_) => panic!("expected mismatched fingerprint to fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("certificate")
                || err.to_string().contains("application verification failure"),
            "unexpected error: {err}"
        );
        worker.join().unwrap();
    }

    #[test]
    fn wrap_stream_for_vision_exposes_tls13_metadata() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = StreamOwned::new(conn, stream);
            let mut discard = [0_u8; 1];
            let _ = stream.read(&mut discard);
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let mut stream = crate::tls_client::wrap_stream_for_vision(
            Box::new(stream),
            &TransportTarget::new("localhost", listen_addr.port()),
            &tls,
            &[],
        )
        .unwrap();
        assert!(stream.negotiated_tls13());
        assert!(stream.negotiated_cipher_suite().is_some());
        stream.shutdown_write().unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn vision_stream_over_tls_round_trip_preserves_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let mut stream = vision::VisionStream::new(
                Box::new(stream),
                true,
                *Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811")
                    .unwrap()
                    .as_bytes(),
            );
            let mut payload = vec![0_u8; 9];
            let read = stream.read(&mut payload).unwrap();
            assert_eq!(&payload[..read], b"\x17\x03\x03vision");
            stream.write_all(b"\x17\x03\x03reply").unwrap();
            stream.shutdown_write().unwrap();
        });

        let stream = std::net::TcpStream::connect(listen_addr).unwrap();
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let tls_stream = crate::tls_client::wrap_stream_for_vision(
            Box::new(stream),
            &TransportTarget::new("localhost", listen_addr.port()),
            &tls,
            &[],
        )
        .unwrap();
        let mut stream = vision::VisionStream::new(
            Box::new(tls_stream),
            true,
            *Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811")
                .unwrap()
                .as_bytes(),
        );
        stream.write_all(b"\x17\x03\x03vision").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = [0_u8; 8];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"\x17\x03\x03reply");
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_wraps_vless_vision_without_reality_in_vision_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (version, uuid, addons, command, target, accepted) =
                crate::vless::read_request(&mut stream);
            assert_eq!(version, crate::vless::VERSION);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(
                addons,
                [
                    0x0a, 0x10, b'x', b't', b'l', b's', b'-', b'r', b'p', b'r', b'x', b'-',
                    b'v', b'i', b's', b'i', b'o', b'n'
                ]
            );
            assert_eq!(command, crate::vless::COMMAND_TCP);
            assert_eq!(target, "final.example.com:443");
            match accepted {
                crate::vless::AcceptedStream::Tcp => {}
                _ => panic!("expected accepted tcp request"),
            }
            let mut stream = vision::VisionStream::new(
                Box::new(stream),
                true,
                *Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811")
                    .unwrap()
                    .as_bytes(),
            );
            let mut payload = [0_u8; 9];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"\x17\x03\x03vision");
            stream.get_mut().write_all(&[crate::vless::VERSION, 0]).unwrap();
            stream.write_all(b"\x17\x03\x03reply").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-vless-vision".into(),
            selected_path: vec!["edge-vless-vision".into()],
            leaf_name: "edge-vless-vision".into(),
            hops: vec![TransportHop {
                name: "edge-vless-vision".into(),
                action: TransportAction::VlessConnect {
                    proxy: TransportTarget::new("localhost", addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    flow: "xtls-rprx-vision".into(),
                    reality_public_key: String::new(),
                    reality_short_id: String::new(),
                    reality_support_x25519mlkem768: false,
                    client_fingerprint: String::new(),
                    udp: false,
                    network: String::new(),
                    websocket: WebsocketOptions::default(),
                    grpc: GrpcOptions::default(),
                    h2: Http2Options::default(),
                    http: HttpStreamOptions::default(),
                    xhttp: XHttpOptions::default(),
                    encryption: String::new(),
                    packet_addr: false,
                    xudp: false,
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: Vec::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        assert!((stream.as_ref() as &dyn Any).is::<vision::VisionStream>());
        stream.write_all(b"\x17\x03\x03vision").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = [0_u8; 8];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"\x17\x03\x03reply");
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_vless_h2_vision_without_reality_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut tls_config = build_tls_server_config();
        Arc::get_mut(&mut tls_config)
            .unwrap()
            .alpn_protocols = vec![b"h2".to_vec()];
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "PUT");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vless-h2");
            let (version, uuid, addons, command, target, accepted) =
                crate::vless::read_request(&mut *stream);
            assert_eq!(version, crate::vless::VERSION);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(
                addons,
                [
                    0x0a, 0x10, b'x', b't', b'l', b's', b'-', b'r', b'p', b'r', b'x', b'-',
                    b'v', b'i', b's', b'i', b'o', b'n'
                ]
            );
            assert_eq!(command, crate::vless::COMMAND_TCP);
            assert_eq!(target, "final.example.com:443");
            match accepted {
                crate::vless::AcceptedStream::Tcp => {}
                _ => panic!("expected accepted tcp request"),
            }
            let mut stream = vision::VisionStream::new(
                stream,
                true,
                *Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811")
                    .unwrap()
                    .as_bytes(),
            );
            let mut payload = [0_u8; 9];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"\x17\x03\x03vision");
            stream.get_mut().write_all(&[crate::vless::VERSION, 0]).unwrap();
            stream.write_all(b"\x17\x03\x03reply").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-vless-h2-vision".into(),
            selected_path: vec!["edge-vless-h2-vision".into()],
            leaf_name: "edge-vless-h2-vision".into(),
            hops: vec![TransportHop {
                name: "edge-vless-h2-vision".into(),
                action: TransportAction::VlessConnect {
                    proxy: TransportTarget::new("localhost", addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    flow: "xtls-rprx-vision".into(),
                    reality_public_key: String::new(),
                    reality_short_id: String::new(),
                    reality_support_x25519mlkem768: false,
                    client_fingerprint: String::new(),
                    udp: false,
                    network: "h2".into(),
                    websocket: WebsocketOptions::default(),
                    grpc: GrpcOptions::default(),
                    h2: Http2Options {
                        host: vec!["localhost".into()],
                        path: "/vless-h2".into(),
                    },
                    http: HttpStreamOptions::default(),
                    xhttp: XHttpOptions::default(),
                    encryption: String::new(),
                    packet_addr: false,
                    xudp: false,
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: Vec::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        assert!((stream.as_ref() as &dyn Any).is::<vision::VisionStream>());
        stream.write_all(b"\x17\x03\x03vision").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = [0_u8; 8];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"\x17\x03\x03reply");
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_vless_grpc_vision_without_reality_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut tls_config = build_tls_server_config();
        Arc::get_mut(&mut tls_config)
            .unwrap()
            .alpn_protocols = vec![b"h2".to_vec()];
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, format!("localhost:{}", addr.port()));
            assert_eq!(request.path, "/example/Tun");
            let mut stream = accept_grpc_test_stream(stream);
            let (version, uuid, addons, command, target, accepted) =
                crate::vless::read_request(&mut *stream);
            assert_eq!(version, crate::vless::VERSION);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(
                addons,
                [
                    0x0a, 0x10, b'x', b't', b'l', b's', b'-', b'r', b'p', b'r', b'x', b'-',
                    b'v', b'i', b's', b'i', b'o', b'n'
                ]
            );
            assert_eq!(command, crate::vless::COMMAND_TCP);
            assert_eq!(target, "final.example.com:443");
            match accepted {
                crate::vless::AcceptedStream::Tcp => {}
                _ => panic!("expected accepted tcp request"),
            }
            let mut stream = vision::VisionStream::new(
                stream,
                true,
                *Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811")
                    .unwrap()
                    .as_bytes(),
            );
            let mut payload = [0_u8; 9];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"\x17\x03\x03vision");
            stream.get_mut().write_all(&[crate::vless::VERSION, 0]).unwrap();
            stream.write_all(b"\x17\x03\x03reply").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-vless-grpc-vision".into(),
            selected_path: vec!["edge-vless-grpc-vision".into()],
            leaf_name: "edge-vless-grpc-vision".into(),
            hops: vec![TransportHop {
                name: "edge-vless-grpc-vision".into(),
                action: TransportAction::VlessConnect {
                    proxy: TransportTarget::new("localhost", addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    flow: "xtls-rprx-vision".into(),
                    reality_public_key: String::new(),
                    reality_short_id: String::new(),
                    reality_support_x25519mlkem768: false,
                    client_fingerprint: String::new(),
                    udp: false,
                    network: "grpc".into(),
                    websocket: WebsocketOptions::default(),
                    grpc: GrpcOptions {
                        service_name: "example".into(),
                        ..Default::default()
                    },
                    h2: Http2Options::default(),
                    http: HttpStreamOptions::default(),
                    xhttp: XHttpOptions::default(),
                    encryption: String::new(),
                    packet_addr: false,
                    xudp: false,
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: Vec::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        assert!((stream.as_ref() as &dyn Any).is::<vision::VisionStream>());
        stream.write_all(b"\x17\x03\x03vision").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = [0_u8; 8];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"\x17\x03\x03reply");
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_vless_ws_vision_without_reality_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (request, mut stream) = accept_websocket_test_stream(Box::new(stream));
            assert!(request.starts_with("GET /vless-ws HTTP/1.1\r\n"));
            let (version, uuid, addons, command, target, accepted) =
                crate::vless::read_request(&mut *stream);
            assert_eq!(version, crate::vless::VERSION);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(
                addons,
                [
                    0x0a, 0x10, b'x', b't', b'l', b's', b'-', b'r', b'p', b'r', b'x', b'-',
                    b'v', b'i', b's', b'i', b'o', b'n'
                ]
            );
            assert_eq!(command, crate::vless::COMMAND_TCP);
            assert_eq!(target, "final.example.com:443");
            match accepted {
                crate::vless::AcceptedStream::Tcp => {}
                _ => panic!("expected accepted tcp request"),
            }
            let mut stream = vision::VisionStream::new(
                stream,
                true,
                *Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811")
                    .unwrap()
                    .as_bytes(),
            );
            let mut payload = [0_u8; 9];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"\x17\x03\x03vision");
            stream.get_mut().write_all(&[crate::vless::VERSION, 0]).unwrap();
            stream.write_all(b"\x17\x03\x03reply").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-vless-ws-vision".into(),
            selected_path: vec!["edge-vless-ws-vision".into()],
            leaf_name: "edge-vless-ws-vision".into(),
            hops: vec![TransportHop {
                name: "edge-vless-ws-vision".into(),
                action: TransportAction::VlessConnect {
                    proxy: TransportTarget::new("localhost", addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    flow: "xtls-rprx-vision".into(),
                    reality_public_key: String::new(),
                    reality_short_id: String::new(),
                    reality_support_x25519mlkem768: false,
                    client_fingerprint: String::new(),
                    udp: false,
                    network: "ws".into(),
                    websocket: WebsocketOptions {
                        path: "/vless-ws".into(),
                        ..Default::default()
                    },
                    grpc: GrpcOptions::default(),
                    h2: Http2Options::default(),
                    http: HttpStreamOptions::default(),
                    xhttp: XHttpOptions::default(),
                    encryption: String::new(),
                    packet_addr: false,
                    xudp: false,
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: Vec::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        assert!((stream.as_ref() as &dyn Any).is::<vision::VisionStream>());
        stream.write_all(b"\x17\x03\x03vision").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = [0_u8; 8];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"\x17\x03\x03reply");
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_vless_http_vision_without_reality_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let tls_config = build_tls_server_config();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(tls_config).unwrap();
            let mut stream = TestRustlsServerStream(StreamOwned::new(conn, stream));
            let (_request, tail) = read_http_headers_with_tail(&mut stream);
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            stream.write_all(response).unwrap();
            stream.flush().unwrap();
            let mut stream = prepend_bytes(Box::new(stream), tail);
            let (version, uuid, addons, command, target, accepted) =
                crate::vless::read_request(&mut *stream);
            assert_eq!(version, crate::vless::VERSION);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(
                addons,
                [
                    0x0a, 0x10, b'x', b't', b'l', b's', b'-', b'r', b'p', b'r', b'x', b'-',
                    b'v', b'i', b's', b'i', b'o', b'n'
                ]
            );
            assert_eq!(command, crate::vless::COMMAND_TCP);
            assert_eq!(target, "final.example.com:443");
            match accepted {
                crate::vless::AcceptedStream::Tcp => {}
                _ => panic!("expected accepted tcp request"),
            }
            let mut stream = vision::VisionStream::new(
                stream,
                true,
                *Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811")
                    .unwrap()
                    .as_bytes(),
            );
            let mut payload = [0_u8; 9];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"\x17\x03\x03vision");
            stream.get_mut().write_all(&[crate::vless::VERSION, 0]).unwrap();
            stream.write_all(b"\x17\x03\x03reply").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-vless-http-vision".into(),
            selected_path: vec!["edge-vless-http-vision".into()],
            leaf_name: "edge-vless-http-vision".into(),
            hops: vec![TransportHop {
                name: "edge-vless-http-vision".into(),
                action: TransportAction::VlessConnect {
                    proxy: TransportTarget::new("localhost", listen_addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    flow: "xtls-rprx-vision".into(),
                    reality_public_key: String::new(),
                    reality_short_id: String::new(),
                    reality_support_x25519mlkem768: false,
                    client_fingerprint: String::new(),
                    udp: false,
                    network: "http".into(),
                    websocket: WebsocketOptions::default(),
                    grpc: GrpcOptions::default(),
                    h2: Http2Options::default(),
                    http: HttpStreamOptions {
                        method: "GET".into(),
                        host: vec!["localhost".into()],
                        path: vec!["/vless-http".into()],
                        headers: BTreeMap::new(),
                    },
                    xhttp: XHttpOptions::default(),
                    encryption: String::new(),
                    packet_addr: false,
                    xudp: false,
                    tls: TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: Vec::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        assert!((stream.as_ref() as &dyn Any).is::<vision::VisionStream>());
        stream.write_all(b"\x17\x03\x03vision").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = [0_u8; 8];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"\x17\x03\x03reply");
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_vmess_h2_over_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) = accept_h2_test_stream(Box::new(stream)).unwrap();
            assert_eq!(request.method, "PUT");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vmess-h2");
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-h2").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-vmess-h2".into(),
            selected_path: vec!["edge-vmess-h2".into()],
            leaf_name: "edge-vmess-h2".into(),
            hops: vec![TransportHop {
                name: "edge-vmess-h2".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "h2".into(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions::default(),
                    h2: crate::Http2Options {
                        host: vec!["localhost".into()],
                        path: "/vmess-h2".into(),
                    },
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
        assert_eq!(reply, b"pong-vmess-h2".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_vmess_grpc_over_tls_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut tls_config = build_tls_server_config();
        Arc::get_mut(&mut tls_config)
            .unwrap()
            .alpn_protocols = vec![b"h2".to_vec()];
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, format!("localhost:{}", addr.port()));
            assert_eq!(request.path, "/example/Tun");
            let stream = accept_grpc_test_stream(stream);
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-grpc-tls").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-vmess-grpc-tls".into(),
            selected_path: vec!["edge-vmess-grpc-tls".into()],
            leaf_name: "edge-vmess-grpc-tls".into(),
            hops: vec![TransportHop {
                name: "edge-vmess-grpc-tls".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("localhost", addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "grpc".into(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions {
                        service_name: "example".into(),
                        ..Default::default()
                    },
                    h2: crate::Http2Options::default(),
                    http: crate::HttpStreamOptions::default(),
                    xhttp: crate::XHttpOptions::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: crate::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
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
        assert_eq!(reply, b"pong-vmess-grpc-tls".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_runs_vmess_h2_over_tls_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut tls_config = build_tls_server_config();
        Arc::get_mut(&mut tls_config)
            .unwrap()
            .alpn_protocols = vec![b"h2".to_vec()];
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "PUT");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/vmess-h2");
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-h2-tls").unwrap();
            stream.shutdown_write().unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-vmess-h2-tls".into(),
            selected_path: vec!["edge-vmess-h2-tls".into()],
            leaf_name: "edge-vmess-h2-tls".into(),
            hops: vec![TransportHop {
                name: "edge-vmess-h2-tls".into(),
                action: TransportAction::VmessConnect {
                    proxy: TransportTarget::new("localhost", addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    alter_id: 0,
                    cipher: "none".into(),
                    udp: false,
                    network: "h2".into(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions::default(),
                    h2: crate::Http2Options {
                        host: vec!["localhost".into()],
                        path: "/vmess-h2".into(),
                    },
                    http: crate::HttpStreamOptions::default(),
                    xhttp: crate::XHttpOptions::default(),
                    packet_addr: false,
                    xudp: false,
                    global_padding: false,
                    authenticated_length: false,
                    tls: crate::TlsOptions {
                        enabled: true,
                        sni: "localhost".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
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
        assert_eq!(reply, b"pong-vmess-h2-tls".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn vmess_wrap_stream_over_h2_tls_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut tls_config = build_tls_server_config();
        Arc::get_mut(&mut tls_config)
            .unwrap()
            .alpn_protocols = vec![b"h2".to_vec()];
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "PUT");
            assert_eq!(request.authority, format!("localhost:{}", addr.port()));
            assert_eq!(request.path, "/vmess-h2");
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-h2-tls-direct").unwrap();
            stream.shutdown_write().unwrap();
        });

        let stream = std::net::TcpStream::connect(addr).unwrap();
        let tls = crate::TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let stream = crate::h2_stream::wrap_tls_stream_with_request(
            Box::new(stream),
            &TransportTarget::new("localhost", addr.port()),
            &tls,
            &["h2".to_owned()],
            crate::h2_stream::H2RequestOptions {
                authority: format!("localhost:{}", addr.port()),
                path: "/vmess-h2".into(),
                method: "PUT".into(),
                headers: vec![("accept-encoding".into(), "identity".into())],
            },
        )
        .unwrap();
        let mut stream = crate::vmess::wrap_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
            &TransportTarget::new("final.example.com", 443),
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vmess-h2-tls-direct".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn vmess_wrap_stream_over_grpc_tls_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut tls_config = build_tls_server_config();
        Arc::get_mut(&mut tls_config)
            .unwrap()
            .alpn_protocols = vec![b"h2".to_vec()];
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "POST");
            assert_eq!(request.authority, format!("localhost:{}", addr.port()));
            assert_eq!(request.path, "/example/Tun");
            let stream = accept_grpc_test_stream(stream);
            let accepted = accept_vmess_test_stream(
                stream,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                "none",
            )
            .unwrap();
            let VmessAcceptedTestStream::Tcp { target, mut stream } = accepted else {
                panic!("expected vmess tcp stream");
            };
            assert_eq!(target, "final.example.com:443");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vmess-grpc-tls-direct").unwrap();
            stream.shutdown_write().unwrap();
        });

        let stream = std::net::TcpStream::connect(addr).unwrap();
        let tls = crate::TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let grpc = crate::GrpcOptions {
            service_name: "example".into(),
            ..Default::default()
        };
        let stream = wrap_grpc_tls_proxy_stream(
            Box::new(stream),
            TransportTarget::new("localhost", addr.port()),
            &tls,
            &grpc,
        )
        .unwrap();
        let mut stream = crate::vmess::wrap_stream(
            stream,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            0,
            "none",
            false,
            false,
            &TransportTarget::new("final.example.com", 443),
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-vmess-grpc-tls-direct".to_vec());
        worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_rejects_unknown_snell_obfs_mode() {
        let plan = TransportPlan {
            requested: "edge-snell".into(),
            selected_path: vec!["edge-snell".into()],
            leaf_name: "edge-snell".into(),
            hops: vec![TransportHop {
                name: "edge-snell".into(),
                action: TransportAction::SnellConnect {
                    proxy: TransportTarget::new("127.0.0.1", 8443),
                    psk: "secret-psk".into(),
                    version: 3,
                    obfs_mode: "quic".into(),
                    obfs_host: "bing.com".into(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        match executor.run_plan(&plan) {
            Err(err) => assert_eq!(
                err,
                super::TransportError::UnsupportedFeature {
                    proxy: "127.0.0.1:8443".into(),
                    feature: "obfs=quic".into(),
                }
            ),
            Ok(_) => panic!("expected snell obfs to be rejected"),
        }
    }

    #[test]
    fn hy2_transport_action_summary_uses_hysteria2_label() {
        let action = TransportAction::Hy2Connect {
            proxy: TransportTarget::new("hy2.example.com", 8443),
            password: "secret".into(),
            sni: "edge.example.com".into(),
            certificate: String::new(),
            private_key: String::new(),
            obfs: String::new(),
            obfs_password: String::new(),
            realm_enabled: false,
            realm_server_url: String::new(),
            realm_token: String::new(),
            realm_id: String::new(),
            realm_stun_servers: Vec::new(),
            realm_sni: String::new(),
            realm_skip_cert_verify: false,
            realm_fingerprint: String::new(),
            realm_certificate: String::new(),
            realm_private_key: String::new(),
            realm_alpn: Vec::new(),
            realm_proxy: String::new(),
            realm_proxy_plan: None,
            skip_cert_verify: true,
            socket: SocketOptions::default(),
            target: TransportTarget::new("final.example.com", 443),
        };

        assert_eq!(
            action.summary(),
            "hysteria2 hy2.example.com:8443 -> final.example.com:443"
        );
    }

    #[test]
    fn hysteria_transport_action_summary_uses_hysteria_label() {
        let action = TransportAction::HysteriaConnect {
            proxy: TransportTarget::new("hy.example.com", 8443),
            ports: String::new(),
            protocol: "udp".into(),
            auth: String::new(),
            auth_str: "secret".into(),
            obfs: String::new(),
            sni: "edge.example.com".into(),
            alpn: vec!["hysteria".into()],
            up: "10 Mbps".into(),
            down: "50 Mbps".into(),
            up_speed: 0,
            down_speed: 0,
            disable_mtu_discovery: false,
            fast_open: false,
            hop_interval: 10,
            skip_cert_verify: true,
            socket: SocketOptions::default(),
            target: TransportTarget::new("final.example.com", 443),
        };

        assert_eq!(
            action.summary(),
            "hysteria hy.example.com:8443 -> final.example.com:443"
        );
    }

    #[test]
    fn tcp_executor_rejects_unknown_hy2_obfs() {
        let plan = TransportPlan {
            requested: "edge-hy2".into(),
            selected_path: vec!["edge-hy2".into()],
            leaf_name: "edge-hy2".into(),
            hops: vec![TransportHop {
                name: "edge-hy2".into(),
                action: TransportAction::Hy2Connect {
                    proxy: TransportTarget::new("127.0.0.1", 8443),
                    password: "secret".into(),
                    sni: "edge.example.com".into(),
                    certificate: String::new(),
                    private_key: String::new(),
                    obfs: "custom-obfs".into(),
                    obfs_password: "hidden".into(),
                    realm_enabled: false,
                    realm_server_url: String::new(),
                    realm_token: String::new(),
                    realm_id: String::new(),
                    realm_stun_servers: Vec::new(),
                    realm_sni: String::new(),
                    realm_skip_cert_verify: false,
                    realm_fingerprint: String::new(),
                    realm_certificate: String::new(),
                    realm_private_key: String::new(),
                    realm_alpn: Vec::new(),
                    realm_proxy: String::new(),
                    realm_proxy_plan: None,
                    skip_cert_verify: true,
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        match executor.run_plan(&plan) {
            Err(err) => assert_eq!(
                err,
                super::TransportError::UnsupportedFeature {
                    proxy: "127.0.0.1:8443".into(),
                    feature: "hysteria2 obfs=custom-obfs".into(),
                }
            ),
            Ok(_) => panic!("expected unknown hysteria2 obfs to be rejected"),
        }
    }

    #[test]
    fn tcp_executor_attempts_hy2_realm_opts_flow() {
        let plan = TransportPlan {
            requested: "edge-hy2".into(),
            selected_path: vec!["edge-hy2".into()],
            leaf_name: "edge-hy2".into(),
            hops: vec![TransportHop {
                name: "edge-hy2".into(),
                action: TransportAction::Hy2Connect {
                    proxy: TransportTarget::new("127.0.0.1", 8443),
                    password: "secret".into(),
                    sni: "edge.example.com".into(),
                    certificate: String::new(),
                    private_key: String::new(),
                    obfs: String::new(),
                    obfs_password: String::new(),
                    realm_enabled: true,
                    realm_server_url: "https://realm.example.com".into(),
                    realm_token: "public".into(),
                    realm_id: "my-cabin-1f3a8c2e9b".into(),
                    realm_stun_servers: vec!["stun.nextcloud.com:3478".into()],
                    realm_sni: "realm.example.com".into(),
                    realm_skip_cert_verify: true,
                    realm_fingerprint: String::new(),
                    realm_certificate: String::new(),
                    realm_private_key: String::new(),
                    realm_alpn: vec!["h2".into()],
                    realm_proxy: String::new(),
                    realm_proxy_plan: None,
                    skip_cert_verify: true,
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        match executor.run_plan(&plan) {
            Err(super::TransportError::Io { message, .. }) => {
                assert!(
                    message.contains("realm.example.com")
                        || message.contains("127.0.0.1:8443")
                        || message.contains("stun.nextcloud.com")
                        || message.contains("stun")
                        || message.contains("connect")
                        || message.contains("punch"),
                    "{message}"
                );
            }
            Err(other) => panic!("expected io-style realm flow failure, got {other:?}"),
            Ok(_) => panic!("expected realm-opts hy2 to attempt network flow"),
        }
    }

    #[test]
    fn tcp_executor_routes_hy2_realm_control_through_nested_socks5_plan() {
        let stun_server = TestStunServer::start();
        let realm_server = TcpListener::bind("127.0.0.1:0").unwrap();
        let realm_addr = realm_server.local_addr().unwrap();
        let realm_worker = thread::spawn(move || {
            let (mut stream, _) = realm_server.accept().unwrap();
            let (request, _tail) = read_http_headers_with_tail(&mut stream);
            assert!(request.starts_with("POST /v1/alpha/connect HTTP/1.1\r\n"), "{request}");
            assert!(request.contains("Host: realm.example.com\r\n"), "{request}");
            assert!(request.contains("Authorization: Bearer public\r\n"), "{request}");
            send_http_response(
                &mut stream,
                "200 OK",
                br#"{"addresses":["127.0.0.1:7001"],"nonce":"00112233445566778899aabbccddeeff","obfs":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}"#,
            );
        });
        let socks_server = TcpListener::bind("127.0.0.1:0").unwrap();
        let socks_addr = socks_server.local_addr().unwrap();
        let socks_worker = thread::spawn(move || {
            let (mut control, _) = socks_server.accept().unwrap();
            let mut greeting = [0_u8; 3];
            control.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            control.write_all(&[0x05, 0x00]).unwrap();

            let mut header = [0_u8; 4];
            control.read_exact(&mut header).unwrap();
            assert_eq!(&header[..3], &[0x05, 0x01, 0x00]);
            assert_eq!(header[3], 0x03);
            let mut len = [0_u8; 1];
            control.read_exact(&mut len).unwrap();
            let mut host = vec![0_u8; len[0] as usize];
            control.read_exact(&mut host).unwrap();
            assert_eq!(&host, b"realm.example.com");
            let mut port = [0_u8; 2];
            control.read_exact(&mut port).unwrap();
            assert_eq!(u16::from_be_bytes(port), 80);

            let mut reply = vec![0x05, 0x00, 0x00, 0x01];
            reply.extend_from_slice(&[127, 0, 0, 1]);
            reply.extend_from_slice(&0_u16.to_be_bytes());
            control.write_all(&reply).unwrap();

            let mut upstream = TcpStream::connect(realm_addr).unwrap();
            let mut control_writer = control.try_clone().unwrap();
            let mut upstream_writer = upstream.try_clone().unwrap();
            let upload = thread::spawn(move || {
                let _ = std::io::copy(&mut control, &mut upstream_writer);
                let _ = upstream_writer.shutdown(Shutdown::Write);
            });
            let download = thread::spawn(move || {
                let _ = std::io::copy(&mut upstream, &mut control_writer);
                let _ = control_writer.shutdown(Shutdown::Write);
            });
            upload.join().unwrap();
            download.join().unwrap();
        });
        let plan = TransportPlan {
            requested: "edge-hy2".into(),
            selected_path: vec!["edge-hy2".into()],
            leaf_name: "edge-hy2".into(),
            hops: vec![TransportHop {
                name: "edge-hy2".into(),
                action: TransportAction::Hy2Connect {
                    proxy: TransportTarget::new("127.0.0.1", 8443),
                    password: "secret".into(),
                    sni: "edge.example.com".into(),
                    certificate: String::new(),
                    private_key: String::new(),
                    obfs: String::new(),
                    obfs_password: String::new(),
                    realm_enabled: true,
                    realm_server_url: "https://realm.example.com".into(),
                    realm_token: "public".into(),
                    realm_id: "alpha".into(),
                    realm_stun_servers: vec![stun_server.addr.to_string()],
                    realm_sni: "realm.example.com".into(),
                    realm_skip_cert_verify: false,
                    realm_fingerprint: String::new(),
                    realm_certificate: String::new(),
                    realm_private_key: String::new(),
                    realm_alpn: Vec::new(),
                    realm_proxy: "outer-socks".into(),
                    realm_proxy_plan: Some(Box::new(TransportPlan {
                        requested: "outer-socks".into(),
                        selected_path: vec!["outer-socks".into()],
                        leaf_name: "outer-socks".into(),
                        hops: vec![TransportHop {
                            name: "outer-socks".into(),
                            action: TransportAction::Socks5Connect {
                                proxy: TransportTarget::new("127.0.0.1", socks_addr.port()),
                                auth: None,
                                tls: TlsOptions::default(),
                                udp: false,
                                socket: SocketOptions::default(),
                                target: TransportTarget::new("realm.example.com", 80),
                            },
                        }],
                    })),
                    skip_cert_verify: true,
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        match executor.run_plan(&plan) {
            Err(super::TransportError::Io { message, .. }) => {
                assert!(message.contains("punch") || message.contains("stun"), "{message}");
            }
            Err(other) => panic!("expected io-style realm flow failure, got {other:?}"),
            Ok(_) => panic!("expected hy2 realm flow to continue beyond control-plane connect"),
        }

        socks_worker.join().unwrap();
        realm_worker.join().unwrap();
        stun_server.shutdown();
    }

    #[test]
    fn hy2_realm_control_client_connects_via_socks5_proxy() {
        let realm_server = TcpListener::bind("127.0.0.1:0").unwrap();
        let realm_addr = realm_server.local_addr().unwrap();
        let realm_worker = thread::spawn(move || {
            let (mut stream, _) = realm_server.accept().unwrap();
            let (request, _tail) = read_http_headers_with_tail(&mut stream);
            assert!(request.starts_with("POST /v1/alpha/connect HTTP/1.1\r\n"), "{request}");
            assert!(request.contains(&format!("Host: 127.0.0.1:{}\r\n", realm_addr.port())));
            assert!(request.contains("Authorization: Bearer public\r\n"), "{request}");
            send_http_response(
                &mut stream,
                "200 OK",
                br#"{"addresses":["127.0.0.1:7001"],"nonce":"00112233445566778899aabbccddeeff","obfs":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}"#,
            );
        });

        let proxy_server = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy_server.local_addr().unwrap();
        let proxy_worker = thread::spawn(move || {
            let (mut control, _) = proxy_server.accept().unwrap();
            let mut greeting = [0_u8; 3];
            control.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            control.write_all(&[0x05, 0x00]).unwrap();

            let mut header = [0_u8; 4];
            control.read_exact(&mut header).unwrap();
            assert_eq!(&header[..3], &[0x05, 0x01, 0x00]);
            match header[3] {
                0x01 => {
                    let mut addr = [0_u8; 4];
                    control.read_exact(&mut addr).unwrap();
                    assert_eq!(SocketAddr::from((addr, 0)).ip(), realm_addr.ip());
                }
                other => panic!("unexpected atyp {other}"),
            }
            let mut port = [0_u8; 2];
            control.read_exact(&mut port).unwrap();
            assert_eq!(u16::from_be_bytes(port), realm_addr.port());

            let mut reply = vec![0x05, 0x00, 0x00, 0x01];
            reply.extend_from_slice(&[127, 0, 0, 1]);
            reply.extend_from_slice(&0_u16.to_be_bytes());
            control.write_all(&reply).unwrap();

            let mut upstream = std::net::TcpStream::connect(realm_addr).unwrap();
            let mut control_writer = control.try_clone().unwrap();
            let mut upstream_writer = upstream.try_clone().unwrap();
            let upload = thread::spawn(move || {
                let _ = std::io::copy(&mut control, &mut upstream_writer);
                let _ = upstream_writer.shutdown(std::net::Shutdown::Write);
            });
            let download = thread::spawn(move || {
                let _ = std::io::copy(&mut upstream, &mut control_writer);
                let _ = control_writer.shutdown(std::net::Shutdown::Write);
            });
            upload.join().unwrap();
            download.join().unwrap();
        });

        let client = crate::hy2_realm::RealmControlClient::new(&crate::hy2_realm::Hy2RealmOptions {
            enabled: true,
            server_url: format!("http://127.0.0.1:{}", realm_addr.port()),
            token: "public".into(),
            realm_id: "alpha".into(),
            stun_servers: vec!["127.0.0.1:3478".into()],
            sni: String::new(),
            skip_cert_verify: false,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
            alpn: Vec::new(),
            proxy: format!("socks5://127.0.0.1:{}", proxy_addr.port()),
            proxy_plan: None,
        })
        .unwrap();
        let response = client
            .connect(
                "alpha",
                &[SocketAddr::from(([127, 0, 0, 1], 6001))],
                crate::hy2_realm::PunchMetadata {
                    nonce: [0x11; 16],
                    obfuscation_key: [0x22; 32],
                },
            )
            .unwrap();
        assert_eq!(response.addresses, vec![SocketAddr::from(([127, 0, 0, 1], 7001))]);

        proxy_worker.join().unwrap();
        realm_worker.join().unwrap();
    }

    #[test]
    fn tcp_executor_validates_vision_reality_key_before_dialing() {
        let plan = TransportPlan {
            requested: "edge-vless".into(),
            selected_path: vec!["edge-vless".into()],
            leaf_name: "edge-vless".into(),
            hops: vec![TransportHop {
                name: "edge-vless".into(),
                action: TransportAction::VlessConnect {
                    proxy: TransportTarget::new("127.0.0.1", 443),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    flow: "xtls-rprx-vision".into(),
                    reality_public_key: "abcdef".into(),
                    reality_short_id: String::new(),
                    reality_support_x25519mlkem768: false,
                    client_fingerprint: "chrome".into(),
                    udp: false,
                    network: "tcp".into(),
                    websocket: WebsocketOptions::default(),
                    grpc: GrpcOptions::default(),
                    h2: Http2Options::default(),
                    http: HttpStreamOptions::default(),
                    xhttp: XHttpOptions::default(),
                    encryption: String::new(),
                    packet_addr: false,
                    xudp: false,
                    tls: TlsOptions {
                        enabled: true,
                        sni: "edge.example.com".into(),
                        skip_cert_verify: true,
                        fingerprint: String::new(),
                        certificate: String::new(),
                        private_key: String::new(),
                    },
                    alpn: Vec::new(),
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("final.example.com", 443),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        assert!(matches!(executor.run_plan(&plan), Err(super::TransportError::InvalidPlan(_))));
    }

    #[test]
    fn tcp_executor_chains_outer_socks5_and_gost_relay() {
        let mut dialer = FakeDialer::new();
        let handle = dialer.push_connection(
            "outer.example.com:1080",
            [
                vec![
                    0x05, 0x00, // socks no-auth
                    0x05, 0x00, 0x00, 0x03, 17,
                ],
                b"relay.example.com".to_vec(),
                vec![0x20, 0xfb], // 8443
                vec![0x01, 0x00, 0x00, 0x00],
            ]
            .concat(),
        );
        let plan = TransportPlan {
            requested: "relay".into(),
            selected_path: vec!["relay".into()],
            leaf_name: "relay".into(),
            hops: vec![
                TransportHop {
                    name: "outer".into(),
                    action: TransportAction::Socks5Connect {
                        proxy: TransportTarget::new("outer.example.com", 1080),
                        auth: None,
                        tls: TlsOptions::default(),
                        udp: false,
                        socket: SocketOptions::default(),
                        target: TransportTarget::new("relay.example.com", 8443),
                    },
                },
                TransportHop {
                    name: "relay".into(),
                    action: TransportAction::GostRelay {
                        proxy: TransportTarget::new("relay.example.com", 8443),
                        auth: None,
                        forward: false,
                        tls: TlsOptions::default(),
                        mux: false,
                        socket: SocketOptions::default(),
                        target: TransportTarget::new("final.example.com", 443),
                    },
                },
            ],
        };
        let mut executor = TcpTransportExecutor::new(dialer);
        executor.run_plan(&plan).unwrap();

        let writes = handle.writes();
        assert_eq!(&writes[0..3], &[0x05, 0x01, 0x00]);
        let relay_start = writes
            .windows(2)
            .position(|window| window == [0x01, 0x01])
            .unwrap();
        let request = parse_gost_relay_request(&writes[relay_start..]);
        assert_eq!(
            request.target,
            Some(TransportTarget::new("final.example.com", 443))
        );
        assert_eq!(executor.dialer().calls, vec!["outer.example.com:1080"]);
    }

    #[test]
    fn tcp_executor_chains_outer_socks5_and_inner_http() {
        let mut dialer = FakeDialer::new();
        let handle = dialer.push_connection(
            "outer.example.com:1080",
            [
                vec![
                    0x05, 0x00, // socks no-auth
                    0x05, 0x00, 0x00, 0x03, 16,
                ],
                b"leaf.example.com".to_vec(),
                vec![0x20, 0xfb], // 8443
                b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec(),
            ]
            .concat(),
        );
        let plan = TransportPlan {
            requested: "leaf".into(),
            selected_path: vec!["leaf".into()],
            leaf_name: "leaf".into(),
            hops: vec![
                TransportHop {
                    name: "outer".into(),
                    action: TransportAction::Socks5Connect {
                        proxy: TransportTarget::new("outer.example.com", 1080),
                        auth: None,
                        tls: TlsOptions::default(),
                        udp: false,
                        socket: SocketOptions::default(),
                        target: TransportTarget::new("leaf.example.com", 8443),
                    },
                },
                TransportHop {
                    name: "leaf".into(),
                    action: TransportAction::HttpConnect {
                        proxy: TransportTarget::new("leaf.example.com", 8443),
                        auth: None,
                        tls: TlsOptions::default(),
                        headers: BTreeMap::new(),
                        socket: SocketOptions::default(),
                        target: TransportTarget::new("final.example.com", 443),
                    },
                },
            ],
        };
        let mut executor = TcpTransportExecutor::new(dialer);
        executor.run_plan(&plan).unwrap();

        let written = handle.writes();
        assert_eq!(&written[0..3], &[0x05, 0x01, 0x00]);
        let http_start = written
            .windows("CONNECT ".len())
            .position(|window| window == b"CONNECT ")
            .unwrap();
        let request = String::from_utf8(written[http_start..].to_vec()).unwrap();
        assert!(request.starts_with("CONNECT final.example.com:443 HTTP/1.1\r\n"));
        assert_eq!(executor.dialer().calls, vec!["outer.example.com:1080"]);
        assert_eq!(executor.trace().len(), 2);
    }

    #[test]
    fn tcp_executor_direct_chain_only_dials_once() {
        let mut dialer = FakeDialer::new();
        dialer.push_connection("final.example.com:443", Vec::new());
        let plan = TransportPlan {
            requested: "leaf".into(),
            selected_path: vec!["leaf".into()],
            leaf_name: "leaf".into(),
            hops: vec![
                TransportHop {
                    name: "outer".into(),
                    action: TransportAction::Direct {
                        socket: SocketOptions::default(),
                        target: TransportTarget::new("final.example.com", 443),
                    },
                },
                TransportHop {
                    name: "leaf".into(),
                    action: TransportAction::Direct {
                        socket: SocketOptions::default(),
                        target: TransportTarget::new("final.example.com", 443),
                    },
                },
            ],
        };
        let mut executor = TcpTransportExecutor::new(dialer);
        executor.run_plan(&plan).unwrap();
        assert_eq!(executor.dialer().calls, vec!["final.example.com:443"]);
    }

    #[test]
    fn masque_h2_udp_stream_roundtrips_ip_capsules() {
        let (tls_config, cert_pem, server_public_key) =
            build_tls_server_config_with_pem_and_public_key();
        register_test_root_certificate(&cert_pem).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (private_key, _client_public_key) = build_masque_key_material();

        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "CONNECT");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/");
            assert_eq!(
                request.headers.get("cf-connect-proto").map(String::as_str),
                Some("cf-connect-ip")
            );

            let (capsule_type, packet) = read_h2_capsule(&mut *stream);
            assert_eq!(capsule_type, 0);
            let (source, destination, payload) =
                crate::ip_packet_tunnel::decode_ipv4_udp_packet_parts(&packet).unwrap();
            assert_eq!(destination, "8.8.8.8:53".parse().unwrap());
            assert_eq!(payload, b"via-masque");

            let mut reply = crate::ip_packet_tunnel::encode_ipv4_udp_packet(
                Ipv4Addr::new(1, 1, 1, 1),
                source,
                b"masque-ok",
            )
            .unwrap();
            reply[20..22].copy_from_slice(&destination.port().to_be_bytes());
            write_h2_capsule(&mut *stream, 0, &reply);
        });

        let stream = TcpStream::connect(addr).unwrap();
        let options = MasqueConnectOptions {
            private_key,
            public_key: server_public_key,
            ip: "10.10.0.2/32".into(),
            ipv6: String::new(),
            uri: "https://localhost/".into(),
            mtu: 1300,
            network: "h2".into(),
            remote_dns_resolve: false,
            dns: Vec::new(),
        };
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: false,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let mut stream = open_masque_udp_stream(
            Box::new(stream),
            &TransportTarget::new("localhost", addr.port()),
            &options,
            &tls,
        )
        .unwrap();
        write_masque_udp_packet(&mut *stream, "8.8.8.8:53".parse().unwrap(), b"via-masque")
            .unwrap();
        let (source, payload) = read_masque_udp_packet(&mut *stream).unwrap();
        assert_eq!(source, "1.1.1.1:53".parse().unwrap());
        assert_eq!(payload, b"masque-ok");
        worker.join().unwrap();
    }

    #[test]
    fn masque_h2_udp_stream_resolves_remote_dns_over_tunnel() {
        let (tls_config, cert_pem, server_public_key) =
            build_tls_server_config_with_pem_and_public_key();
        register_test_root_certificate(&cert_pem).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (private_key, _client_public_key) = build_masque_key_material();

        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "CONNECT");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/");

            let (capsule_type, packet) = read_h2_capsule(&mut *stream);
            assert_eq!(capsule_type, 0);
            let (source, destination, payload) =
                crate::ip_packet_tunnel::decode_ipv4_udp_packet_parts(&packet).unwrap();
            assert_eq!(destination, "1.1.1.1:53".parse().unwrap());
            let query = mihomo_dns::build_dns_query_for_tests(
                "edge.example.com",
                mihomo_dns::DnsRecordType::A,
                u16::from_be_bytes([payload[0], payload[1]]),
            )
            .unwrap();
            assert_eq!(payload, query);

            let response = {
                let parsed = mihomo_dns::parse_dns_response_for_tests(
                    &{
                        let mut response = Vec::new();
                        response.extend_from_slice(&u16::from_be_bytes([payload[0], payload[1]]).to_be_bytes());
                        response.extend_from_slice(&0x8180_u16.to_be_bytes());
                        response.extend_from_slice(&1_u16.to_be_bytes());
                        response.extend_from_slice(&1_u16.to_be_bytes());
                        response.extend_from_slice(&0_u16.to_be_bytes());
                        response.extend_from_slice(&0_u16.to_be_bytes());
                        response.extend_from_slice(&payload[12..]);
                        response.extend_from_slice(&0xC00C_u16.to_be_bytes());
                        response.extend_from_slice(&1_u16.to_be_bytes());
                        response.extend_from_slice(&1_u16.to_be_bytes());
                        response.extend_from_slice(&60_u32.to_be_bytes());
                        response.extend_from_slice(&4_u16.to_be_bytes());
                        response.extend_from_slice(&[8, 8, 8, 8]);
                        response
                    },
                    u16::from_be_bytes([payload[0], payload[1]]),
                    mihomo_dns::DnsRecordType::A,
                )
                .unwrap();
                assert_eq!(
                    parsed,
                    vec!["8.8.8.8".parse::<std::net::IpAddr>().unwrap()]
                );
                let mut response = Vec::new();
                response.extend_from_slice(&u16::from_be_bytes([payload[0], payload[1]]).to_be_bytes());
                response.extend_from_slice(&0x8180_u16.to_be_bytes());
                response.extend_from_slice(&1_u16.to_be_bytes());
                response.extend_from_slice(&1_u16.to_be_bytes());
                response.extend_from_slice(&0_u16.to_be_bytes());
                response.extend_from_slice(&0_u16.to_be_bytes());
                response.extend_from_slice(&payload[12..]);
                response.extend_from_slice(&0xC00C_u16.to_be_bytes());
                response.extend_from_slice(&1_u16.to_be_bytes());
                response.extend_from_slice(&1_u16.to_be_bytes());
                response.extend_from_slice(&60_u32.to_be_bytes());
                response.extend_from_slice(&4_u16.to_be_bytes());
                response.extend_from_slice(&[8, 8, 8, 8]);
                response
            };
            let client_ip = match source.ip() {
                std::net::IpAddr::V4(ip) => ip,
                std::net::IpAddr::V6(_) => panic!("expected ipv4 dns source"),
            };
            let mut reply = crate::ip_packet_tunnel::encode_ipv4_udp_packet(
                Ipv4Addr::new(1, 1, 1, 1),
                source,
                &response,
            )
            .unwrap();
            reply[20..22].copy_from_slice(&destination.port().to_be_bytes());
            reply[16..20].copy_from_slice(&client_ip.octets());
            let checksum = {
                let mut header = reply[..20].to_vec();
                header[10] = 0;
                header[11] = 0;
                let mut sum = 0_u32;
                let mut chunks = header.chunks_exact(2);
                for chunk in &mut chunks {
                    sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
                }
                while (sum >> 16) != 0 {
                    sum = (sum & 0xffff) + (sum >> 16);
                }
                !(sum as u16)
            };
            reply[10..12].copy_from_slice(&checksum.to_be_bytes());
            write_h2_capsule(&mut *stream, 0, &reply);
        });

        let stream = TcpStream::connect(addr).unwrap();
        let options = MasqueConnectOptions {
            private_key,
            public_key: server_public_key,
            ip: "10.10.0.2/32".into(),
            ipv6: String::new(),
            uri: "https://localhost/".into(),
            mtu: 1300,
            network: "h2".into(),
            remote_dns_resolve: true,
            dns: vec!["udp://1.1.1.1".into()],
        };
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: false,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let mut stream = open_masque_udp_stream(
            Box::new(stream),
            &TransportTarget::new("localhost", addr.port()),
            &options,
            &tls,
        )
        .unwrap();
        let resolved =
            crate::resolve_masque_host_via_udp_stream(&mut *stream, &options, "edge.example.com")
                .unwrap();
        assert_eq!(resolved, Ipv4Addr::new(8, 8, 8, 8));
        worker.join().unwrap();
    }

    #[test]
    fn masque_h2_tcp_stream_roundtrips_ip_packets() {
        let (tls_config, cert_pem, server_public_key) =
            build_tls_server_config_with_pem_and_public_key();
        register_test_root_certificate(&cert_pem).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (private_key, _client_public_key) = build_masque_key_material();

        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "CONNECT");
            assert_eq!(request.authority, "localhost");
            assert_eq!(request.path, "/");

            let mut session = None::<MasqueTestTcpSession>;
            loop {
                let (capsule_type, packet) = read_h2_capsule(&mut *stream);
                assert_eq!(capsule_type, 0);
                let ipv4 = SmolIpv4Packet::new_checked(&packet).unwrap();
                assert_eq!(ipv4.next_header(), SmolIpProtocol::Tcp);
                let tcp = SmolTcpPacket::new_checked(ipv4.payload()).unwrap();
                let src_ip = Ipv4Addr::from(ipv4.src_addr());
                let dst_ip = Ipv4Addr::from(ipv4.dst_addr());

                if tcp.syn() && !tcp.ack() {
                    let client_seq = tcp.seq_number().0 as u32;
                    let new_session = MasqueTestTcpSession {
                        client_ip: src_ip,
                        client_port: tcp.src_port(),
                        server_ip: dst_ip,
                        server_port: tcp.dst_port(),
                        server_seq: 0x1020_3040,
                        next_ack: client_seq.wrapping_add(1),
                        syn_acked: false,
                        pong_sent: false,
                    };
                    let syn_ack = build_masque_test_tcp_packet(
                        &new_session,
                        SmolTcpControl::Syn,
                        Some(new_session.next_ack),
                        new_session.server_seq,
                        &[],
                    );
                    let mut stored = new_session;
                    stored.server_seq = stored.server_seq.wrapping_add(1);
                    session = Some(stored);
                    write_h2_capsule(&mut *stream, 0, &syn_ack);
                    continue;
                }

                let Some(current) = session.as_mut() else {
                    continue;
                };
                if src_ip != current.client_ip
                    || dst_ip != current.server_ip
                    || tcp.src_port() != current.client_port
                    || tcp.dst_port() != current.server_port
                {
                    continue;
                }

                let payload = tcp.payload();
                let seq = tcp.seq_number().0 as u32;

                if tcp.ack() && !current.syn_acked && payload.is_empty() && seq == current.next_ack
                {
                    current.syn_acked = true;
                    continue;
                }

                if !payload.is_empty() && payload == b"ping" && !current.pong_sent {
                    current.next_ack = seq.wrapping_add(payload.len() as u32);
                    let pong = build_masque_test_tcp_packet(
                        current,
                        SmolTcpControl::Psh,
                        Some(current.next_ack),
                        current.server_seq,
                        b"pong",
                    );
                    current.server_seq = current.server_seq.wrapping_add(4);
                    current.pong_sent = true;
                    write_h2_capsule(&mut *stream, 0, &pong);
                    break;
                }
            }
        });

        let stream = TcpStream::connect(addr).unwrap();
        let options = MasqueConnectOptions {
            private_key,
            public_key: server_public_key,
            ip: "10.10.0.2/32".into(),
            ipv6: String::new(),
            uri: "https://localhost/".into(),
            mtu: 1300,
            network: "h2".into(),
            remote_dns_resolve: false,
            dns: Vec::new(),
        };
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: false,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let target = TransportTarget::new("8.8.8.8", 443);
        let mut stream = super::masque_stream::connect_stream(
            Box::new(stream),
            &TransportTarget::new("localhost", addr.port()),
            &options,
            &tls,
            &target,
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        let mut reply = [0_u8; 4];
        let read = stream.read(&mut reply).unwrap();
        assert_eq!(read, 4);
        assert_eq!(&reply, b"pong");
        worker.join().unwrap();
    }

    #[test]
    fn masque_h2_udp_stream_rejects_wrong_server_public_key() {
        let (tls_config, cert_pem, _server_public_key) =
            build_tls_server_config_with_pem_and_public_key();
        register_test_root_certificate(&cert_pem).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (private_key, wrong_public_key) = build_masque_key_material();

        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ = accept_h2_tls_test_stream(Box::new(stream), tls_config);
        });

        let stream = TcpStream::connect(addr).unwrap();
        let options = MasqueConnectOptions {
            private_key,
            public_key: wrong_public_key,
            ip: "10.10.0.2/32".into(),
            ipv6: String::new(),
            uri: "https://localhost/".into(),
            mtu: 1300,
            network: "h2".into(),
            remote_dns_resolve: false,
            dns: Vec::new(),
        };
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: false,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let err = match open_masque_udp_stream(
            Box::new(stream),
            &TransportTarget::new("localhost", addr.port()),
            &options,
            &tls,
        ) {
            Ok(_) => panic!("expected masque public-key pinning failure"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("ApplicationVerificationFailure")
                || err.to_string().contains("invalid peer certificate")
                || err.to_string().contains("certificate"),
            "{err}"
        );
        worker.join().unwrap();
    }

    #[test]
    fn masque_h2_udp_stream_roundtrips_over_boxed_tcp_relay() {
        let (tls_config, cert_pem, server_public_key) =
            build_tls_server_config_with_pem_and_public_key();
        register_test_root_certificate(&cert_pem).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();
        let relay = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let (private_key, _client_public_key) = build_masque_key_material();

        let server_worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "CONNECT");
            assert_eq!(request.authority, "localhost");

            let (capsule_type, packet) = read_h2_capsule(&mut *stream);
            assert_eq!(capsule_type, 0);
            let (source, destination, payload) =
                crate::ip_packet_tunnel::decode_ipv4_udp_packet_parts(&packet).unwrap();
            assert_eq!(destination, "8.8.8.8:53".parse().unwrap());
            assert_eq!(payload, b"via-masque-relay");

            let mut reply = crate::ip_packet_tunnel::encode_ipv4_udp_packet(
                Ipv4Addr::new(9, 9, 9, 9),
                source,
                b"masque-relay-ok",
            )
            .unwrap();
            reply[20..22].copy_from_slice(&destination.port().to_be_bytes());
            write_h2_capsule(&mut *stream, 0, &reply);
        });

        let relay_worker = thread::spawn(move || {
            let (downstream, _) = relay.accept().unwrap();
            let upstream = TcpStream::connect(server_addr).unwrap();
            let _ = downstream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
            let _ = downstream.set_write_timeout(Some(std::time::Duration::from_secs(1)));
            let _ = upstream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
            let _ = upstream.set_write_timeout(Some(std::time::Duration::from_secs(1)));
            let mut downstream_read = downstream.try_clone().unwrap();
            let mut downstream_write = downstream;
            let mut upstream_read = upstream.try_clone().unwrap();
            let mut upstream_write = upstream;
            let a = thread::spawn(move || {
                let _ = std::io::copy(&mut downstream_read, &mut upstream_write);
            });
            let b = thread::spawn(move || {
                let _ = std::io::copy(&mut upstream_read, &mut downstream_write);
            });
            let _ = a.join();
            let _ = b.join();
        });

        let stream = TcpStream::connect(relay_addr).unwrap();
        let options = MasqueConnectOptions {
            private_key,
            public_key: server_public_key,
            ip: "10.10.0.2/32".into(),
            ipv6: String::new(),
            uri: "https://localhost/".into(),
            mtu: 1300,
            network: "h2".into(),
            remote_dns_resolve: false,
            dns: Vec::new(),
        };
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: false,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let mut stream = open_masque_udp_stream(
            Box::new(stream),
            &TransportTarget::new("localhost", relay_addr.port()),
            &options,
            &tls,
        )
        .unwrap();
        write_masque_udp_packet(
            &mut *stream,
            "8.8.8.8:53".parse().unwrap(),
            b"via-masque-relay",
        )
        .unwrap();
        let (source, payload) = read_masque_udp_packet(&mut *stream).unwrap();
        assert_eq!(source, "9.9.9.9:53".parse().unwrap());
        assert_eq!(payload, b"masque-relay-ok");
        server_worker.join().unwrap();
        relay_worker.join().unwrap();
    }

    #[test]
    fn wireguard_udp_stream_resolves_remote_dns_over_tunnel() {
        let wg_server = TransportWireGuardServer::start();
        let options = super::wireguard_stream::WireGuardOptions {
            private_key: wg_server.client_private_key.clone(),
            ip: "100.64.0.2/32".into(),
            ipv6: String::new(),
            workers: 2,
            mtu: 1380,
            remote_dns_resolve: true,
            dns: vec!["udp://100.64.0.1:5353".into()],
            peers: vec![super::wireguard_stream::WireGuardPeerOptions {
                server: "127.0.0.1".into(),
                port: wg_server.addr.port(),
                public_key: wg_server.server_public_key.clone(),
                allowed_ips: vec!["100.64.0.0/24".into()],
                persistent_keepalive: 15,
            }],
        };
        let mut stream = super::wireguard_stream::open_udp_stream(&options).unwrap();
        let resolved =
            super::wireguard_stream::resolve_remote_target_host(&mut *stream, &options, "edge.example.com")
                .unwrap();
        assert_eq!(resolved, Ipv4Addr::new(100, 64, 0, 1));
        super::wireguard_stream::write_udp_packet(&mut *stream, "100.64.0.1:5353".parse().unwrap(), b"via-wireguard")
            .unwrap();
        let (source, payload) = super::wireguard_stream::read_udp_packet(&mut *stream).unwrap();
        assert_eq!(source, "100.64.0.1:5353".parse().unwrap());
        assert_eq!(payload, b"wireguard-ok");
        wg_server.shutdown();
    }

    #[test]
    fn wireguard_tcp_stream_resolves_remote_dns_over_tunnel() {
        let wg_server = TransportWireGuardServer::start();
        let plan = TransportPlan {
            requested: "edge-wg".into(),
            selected_path: vec!["edge-wg".into()],
            leaf_name: "edge-wg".into(),
            hops: vec![TransportHop {
                name: "edge-wg".into(),
                action: TransportAction::WireGuardConnect {
                    proxy: TransportTarget::new("127.0.0.1", wg_server.addr.port()),
                    private_key: wg_server.client_private_key.clone(),
                    ip: "100.64.0.2/32".into(),
                    ipv6: String::new(),
                    workers: 2,
                    tunnel_dns: super::TunnelDnsOptions {
                        remote_dns_resolve: true,
                        dns: vec!["udp://100.64.0.1:5353".into()],
                    },
                    peers: vec![super::WireGuardPeerTransportOptions {
                        server: "127.0.0.1".into(),
                        port: wg_server.addr.port(),
                        public_key: wg_server.server_public_key.clone(),
                        allowed_ips: vec!["100.64.0.0/24".into()],
                        persistent_keepalive: 15,
                    }],
                    outer_socks5: None,
                    mtu: 1380,
                    socket: SocketOptions::default(),
                    target: TransportTarget::new("edge.example.com", 8080),
                },
            }],
        };
        let mut executor = TcpTransportExecutor::new(SystemTcpDialer);
        let mut stream = executor.run_plan(&plan).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.shutdown_write().unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"pong-wireguard");
        wg_server.shutdown();
    }

    #[test]
    fn masque_h2_tcp_stream_roundtrips_over_boxed_tcp_relay() {
        let (tls_config, cert_pem, server_public_key) =
            build_tls_server_config_with_pem_and_public_key();
        register_test_root_certificate(&cert_pem).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();
        let relay = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let (private_key, _client_public_key) = build_masque_key_material();

        let server_worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (request, mut stream) =
                accept_h2_tls_test_stream(Box::new(stream), tls_config).unwrap();
            assert_eq!(request.method, "CONNECT");
            assert_eq!(request.authority, "localhost");

            let mut session = None::<MasqueTestTcpSession>;
            loop {
                let (capsule_type, packet) = read_h2_capsule(&mut *stream);
                assert_eq!(capsule_type, 0);
                let ipv4 = SmolIpv4Packet::new_checked(&packet).unwrap();
                assert_eq!(ipv4.next_header(), SmolIpProtocol::Tcp);
                let tcp = SmolTcpPacket::new_checked(ipv4.payload()).unwrap();
                let src_ip = Ipv4Addr::from(ipv4.src_addr());
                let dst_ip = Ipv4Addr::from(ipv4.dst_addr());

                if tcp.syn() && !tcp.ack() {
                    let client_seq = tcp.seq_number().0 as u32;
                    let new_session = MasqueTestTcpSession {
                        client_ip: src_ip,
                        client_port: tcp.src_port(),
                        server_ip: dst_ip,
                        server_port: tcp.dst_port(),
                        server_seq: 0x1020_3040,
                        next_ack: client_seq.wrapping_add(1),
                        syn_acked: false,
                        pong_sent: false,
                    };
                    let syn_ack = build_masque_test_tcp_packet(
                        &new_session,
                        SmolTcpControl::Syn,
                        Some(new_session.next_ack),
                        new_session.server_seq,
                        &[],
                    );
                    let mut stored = new_session;
                    stored.server_seq = stored.server_seq.wrapping_add(1);
                    session = Some(stored);
                    write_h2_capsule(&mut *stream, 0, &syn_ack);
                    continue;
                }

                let Some(current) = session.as_mut() else {
                    continue;
                };
                if src_ip != current.client_ip
                    || dst_ip != current.server_ip
                    || tcp.src_port() != current.client_port
                    || tcp.dst_port() != current.server_port
                {
                    continue;
                }

                let payload = tcp.payload();
                let seq = tcp.seq_number().0 as u32;

                if tcp.ack() && !current.syn_acked && payload.is_empty() && seq == current.next_ack
                {
                    current.syn_acked = true;
                    continue;
                }

                if !payload.is_empty() && payload == b"ping" && !current.pong_sent {
                    current.next_ack = seq.wrapping_add(payload.len() as u32);
                    let pong = build_masque_test_tcp_packet(
                        current,
                        SmolTcpControl::Psh,
                        Some(current.next_ack),
                        current.server_seq,
                        b"pong",
                    );
                    current.server_seq = current.server_seq.wrapping_add(4);
                    current.pong_sent = true;
                    write_h2_capsule(&mut *stream, 0, &pong);
                    break;
                }
            }
        });

        let relay_worker = thread::spawn(move || {
            let (downstream, _) = relay.accept().unwrap();
            let upstream = TcpStream::connect(server_addr).unwrap();
            let _ = downstream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
            let _ = downstream.set_write_timeout(Some(std::time::Duration::from_secs(1)));
            let _ = upstream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
            let _ = upstream.set_write_timeout(Some(std::time::Duration::from_secs(1)));
            let mut downstream_read = downstream.try_clone().unwrap();
            let mut downstream_write = downstream;
            let mut upstream_read = upstream.try_clone().unwrap();
            let mut upstream_write = upstream;
            let a = thread::spawn(move || {
                let _ = std::io::copy(&mut downstream_read, &mut upstream_write);
            });
            let b = thread::spawn(move || {
                let _ = std::io::copy(&mut upstream_read, &mut downstream_write);
            });
            let _ = a.join();
            let _ = b.join();
        });

        let stream = TcpStream::connect(relay_addr).unwrap();
        let options = MasqueConnectOptions {
            private_key,
            public_key: server_public_key,
            ip: "10.10.0.2/32".into(),
            ipv6: String::new(),
            uri: "https://localhost/".into(),
            mtu: 1300,
            network: "h2".into(),
            remote_dns_resolve: false,
            dns: Vec::new(),
        };
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: false,
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        };
        let target = TransportTarget::new("8.8.8.8", 443);
        let mut stream = super::masque_stream::connect_stream(
            Box::new(stream),
            &TransportTarget::new("localhost", relay_addr.port()),
            &options,
            &tls,
            &target,
        )
        .unwrap();
        stream.write_all(b"ping").unwrap();
        let mut reply = [0_u8; 4];
        let read = stream.read(&mut reply).unwrap();
        assert_eq!(read, 4);
        assert_eq!(&reply, b"pong");
        server_worker.join().unwrap();
        relay_worker.join().unwrap();
    }
