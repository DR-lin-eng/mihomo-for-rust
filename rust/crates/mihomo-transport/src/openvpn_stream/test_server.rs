use std::io;
use std::io::{Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, SocketAddr, TcpListener as NetTcpListener, UdpSocket as NetUdpSocket,
};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection, StreamOwned};
use rustls::server::AllowAnyAuthenticatedClient;
use smoltcp::wire::{
    IpAddress as SmolIpAddress, IpProtocol as SmolIpProtocol, Ipv4Address as SmolIpv4Address,
    Ipv4Packet as SmolIpv4Packet, Ipv4Repr as SmolIpv4Repr, TcpControl as SmolTcpControl,
    TcpPacket as SmolTcpPacket, TcpRepr as SmolTcpRepr, TcpSeqNumber as SmolTcpSeqNumber,
};

use crate::TransportError;

use super::{
    decode_static_key, derive_client_key_material, marshal_server_key_method2_record,
    new_tls_crypt_keys, parse_client_key_method2_record, read_null_terminated_message,
    swap_key_material, udp_bridge, ControlChannel, ControlConn, DataChannel, KeySource,
    KeySource2, OpenVpnOpcode, PacketIo, PacketMux, StreamPacketIo, DEFAULT_HANDSHAKE_TIMEOUT,
    OPENVPN_TEST_CA_PEM, OPENVPN_TEST_KEY_PEM, OPENVPN_TEST_TLS_CRYPT_PEM, PUSH_REQUEST,
};

pub struct OpenVpnTestServer {
    addr: SocketAddr,
    shutdown_tx: mpsc::Sender<()>,
    thread: Option<thread::JoinHandle<()>>,
}

#[derive(Clone, Debug, Default)]
struct OpenVpnTestServerTlsConfig {
    client_cert_der: Option<Vec<u8>>,
}

struct OpenVpnTestTcpSession {
    client_ip: Ipv4Addr,
    client_port: u16,
    server_ip: Ipv4Addr,
    server_port: u16,
    server_seq: u32,
    next_ack: u32,
    syn_acked: bool,
    pong_sent: bool,
}

struct ServerDatagramPacketIo {
    socket: NetUdpSocket,
    peer: Option<SocketAddr>,
}

impl OpenVpnTestServer {
    pub fn start() -> io::Result<Self> {
        Self::start_with_tls_config(OpenVpnTestServerTlsConfig::default())
    }

    pub fn start_with_client_auth(client_cert_der: Vec<u8>) -> io::Result<Self> {
        Self::start_with_tls_config(OpenVpnTestServerTlsConfig {
            client_cert_der: Some(client_cert_der),
        })
    }

    pub fn start_tcp() -> io::Result<Self> {
        Self::start_tcp_with_tls_config(OpenVpnTestServerTlsConfig::default())
    }

    pub fn start_tcp_with_client_auth(client_cert_der: Vec<u8>) -> io::Result<Self> {
        Self::start_tcp_with_tls_config(OpenVpnTestServerTlsConfig {
            client_cert_der: Some(client_cert_der),
        })
    }

    fn start_with_tls_config(tls_config: OpenVpnTestServerTlsConfig) -> io::Result<Self> {
        let socket = NetUdpSocket::bind("127.0.0.1:0")?;
        let addr = socket.local_addr()?;
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            let _ = run_openvpn_test_server(
                Box::new(ServerDatagramPacketIo::new(socket)),
                shutdown_rx,
                tls_config,
            );
        });
        Ok(Self {
            addr,
            shutdown_tx,
            thread: Some(thread),
        })
    }

    fn start_tcp_with_tls_config(tls_config: OpenVpnTestServerTlsConfig) -> io::Result<Self> {
        let listener = NetTcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            let _ = run_openvpn_test_server_tcp_listener(listener, shutdown_rx, tls_config);
        });
        Ok(Self {
            addr,
            shutdown_tx,
            thread: Some(thread),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn ca_pem(&self) -> &'static str {
        OPENVPN_TEST_CA_PEM
    }

    pub fn tls_crypt_pem(&self) -> &'static str {
        OPENVPN_TEST_TLS_CRYPT_PEM
    }

    pub fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl ServerDatagramPacketIo {
    fn new(socket: NetUdpSocket) -> Self {
        Self { socket, peer: None }
    }
}

impl PacketIo for ServerDatagramPacketIo {
    fn read_packet(&mut self, timeout: Option<Duration>) -> io::Result<Vec<u8>> {
        self.socket.set_read_timeout(timeout)?;
        let mut buf = [0_u8; 64 * 1024];
        let (read, peer) = self.socket.recv_from(&mut buf)?;
        self.peer = Some(peer);
        Ok(buf[..read].to_vec())
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let peer = self
            .peer
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "openvpn test peer not learned"))?;
        self.socket.send_to(packet, peer).map(|_| ())
    }

    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn remote_addr(&self) -> io::Result<SocketAddr> {
        self.peer
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "openvpn test peer not learned"))
    }
}

fn run_openvpn_test_server(
    io: Box<dyn PacketIo>,
    shutdown_rx: mpsc::Receiver<()>,
    tls_config: OpenVpnTestServerTlsConfig,
) -> Result<(), TransportError> {
    let static_key = decode_static_key(OPENVPN_TEST_TLS_CRYPT_PEM.as_bytes())?;
    let server_crypt = new_tls_crypt_keys(&static_key, false)?;
    let server_mux = Arc::new(Mutex::new(PacketMux::new(io)));
    let server_control = ControlChannel::new(Arc::clone(&server_mux), server_crypt, *b"server01");

    let reset = server_control
        .read(Some(DEFAULT_HANDSHAKE_TIMEOUT))
        .map_err(TransportError::from)?;
    server_control.set_remote_session_id(reset.local_session);
    server_control
        .send(OpenVpnOpcode::ControlHardResetServerV2, &[])
        .map_err(TransportError::from)?;

    let mut tls = StreamOwned::new(
        ServerConnection::new(build_openvpn_test_server_config(&tls_config)?).map_err(|err| {
            TransportError::InvalidPlan(format!("openvpn test server tls config: {err}"))
        })?,
        ControlConn::new(server_control.clone()),
    );
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }

    let mut km2_buf = vec![0_u8; 1024];
    let read = tls.read(&mut km2_buf)?;
    let client_record = parse_client_key_method2_record(&km2_buf[..read])?;
    let server_random1 = [0x31_u8; 32];
    let server_random2 = [0x41_u8; 32];
    let server_record = marshal_server_key_method2_record(
        server_random1,
        server_random2,
        &client_record.options,
        "IV_VER=server\n",
    );
    tls.write_all(&server_record)?;
    tls.flush()?;

    let keys = derive_client_key_material(
        &KeySource2 {
            client: client_record.sources.client.clone(),
            server: KeySource {
                pre_master: [0_u8; 48],
                random1: server_random1,
                random2: server_random2,
            },
        },
        &reset.local_session,
        &server_control.local_session_id(),
        16,
    )?;
    let server_keys = swap_key_material(&keys);

    let push_request = read_null_terminated_message(&mut tls)?;
    if push_request != PUSH_REQUEST {
        return Err(TransportError::InvalidPlan(format!(
            "unexpected openvpn push request {:?}",
            push_request
        )));
    }
    tls.write_all(
        b"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,dhcp-option DNS 1.1.1.1,peer-id 7\0",
    )?;
    tls.flush()?;

    let mut server_data = DataChannel::new(&server_keys, 7)?;
    let mut tcp_session = None;
    loop {
        if shutdown_rx.try_recv().is_ok() {
            break;
        }
        let encrypted = match server_mux
            .lock()
            .map_err(|_| io::Error::other("openvpn test server packet mux mutex poisoned"))?
            .read_data_packet(Some(Duration::from_millis(100)))
        {
            Ok(packet) => packet,
            Err(err)
                if matches!(err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) =>
            {
                continue;
            }
            Err(err) => return Err(TransportError::from(err)),
        };
        let packet = match server_data.decrypt(&encrypted) {
            Ok(packet) => packet,
            Err(_) => continue,
        };
        match handle_openvpn_test_server_ip_packet(&packet, &mut tcp_session)? {
            Some(response) => {
                let encrypted = server_data.encrypt(&response)?;
                server_mux
                    .lock()
                    .map_err(|_| io::Error::other("openvpn test server packet mux mutex poisoned"))?
                    .write_packet(&encrypted)?;
            }
            None => continue,
        }
    }
    Ok(())
}

fn run_openvpn_test_server_tcp_listener(
    listener: NetTcpListener,
    shutdown_rx: mpsc::Receiver<()>,
    tls_config: OpenVpnTestServerTlsConfig,
) -> Result<(), TransportError> {
    listener.set_nonblocking(true)?;
    loop {
        if shutdown_rx.try_recv().is_ok() {
            return Ok(());
        }
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                return run_openvpn_test_server(
                    Box::new(StreamPacketIo::new(stream)),
                    shutdown_rx,
                    tls_config,
                );
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(TransportError::from(err)),
        }
    }
}

fn handle_openvpn_test_server_ip_packet(
    packet: &[u8],
    tcp_session: &mut Option<OpenVpnTestTcpSession>,
) -> Result<Option<Vec<u8>>, TransportError> {
    let ipv4 = SmolIpv4Packet::new_checked(packet)
        .map_err(|_| TransportError::InvalidPlan("openvpn test server ipv4 packet truncated".to_owned()))?;
    if !ipv4.verify_checksum() {
        return Err(TransportError::InvalidPlan(
            "openvpn test server received ipv4 packet with invalid checksum".to_owned(),
        ));
    }

    match ipv4.next_header() {
        SmolIpProtocol::Udp => handle_openvpn_test_server_udp_packet(packet).map(Some),
        SmolIpProtocol::Tcp => handle_openvpn_test_server_tcp_packet(packet, tcp_session),
        protocol => Err(TransportError::InvalidPlan(format!(
            "openvpn test server unsupported ipv4 protocol: {protocol}"
        ))),
    }
}

fn handle_openvpn_test_server_udp_packet(packet: &[u8]) -> Result<Vec<u8>, TransportError> {
    let (source, destination, payload) = udp_bridge::decode_ipv4_udp_packet_parts(packet)?;
    let source_ip = match source.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => {
            return Err(TransportError::InvalidPlan(
                "openvpn test server expects ipv4 udp packets".to_owned(),
            ))
        }
    };
    if payload == b"via-openvpn" {
        let response = udp_bridge::encode_ipv4_udp_packet(
            Ipv4Addr::new(8, 8, 8, 8),
            SocketAddr::new(IpAddr::V4(source_ip), source.port()),
            b"openvpn-ok",
        )?;
        let mut response = response;
        response[20..22].copy_from_slice(&destination.port().to_be_bytes());
        return Ok(response);
    }

    if destination == "10.8.0.1:5353".parse().unwrap() {
        let query_id = u16::from_be_bytes([payload[0], payload[1]]);
        let expected = mihomo_dns::build_dns_query_for_tests(
            "edge.example.com",
            mihomo_dns::DnsRecordType::A,
            query_id,
        )
        .map_err(|err| TransportError::InvalidPlan(err.to_string()))?;
        if payload == expected {
            let mut dns_response = Vec::new();
            dns_response.extend_from_slice(&query_id.to_be_bytes());
            dns_response.extend_from_slice(&0x8180_u16.to_be_bytes());
            dns_response.extend_from_slice(&1_u16.to_be_bytes());
            dns_response.extend_from_slice(&1_u16.to_be_bytes());
            dns_response.extend_from_slice(&0_u16.to_be_bytes());
            dns_response.extend_from_slice(&0_u16.to_be_bytes());
            dns_response.extend_from_slice(&payload[12..]);
            dns_response.extend_from_slice(&0xC00C_u16.to_be_bytes());
            dns_response.extend_from_slice(&1_u16.to_be_bytes());
            dns_response.extend_from_slice(&1_u16.to_be_bytes());
            dns_response.extend_from_slice(&60_u32.to_be_bytes());
            dns_response.extend_from_slice(&4_u16.to_be_bytes());
            dns_response.extend_from_slice(&[10, 8, 0, 1]);
            let response = udp_bridge::encode_ipv4_udp_packet(
                Ipv4Addr::new(10, 8, 0, 1),
                SocketAddr::new(IpAddr::V4(source_ip), source.port()),
                &dns_response,
            )?;
            let mut response = response;
            response[20..22].copy_from_slice(&destination.port().to_be_bytes());
            return Ok(response);
        }
    }

    let response = udp_bridge::encode_ipv4_udp_packet(
        Ipv4Addr::new(8, 8, 8, 8),
        SocketAddr::new(IpAddr::V4(source_ip), source.port()),
        b"openvpn-unknown",
    )?;
    let mut response = response;
    response[20..22].copy_from_slice(&destination.port().to_be_bytes());
    Ok(response)
}

fn handle_openvpn_test_server_tcp_packet(
    packet: &[u8],
    tcp_session: &mut Option<OpenVpnTestTcpSession>,
) -> Result<Option<Vec<u8>>, TransportError> {
    let ipv4 = SmolIpv4Packet::new_checked(packet)
        .map_err(|_| TransportError::InvalidPlan("openvpn test server ipv4 tcp packet truncated".to_owned()))?;
    let src_ip = Ipv4Addr::from(ipv4.src_addr());
    let dst_ip = Ipv4Addr::from(ipv4.dst_addr());
    let tcp = SmolTcpPacket::new_checked(ipv4.payload())
        .map_err(|_| TransportError::InvalidPlan("openvpn test server tcp packet truncated".to_owned()))?;
    let src_addr = SmolIpAddress::Ipv4(ipv4.src_addr());
    let dst_addr = SmolIpAddress::Ipv4(ipv4.dst_addr());
    if !tcp.verify_checksum(&src_addr, &dst_addr) {
        return Err(TransportError::InvalidPlan(
            "openvpn test server received tcp packet with invalid checksum".to_owned(),
        ));
    }

    if tcp.dst_port() != 443 {
        return Ok(None);
    }

    if tcp.rst() {
        return Ok(None);
    }

    if tcp.syn() && !tcp.ack() {
        let client_seq = tcp.seq_number().0 as u32;
        let session = OpenVpnTestTcpSession {
            client_ip: src_ip,
            client_port: tcp.src_port(),
            server_ip: dst_ip,
            server_port: tcp.dst_port(),
            server_seq: 0x1020_3040,
            next_ack: client_seq.wrapping_add(1),
            syn_acked: false,
            pong_sent: false,
        };
        let response = build_openvpn_test_server_tcp_packet(
            &session,
            SmolTcpControl::Syn,
            Some(session.next_ack),
            session.server_seq,
            &[],
        )?;
        let mut session = session;
        session.server_seq = session.server_seq.wrapping_add(1);
        *tcp_session = Some(session);
        return Ok(Some(response));
    }

    let Some(session) = tcp_session.as_mut() else {
        return Ok(None);
    };
    if src_ip != session.client_ip
        || dst_ip != session.server_ip
        || tcp.src_port() != session.client_port
        || tcp.dst_port() != session.server_port
    {
        return Ok(None);
    }

    let payload = tcp.payload();
    let seq = tcp.seq_number().0 as u32;

    if tcp.ack() && !session.syn_acked && payload.is_empty() && seq == session.next_ack {
        session.syn_acked = true;
        return Ok(None);
    }

    if !payload.is_empty() && payload == b"ping" && !session.pong_sent {
        session.next_ack = seq.wrapping_add(payload.len() as u32);
        let response = build_openvpn_test_server_tcp_packet(
            session,
            SmolTcpControl::Psh,
            Some(session.next_ack),
            session.server_seq,
            b"pong",
        )?;
        session.server_seq = session.server_seq.wrapping_add(4);
        session.pong_sent = true;
        return Ok(Some(response));
    }

    if tcp.fin() {
        session.next_ack = seq.wrapping_add(1);
        let response = build_openvpn_test_server_tcp_packet(
            session,
            SmolTcpControl::Fin,
            Some(session.next_ack),
            session.server_seq,
            &[],
        )?;
        session.server_seq = session.server_seq.wrapping_add(1);
        return Ok(Some(response));
    }

    Ok(None)
}

fn build_openvpn_test_server_tcp_packet(
    session: &OpenVpnTestTcpSession,
    control: SmolTcpControl,
    ack_number: Option<u32>,
    seq_number: u32,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
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
        ip_repr.emit(&mut ipv4_packet, &smoltcp::phy::ChecksumCapabilities::default());
    }
    {
        let mut tcp_packet = SmolTcpPacket::new_unchecked(&mut bytes[ip_repr.buffer_len()..]);
        tcp_repr.emit(
            &mut tcp_packet,
            &SmolIpAddress::Ipv4(src_ip),
            &SmolIpAddress::Ipv4(dst_ip),
            &smoltcp::phy::ChecksumCapabilities::default(),
        );
    }
    Ok(bytes)
}

fn build_openvpn_test_server_config(
    tls_config: &OpenVpnTestServerTlsConfig,
) -> Result<Arc<ServerConfig>, TransportError> {
    let mut cert_reader = std::io::Cursor::new(OPENVPN_TEST_CA_PEM.as_bytes());
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .map_err(|err| TransportError::InvalidPlan(format!("parse openvpn test cert: {err}")))?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<_>>();
    if certs.is_empty() {
        return Err(TransportError::InvalidPlan(
            "parse openvpn test certificate".to_owned(),
        ));
    }
    let mut key_reader = std::io::Cursor::new(OPENVPN_TEST_KEY_PEM.as_bytes());
    let key = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .map_err(|err| TransportError::InvalidPlan(format!("parse openvpn test key: {err}")))?
        .into_iter()
        .next()
        .map(PrivateKey)
        .ok_or_else(|| TransportError::InvalidPlan("parse openvpn test private key".to_owned()))?;

    let builder = ServerConfig::builder().with_safe_defaults();
    let server = if let Some(client_cert_der) = &tls_config.client_cert_der {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(&Certificate(client_cert_der.clone()))
            .map_err(|err| TransportError::InvalidPlan(format!("parse openvpn test client cert: {err}")))?;
        let verifier = AllowAnyAuthenticatedClient::new(roots);
        builder
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(certs, key)
    } else {
        builder.with_no_client_auth().with_single_cert(certs, key)
    };
    Ok(Arc::new(server.map_err(|err| {
        TransportError::InvalidPlan(format!("openvpn test server config: {err}"))
    })?))
}
