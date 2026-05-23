use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use mihomo_core::{BoxedTcpStream, TcpStream};
use uuid::Uuid;

use crate::{packetaddr_magic_target, TransportError, TransportTarget};

const VERSION: u8 = 0;
const COMMAND_TCP: u8 = 0x01;
const COMMAND_UDP: u8 = 0x02;
const COMMAND_MUX: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;
const XUDP_STATUS_NEW: u8 = 0x01;
const XUDP_STATUS_KEEP: u8 = 0x02;
const XUDP_STATUS_END: u8 = 0x03;
const XUDP_STATUS_KEEPALIVE: u8 = 0x04;
const XUDP_OPTION_DATA: u8 = 0x01;
const XUDP_NETWORK_UDP: u8 = 0x02;
#[cfg(test)]
const VLESS_MUX_TARGET: &str = "v1.mux.cool:666";

pub(crate) fn wrap_stream(
    stream: BoxedTcpStream,
    uuid: &str,
    target: &TransportTarget,
) -> Result<BoxedTcpStream, TransportError> {
    Ok(Box::new(VlessStream::new(
        stream,
        build_request(uuid, COMMAND_TCP, Some(target))?,
    )?))
}

pub(crate) fn open_udp_stream(
    stream: BoxedTcpStream,
    uuid: &str,
    target: SocketAddr,
) -> Result<BoxedTcpStream, TransportError> {
    let target = TransportTarget::new(target.ip().to_string(), target.port());
    let mut stream = VlessStream::new(stream, build_request(uuid, COMMAND_UDP, Some(&target))?)?;
    stream.ensure_request_sent(&[])?;
    Ok(Box::new(stream))
}

pub(crate) fn open_packetaddr_udp_stream(
    stream: BoxedTcpStream,
    uuid: &str,
) -> Result<BoxedTcpStream, TransportError> {
    let target = packetaddr_magic_target();
    let mut stream = VlessStream::new(stream, build_request(uuid, COMMAND_UDP, Some(&target))?)?;
    stream.ensure_request_sent(&[])?;
    Ok(Box::new(stream))
}

pub(crate) fn open_xudp_stream(
    stream: BoxedTcpStream,
    uuid: &str,
) -> Result<BoxedTcpStream, TransportError> {
    let mut stream = VlessStream::new(stream, build_request(uuid, COMMAND_MUX, None)?)?;
    stream.ensure_request_sent(&[])?;
    Ok(Box::new(stream))
}

pub(crate) fn write_udp_packet(stream: &mut dyn Write, payload: &[u8]) -> io::Result<usize> {
    if payload.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("vless udp packet too large: {}", payload.len()),
        ));
    }
    stream.write_all(&(payload.len() as u16).to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(payload.len())
}

pub(crate) fn read_udp_packet(stream: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length)?;
    let length = u16::from_be_bytes(length) as usize;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

pub(crate) fn write_xudp_packet(
    stream: &mut dyn Write,
    target: SocketAddr,
    payload: &[u8],
) -> io::Result<usize> {
    let target = encode_xudp_addr(target);
    let header_len = 5 + target.len();
    if header_len > u16::MAX as usize || payload.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "vless xudp packet too large",
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
                    "vless xudp stream closed",
                ))
            }
            XUDP_STATUS_KEEPALIVE => {
                if header_len < 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vless xudp keepalive header too short",
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
                    format!("unexpected vless xudp status {other}"),
                ))
            }
        }
        if header[3] & 0x02 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "vless xudp remote closed",
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
                "vless xudp header too short",
            ));
        }
        if remaining.first().copied() != Some(XUDP_NETWORK_UDP) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected vless xudp network type",
            ));
        }
        let (target, consumed) = decode_xudp_addr(&remaining[1..])?;
        if 1 + consumed + 2 != remaining.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vless xudp payload length trailer is malformed",
            ));
        }
        let payload_len =
            u16::from_be_bytes([remaining[1 + consumed], remaining[1 + consumed + 1]]) as usize;
        let mut payload = vec![0_u8; payload_len];
        stream.read_exact(&mut payload)?;
        return Ok((target, payload));
    }
}

fn build_request(
    uuid: &str,
    command: u8,
    target: Option<&TransportTarget>,
) -> Result<Vec<u8>, TransportError> {
    let uuid = Uuid::parse_str(uuid).map_err(|err| {
        TransportError::InvalidPlan(format!("invalid vless uuid {uuid:?}: {err}"))
    })?;
    let target_host_len = target.map(|target| target.host.len()).unwrap_or_default();
    let mut request = Vec::with_capacity(1 + 16 + 1 + 1 + 2 + 1 + target_host_len + 16);
    request.push(VERSION);
    request.extend_from_slice(uuid.as_bytes());
    request.push(0);
    request.push(command);
    if command != COMMAND_MUX {
        let target = target.ok_or_else(|| {
            TransportError::InvalidPlan("vless non-mux request requires target".to_owned())
        })?;
        request.extend_from_slice(&target.port.to_be_bytes());
        encode_addr_into(&mut request, target)?;
    }
    Ok(request)
}

fn encode_addr_into(buffer: &mut Vec<u8>, target: &TransportTarget) -> Result<(), TransportError> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(addr) => {
                buffer.push(ATYP_IPV4);
                buffer.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                buffer.push(ATYP_IPV6);
                buffer.extend_from_slice(&addr.octets());
            }
        }
        return Ok(());
    }

    let host = target.host.as_bytes();
    if host.len() > u8::MAX as usize {
        return Err(TransportError::InvalidPlan(
            "vless domain target must fit within 255 bytes".to_owned(),
        ));
    }
    buffer.push(ATYP_DOMAIN);
    buffer.push(host.len() as u8);
    buffer.extend_from_slice(host);
    Ok(())
}

struct VlessStream {
    inner: BoxedTcpStream,
    request: Vec<u8>,
    request_sent: bool,
    response_received: bool,
}

impl VlessStream {
    fn new(inner: BoxedTcpStream, request: Vec<u8>) -> Result<Self, TransportError> {
        Ok(Self {
            inner,
            request,
            request_sent: false,
            response_received: false,
        })
    }

    fn ensure_request_sent(&mut self, payload: &[u8]) -> io::Result<()> {
        if self.request_sent {
            if !payload.is_empty() {
                self.inner.write_all(payload)?;
            }
            return Ok(());
        }
        self.inner.write_all(&self.request)?;
        if !payload.is_empty() {
            self.inner.write_all(payload)?;
        }
        self.inner.flush()?;
        self.request_sent = true;
        Ok(())
    }

    fn ensure_response_received(&mut self) -> io::Result<()> {
        if self.response_received {
            return Ok(());
        }
        let mut header = [0_u8; 2];
        self.inner.read_exact(&mut header)?;
        if header[0] != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected vless response version {}", header[0]),
            ));
        }
        let addon_len = header[1] as usize;
        if addon_len != 0 {
            let mut discard = vec![0_u8; addon_len];
            self.inner.read_exact(&mut discard)?;
        }
        self.response_received = true;
        Ok(())
    }
}

fn encode_xudp_addr(target: SocketAddr) -> Vec<u8> {
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
    out
}

fn decode_xudp_addr(payload: &[u8]) -> io::Result<(SocketAddr, usize)> {
    if payload.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "vless xudp address too short",
        ));
    }
    let port = u16::from_be_bytes([payload[0], payload[1]]);
    match payload[2] {
        ATYP_IPV4 => {
            if payload.len() < 7 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "vless xudp ipv4 address truncated",
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
                    "vless xudp ipv6 address truncated",
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
                    "vless xudp domain length missing",
                ));
            }
            let length = payload[3] as usize;
            if payload.len() < 4 + length {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "vless xudp domain address truncated",
                ));
            }
            let host = String::from_utf8_lossy(&payload[4..4 + length]).into_owned();
            let mut addrs = (host.as_str(), port).to_socket_addrs()?;
            let addr = addrs.next().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "vless xudp domain target unresolved",
                )
            })?;
            Ok((addr, 4 + length))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported vless xudp atyp {other}"),
        )),
    }
}

impl Read for VlessStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.ensure_response_received()?;
        self.inner.read(buf)
    }
}

impl Write for VlessStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.ensure_request_sent(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpStream for VlessStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "vless stream does not support cloning",
        ))
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.ensure_request_sent(&[])?;
        self.inner.shutdown_write()
    }

    fn shutdown_all(&mut self) -> io::Result<()> {
        self.inner.shutdown_all()
    }
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
    use uuid::Uuid;

    use super::{
        open_udp_stream, open_xudp_stream, read_udp_packet, read_xudp_packet, write_udp_packet,
        write_xudp_packet, ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, COMMAND_MUX, COMMAND_TCP,
        COMMAND_UDP, VERSION, VLESS_MUX_TARGET,
    };

    enum AcceptedStream {
        Tcp,
        Udp,
        Xudp,
    }

    #[test]
    fn vless_tcp_stream_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (version, uuid, command, target, accepted) = read_request(&mut stream);
            assert_eq!(version, VERSION);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, COMMAND_TCP);
            assert_eq!(target, "final.example.com:443");
            match accepted {
                AcceptedStream::Tcp => {}
                _ => panic!("expected accepted tcp request"),
            }
            stream.write_all(&[VERSION, 0]).unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong-vless").unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
        });

        let plan = TransportPlan {
            requested: "edge-vless".into(),
            selected_path: vec!["edge-vless".into()],
            leaf_name: "edge-vless".into(),
            hops: vec![TransportHop {
                name: "edge-vless".into(),
                action: TransportAction::VlessConnect {
                    proxy: TransportTarget::new("127.0.0.1", addr.port()),
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    udp: false,
                    flow: String::new(),
                    network: String::new(),
                    websocket: crate::WebsocketOptions::default(),
                    grpc: crate::GrpcOptions::default(),
                    h2: crate::Http2Options::default(),
                    http: crate::HttpStreamOptions::default(),
                    xhttp: crate::XHttpOptions::default(),
                    encryption: String::new(),
                    packet_addr: false,
                    xudp: false,
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
        assert_eq!(reply, b"pong-vless");
        worker.join().unwrap();
    }

    #[test]
    fn vless_udp_stream_round_trip_preserves_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (version, uuid, command, target, accepted) = read_request(&mut stream);
            assert_eq!(version, VERSION);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, COMMAND_UDP);
            assert_eq!(target, "127.0.0.1:5353");
            match accepted {
                AcceptedStream::Udp => {}
                _ => panic!("expected accepted udp request"),
            }
            stream.write_all(&[VERSION, 0]).unwrap();
            let mut len = [0_u8; 2];
            stream.read_exact(&mut len).unwrap();
            let len = u16::from_be_bytes(len) as usize;
            let mut payload = vec![0_u8; len];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(payload, b"via-vless");
            stream.write_all(&(8_u16.to_be_bytes())).unwrap();
            stream.write_all(b"vless-ok").unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
        });

        let mut stream = open_udp_stream(
            Box::new(std::net::TcpStream::connect(addr).unwrap()),
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            "127.0.0.1:5353".parse().unwrap(),
        )
        .unwrap();
        write_udp_packet(&mut *stream, b"via-vless").unwrap();
        let payload = read_udp_packet(&mut *stream).unwrap();
        assert_eq!(payload, b"vless-ok");
        worker.join().unwrap();
    }

    #[test]
    fn vless_xudp_stream_round_trip_preserves_target_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (version, uuid, command, target, accepted) = read_request(&mut stream);
            assert_eq!(version, VERSION);
            assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
            assert_eq!(command, COMMAND_MUX);
            assert_eq!(target, VLESS_MUX_TARGET);
            match accepted {
                AcceptedStream::Xudp => {}
                _ => panic!("expected accepted xudp request"),
            }
            stream.write_all(&[VERSION, 0]).unwrap();
            let (target, payload) = read_xudp_packet(&mut stream).unwrap();
            assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
            assert_eq!(payload, b"via-vless");
            write_xudp_packet(&mut stream, target, b"vless-ok").unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
        });

        let mut stream = open_xudp_stream(
            Box::new(std::net::TcpStream::connect(addr).unwrap()),
            "b831381d-6324-4d53-ad4f-8cda48b30811",
        )
        .unwrap();
        write_xudp_packet(&mut *stream, "127.0.0.1:5353".parse().unwrap(), b"via-vless")
            .unwrap();
        let (target, payload) = read_xudp_packet(&mut *stream).unwrap();
        assert_eq!(target, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(payload, b"vless-ok");
        worker.join().unwrap();
    }

    #[test]
    fn vless_xudp_reader_skips_keepalive_and_no_data_frames() {
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
    fn vless_xudp_reader_supports_domain_targets() {
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

    fn read_request(stream: &mut dyn Read) -> (u8, String, u8, String, AcceptedStream) {
        let mut version = [0_u8; 1];
        stream.read_exact(&mut version).unwrap();
        let mut uuid = [0_u8; 16];
        stream.read_exact(&mut uuid).unwrap();
        let mut addon_len = [0_u8; 1];
        stream.read_exact(&mut addon_len).unwrap();
        assert_eq!(addon_len[0], 0);
        let mut command = [0_u8; 1];
        stream.read_exact(&mut command).unwrap();
        if command[0] == COMMAND_MUX {
            return (
                version[0],
                Uuid::from_bytes(uuid).to_string(),
                command[0],
                VLESS_MUX_TARGET.to_owned(),
                AcceptedStream::Xudp,
            );
        }
        let mut port = [0_u8; 2];
        stream.read_exact(&mut port).unwrap();
        let port = u16::from_be_bytes(port);
        let mut atyp = [0_u8; 1];
        stream.read_exact(&mut atyp).unwrap();
        let host = match atyp[0] {
            ATYP_IPV4 => {
                let mut octets = [0_u8; 4];
                stream.read_exact(&mut octets).unwrap();
                std::net::Ipv4Addr::from(octets).to_string()
            }
            ATYP_IPV6 => {
                let mut octets = [0_u8; 16];
                stream.read_exact(&mut octets).unwrap();
                std::net::Ipv6Addr::from(octets).to_string()
            }
            ATYP_DOMAIN => {
                let mut len = [0_u8; 1];
                stream.read_exact(&mut len).unwrap();
                let mut host = vec![0_u8; len[0] as usize];
                stream.read_exact(&mut host).unwrap();
                String::from_utf8(host).unwrap()
            }
            other => panic!("unexpected vless atyp {other}"),
        };
        (
            version[0],
            Uuid::from_bytes(uuid).to_string(),
            command[0],
            format!("{host}:{port}"),
            if command[0] == COMMAND_UDP {
                AcceptedStream::Udp
            } else {
                AcceptedStream::Tcp
            },
        )
    }
}
