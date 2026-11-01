use std::io;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use mihomo_core::BoxedTcpStream;
use mihomo_runtime::{
    build_runtime_registry, dispatch_tun_tcp_stream_with_dialer, RuntimeTunnel,
};
use mihomo_transport::{
    SocketOptions, TcpDialPurpose, TcpDialer, TransportError, TransportTarget,
};
use smoltcp::wire::{TcpControl, TcpRepr, TcpSeqNumber};

use crate::tun_tcp_packet::{parse_tun_tcp_packet, TunTcpFlowKey};

use super::{TunTcpPassiveStack, TunTcpStreamHandle};

#[test]
fn passive_stack_replies_to_syn_and_reaches_established() {
    let client: std::net::SocketAddr = "10.0.0.2:50000".parse().unwrap();
    let server: std::net::SocketAddr = "93.184.216.34:443".parse().unwrap();
    let syn = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        64,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(100),
            ack_number: None,
            window_len: 65535,
            window_scale: Some(7),
            max_seg_size: Some(1460),
            sack_permitted: true,
            sack_ranges: [None, None, None],
            payload: &[],
        },
    )
    .unwrap();
    let parsed_syn = parse_tun_tcp_packet(&syn).unwrap();
    let mut stack = TunTcpPassiveStack::new(&parsed_syn, 1500).unwrap();
    stack.ingest_packet(&parsed_syn).unwrap();
    stack.poll();
    let outgoing = stack.drain_outgoing();
    assert!(!outgoing.is_empty());
    let syn_ack = parse_tun_tcp_packet(&outgoing[0]).unwrap();
    assert_eq!(syn_ack.destination, client);
    assert_eq!(syn_ack.source, server);
    assert_eq!(syn_ack.tcp_repr.control, TcpControl::Syn);
    let ack = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        64,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::None,
            seq_number: TcpSeqNumber(101),
            ack_number: Some(syn_ack.tcp_repr.seq_number + 1),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: &[],
        },
    )
    .unwrap();
    let parsed_ack = parse_tun_tcp_packet(&ack).unwrap();
    stack.ingest_packet(&parsed_ack).unwrap();
    stack.poll();
    assert!(stack.is_established());
}

#[test]
fn passive_stack_receives_and_sends_application_payload() {
    let client: std::net::SocketAddr = "10.0.0.2:50001".parse().unwrap();
    let server: std::net::SocketAddr = "93.184.216.34:80".parse().unwrap();
    let syn = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        32,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(1000),
            ack_number: None,
            window_len: 65535,
            window_scale: Some(7),
            max_seg_size: Some(1460),
            sack_permitted: true,
            sack_ranges: [None, None, None],
            payload: &[],
        },
    )
    .unwrap();
    let parsed_syn = parse_tun_tcp_packet(&syn).unwrap();
    let mut stack = TunTcpPassiveStack::new(&parsed_syn, 1500).unwrap();
    stack.ingest_packet(&parsed_syn).unwrap();
    stack.poll();
    let syn_ack = parse_tun_tcp_packet(&stack.drain_outgoing()[0]).unwrap();
    let ack = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        32,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::None,
            seq_number: TcpSeqNumber(1001),
            ack_number: Some(syn_ack.tcp_repr.seq_number + 1),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: &[],
        },
    )
    .unwrap();
    let parsed_ack = parse_tun_tcp_packet(&ack).unwrap();
    stack.ingest_packet(&parsed_ack).unwrap();
    stack.poll();
    assert!(stack.is_established());

    let data = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        32,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::Psh,
            seq_number: TcpSeqNumber(1001),
            ack_number: Some(syn_ack.tcp_repr.seq_number + 1),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: b"hello",
        },
    )
    .unwrap();
    let parsed_data = parse_tun_tcp_packet(&data).unwrap();
    stack.ingest_packet(&parsed_data).unwrap();
    stack.poll();
    assert_eq!(stack.recv_application().unwrap(), Some(b"hello".to_vec()));

    let sent = stack.send_application(b"world").unwrap();
    assert_eq!(sent, 5);
    stack.poll();
    let outgoing = stack.drain_outgoing();
    assert!(outgoing.iter().any(|packet| {
        let parsed = parse_tun_tcp_packet(packet).unwrap();
        parsed.flow_key()
            == TunTcpFlowKey {
                source: server,
                destination: client,
            }
            && parsed.tcp_repr.payload == b"world"
    }));
}

#[test]
fn tun_tcp_stream_handle_reads_and_writes_application_payload() {
    let client: std::net::SocketAddr = "10.0.0.2:50002".parse().unwrap();
    let server: std::net::SocketAddr = "93.184.216.34:443".parse().unwrap();
    let syn = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        64,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(2000),
            ack_number: None,
            window_len: 65535,
            window_scale: Some(7),
            max_seg_size: Some(1460),
            sack_permitted: true,
            sack_ranges: [None, None, None],
            payload: &[],
        },
    )
    .unwrap();
    let parsed_syn = parse_tun_tcp_packet(&syn).unwrap();
    let mut stack = TunTcpPassiveStack::new(&parsed_syn, 1500).unwrap();
    stack.ingest_packet(&parsed_syn).unwrap();
    stack.poll();
    let syn_ack = parse_tun_tcp_packet(&stack.drain_outgoing()[0]).unwrap();
    let ack = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        64,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::None,
            seq_number: TcpSeqNumber(2001),
            ack_number: Some(syn_ack.tcp_repr.seq_number + 1),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: &[],
        },
    )
    .unwrap();
    let parsed_ack = parse_tun_tcp_packet(&ack).unwrap();
    stack.ingest_packet(&parsed_ack).unwrap();
    stack.poll();
    assert!(stack.is_established());

    let handle = TunTcpStreamHandle::new(stack);
    let stack_ref = handle.stack();
    {
        let mut locked = stack_ref.lock().unwrap();
        let incoming = crate::tun_tcp_packet::encode_tun_tcp_packet(
            client,
            server,
            64,
            &TcpRepr {
                src_port: client.port(),
                dst_port: server.port(),
                control: TcpControl::Psh,
                seq_number: TcpSeqNumber(2001),
                ack_number: Some(syn_ack.tcp_repr.seq_number + 1),
                window_len: 65535,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None, None, None],
                payload: b"hello",
            },
        )
        .unwrap();
        let parsed = parse_tun_tcp_packet(&incoming).unwrap();
        locked.ingest_packet(&parsed).unwrap();
    }
    let mut reader = handle.clone();
    let mut buf = [0_u8; 5];
    assert_eq!(reader.read(&mut buf).unwrap(), 5);
    assert_eq!(&buf, b"hello");

    let mut writer = handle.clone();
    assert_eq!(writer.write(b"world").unwrap(), 5);
    let outgoing = {
        let mut locked = stack_ref.lock().unwrap();
        locked.drain_outgoing()
    };
    assert!(outgoing.iter().any(|packet| {
        let parsed = parse_tun_tcp_packet(packet).unwrap();
        parsed.tcp_repr.payload == b"world"
    }));
}

#[test]
fn tun_tcp_stream_handle_returns_eof_after_peer_fin() {
    let client: std::net::SocketAddr = "10.0.0.2:50012".parse().unwrap();
    let server: std::net::SocketAddr = "93.184.216.34:443".parse().unwrap();
    let syn = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        64,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(4000),
            ack_number: None,
            window_len: 65535,
            window_scale: Some(7),
            max_seg_size: Some(1460),
            sack_permitted: true,
            sack_ranges: [None, None, None],
            payload: &[],
        },
    )
    .unwrap();
    let parsed_syn = parse_tun_tcp_packet(&syn).unwrap();
    let mut stack = TunTcpPassiveStack::new(&parsed_syn, 1500).unwrap();
    stack.ingest_packet(&parsed_syn).unwrap();
    stack.poll();
    let syn_ack = parse_tun_tcp_packet(&stack.drain_outgoing()[0]).unwrap();
    let ack = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        64,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::None,
            seq_number: TcpSeqNumber(4001),
            ack_number: Some(syn_ack.tcp_repr.seq_number + 1),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: &[],
        },
    )
    .unwrap();
    let parsed_ack = parse_tun_tcp_packet(&ack).unwrap();
    stack.ingest_packet(&parsed_ack).unwrap();
    stack.poll();
    assert!(stack.is_established());

    let mut handle = TunTcpStreamHandle::new(stack);
    let stack_ref = handle.stack();
    {
        let mut locked = stack_ref.lock().unwrap();
        let peer_fin = crate::tun_tcp_packet::encode_tun_tcp_packet(
            client,
            server,
            64,
            &TcpRepr {
                src_port: client.port(),
                dst_port: server.port(),
                control: TcpControl::Fin,
                seq_number: TcpSeqNumber(4001),
                ack_number: Some(syn_ack.tcp_repr.seq_number + 1),
                window_len: 65535,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None, None, None],
                payload: &[],
            },
        )
        .unwrap();
        let parsed_fin = parse_tun_tcp_packet(&peer_fin).unwrap();
        locked.ingest_packet(&parsed_fin).unwrap();
        locked.poll();
        let outgoing = locked.drain_outgoing();
        assert!(!outgoing.is_empty());
    }

    let mut buf = [0_u8; 1];
    assert_eq!(handle.read(&mut buf).unwrap(), 0);
}

#[test]
fn tun_tcp_stream_handle_waits_for_packet_delivery_without_busy_polling_loop() {
    let client: std::net::SocketAddr = "10.0.0.2:50013".parse().unwrap();
    let server: std::net::SocketAddr = "93.184.216.34:443".parse().unwrap();
    let syn = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        64,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(4500),
            ack_number: None,
            window_len: 65535,
            window_scale: Some(7),
            max_seg_size: Some(1460),
            sack_permitted: true,
            sack_ranges: [None, None, None],
            payload: &[],
        },
    )
    .unwrap();
    let parsed_syn = parse_tun_tcp_packet(&syn).unwrap();
    let mut stack = TunTcpPassiveStack::new(&parsed_syn, 1500).unwrap();
    stack.ingest_packet(&parsed_syn).unwrap();
    stack.poll();
    let syn_ack = parse_tun_tcp_packet(&stack.drain_outgoing()[0]).unwrap();
    let ack = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        64,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::None,
            seq_number: TcpSeqNumber(4501),
            ack_number: Some(syn_ack.tcp_repr.seq_number + 1),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: &[],
        },
    )
    .unwrap();
    let parsed_ack = parse_tun_tcp_packet(&ack).unwrap();
    stack.ingest_packet(&parsed_ack).unwrap();
    stack.poll();
    assert!(stack.is_established());

    let handle = TunTcpStreamHandle::new(stack);
    let stack_ref = handle.stack();
    let reader_handle = handle.clone();

    let reader_thread = thread::spawn(move || {
        let mut reader = reader_handle;
        let started = Instant::now();
        let mut buf = [0_u8; 5];
        let read = reader.read(&mut buf).unwrap();
        (started.elapsed(), read, buf)
    });

    thread::sleep(Duration::from_millis(80));
    {
        let mut locked = stack_ref.lock().unwrap();
        let incoming = crate::tun_tcp_packet::encode_tun_tcp_packet(
            client,
            server,
            64,
            &TcpRepr {
                src_port: client.port(),
                dst_port: server.port(),
                control: TcpControl::Psh,
                seq_number: TcpSeqNumber(4501),
                ack_number: Some(syn_ack.tcp_repr.seq_number + 1),
                window_len: 65535,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None, None, None],
                payload: b"hello",
            },
        )
        .unwrap();
        let parsed = parse_tun_tcp_packet(&incoming).unwrap();
        locked.ingest_packet(&parsed).unwrap();
        locked.poll();
    }

    let (elapsed, read, buf) = reader_thread.join().unwrap();
    assert!(elapsed >= Duration::from_millis(60), "elapsed={elapsed:?}");
    assert_eq!(read, 5);
    assert_eq!(&buf, b"hello");
}

#[derive(Default)]
struct MemoryDuplexState {
    reader: std::io::Cursor<Vec<u8>>,
    written: Vec<u8>,
}

#[derive(Clone)]
struct MemoryDuplex(Arc<Mutex<MemoryDuplexState>>);

impl MemoryDuplex {
    fn new(readable: &[u8]) -> Self {
        Self(Arc::new(Mutex::new(MemoryDuplexState {
            reader: std::io::Cursor::new(readable.to_vec()),
            written: Vec::new(),
        })))
    }

    fn written(&self) -> Vec<u8> {
        self.0.lock().unwrap().written.clone()
    }
}

impl Read for MemoryDuplex {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.lock().unwrap().reader.read(buf)
    }
}

impl Write for MemoryDuplex {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl mihomo_core::TcpStream for MemoryDuplex {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(self.clone()))
    }
}

struct FakeDialer {
    upstream: MemoryDuplex,
}

impl TcpDialer for FakeDialer {
    fn connect(
        &mut self,
        _target: &TransportTarget,
        _socket: &SocketOptions,
        _purpose: TcpDialPurpose,
    ) -> Result<BoxedTcpStream, TransportError> {
        Ok(Box::new(self.upstream.clone()))
    }
}

struct RealTcpDialer;

impl TcpDialer for RealTcpDialer {
    fn connect(
        &mut self,
        target: &TransportTarget,
        _socket: &SocketOptions,
        _purpose: TcpDialPurpose,
    ) -> Result<BoxedTcpStream, TransportError> {
        let stream = TcpStream::connect((target.host.as_str(), target.port))
            .map_err(TransportError::from)?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .map_err(TransportError::from)?;
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .map_err(TransportError::from)?;
        Ok(Box::new(stream))
    }
}

#[test]
fn single_bridge_dispatches_tun_tcp_stream_through_runtime_tunnel() {
    let document = mihomo_config::parse_runtime_config_document(
        r#"
tun:
  enable: true
  proxy: special
proxies:
  - type: http
    name: special
    server: special.example.com
    port: 8080
"#,
    )
    .unwrap();
    let spec = mihomo_runtime::build_tun_runtime_specs(&document).remove(0);
    let registry = build_runtime_registry(&document).unwrap();
    let tunnel = Arc::new(RuntimeTunnel::new(document.mode.clone(), registry));
    let client: std::net::SocketAddr = "10.0.0.2:50003".parse().unwrap();
    let server: std::net::SocketAddr = "93.184.216.34:443".parse().unwrap();
    let first_packet = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        64,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(3000),
            ack_number: None,
            window_len: 65535,
            window_scale: Some(7),
            max_seg_size: Some(1460),
            sack_permitted: true,
            sack_ranges: [None, None, None],
            payload: &[],
        },
    )
    .unwrap();
    let parsed = parse_tun_tcp_packet(&first_packet).unwrap();
    let mut stack = TunTcpPassiveStack::new(&parsed, 1500).unwrap();
    stack.ingest_packet(&parsed).unwrap();
    stack.poll();
    let syn_ack = parse_tun_tcp_packet(&stack.drain_outgoing()[0]).unwrap();
    let ack = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        64,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::None,
            seq_number: TcpSeqNumber(3001),
            ack_number: Some(syn_ack.tcp_repr.seq_number + 1),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: &[],
        },
    )
    .unwrap();
    let client_data = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        64,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::Psh,
            seq_number: TcpSeqNumber(3001),
            ack_number: Some(syn_ack.tcp_repr.seq_number + 1),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: b"client-data",
        },
    )
    .unwrap();
    let client_fin = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        64,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::Fin,
            seq_number: TcpSeqNumber(3012),
            ack_number: Some(syn_ack.tcp_repr.seq_number + 1),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: &[],
        },
    )
    .unwrap();
    stack.ingest_packet(&parse_tun_tcp_packet(&ack).unwrap()).unwrap();
    stack
        .ingest_packet(&parse_tun_tcp_packet(&client_data).unwrap())
        .unwrap();
    stack
        .ingest_packet(&parse_tun_tcp_packet(&client_fin).unwrap())
        .unwrap();
    let handle = TunTcpStreamHandle::new(stack);
    let stack_ref = handle.stack();
    let upstream = MemoryDuplex::new(b"HTTP/1.1 200 Connection Established\r\n\r\nserver-data");
    let stats = dispatch_tun_tcp_stream_with_dialer(
        &spec,
        &tunnel,
        handle,
        Some(client),
        server,
        FakeDialer {
            upstream: upstream.clone(),
        },
    )
    .unwrap();
    let outgoing = {
        let mut locked = stack_ref.lock().unwrap();
        locked.poll();
        locked.drain_outgoing()
    };
    assert!(stats.right_to_left >= b"server-data".len() as u64);
    let written = String::from_utf8(upstream.written()).unwrap();
    assert!(written.contains("CONNECT 93.184.216.34:443 HTTP/1.1\r\n"));
    assert!(outgoing.iter().any(|packet| {
        let parsed = parse_tun_tcp_packet(packet).unwrap();
        parsed.tcp_repr.payload.ends_with(b"server-data")
    }));
}

#[test]
fn single_bridge_dispatches_tun_tcp_stream_through_real_http_proxy_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut buf = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buf).unwrap();
            assert!(read > 0, "proxy request closed before headers");
            request.extend_from_slice(&buf[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
            .unwrap();
        let mut tail = request[header_end..].to_vec();
        let request = String::from_utf8(request).unwrap();
        assert!(
            request.starts_with("CONNECT 93.184.216.34:443 HTTP/1.1\r\n"),
            "{request}"
        );
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        stream.flush().unwrap();

        while tail.len() < b"client-data".len() {
            let read = stream.read(&mut buf).unwrap();
            assert!(read > 0, "proxy payload closed before body");
            tail.extend_from_slice(&buf[..read]);
        }
        assert_eq!(&tail[..b"client-data".len()], b"client-data");
        stream.write_all(b"server-data").unwrap();
        stream.flush().unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
    });

    let document = mihomo_config::parse_runtime_config_document(
        &format!(
            r#"
tun:
  enable: true
  proxy: special
proxies:
  - type: http
    name: special
    server: 127.0.0.1
    port: {}
"#,
            proxy_addr.port()
        ),
    )
    .unwrap();
    let spec = mihomo_runtime::build_tun_runtime_specs(&document).remove(0);
    let registry = build_runtime_registry(&document).unwrap();
    let tunnel = Arc::new(RuntimeTunnel::new(document.mode.clone(), registry));
    let client: std::net::SocketAddr = "10.0.0.2:50004".parse().unwrap();
    let server: std::net::SocketAddr = "93.184.216.34:443".parse().unwrap();
    let first_packet = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        64,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(5000),
            ack_number: None,
            window_len: 65535,
            window_scale: Some(7),
            max_seg_size: Some(1460),
            sack_permitted: true,
            sack_ranges: [None, None, None],
            payload: &[],
        },
    )
    .unwrap();
    let parsed = parse_tun_tcp_packet(&first_packet).unwrap();
    let mut stack = TunTcpPassiveStack::new(&parsed, 1500).unwrap();
    stack.ingest_packet(&parsed).unwrap();
    stack.poll();
    let syn_ack = parse_tun_tcp_packet(&stack.drain_outgoing()[0]).unwrap();
    let ack = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        64,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::None,
            seq_number: TcpSeqNumber(5001),
            ack_number: Some(syn_ack.tcp_repr.seq_number + 1),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: &[],
        },
    )
    .unwrap();
    let client_data = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        64,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::Psh,
            seq_number: TcpSeqNumber(5001),
            ack_number: Some(syn_ack.tcp_repr.seq_number + 1),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: b"client-data",
        },
    )
    .unwrap();
    let client_fin = crate::tun_tcp_packet::encode_tun_tcp_packet(
        client,
        server,
        64,
        &TcpRepr {
            src_port: client.port(),
            dst_port: server.port(),
            control: TcpControl::Fin,
            seq_number: TcpSeqNumber(5012),
            ack_number: Some(syn_ack.tcp_repr.seq_number + 1),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: &[],
        },
    )
    .unwrap();
    stack.ingest_packet(&parse_tun_tcp_packet(&ack).unwrap()).unwrap();
    stack
        .ingest_packet(&parse_tun_tcp_packet(&client_data).unwrap())
        .unwrap();
    stack
        .ingest_packet(&parse_tun_tcp_packet(&client_fin).unwrap())
        .unwrap();
    let handle = TunTcpStreamHandle::new(stack);
    let stack_ref = handle.stack();
    let stats = dispatch_tun_tcp_stream_with_dialer(
        &spec,
        &tunnel,
        handle,
        Some(client),
        server,
        RealTcpDialer,
    )
    .unwrap();

    let outgoing = {
        let mut locked = stack_ref.lock().unwrap();
        locked.poll();
        locked.drain_outgoing()
    };
    assert_eq!(stats.left_to_right, b"client-data".len() as u64);
    assert_eq!(stats.right_to_left, b"server-data".len() as u64);
    assert!(outgoing.iter().any(|packet| {
        let parsed = parse_tun_tcp_packet(packet).unwrap();
        parsed.tcp_repr.payload.ends_with(b"server-data")
    }));
    worker.join().unwrap();
}
