use super::*;
use std::collections::VecDeque;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};

const USER: [u8; 16] = [7; 16];

pub(crate) fn server_hello(cipher: u16, tls13: bool) -> Vec<u8> {
    let mut hello = vec![3, 3];
    hello.extend_from_slice(&[0x42; 32]);
    hello.push(0); // Empty legacy session ID is legal.
    hello.extend_from_slice(&cipher.to_be_bytes());
    hello.push(0);
    if tls13 {
        hello.extend_from_slice(&[0, 6, 0, 43, 0, 2, 3, 4]);
    } else {
        hello.extend_from_slice(&[0, 0]);
    }
    let mut hs = vec![2, 0, 0, hello.len() as u8];
    hs.extend_from_slice(&hello);
    let mut record = vec![22, 3, 3];
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

fn wire_frame(uuid: bool, command: u8, content: &[u8], padding: usize) -> Vec<u8> {
    let mut frame = Vec::new();
    if uuid {
        frame.extend_from_slice(&USER);
    }
    frame.push(command);
    frame.extend_from_slice(&(content.len() as u16).to_be_bytes());
    frame.extend_from_slice(&(padding as u16).to_be_bytes());
    frame.extend_from_slice(content);
    frame.resize(frame.len() + padding, 0);
    frame
}

enum Input {
    Bytes(Cursor<Vec<u8>>),
    Block,
}
#[derive(Clone)]
struct TestStream {
    input: Arc<Mutex<VecDeque<Input>>>,
    output: Arc<Mutex<Vec<u8>>>,
    direct_read: Arc<AtomicBool>,
    direct_write: Arc<AtomicBool>,
    passthrough: bool,
}
impl TestStream {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            input: Arc::new(Mutex::new(VecDeque::from([Input::Bytes(Cursor::new(
                bytes,
            ))]))),
            output: Arc::new(Mutex::new(Vec::new())),
            direct_read: Arc::new(AtomicBool::new(false)),
            direct_write: Arc::new(AtomicBool::new(false)),
            passthrough: true,
        }
    }
}
impl Read for TestStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut input = self.input.lock().unwrap();
        loop {
            match input.front_mut() {
                Some(Input::Bytes(bytes)) => {
                    let n = bytes.read(buf)?;
                    if n > 0 || buf.is_empty() {
                        return Ok(n);
                    }
                    input.pop_front();
                }
                Some(Input::Block) => {
                    input.pop_front();
                    return Err(io::Error::from(io::ErrorKind::WouldBlock));
                }
                None => return Ok(0),
            }
        }
    }
}
impl Write for TestStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Exercise write_all's partial-write handling.
        let n = buf.len().min(31);
        self.output.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl TcpStream for TestStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Ok(Box::new(self.clone()))
    }
    fn supports_tls_passthrough(&self) -> bool {
        self.passthrough
    }
    fn start_tls_passthrough_read(&mut self) -> io::Result<()> {
        self.direct_read.store(true, Ordering::Relaxed);
        Ok(())
    }
    fn start_tls_passthrough_write(&mut self) -> io::Result<()> {
        self.direct_write.store(true, Ordering::Relaxed);
        Ok(())
    }
}

#[test]
fn tls_probe_handles_fragmented_server_hello_and_opposite_direction() {
    let mut state = VisionTlsState::default();
    // A partial record in the opposite direction must not corrupt parsing.
    state.filter_tls(&[22]);
    for byte in server_hello(0x1301, true) {
        state.filter_read_tls(&[byte]);
    }
    assert!(state.is_tls && state.is_tls12_or_above && state.enable_xtls);
}

#[test]
fn tls_probe_requires_tls13_and_supported_cipher() {
    for (cipher, version, direct) in [
        (0x1301, true, true),
        (0x1302, true, true),
        (0x1303, true, true),
        (0x1304, true, true),
        (0x1305, true, false),
        (0xc02f, false, false),
    ] {
        let mut state = VisionTlsState::default();
        state.filter_tls(&server_hello(cipher, version));
        assert!(state.is_tls && state.is_tls12_or_above);
        assert_eq!(state.enable_xtls, direct);
    }
}

#[test]
fn tls_probe_does_not_match_supported_version_bytes_in_random() {
    let mut hello = server_hello(0x1301, false);
    hello[11..17].copy_from_slice(&[0, 43, 0, 2, 3, 4]);
    let mut state = VisionTlsState::default();
    state.filter_tls(&hello);
    assert!(!state.enable_xtls);
}

#[test]
fn padding_only_frames_and_end_frame_do_not_report_eof() {
    let mut input = wire_frame(true, 0, b"", 17);
    input.extend(wire_frame(false, 1, b"hello", 9));
    input.extend_from_slice(b"raw");
    let mut stream = VisionStream::new(Box::new(TestStream::new(input)), true, USER);
    assert_eq!(stream.read(&mut []).unwrap(), 0);
    let mut result = Vec::new();
    stream.read_to_end(&mut result).unwrap();
    assert_eq!(result, b"helloraw");
}

#[test]
fn fragmented_header_and_padding_resume_after_would_block() {
    let frame = wire_frame(true, 1, b"hello", 9);
    let inner = TestStream::new(Vec::new());
    *inner.input.lock().unwrap() = VecDeque::from([
        Input::Bytes(Cursor::new(frame[..7].to_vec())),
        Input::Block,
        Input::Bytes(Cursor::new(frame[7..29].to_vec())),
        Input::Block,
        Input::Bytes(Cursor::new(frame[29..].to_vec())),
        Input::Bytes(Cursor::new(b"raw".to_vec())),
    ]);
    let mut stream = VisionStream::new(Box::new(inner), true, USER);
    let mut buf = [0; 16];
    assert_eq!(
        stream.read(&mut buf).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    let n = stream.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"hello");
    assert_eq!(
        stream.read(&mut buf).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    let n = stream.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"raw");
}

#[test]
fn invalid_uuid_unknown_command_and_truncation_are_rejected() {
    let mut bad_uuid = wire_frame(true, 1, b"x", 0);
    bad_uuid[0] ^= 1;
    for bytes in [bad_uuid, wire_frame(true, 3, b"x", 0)] {
        let mut stream = VisionStream::new(Box::new(TestStream::new(bytes)), true, USER);
        assert_eq!(
            stream.read(&mut [0; 32]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    let mut bytes = wire_frame(true, 0, b"abc", 0);
    bytes.pop();
    let mut stream = VisionStream::new(Box::new(TestStream::new(bytes)), true, USER);
    let mut buf = Vec::new();
    assert_eq!(
        stream.read_to_end(&mut buf).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[test]
fn plaintext_stops_padding_after_probe_budget() {
    let inner = TestStream::new(Vec::new());
    let mut stream = VisionStream::new(Box::new(inner.clone()), true, USER);
    for _ in 0..7 {
        stream.write_all(b"plain text").unwrap();
    }
    stream.write_all(b"unframed").unwrap();
    let output = inner.output.lock().unwrap().clone();
    let mut offset = 16;
    for command in [0, 0, 0, 0, 0, 0, 1] {
        assert_eq!(output[offset], command);
        let content = u16::from_be_bytes([output[offset + 1], output[offset + 2]]) as usize;
        let padding = u16::from_be_bytes([output[offset + 3], output[offset + 4]]) as usize;
        assert_eq!(&output[offset + 5..offset + 5 + content], b"plain text");
        assert!(padding < 256);
        offset += 5 + content + padding;
    }
    assert_eq!(&output[offset..], b"unframed");
}

#[test]
fn large_write_reshapes_frames_without_u16_truncation() {
    let inner = TestStream::new(Vec::new());
    let mut stream = VisionStream::new(Box::new(inner.clone()), true, USER);
    let payload = vec![0x61; 200_000];
    stream.write_all(&payload).unwrap();
    let output = inner.output.lock().unwrap().clone();
    let mut received = Vec::new();
    let mut offset = 16;
    while offset < output.len() {
        assert_eq!(output[offset], 0);
        let n = u16::from_be_bytes([output[offset + 1], output[offset + 2]]) as usize;
        let pad = u16::from_be_bytes([output[offset + 3], output[offset + 4]]) as usize;
        assert!(n <= BUFFER_LIMIT);
        received.extend_from_slice(&output[offset + 5..offset + 5 + n]);
        offset += 5 + n + pad;
    }
    assert_eq!(received, payload);
}

#[test]
fn reader_shares_tls_state_with_writer_clone_and_switches_directions_independently() {
    let hello = server_hello(0x1301, true);
    let mut input = wire_frame(true, 0, &hello, 0);
    input.extend(wire_frame(false, 2, b"response", 20));
    input.extend_from_slice(b"direct response");
    let inner = TestStream::new(input);
    let mut stream = VisionStream::new(Box::new(inner.clone()), true, USER);
    let mut writer = stream.try_clone_box().unwrap();
    let mut got = vec![0; hello.len()];
    stream.read_exact(&mut got).unwrap();
    assert!(stream.xtls_enabled() && stream.tls13());
    writer.write_all(b"\x17\x03\x03\x00\x03abc").unwrap();
    assert_eq!(inner.output.lock().unwrap()[16], 2);
    assert!(inner.direct_write.load(Ordering::Relaxed));
    assert!(!inner.direct_read.load(Ordering::Relaxed));
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, b"responsedirect response");
    assert!(inner.direct_read.load(Ordering::Relaxed));
}

#[test]
fn transport_without_passthrough_uses_padding_end() {
    let inner = TestStream {
        passthrough: false,
        ..TestStream::new(Vec::new())
    };
    let mut stream = VisionStream::new(Box::new(inner.clone()), true, USER);
    stream
        .tls_state
        .lock()
        .unwrap()
        .filter_read_tls(&server_hello(0x1301, true));
    stream.write_all(b"\x17\x03\x03\x00\x03abc").unwrap();
    assert_eq!(inner.output.lock().unwrap()[16], 1);
}

#[test]
fn vision_tls_direct_read_drains_plaintext_without_consuming_coalesced_raw_bytes() {
    use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection, StreamOwned};
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![Certificate(generated.cert.der().to_vec())],
            PrivateKey(generated.key_pair.serialize_der()),
        )
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut tls = StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), socket);
        tls.read_exact(&mut [0; 1]).unwrap();
        let mut final_plaintext = wire_frame(true, 2, b"framed", 23);
        final_plaintext.extend_from_slice(b"buffered plaintext");
        tls.conn.writer().write_all(&final_plaintext).unwrap();
        let mut coalesced = Vec::new();
        while tls.conn.wants_write() {
            tls.conn.write_tls(&mut coalesced).unwrap();
        }
        coalesced.extend_from_slice(b"\x17\x03\x03\x00\x03raw");
        tls.sock.write_all(&coalesced).unwrap();
        tls.sock.shutdown(std::net::Shutdown::Write).unwrap();
    });
    let socket = std::net::TcpStream::connect(addr).unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut tls = crate::tls_client::wrap_stream_for_vision(
        Box::new(socket),
        &crate::TransportTarget::new("localhost", addr.port()),
        &crate::TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            ..Default::default()
        },
        &[],
    )
    .unwrap();
    tls.write_all(b"!").unwrap();
    let mut stream = VisionStream::new(Box::new(tls), true, USER);
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"framedbuffered plaintext\x17\x03\x03\x00\x03raw");
    worker.join().unwrap();
}

#[test]
fn vision_tls_large_records_and_close_notify_do_not_require_tcp_eof() {
    use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection, StreamOwned};
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![Certificate(generated.cert.der().to_vec())],
            PrivateKey(generated.key_pair.serialize_der()),
        )
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (finished, keep_open) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let mut tls = StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), socket);
        tls.read_exact(&mut [0; 1]).unwrap();
        tls.write_all(&vec![0x5a; 512 * 1024]).unwrap();
        tls.flush().unwrap();
        tls.conn.send_close_notify();
        while tls.conn.wants_write() {
            tls.conn.write_tls(&mut tls.sock).unwrap();
        }
        // TLS EOF is sufficient; the peer must not wait for TCP EOF too.
        let _ = keep_open.recv_timeout(std::time::Duration::from_secs(6));
    });
    let socket = std::net::TcpStream::connect(addr).unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut tls = crate::tls_client::wrap_stream_for_vision(
        Box::new(socket),
        &crate::TransportTarget::new("localhost", addr.port()),
        &crate::TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            ..Default::default()
        },
        &[],
    )
    .unwrap();
    tls.write_all(b"!").unwrap();
    let mut bytes = Vec::new();
    tls.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, vec![0x5a; 512 * 1024]);
    finished.send(()).unwrap();
    worker.join().unwrap();
}

#[test]
fn vision_preserves_partial_vless_response_header_and_addons_across_timeouts() {
    let inner = TestStream::new(Vec::new());
    *inner.input.lock().unwrap() = VecDeque::from([
        Input::Bytes(Cursor::new(vec![0])),
        Input::Block,
        Input::Bytes(Cursor::new(vec![2, 0xaa])),
        Input::Block,
        Input::Bytes(Cursor::new(vec![0xbb])),
        Input::Bytes(Cursor::new(wire_frame(true, 1, b"hello", 0))),
    ]);
    let vless = crate::vless::wrap_stream(
        Box::new(inner),
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        &crate::TransportTarget::new("localhost", 443),
    )
    .unwrap();
    let mut stream = VisionStream::new(vless, true, USER);
    let mut data = [0; 5];
    for _ in 0..2 {
        assert_eq!(
            stream.read(&mut data).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    stream.read_exact(&mut data).unwrap();
    assert_eq!(&data, b"hello");
}

#[test]
fn vision_rejects_tls12_outer_connection() {
    use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection, StreamOwned};
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let config = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![Certificate(generated.cert.der().to_vec())],
            PrivateKey(generated.key_pair.serialize_der()),
        )
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let mut tls = StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), socket);
        let _ = tls.read(&mut [0; 1]);
    });
    let result = crate::wrap_vless_vision_tls_stream(
        Box::new(std::net::TcpStream::connect(addr).unwrap()),
        crate::TransportTarget::new("localhost", addr.port()),
        &crate::TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            ..Default::default()
        },
        &[],
    );
    assert!(
        matches!(result, Err(crate::TransportError::UnsupportedFeature { feature, .. })
        if feature.contains("TLS 1.3"))
    );
    worker.join().unwrap();
}
