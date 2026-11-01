use super::*;

struct WireStream(Cursor<Vec<u8>>);
impl Read for WireStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}
impl Write for WireStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl TcpStream for WireStream {
    fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[test]
fn coalesced_close_notify_preserves_pending_plaintext_before_eof() {
    for vision in [false, true] {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(
                vec![Certificate(cert.cert.der().to_vec())],
                rustls::PrivateKey(cert.key_pair.serialize_der()),
            )
            .unwrap();
        let tls = TlsOptions {
            enabled: true,
            sni: "localhost".into(),
            skip_cert_verify: true,
            ..Default::default()
        };
        let proxy = TransportTarget::new("localhost", 443);
        let config = build_client_config(&proxy, &tls, &[]).unwrap();
        let mut client = ClientConnection::new(config, server_name(&proxy, &tls).unwrap()).unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
        for _ in 0..8 {
            let mut wire = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut wire).unwrap();
            }
            if !wire.is_empty() {
                server.read_tls(&mut Cursor::new(wire)).unwrap();
                server.process_new_packets().unwrap();
            }
            let mut wire = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut wire).unwrap();
            }
            if !wire.is_empty() {
                client.read_tls(&mut Cursor::new(wire)).unwrap();
                client.process_new_packets().unwrap();
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        assert!(!client.is_handshaking() && !server.is_handshaking());
        server.writer().write_all(b"\0payload\0").unwrap();
        server.send_close_notify();
        let mut wire = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut wire).unwrap();
        }
        let mut stream = TlsClientStream {
            core: Arc::new(TlsClientCore {
                conn: Mutex::new(client),
                write_direct: AtomicBool::new(false),
                vision,
            }),
            socket: Box::new(WireStream(Cursor::new(wire))),
            record: TlsRecordBuffer::default(),
            read_direct: false,
        };
        let mut received = Vec::new();
        stream.read_to_end(&mut received).unwrap();
        assert_eq!(received, b"\0payload\0", "vision={vision}");
    }
}
