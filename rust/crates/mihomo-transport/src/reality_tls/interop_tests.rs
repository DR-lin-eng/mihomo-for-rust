use super::*;

#[test]
fn hkdf_extract_matches_rfc5869_case_one() {
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let actual = hkdf_extract(CipherSuite::Aes128GcmSha256, &salt, &[0x0b; 22]);
    assert_eq!(
        hex::encode(actual),
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    );
}

#[test]
fn tls13_early_secret_matches_rfc8448() {
    let early = hkdf_extract(CipherSuite::Aes128GcmSha256, &[0; 32], &[0; 32]);
    assert_eq!(
        hex::encode(&early),
        "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
    );
    let derived = hkdf_expand_label(
        CipherSuite::Aes128GcmSha256,
        &early,
        "derived",
        &Sha256::digest([]),
        32,
    );
    assert_eq!(
        hex::encode(derived),
        "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"
    );
}

#[test]
fn sha384_transcript_is_sha384_rather_than_truncated_sha512() {
    assert_eq!(hex::encode(TranscriptState::new(CipherSuite::Aes256GcmSha384).snapshot_hash()),
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
}

#[test]
fn proof_uses_hmac_sha512_and_certificate_is_valid_der() {
    let auth: [u8; 32] = std::array::from_fn(|i| i as u8);
    let public: [u8; 32] = std::array::from_fn(|i| (i + 32) as u8);
    // Reference computed independently with Python's hmac/hashlib.
    let proof = reality_certificate_proof(&auth, &public);
    assert_eq!(hex::encode(&proof), "929cab2abf94c68bab4d0f4de3ee8e3c112c0a2bbc7fc66dffc2b82212fe2984a39fb699258440725ab6de60856be50a1cf399a069fc4ab8a5b9107b633fc93d");
    let mut der = build_certificate_der(&public);
    let offset = der.len() - 64;
    der[offset..].copy_from_slice(&proof);
    let (parsed, signature) = parse_self_signed_cert(&der).unwrap();
    assert_eq!(parsed, public);
    assert_eq!(signature.unwrap(), proof);
}

#[test]
fn independent_rustls_server_accepts_reality_client_hello() {
    use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection};
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![Certificate(generated.cert.der().to_vec())],
            PrivateKey(generated.key_pair.serialize_der()),
        )
        .unwrap();
    let client_config = RealityClientConfig {
        public_key: [0; 32],
        short_id: [0; 8],
        server_name: "localhost".into(),
        ..Default::default()
    };
    let dk = ml_kem::ml_kem_768::DecapsulationKey::from_seed([0; 64].into());
    let encapsulation = dk.encapsulation_key().to_bytes().0;
    let (hello, _) = build_client_hello(&client_config, &[0x42; 32], &encapsulation, &[0x24; 32]);
    let mut record = vec![22, 3, 3];
    record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello);
    let mut server = ServerConnection::new(Arc::new(config)).unwrap();
    server.read_tls(&mut std::io::Cursor::new(record)).unwrap();
    server.process_new_packets().unwrap();
    assert_eq!(
        server.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert!(server.wants_write());
}

fn application_stream(inner_plaintexts: &[&[u8]]) -> BoxedTcpStream {
    use std::io::Cursor;
    struct WireStream(Cursor<Vec<u8>>);
    impl Read for WireStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }
    impl Write for WireStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
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
    let key = [0x42; 16];
    let iv = [0x24; 12];
    let cipher = || SuiteAead::new(CipherSuite::Aes128GcmSha256, &key).unwrap();
    let mut wire = Vec::new();
    for (seq, plaintext) in inner_plaintexts.iter().enumerate() {
        let ciphertext = cipher().seal(&iv, seq as u64, plaintext, &[23, 3, 3]);
        wire.extend_from_slice(&[23, 3, 3]);
        wire.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
        wire.extend_from_slice(&ciphertext);
    }
    Box::new(RealityStream {
        read_socket: Box::new(WireStream(Cursor::new(wire))),
        write_socket: None,
        read_aead: cipher(),
        read_iv: iv,
        read_seq: 0,
        read_record: Default::default(),
        write_state: Arc::new(Mutex::new(RealityWriteState {
            aead: cipher(),
            iv,
            seq: 0,
            direct: false,
        })),
        read_direct: false,
        read_buf: Vec::new(),
        read_off: 0,
        read_finished: false,
        handshake_client_aead: None,
        handshake_client_iv: [0; 12],
        handshake_client_seq: 0,
    })
}

#[test]
fn reality_empty_padded_record_before_vless_response_does_not_become_version_23() {
    // Xray disguises the camouflage site's session-ticket record as empty
    // application data: content type 0x17 followed by zero padding, with no
    // application payload. It still consumes a TLS record sequence number.
    let empty_ticket = [0x17, 0, 0, 0, 0, 0, 0];
    let response = [0, 0, b'o', b'k', 0, 0, 0x17, 0, 0, 0];
    let inner = application_stream(&[&empty_ticket, &response]);
    let mut vless = crate::vless::wrap_stream(
        inner,
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        &TransportTarget::new("localhost", 443),
    )
    .unwrap();
    let mut bytes = Vec::new();
    vless.read_to_end(&mut bytes).unwrap();
    assert_eq!(
        bytes, b"ok\0\0",
        "application zero bytes must survive TLS padding removal"
    );
}

#[test]
fn reality_padded_post_handshake_records_are_not_exposed_as_vless_response() {
    let ticket = [4, 0, 0, 1, 0x42, 22, 0, 0, 0, 0];
    let response = [0, 0, b'o', b'k', 23];
    let inner = application_stream(&[&ticket, &response]);
    let mut vless = crate::vless::wrap_stream(
        inner,
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        &TransportTarget::new("localhost", 443),
    )
    .unwrap();
    let mut bytes = Vec::new();
    vless.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"ok");
}

#[test]
fn tls_inner_plaintext_preserves_content_zeros_and_rejects_missing_or_unknown_type() {
    for padding in [0, 1, 64, 4096] {
        let mut wire = vec![0, b'a', 0, 0, 23];
        wire.resize(wire.len() + padding, 0);
        let (kind, content) = decode_inner_plaintext(wire).unwrap();
        assert_eq!(kind, 23);
        assert_eq!(content, [0, b'a', 0, 0]);
    }
    for invalid in [Vec::new(), vec![0; 4096], vec![0x42, 0, 0], vec![20, 0]] {
        assert_eq!(
            decode_inner_plaintext(invalid).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[test]
fn reality_close_notify_is_eof_and_alerts_are_not_exposed_as_application_data() {
    let payload = [b'o', b'k', 23, 0, 0];
    let close = [1, 0, 21, 0, 0, 0];
    let mut stream = application_stream(&[&payload, &close]);
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"ok");
    let alert = [2, 40, 21, 0, 0];
    let mut stream = application_stream(&[&alert]);
    assert_eq!(
        stream.read(&mut [0; 64]).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn reality_invalid_vless_response_is_still_rejected_after_tls_unpadding() {
    // An actual TLS-looking payload is not a substitute for the VLESS header.
    let invalid_response = [23, 3, 3, 0, 1, b'x', 23, 0, 0];
    let inner = application_stream(&[&invalid_response]);
    let mut vless = crate::vless::wrap_stream(
        inner,
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        &TransportTarget::new("localhost", 443),
    )
    .unwrap();
    let err = vless.read(&mut [0; 32]).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err
        .to_string()
        .contains("unexpected vless response version 23"));
}

fn test_client_hello_config() -> RealityClientConfig {
    RealityClientConfig {
        public_key: [0; 32],
        short_id: [0; 8],
        server_name: "localhost".into(),
        ..Default::default()
    }
}

fn test_client_hello(config: &RealityClientConfig) -> Vec<u8> {
    let dk = ml_kem::ml_kem_768::DecapsulationKey::from_seed([0; 64].into());
    build_client_hello(
        config,
        &[0x42; 32],
        &dk.encapsulation_key().to_bytes().0,
        &[0x24; 32],
    )
    .0
}

#[test]
fn compatibility_legacy_client_hello_does_not_offer_mlkem_by_default() {
    let hello = test_client_hello(&test_client_hello_config());
    let parsed = parse_client_hello(&hello).unwrap();
    assert_eq!(
        parsed.key_shares.iter().map(|s| s.0).collect::<Vec<_>>(),
        [GROUP_X25519]
    );
}

#[test]
fn compatibility_client_hello_supports_http11_only_camouflage() {
    use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection};
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![Certificate(generated.cert.der().to_vec())],
            PrivateKey(generated.key_pair.serialize_der()),
        )
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let hello = test_client_hello(&test_client_hello_config());
    let mut wire = vec![22, 3, 3];
    wire.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    wire.extend_from_slice(&hello);
    let mut server = ServerConnection::new(Arc::new(config)).unwrap();
    server.read_tls(&mut std::io::Cursor::new(wire)).unwrap();
    server.process_new_packets().unwrap();
    assert_eq!(server.alpn_protocol(), Some(b"http/1.1".as_slice()));
}

#[test]
fn compatibility_server_hello_spans_tls_records() {
    let record = fake_site_server_hello();
    let hello = &record[5..];
    let mut wire = vec![20, 3, 3, 0, 1, 1];
    for fragment in hello.chunks(3) {
        wire.extend_from_slice(&[22, 3, 3]);
        wire.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        wire.extend_from_slice(fragment);
    }
    assert_eq!(
        read_server_hello_message(&mut std::io::Cursor::new(wire)).unwrap(),
        hello
    );
}

#[test]
fn compatibility_server_hello_reports_tls_alerts_without_hiding_reason() {
    for (description, expected) in [
        (40, "handshake_failure"),
        (112, "unrecognized_name"),
        (120, "no_application_protocol"),
    ] {
        let wire = vec![21, 3, 3, 0, 2, 2, description];
        let err = read_server_hello_message(&mut std::io::Cursor::new(wire)).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("before ServerHello"), "{text}");
        assert!(text.contains(expected), "{text}");
        assert!(text.contains(&description.to_string()), "{text}");
    }
}

#[test]
fn compatibility_mlkem_profile_explicitly_offers_both_key_shares() {
    let mut config = test_client_hello_config();
    config.support_x25519mlkem768 = true;
    let hello = test_client_hello(&config);
    let parsed = parse_client_hello(&hello).unwrap();
    assert_eq!(
        parsed
            .key_shares
            .iter()
            .map(|s| (s.0, s.2))
            .collect::<Vec<_>>(),
        [
            (GROUP_X25519_MLKEM768, MLKEM_ENCAP_KEY_SIZE + 32),
            (GROUP_X25519, 32)
        ]
    );
}

#[test]
fn compatibility_reality_record_resumes_after_read_timeouts() {
    use std::collections::VecDeque;
    struct PausingStream {
        inner: BoxedTcpStream,
        pieces: VecDeque<usize>,
    }
    impl Read for PausingStream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            match self.pieces.pop_front() {
                Some(0) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                Some(n) => {
                    let limit = n.min(bytes.len());
                    self.inner.read(&mut bytes[..limit])
                }
                None => self.inner.read(bytes),
            }
        }
    }
    impl Write for PausingStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.inner.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }
    impl TcpStream for PausingStream {
        fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
            self.inner.try_clone_box()
        }
    }
    let response = [0, 0, b'o', b'k', 23];
    let mut inner = application_stream(&[&response]);
    let stream = (inner.as_mut() as &mut dyn std::any::Any)
        .downcast_mut::<RealityStream>()
        .unwrap();
    let socket = std::mem::replace(&mut stream.read_socket, application_stream(&[]));
    stream.read_socket = Box::new(PausingStream {
        inner: socket,
        pieces: [2, 0, 1, 0, 2, 3, 0, 4, 0].into(),
    });
    let mut vless = crate::vless::wrap_stream(
        inner,
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        &TransportTarget::new("localhost", 443),
    )
    .unwrap();
    let mut buf = [0; 2];
    for _ in 0..4 {
        assert_eq!(
            vless.read(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    vless.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ok");
}

#[test]
fn compatibility_first_client_hello_record_uses_legacy_tls10_version() {
    struct CaptureStream(Arc<Mutex<Vec<u8>>>);
    impl Read for CaptureStream {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }
    impl Write for CaptureStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl TcpStream for CaptureStream {
        fn try_clone_box(&self) -> io::Result<BoxedTcpStream> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }
    let wire = Arc::new(Mutex::new(Vec::new()));
    let _ = wrap_stream(
        Box::new(CaptureStream(Arc::clone(&wire))),
        &test_client_hello_config(),
        &TransportTarget::new("localhost", 443),
    );
    let bytes = wire.lock().unwrap();
    assert_eq!(
        &bytes[..3],
        &[22, 3, 1],
        "old REALITY servers require TLS 1.0 record framing for the first ClientHello"
    );
    assert_eq!(
        &bytes[9..11],
        &[3, 3],
        "the ClientHello legacy_version itself remains TLS 1.2"
    );
}
