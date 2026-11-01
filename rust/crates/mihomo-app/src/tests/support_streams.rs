    struct ServerWebsocketStream {
        inner: mihomo_core::BoxedTcpStream,
        pending: Vec<u8>,
        offset: usize,
    }

    struct TestRustlsServerStream(StreamOwned<ServerConnection, TcpStream>);

    struct SplitTestStream {
        reader: BoxedTcpStream,
        writer: BoxedTcpStream,
    }

    #[allow(dead_code)]
    struct TestPrefixedStream {
        prefix: std::io::Cursor<Vec<u8>>,
        inner: mihomo_core::BoxedTcpStream,
    }

    impl ServerWebsocketStream {
        fn new(inner: mihomo_core::BoxedTcpStream) -> Self {
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
        fn try_clone_box(&self) -> std::io::Result<mihomo_core::BoxedTcpStream> {
            Ok(Box::new(Self::new(self.inner.try_clone_box()?)))
        }

        fn shutdown_write(&mut self) -> std::io::Result<()> {
            self.inner.shutdown_write()
        }

        fn shutdown_all(&mut self) -> std::io::Result<()> {
            self.inner.shutdown_all()
        }
    }

    impl Read for TestRustlsServerStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for TestRustlsServerStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }

    impl mihomo_core::TcpStream for TestRustlsServerStream {
        fn try_clone_box(&self) -> std::io::Result<mihomo_core::BoxedTcpStream> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "test rustls server stream does not support cloning",
            ))
        }

        fn shutdown_write(&mut self) -> std::io::Result<()> {
            self.0.sock.shutdown(std::net::Shutdown::Write)
        }

        fn shutdown_all(&mut self) -> std::io::Result<()> {
            self.0.sock.shutdown(std::net::Shutdown::Both)
        }
    }

    impl SplitTestStream {
        fn new(reader: BoxedTcpStream, writer: BoxedTcpStream) -> Self {
            Self { reader, writer }
        }
    }

    impl Read for SplitTestStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reader.read(buf)
        }
    }

    impl Write for SplitTestStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writer.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.writer.flush()
        }
    }

    impl mihomo_core::TcpStream for SplitTestStream {
        fn try_clone_box(&self) -> std::io::Result<mihomo_core::BoxedTcpStream> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "split test stream does not support cloning",
            ))
        }

        fn shutdown_write(&mut self) -> std::io::Result<()> {
            self.writer.shutdown_write()
        }

        fn shutdown_all(&mut self) -> std::io::Result<()> {
            self.writer.shutdown_write()?;
            self.reader.shutdown_all()
        }
    }

    impl Read for TestPrefixedStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let read = self.prefix.read(buf)?;
            if read != 0 {
                return Ok(read);
            }
            self.inner.read(buf)
        }
    }

    impl Write for TestPrefixedStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inner.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    impl mihomo_core::TcpStream for TestPrefixedStream {
        fn try_clone_box(&self) -> std::io::Result<mihomo_core::BoxedTcpStream> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "test prefixed stream does not support cloning",
            ))
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

    fn accept_websocket_test_stream(
        mut stream: mihomo_core::BoxedTcpStream,
    ) -> (String, mihomo_core::BoxedTcpStream) {
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

    fn connect_websocket_client_stream(
        addr: SocketAddr,
        path: &str,
        host: Option<&str>,
    ) -> mihomo_core::BoxedTcpStream {
        let mut headers = BTreeMap::new();
        if let Some(host) = host {
            headers.insert("Host".to_owned(), host.to_owned());
        }
        mihomo_transport::wrap_websocket_proxy_stream(
            Box::new(TcpStream::connect(addr).unwrap()),
            mihomo_transport::TransportTarget::new(addr.ip().to_string(), addr.port()),
            &mihomo_transport::WebsocketOptions {
                path: path.to_owned(),
                headers,
                ..Default::default()
            },
        )
        .unwrap()
    }

    fn accept_websocket_upgrade_test_stream(
        mut stream: mihomo_core::BoxedTcpStream,
    ) -> (String, mihomo_core::BoxedTcpStream) {
        let request = read_http_headers(&mut *stream);
        assert!(
            !request
                .lines()
                .any(|line| line.starts_with("Sec-WebSocket-Key:")),
            "v2ray http upgrade must not send Sec-WebSocket-Key"
        );
        let response =
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
        (request, stream)
    }

    fn accept_websocket_upgrade_fast_open_test_stream(
        mut stream: TestRustlsServerStream,
    ) -> (String, mihomo_core::BoxedTcpStream) {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        let header_end = loop {
            let read = stream.read(&mut chunk).unwrap();
            assert_ne!(read, 0);
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let request = String::from_utf8(buffer[..header_end].to_vec()).unwrap();
        let mut prefix = buffer[header_end..].to_vec();
        if prefix.is_empty() {
            let mut extra = [0_u8; 1024];
            let read = stream.read(&mut extra).unwrap();
            assert!(read > 0, "fast-open request did not carry early payload bytes");
            prefix.extend_from_slice(&extra[..read]);
        }
        let response =
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
        (
            request,
            Box::new(TestPrefixedStream {
                prefix: std::io::Cursor::new(prefix),
                inner: Box::new(stream),
            }),
        )
    }

    fn accept_websocket_upgrade_early_data_test_stream(
        mut stream: mihomo_core::BoxedTcpStream,
    ) -> (String, mihomo_core::BoxedTcpStream) {
        let request = read_http_headers(&mut *stream);
        let early_data = request
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("Sec-WebSocket-Protocol") {
                    Some(
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(value.trim())
                            .expect("invalid websocket early data"),
                    )
                } else {
                    None
                }
            })
            .unwrap_or_default();
        let response =
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
        (
            request,
            Box::new(TestPrefixedStream {
                prefix: std::io::Cursor::new(early_data),
                inner: stream,
            }),
        )
    }

    fn accept_websocket_early_data_test_stream(
        mut stream: mihomo_core::BoxedTcpStream,
    ) -> (String, mihomo_core::BoxedTcpStream) {
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
        let early_data = request
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("Sec-WebSocket-Protocol") {
                    Some(
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(value.trim())
                            .expect("invalid websocket early data"),
                    )
                } else {
                    None
                }
            })
            .unwrap_or_default();
        let accept = websocket_accept_key(&key);
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
        (
            request,
            Box::new(TestPrefixedStream {
                prefix: std::io::Cursor::new(early_data),
                inner: Box::new(ServerWebsocketStream::new(stream)),
            }),
        )
    }

    #[allow(dead_code)]
    fn accept_http_stream_test(
        mut stream: mihomo_core::BoxedTcpStream,
    ) -> (String, mihomo_core::BoxedTcpStream) {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        let header_end = loop {
            let read = stream.read(&mut chunk).unwrap();
            assert_ne!(read, 0);
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let request = String::from_utf8(buffer[..header_end].to_vec()).unwrap();
        let mut content_length = 0usize;
        for line in request.lines() {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("Content-Length") {
                content_length = value.trim().parse::<usize>().unwrap();
            }
        }
        let mut prefix = buffer[header_end..].to_vec();
        if prefix.len() < content_length {
            let mut rest = vec![0u8; content_length - prefix.len()];
            stream.read_exact(&mut rest).unwrap();
            prefix.extend_from_slice(&rest);
        }
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
        (
            request,
            Box::new(TestPrefixedStream {
                prefix: std::io::Cursor::new(prefix),
                inner: stream,
            }),
        )
    }

    fn build_tls_server_config_with_pem() -> (std::sync::Arc<ServerConfig>, String) {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let cert_pem = cert.cert.pem();
        let key_der = cert.key_pair.serialize_der();
        (
            std::sync::Arc::new(
                ServerConfig::builder()
                    .with_safe_defaults()
                    .with_no_client_auth()
                    .with_single_cert(vec![Certificate(cert_der)], PrivateKey(key_der))
                    .unwrap(),
            ),
            cert_pem,
        )
    }

    fn build_tls_server_config() -> std::sync::Arc<ServerConfig> {
        build_tls_server_config_with_pem().0
    }
