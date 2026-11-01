    type HmacSha256 = Hmac<Sha256>;
    trait TestHttpIoStream: Read + Write + Send {}
    impl<T: Read + Write + Send> TestHttpIoStream for T {}
    type BoxedTestHttpIoStream = Box<dyn TestHttpIoStream>;
    const TEST_SUDOKU_MUX_FRAME_OPEN: u8 = 0x01;
    const TEST_SUDOKU_MUX_FRAME_DATA: u8 = 0x02;
    const TEST_SUDOKU_MUX_FRAME_CLOSE: u8 = 0x03;

    fn random_edwards_scalar() -> Scalar {
        let mut seed = [0_u8; 64];
        rand_core::OsRng.fill_bytes(&mut seed);
        Scalar::from_bytes_mod_order_wide(&seed)
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const LUT: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(LUT[(byte >> 4) as usize] as char);
            output.push(LUT[(byte & 0x0f) as usize] as char);
        }
        output
    }

    fn open_sudoku_inbound_test_client(
        sudoku_addr: SocketAddr,
        key: &str,
        aead_method: &str,
        table_type: &str,
        padding_min: i32,
        padding_max: i32,
        enable_pure_downlink: bool,
        custom_table: &str,
        custom_tables: &[String],
        target: TransportTarget,
    ) -> BoxedTcpStream {
        open_sudoku_test_stream(
            Box::new(TcpStream::connect(sudoku_addr).unwrap()),
            &TransportTarget::new("127.0.0.1", sudoku_addr.port()),
            key,
            aead_method,
            table_type,
            padding_min,
            padding_max,
            enable_pure_downlink,
            false,
            "",
            false,
            "",
            "",
            custom_table,
            custom_tables,
            &target,
        )
        .unwrap()
    }

    fn sudoku_udp_test_guard() -> std::sync::MutexGuard<'static, ()> {
        static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
        GUARD
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|err| err.into_inner())
    }

    fn sudoku_httpmask_test_guard() -> std::sync::MutexGuard<'static, ()> {
        static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
        GUARD
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|err| err.into_inner())
    }

    fn encode_test_sudoku_address(raw_addr: &str) -> Vec<u8> {
        let (host, port_text) = raw_addr.rsplit_once(':').unwrap();
        let port: u16 = port_text.parse().unwrap();
        let mut out = Vec::new();
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(addr) => {
                    out.push(0x01);
                    out.extend_from_slice(&addr.octets());
                }
                std::net::IpAddr::V6(addr) => {
                    out.push(0x04);
                    out.extend_from_slice(&addr.octets());
                }
            }
        } else {
            out.push(0x03);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        }
        out.extend_from_slice(&port.to_be_bytes());
        out
    }

    fn write_test_sudoku_mux_frame(
        stream: &mut dyn Write,
        frame_type: u8,
        stream_id: u32,
        payload: &[u8],
    ) {
        let mut header = [0_u8; 9];
        header[0] = frame_type;
        header[1..5].copy_from_slice(&stream_id.to_be_bytes());
        header[5..9].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        stream.write_all(&header).unwrap();
        stream.write_all(payload).unwrap();
    }

    fn read_test_sudoku_mux_frame(stream: &mut dyn Read) -> (u8, u32, Vec<u8>) {
        let mut header = [0_u8; 9];
        stream.read_exact(&mut header).unwrap();
        let frame_type = header[0];
        let stream_id = u32::from_be_bytes(header[1..5].try_into().unwrap());
        let payload_len = u32::from_be_bytes(header[5..9].try_into().unwrap()) as usize;
        let mut payload = vec![0_u8; payload_len];
        stream.read_exact(&mut payload).unwrap();
        (frame_type, stream_id, payload)
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SudokuHttpMaskTestMode {
        Stream,
        Poll,
    }

    struct SudokuHttpMaskTestServer {
        addr: SocketAddr,
        accepted: mpsc::Receiver<TcpStream>,
        errors: mpsc::Receiver<String>,
        stop: mpsc::Sender<()>,
        join: Option<thread::JoinHandle<()>>,
    }

    impl SudokuHttpMaskTestServer {
        fn start(
            mode: SudokuHttpMaskTestMode,
            key: &str,
            path_root: &str,
            expected_host: &str,
        ) -> Self {
            Self::start_with_tls(mode, key, path_root, expected_host, None)
        }

        fn start_with_tls(
            mode: SudokuHttpMaskTestMode,
            key: &str,
            path_root: &str,
            expected_host: &str,
            tls_config: Option<std::sync::Arc<ServerConfig>>,
        ) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let addr = listener.local_addr().unwrap();
            let (accepted_tx, accepted_rx) = mpsc::channel();
            let (error_tx, error_rx) = mpsc::channel();
            let (stop_tx, stop_rx) = mpsc::channel();
            let auth = sudoku_httpmask_test_auth(key);
            let sessions: std::sync::Arc<Mutex<std::collections::HashMap<String, TcpStream>>> =
                std::sync::Arc::new(Mutex::new(std::collections::HashMap::new()));
            let next_token = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1));
            let expected_path_root = path_root.to_owned();
            let expected_host = if expected_host.is_empty() {
                addr.to_string()
            } else {
                expected_host.to_owned()
            };
            let join = thread::spawn(move || loop {
                if stop_rx.try_recv().is_ok() {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        let accepted_tx = accepted_tx.clone();
                        let error_tx = error_tx.clone();
                        let sessions = std::sync::Arc::clone(&sessions);
                        let next_token = std::sync::Arc::clone(&next_token);
                        let expected_path_root = expected_path_root.clone();
                        let expected_host = expected_host.clone();
                        let auth = auth.clone();
                        let tls_config = tls_config.clone();
                        thread::spawn(move || {
                            let stream: BoxedTestHttpIoStream = if let Some(tls_config) = tls_config {
                                let conn = ServerConnection::new(tls_config).unwrap();
                                Box::new(TestRustlsServerStream(StreamOwned::new(conn, stream)))
                            } else {
                                Box::new(stream)
                            };
                            if let Err(err) = handle_sudoku_httpmask_test_request(
                                stream,
                                mode,
                                &auth,
                                &expected_path_root,
                                &expected_host,
                                &sessions,
                                &accepted_tx,
                                &next_token,
                            ) {
                                let _ = error_tx.send(err);
                            }
                        });
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) => {
                        let _ = error_tx.send(err.to_string());
                        break;
                    }
                }
            });
            Self {
                addr,
                accepted: accepted_rx,
                errors: error_rx,
                stop: stop_tx,
                join: Some(join),
            }
        }

        fn next_stream(&self) -> TcpStream {
            self.accepted
                .recv_timeout(Duration::from_secs(15))
                .expect("expected accepted sudoku httpmask session stream")
        }

        fn assert_clean(&mut self) {
            self.stop.send(()).ok();
            if let Some(join) = self.join.take() {
                join.join().unwrap();
            }
            if let Ok(err) = self.errors.try_recv() {
                panic!("{err}");
            }
        }
    }

    #[derive(Clone)]
    struct SudokuHttpMaskTestAuth {
        key: [u8; 32],
    }

    fn sudoku_httpmask_test_auth(key: &str) -> SudokuHttpMaskTestAuth {
        let digest = Sha256::digest(format!("sudoku-httpmask-auth-v1:{}", key.trim()).as_bytes());
        let mut derived = [0_u8; 32];
        derived.copy_from_slice(&digest);
        SudokuHttpMaskTestAuth { key: derived }
    }

    impl SudokuHttpMaskTestAuth {
        fn verify(
            &self,
            value: &str,
            mode: SudokuHttpMaskTestMode,
            method: &str,
            path: &str,
        ) -> bool {
            let mut raw = value.trim();
            if raw.len() > "Bearer ".len() && raw[..7].eq_ignore_ascii_case("Bearer ") {
                raw = raw[7..].trim();
            }
            let Ok(decoded) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw) else {
                return false;
            };
            if decoded.len() != 24 {
                return false;
            }
            let ts = u64::from_be_bytes(decoded[..8].try_into().unwrap());
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now.abs_diff(ts) > 60 {
                return false;
            }
            let mode_token = match mode {
                SudokuHttpMaskTestMode::Stream => "stream",
                SudokuHttpMaskTestMode::Poll => "poll",
            };
            let method = method.trim().to_ascii_uppercase();
            let mut mac = HmacSha256::new_from_slice(&self.key).expect("valid hmac key");
            mac.update(mode_token.as_bytes());
            mac.update(&[0]);
            mac.update(method.as_bytes());
            mac.update(&[0]);
            mac.update(path.as_bytes());
            mac.update(&[0]);
            mac.update(&ts.to_be_bytes());
            let full = mac.finalize().into_bytes();
            full[..16] == decoded[8..]
        }
    }

    fn handle_sudoku_httpmask_test_request(
        mut stream: BoxedTestHttpIoStream,
        mode: SudokuHttpMaskTestMode,
        auth: &SudokuHttpMaskTestAuth,
        path_root: &str,
        expected_host: &str,
        sessions: &std::sync::Arc<Mutex<std::collections::HashMap<String, TcpStream>>>,
        accepted_tx: &mpsc::Sender<TcpStream>,
        next_token: &std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) -> Result<(), String> {
        let (request, tail) = read_http_headers_with_tail(&mut *stream).map_err(|err| err.to_string())?;
        if request.is_empty() {
            return Ok(());
        }
        let (method, target, headers) = parse_http_request_parts(&request)?;
        let Some(host) = headers.get("host") else {
            return Err("missing Host header".to_owned());
        };
        if host != expected_host {
            return Err(format!("unexpected Host header: {host}"));
        }
        let Some(tunnel) = headers.get("x-sudoku-tunnel") else {
            return Err("missing X-Sudoku-Tunnel header".to_owned());
        };
        let requested_mode = match tunnel.as_str() {
            "stream" => SudokuHttpMaskTestMode::Stream,
            "poll" => SudokuHttpMaskTestMode::Poll,
            other => return Err(format!("unexpected tunnel mode header {other}")),
        };
        if requested_mode != mode {
            if mode == SudokuHttpMaskTestMode::Poll
                && requested_mode == SudokuHttpMaskTestMode::Stream
                && method.eq_ignore_ascii_case("GET")
            {
                write_basic_http_response(&mut *stream, 404, b"not found")?;
                return Ok(());
            }
            write_basic_http_response(&mut *stream, 404, b"not found")?;
            return Ok(());
        }
        let (path, query) = split_http_target_query(&target);
        let normalized_root = normalize_httpmask_path_root(path_root);
        let relative_path = path.strip_prefix(&normalized_root).unwrap_or(path.as_str());
        match relative_path {
            "/session" | "/stream" | "/api/v1/upload" => {}
            other => return Err(format!("unexpected path {path} (relative {other})")),
        }
        let auth_value = headers
            .get("authorization")
            .cloned()
            .or_else(|| query.get("auth").cloned())
            .ok_or_else(|| "missing auth token".to_owned())?;
        if !auth.verify(&auth_value, requested_mode, &method, relative_path) {
            write_basic_http_response(&mut *stream, 404, b"not found")?;
            return Ok(());
        }

        match (method.as_str(), relative_path) {
            ("GET", "/session") => {
                let token = format!(
                    "token-{}",
                    next_token.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                );
                let (server_stream, client_stream) = tcp_pair().map_err(|err| err.to_string())?;
                sessions
                    .lock()
                    .unwrap()
                    .insert(token.clone(), client_stream);
                accepted_tx.send(server_stream).map_err(|err| err.to_string())?;
                write_basic_http_response(
                    &mut *stream,
                    200,
                    format!("token={token}").as_bytes(),
                )?;
            }
            ("POST", "/api/v1/upload") => {
                let token = query
                    .get("token")
                    .cloned()
                    .ok_or_else(|| "missing token".to_owned())?;
                let mut sessions_guard = sessions.lock().unwrap();
                let Some(session) = sessions_guard.get(&token) else {
                    write_basic_http_response(&mut *stream, 403, b"forbidden")?;
                    return Ok(());
                };
                if query.get("fin").is_some_and(|value| value == "1") {
                    let session = session.try_clone().map_err(|err| err.to_string())?;
                    drop(sessions_guard);
                    let _ = session.shutdown(Shutdown::Write);
                    write_basic_http_response(&mut *stream, 200, b"")?;
                    return Ok(());
                }
                if query.get("close").is_some_and(|value| value == "1") {
                    let _ = session.shutdown(Shutdown::Both);
                    sessions_guard.remove(&token);
                    write_basic_http_response(&mut *stream, 200, b"")?;
                    return Ok(());
                }
                let mut session = session.try_clone().map_err(|err| err.to_string())?;
                drop(sessions_guard);
                let body = read_http_body_with_tail(&request, tail, &mut *stream)
                    .map_err(|err| err.to_string())?;
                match requested_mode {
                    SudokuHttpMaskTestMode::Stream => {
                        session.write_all(&body).map_err(|err| err.to_string())?;
                    }
                    SudokuHttpMaskTestMode::Poll => {
                        for line in String::from_utf8_lossy(&body).lines() {
                            let trimmed = line.trim();
                            if trimmed.is_empty() {
                                continue;
                            }
                            let payload = base64::engine::general_purpose::STANDARD
                                .decode(trimmed)
                                .map_err(|err| err.to_string())?;
                            session.write_all(&payload).map_err(|err| err.to_string())?;
                        }
                    }
                }
                write_basic_http_response(&mut *stream, 200, b"")?;
            }
            ("GET", "/stream") => {
                let token = query
                    .get("token")
                    .cloned()
                    .ok_or_else(|| "missing token".to_owned())?;
                let session = {
                    let guard = sessions.lock().unwrap();
                    let Some(session) = guard.get(&token) else {
                        write_basic_http_response(&mut *stream, 404, b"not found")?;
                        return Ok(());
                    };
                    session.try_clone().map_err(|err| err.to_string())?
                };
                let mut session = session;
                session
                    .set_nonblocking(true)
                    .map_err(|err| err.to_string())?;
                let mut payload = Vec::new();
                let mut buf = [0_u8; 32 * 1024];
                let deadline = std::time::Instant::now()
                    + Duration::from_secs(match requested_mode {
                        SudokuHttpMaskTestMode::Stream => 3,
                        SudokuHttpMaskTestMode::Poll => 3,
                    });
                loop {
                    match session.read(&mut buf) {
                        Ok(0) => {
                            sessions.lock().unwrap().remove(&token);
                            break;
                        }
                        Ok(read) => payload.extend_from_slice(&buf[..read]),
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            if std::time::Instant::now() >= deadline {
                                break;
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(err) => {
                            sessions.lock().unwrap().remove(&token);
                            return Err(err.to_string());
                        }
                    }
                }
                let _ = session.set_nonblocking(false);
                match requested_mode {
                    SudokuHttpMaskTestMode::Stream => {
                        write_chunked_http_response(&mut *stream, &payload)?
                    }
                    SudokuHttpMaskTestMode::Poll => {
                        let body = if payload.is_empty() {
                            b"\n".to_vec()
                        } else {
                            let mut encoded = base64::engine::general_purpose::STANDARD
                                .encode(payload)
                                .into_bytes();
                            encoded.push(b'\n');
                            encoded
                        };
                        write_basic_http_response(&mut *stream, 200, &body)?;
                    }
                }
            }
            other => return Err(format!("unexpected request {other:?}")),
        }

        Ok(())
    }

    fn normalize_httpmask_path_root(root: &str) -> String {
        let trimmed = root.trim().trim_matches('/');
        if trimmed.is_empty() {
            return String::new();
        }
        if trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            format!("/{trimmed}")
        } else {
            String::new()
        }
    }

    fn read_http_headers_with_tail(stream: &mut dyn Read) -> std::io::Result<(String, Vec<u8>)> {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = match stream.read(&mut chunk) {
                Ok(read) => read,
                Err(err)
                    if buffer.is_empty()
                        && matches!(
                            err.kind(),
                            std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::BrokenPipe
                        ) =>
                {
                    return Ok((String::new(), Vec::new()));
                }
                Err(err) => return Err(err),
            };
            if read == 0 {
                if buffer.is_empty() {
                    return Ok((String::new(), Vec::new()));
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "http request closed before headers completed",
                ));
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                let header_end = position + 4;
                return Ok((
                    String::from_utf8_lossy(&buffer[..header_end]).into_owned(),
                    buffer[header_end..].to_vec(),
                ));
            }
        }
    }

    fn parse_http_request_parts(
        request: &str,
    ) -> Result<(String, String, std::collections::HashMap<String, String>), String> {
        let mut lines = request.lines();
        let request_line = lines.next().ok_or_else(|| "missing request line".to_owned())?;
        let mut parts = request_line.split_whitespace();
        let method = parts
            .next()
            .ok_or_else(|| "missing request method".to_owned())?
            .to_owned();
        let target = parts
            .next()
            .ok_or_else(|| "missing request target".to_owned())?
            .to_owned();
        let mut headers = std::collections::HashMap::new();
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
        Ok((method, target, headers))
    }

    fn split_http_target_query(
        target: &str,
    ) -> (String, std::collections::HashMap<String, String>) {
        let Some((path, query)) = target.split_once('?') else {
            return (target.to_owned(), std::collections::HashMap::new());
        };
        let mut params = std::collections::HashMap::new();
        for pair in query.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            params.insert(key.to_owned(), value.to_owned());
        }
        (path.to_owned(), params)
    }

    fn read_http_body_with_tail(
        request: &str,
        mut tail: Vec<u8>,
        stream: &mut dyn Read,
    ) -> std::io::Result<Vec<u8>> {
        let mut content_length = 0usize;
        for line in request.lines() {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("Content-Length") {
                content_length = value.trim().parse::<usize>().unwrap_or(0);
            }
        }
        if tail.len() < content_length {
            let mut rest = vec![0_u8; content_length - tail.len()];
            stream.read_exact(&mut rest)?;
            tail.extend_from_slice(&rest);
        }
        tail.truncate(content_length);
        Ok(tail)
    }

    fn write_basic_http_response(
        stream: &mut dyn Write,
        status: u16,
        body: &[u8],
    ) -> Result<(), String> {
        let reason = match status {
            200 => "OK",
            403 => "Forbidden",
            404 => "Not Found",
            other => return Err(format!("unsupported test status {other}")),
        };
        stream
            .write_all(
                format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .map_err(|err| err.to_string())?;
        stream.write_all(body).map_err(|err| err.to_string())?;
        stream.flush().map_err(|err| err.to_string())
    }

    fn write_chunked_http_response(
        stream: &mut dyn Write,
        body: &[u8],
    ) -> Result<(), String> {
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .map_err(|err| err.to_string())?;
        if !body.is_empty() {
            stream
                .write_all(format!("{:x}\r\n", body.len()).as_bytes())
                .map_err(|err| err.to_string())?;
            stream.write_all(body).map_err(|err| err.to_string())?;
            stream.write_all(b"\r\n").map_err(|err| err.to_string())?;
        }
        stream.write_all(b"0\r\n\r\n").map_err(|err| err.to_string())?;
        stream.flush().map_err(|err| err.to_string())
    }

    fn tcp_pair() -> std::io::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let client = TcpStream::connect(addr)?;
        let (server, _) = listener.accept()?;
        Ok((server, client))
    }
