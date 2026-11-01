    fn fetch_http(addr: SocketAddr, token: Option<&str>) -> String {
        send_http_request(addr, "GET", "/version", token, None)
    }

    fn find_listener_addr(app: &RunningApp, name: &str, kind: &str) -> SocketAddr {
        app.listener_addrs()
            .iter()
            .find(|listener| listener.name == name && listener.kind == kind)
            .map(|listener| listener.local_addr)
            .unwrap()
    }

    fn read_http_headers(stream: &mut dyn Read) -> String {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).unwrap();
            assert_ne!(read, 0);
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                return String::from_utf8(buffer).unwrap();
            }
        }
    }

    fn send_http_response(stream: &mut dyn Write, status: &str, body: &[u8]) {
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len(),
        )
        .unwrap();
        if !body.is_empty() {
            stream.write_all(body).unwrap();
        }
        stream.flush().unwrap();
    }

    fn read_http_until_close(stream: &mut TcpStream) -> String {
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    fn send_http_request(
        addr: SocketAddr,
        method: &str,
        target: &str,
        token: Option<&str>,
        body: Option<&[u8]>,
    ) -> String {
        let mut stream = TcpStream::connect(addr).unwrap();
        let body = body.unwrap_or_default();
        write!(
            stream,
            "{method} {target} HTTP/1.1\r\nHost: localhost\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
            token
                .map(|token| format!("Authorization: Bearer {token}\r\n"))
                .unwrap_or_default(),
            body.len(),
        )
        .unwrap();
        if !body.is_empty() {
            stream.write_all(body).unwrap();
        }
        read_http_until_close(&mut stream)
    }

    fn send_https_request(
        addr: SocketAddr,
        method: &str,
        target: &str,
        token: Option<&str>,
        body: Option<&[u8]>,
    ) -> String {
        let socket = TcpStream::connect(addr).unwrap();
        let tls = mihomo_transport::wrap_tls_proxy_stream(
            Box::new(socket),
            mihomo_transport::TransportTarget::new("localhost", addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: false,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &[],
        )
        .unwrap();
        let mut stream = tls;
        let body = body.unwrap_or_default();
        write!(
            stream,
            "{method} {target} HTTP/1.1\r\nHost: localhost\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
            token
                .map(|token| format!("Authorization: Bearer {token}\r\n"))
                .unwrap_or_default(),
            body.len(),
        )
        .unwrap();
        if !body.is_empty() {
            stream.write_all(body).unwrap();
        }
        read_http_response_message(&mut *stream)
    }

    fn send_https_request_skip_verify(
        addr: SocketAddr,
        method: &str,
        target: &str,
        token: Option<&str>,
        body: Option<&[u8]>,
    ) -> String {
        let socket = TcpStream::connect(addr).unwrap();
        let tls = mihomo_transport::wrap_tls_proxy_stream(
            Box::new(socket),
            mihomo_transport::TransportTarget::new("localhost", addr.port()),
            &mihomo_transport::TlsOptions {
                enabled: true,
                sni: "localhost".into(),
                skip_cert_verify: true,
                fingerprint: String::new(),
                certificate: String::new(),
                private_key: String::new(),
            },
            &[],
        )
        .unwrap();
        let mut stream = tls;
        let body = body.unwrap_or_default();
        write!(
            stream,
            "{method} {target} HTTP/1.1\r\nHost: localhost\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
            token
                .map(|token| format!("Authorization: Bearer {token}\r\n"))
                .unwrap_or_default(),
            body.len(),
        )
        .unwrap();
        if !body.is_empty() {
            stream.write_all(body).unwrap();
        }
        read_http_response_message(&mut *stream)
    }

    fn read_http_response_message(stream: &mut dyn Read) -> String {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        let header_end = loop {
            let read = stream.read(&mut chunk).unwrap();
            assert_ne!(read, 0);
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let headers = String::from_utf8(buffer[..header_end].to_vec()).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or_default();
        let mut body = buffer[header_end..].to_vec();
        while body.len() < content_length {
            let read = stream.read(&mut chunk).unwrap();
            assert_ne!(read, 0);
            body.extend_from_slice(&chunk[..read]);
        }
        format!("{headers}{}", String::from_utf8_lossy(&body[..content_length]))
    }

    fn run_tunnel_roundtrip(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(payload).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        response
    }

    fn relay_test_tcp_bidirectional(downstream: TcpStream, upstream: TcpStream) {
        let mut downstream_read = downstream.try_clone().unwrap();
        let mut downstream_write = downstream;
        let mut upstream_read = upstream.try_clone().unwrap();
        let mut upstream_write = upstream;
        let a = thread::spawn(move || {
            let _ = std::io::copy(&mut downstream_read, &mut upstream_write);
            let _ = upstream_write.shutdown(Shutdown::Write);
        });
        let b = thread::spawn(move || {
            let _ = std::io::copy(&mut upstream_read, &mut downstream_write);
            let _ = downstream_write.shutdown(Shutdown::Write);
        });
        let _ = a.join();
        let _ = b.join();
    }

    fn parse_http_json(response: &str) -> Value {
        let body = response.split("\r\n\r\n").nth(1).unwrap_or_default();
        serde_json::from_str(body).unwrap()
    }

    fn build_socks_udp_associate_request() -> Vec<u8> {
        vec![0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
    }

    fn read_socks5_connect_target(stream: &mut TcpStream) -> SocketAddr {
        let mut greeting = [0_u8; 3];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        stream.write_all(&[0x05, 0x00]).unwrap();
        stream.flush().unwrap();

        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(&header[..3], &[0x05, 0x01, 0x00]);
        let ip = match header[3] {
            0x01 => {
                let mut octets = [0_u8; 4];
                stream.read_exact(&mut octets).unwrap();
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets))
            }
            0x04 => {
                let mut octets = [0_u8; 16];
                stream.read_exact(&mut octets).unwrap();
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
            }
            other => panic!("unexpected atyp {other}"),
        };
        let mut port = [0_u8; 2];
        stream.read_exact(&mut port).unwrap();
        SocketAddr::new(ip, u16::from_be_bytes(port))
    }

    fn write_socks5_connect_reply(stream: &mut TcpStream, bind_addr: SocketAddr) {
        let mut reply = vec![0x05, 0x00, 0x00];
        match bind_addr {
            SocketAddr::V4(addr) => {
                reply.push(0x01);
                reply.extend_from_slice(&addr.ip().octets());
                reply.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                reply.push(0x04);
                reply.extend_from_slice(&addr.ip().octets());
                reply.extend_from_slice(&addr.port().to_be_bytes());
            }
        }
        stream.write_all(&reply).unwrap();
        stream.flush().unwrap();
    }

    fn read_socks_udp_associate_reply(stream: &mut TcpStream) -> SocketAddr {
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(&header[..3], &[0x05, 0x00, 0x00]);
        match header[3] {
            0x01 => {
                let mut addr = [0_u8; 4];
                stream.read_exact(&mut addr).unwrap();
                let mut port = [0_u8; 2];
                stream.read_exact(&mut port).unwrap();
                SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        addr[0], addr[1], addr[2], addr[3],
                    )),
                    u16::from_be_bytes(port),
                )
            }
            0x04 => {
                let mut addr = [0_u8; 16];
                stream.read_exact(&mut addr).unwrap();
                let mut port = [0_u8; 2];
                stream.read_exact(&mut port).unwrap();
                SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr)),
                    u16::from_be_bytes(port),
                )
            }
            other => panic!("unexpected atyp {other}"),
        }
    }

    fn build_socks_udp_request(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x00, 0x00, 0x00];
        match target {
            SocketAddr::V4(addr) => {
                frame.push(0x01);
                frame.extend_from_slice(&addr.ip().octets());
                frame.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                frame.push(0x04);
                frame.extend_from_slice(&addr.ip().octets());
                frame.extend_from_slice(&addr.port().to_be_bytes());
            }
        }
        frame.extend_from_slice(payload);
        frame
    }

    fn build_socks_udp_request_with_frag(
        target: SocketAddr,
        frag: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = vec![0x00, 0x00, frag];
        match target {
            SocketAddr::V4(addr) => {
                frame.push(0x01);
                frame.extend_from_slice(&addr.ip().octets());
                frame.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                frame.push(0x04);
                frame.extend_from_slice(&addr.ip().octets());
                frame.extend_from_slice(&addr.port().to_be_bytes());
            }
        }
        frame.extend_from_slice(payload);
        frame
    }

    fn build_socks_udp_request_with_domain(host: &str, port: u16, payload: &[u8]) -> Vec<u8> {
        let host = host.as_bytes();
        let mut frame = vec![0x00, 0x00, 0x00, 0x03, host.len() as u8];
        frame.extend_from_slice(host);
        frame.extend_from_slice(&port.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn read_gost_relay_target(stream: &mut TcpStream) -> (u8, Option<SocketAddr>) {
        read_gost_relay_target_reader(stream)
    }

    fn read_gost_relay_target_reader(stream: &mut dyn Read) -> (u8, Option<SocketAddr>) {
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(header[0], 0x01);
        let command = header[1];
        let feature_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        let mut features = vec![0_u8; feature_len];
        stream.read_exact(&mut features).unwrap();

        let mut offset = 0;
        while offset < features.len() {
            let feature_type = features[offset];
            let payload_len =
                u16::from_be_bytes([features[offset + 1], features[offset + 2]]) as usize;
            offset += 3;
            let payload = &features[offset..offset + payload_len];
            offset += payload_len;
            if feature_type != 0x02 {
                continue;
            }

            let atyp = payload[0];
            let mut payload_offset = 1;
            let ip = match atyp {
                0x01 => {
                    let ip = std::net::Ipv4Addr::new(
                        payload[payload_offset],
                        payload[payload_offset + 1],
                        payload[payload_offset + 2],
                        payload[payload_offset + 3],
                    );
                    payload_offset += 4;
                    std::net::IpAddr::V4(ip)
                }
                0x04 => {
                    let mut octets = [0_u8; 16];
                    octets.copy_from_slice(&payload[payload_offset..payload_offset + 16]);
                    payload_offset += 16;
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
                }
                other => panic!("unexpected gost relay atyp {other}"),
            };
            let port =
                u16::from_be_bytes([payload[payload_offset], payload[payload_offset + 1]]);
            return (command, Some(SocketAddr::new(ip, port)));
        }

        (command, None)
    }

    fn read_trojan_request(stream: &mut dyn Read) -> (String, u8, String) {
        let mut password = [0_u8; 56];
        stream.read_exact(&mut password).unwrap();
        let mut crlf = [0_u8; 2];
        stream.read_exact(&mut crlf).unwrap();
        assert_eq!(&crlf, b"\r\n");
        let mut command = [0_u8; 1];
        stream.read_exact(&mut command).unwrap();

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
            other => panic!("unexpected trojan atyp {other}"),
        };
        let mut port = [0_u8; 2];
        stream.read_exact(&mut port).unwrap();
        stream.read_exact(&mut crlf).unwrap();
        assert_eq!(&crlf, b"\r\n");

        (
            String::from_utf8(password.to_vec()).unwrap(),
            command[0],
            format!("{host}:{}", u16::from_be_bytes(port)),
        )
    }

    fn read_vless_request(stream: &mut dyn Read) -> (u8, String, u8, String) {
        let mut version = [0_u8; 1];
        stream.read_exact(&mut version).unwrap();

        let mut uuid = [0_u8; 16];
        stream.read_exact(&mut uuid).unwrap();

        let mut addon_len = [0_u8; 1];
        stream.read_exact(&mut addon_len).unwrap();
        assert_eq!(addon_len[0], 0);

        let mut command = [0_u8; 1];
        stream.read_exact(&mut command).unwrap();
        if command[0] == 0x03 {
            return (
                version[0],
                Uuid::from_bytes(uuid).to_string(),
                command[0],
                "v1.mux.cool:666".to_owned(),
            );
        }

        let mut port = [0_u8; 2];
        stream.read_exact(&mut port).unwrap();
        let port = u16::from_be_bytes(port);

        let mut atyp = [0_u8; 1];
        stream.read_exact(&mut atyp).unwrap();
        let host = match atyp[0] {
            0x01 => {
                let mut addr = [0_u8; 4];
                stream.read_exact(&mut addr).unwrap();
                std::net::Ipv4Addr::from(addr).to_string()
            }
            0x03 => {
                let mut addr = [0_u8; 16];
                stream.read_exact(&mut addr).unwrap();
                std::net::Ipv6Addr::from(addr).to_string()
            }
            0x02 => {
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
        )
    }

    fn read_shadowsocks_target_reader(stream: &mut dyn Read) -> String {
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
            other => panic!("unexpected anytls target atyp {other}"),
        };
        let mut port = [0_u8; 2];
        stream.read_exact(&mut port).unwrap();
        format!("{host}:{}", u16::from_be_bytes(port))
    }

    fn read_snell_target_reader(stream: &mut dyn Read, expected_version: u8) -> String {
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(header[0], 1);
        assert_eq!(header[1], if expected_version == 2 { 5 } else { 1 });
        assert_eq!(header[2], 0);
        let host_len = header[3] as usize;
        let mut host = vec![0_u8; host_len];
        stream.read_exact(&mut host).unwrap();
        let mut port = [0_u8; 2];
        stream.read_exact(&mut port).unwrap();
        format!("{}:{}", String::from_utf8(host).unwrap(), u16::from_be_bytes(port))
    }
