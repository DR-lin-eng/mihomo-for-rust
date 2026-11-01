    fn build_tls_server_config_with_fingerprint() -> (std::sync::Arc<ServerConfig>, String) {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();
        let fingerprint = Sha256::digest(&cert_der)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        (
            std::sync::Arc::new(
                ServerConfig::builder()
                    .with_safe_defaults()
                    .with_no_client_auth()
                    .with_single_cert(vec![Certificate(cert_der)], PrivateKey(key_der))
                    .unwrap(),
            ),
            fingerprint,
        )
    }

    fn build_tls_server_config_with_client_auth(
        client_cert_der: Vec<u8>,
    ) -> std::sync::Arc<ServerConfig> {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();
        let mut roots = RootCertStore::empty();
        roots.add(&Certificate(client_cert_der)).unwrap();
        let verifier = AllowAnyAuthenticatedClient::new(roots);
        std::sync::Arc::new(
            ServerConfig::builder()
                .with_safe_defaults()
                .with_client_cert_verifier(std::sync::Arc::new(verifier))
                .with_single_cert(vec![Certificate(cert_der)], PrivateKey(key_der))
                .unwrap(),
        )
    }

    fn indent_block(value: &str, spaces: usize) -> String {
        let indent = " ".repeat(spaces);
        value
            .lines()
            .map(|line| format!("{indent}{line}"))
            .collect::<Vec<_>>()
            .join("\n")
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

    fn read_anytls_uot_request(payload: &[u8]) -> (bool, SocketAddr) {
        let mut cursor = std::io::Cursor::new(payload);
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
                SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
                    u16::from_be_bytes(port),
                )
            }
            0x01 => {
                let mut octets = [0_u8; 16];
                cursor.read_exact(&mut octets).unwrap();
                let mut port = [0_u8; 2];
                cursor.read_exact(&mut port).unwrap();
                SocketAddr::new(
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

    fn read_anytls_uot_packet(payload: &[u8]) -> (SocketAddr, Vec<u8>) {
        let mut cursor = std::io::Cursor::new(payload);
        let mut atyp = [0_u8; 1];
        cursor.read_exact(&mut atyp).unwrap();
        let target = match atyp[0] {
            0x00 => {
                let mut octets = [0_u8; 4];
                cursor.read_exact(&mut octets).unwrap();
                let mut port = [0_u8; 2];
                cursor.read_exact(&mut port).unwrap();
                SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
                    u16::from_be_bytes(port),
                )
            }
            0x01 => {
                let mut octets = [0_u8; 16];
                cursor.read_exact(&mut octets).unwrap();
                let mut port = [0_u8; 2];
                cursor.read_exact(&mut port).unwrap();
                SocketAddr::new(
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

    fn read_trojan_udp_packet_frame(stream: &mut dyn Read) -> (SocketAddr, Vec<u8>) {
        let mut atyp = [0_u8; 1];
        stream.read_exact(&mut atyp).unwrap();
        let host = match atyp[0] {
            0x01 => {
                let mut octets = [0_u8; 4];
                stream.read_exact(&mut octets).unwrap();
                TrojanUdpFrameHost::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)))
            }
            0x04 => {
                let mut octets = [0_u8; 16];
                stream.read_exact(&mut octets).unwrap();
                TrojanUdpFrameHost::Ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
            }
            0x03 => {
                let mut length = [0_u8; 1];
                stream.read_exact(&mut length).unwrap();
                let mut host = vec![0_u8; length[0] as usize];
                stream.read_exact(&mut host).unwrap();
                TrojanUdpFrameHost::Domain(String::from_utf8_lossy(&host).into_owned())
            }
            other => panic!("unexpected trojan udp atyp {other}"),
        };
        let mut port = [0_u8; 2];
        stream.read_exact(&mut port).unwrap();
        let mut len = [0_u8; 2];
        stream.read_exact(&mut len).unwrap();
        let mut crlf = [0_u8; 2];
        stream.read_exact(&mut crlf).unwrap();
        assert_eq!(&crlf, b"\r\n");
        let mut payload = vec![0_u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut payload).unwrap();
        let port = u16::from_be_bytes(port);
        let target = match host {
            TrojanUdpFrameHost::Ip(ip) => SocketAddr::new(ip, port),
            TrojanUdpFrameHost::Domain(host) => (host.as_str(), port)
                .to_socket_addrs()
                .unwrap()
                .next()
                .unwrap(),
        };
        (target, payload)
    }

    fn write_trojan_udp_packet_frame(stream: &mut dyn Write, target: SocketAddr, payload: &[u8]) {
        match target {
            SocketAddr::V4(addr) => {
                stream.write_all(&[0x01]).unwrap();
                stream.write_all(&addr.ip().octets()).unwrap();
            }
            SocketAddr::V6(addr) => {
                stream.write_all(&[0x04]).unwrap();
                stream.write_all(&addr.ip().octets()).unwrap();
            }
        }
        stream.write_all(&target.port().to_be_bytes()).unwrap();
        stream
            .write_all(&(payload.len() as u16).to_be_bytes())
            .unwrap();
        stream.write_all(b"\r\n").unwrap();
        stream.write_all(payload).unwrap();
    }

    fn write_trojan_udp_packet_frame_with_domain(
        stream: &mut dyn Write,
        host: &str,
        port: u16,
        payload: &[u8],
    ) {
        stream.write_all(&[0x03]).unwrap();
        stream.write_all(&[host.len() as u8]).unwrap();
        stream.write_all(host.as_bytes()).unwrap();
        stream.write_all(&port.to_be_bytes()).unwrap();
        stream
            .write_all(&(payload.len() as u16).to_be_bytes())
            .unwrap();
        stream.write_all(b"\r\n").unwrap();
        stream.write_all(payload).unwrap();
    }

    fn write_xudp_packet_frame_with_domain(
        stream: &mut dyn Write,
        host: &str,
        port: u16,
        payload: &[u8],
    ) {
        let header_len = (9 + host.len()) as u16;
        stream.write_all(&header_len.to_be_bytes()).unwrap();
        stream.write_all(&[0x00, 0x00, 0x01, 0x01]).unwrap();
        stream.write_all(&[0x02]).unwrap();
        stream.write_all(&port.to_be_bytes()).unwrap();
        stream.write_all(&[0x02, host.len() as u8]).unwrap();
        stream.write_all(host.as_bytes()).unwrap();
        stream
            .write_all(&(payload.len() as u16).to_be_bytes())
            .unwrap();
        stream.write_all(payload).unwrap();
    }

    fn write_snell_udp_packet_with_domain(
        stream: &mut dyn Write,
        host: &str,
        port: u16,
        payload: &[u8],
    ) {
        let mut packet = Vec::with_capacity(1 + 1 + host.len() + 2 + payload.len());
        packet.push(0x01);
        packet.push(host.len() as u8);
        packet.extend_from_slice(host.as_bytes());
        packet.extend_from_slice(&port.to_be_bytes());
        packet.extend_from_slice(payload);
        stream.write_all(&packet).unwrap();
    }

    fn write_sudoku_udp_packet_with_domain(
        stream: &mut dyn Write,
        host: &str,
        port: u16,
        payload: &[u8],
    ) {
        let mut addr = Vec::with_capacity(1 + 1 + host.len() + 2);
        addr.push(0x03);
        addr.push(host.len() as u8);
        addr.extend_from_slice(host.as_bytes());
        addr.extend_from_slice(&port.to_be_bytes());

        let mut packet = Vec::with_capacity(2 + 2 + addr.len() + payload.len());
        packet.extend_from_slice(&(addr.len() as u16).to_be_bytes());
        packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        packet.extend_from_slice(&addr);
        packet.extend_from_slice(payload);
        stream.write_all(&packet).unwrap();
    }

    enum TrojanUdpFrameHost {
        Ip(std::net::IpAddr),
        Domain(String),
    }

    fn read_trusttunnel_udp_packet_frame_from_client(stream: &mut dyn Read) -> (SocketAddr, Vec<u8>) {
        let mut header = [0_u8; 4 + 16 + 2 + 16 + 2 + 1];
        stream.read_exact(&mut header).unwrap();
        let length = u32::from_be_bytes(header[0..4].try_into().unwrap()) as usize;
        let destination_ip = {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&header[22..38]);
            if octets[..12].iter().all(|value| *value == 0)
                && !(octets[12] == 0 && octets[13] == 0 && octets[14] == 0 && octets[15] == 1)
            {
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    octets[12], octets[13], octets[14], octets[15],
                ))
            } else {
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
            }
        };
        let destination_port = u16::from_be_bytes(header[38..40].try_into().unwrap());
        let app_name_len = header[40] as usize;
        if app_name_len > 0 {
            let mut app_name = vec![0_u8; app_name_len];
            stream.read_exact(&mut app_name).unwrap();
        }
        let payload_len = length - (16 + 2 + 16 + 2 + 1 + app_name_len);
        let mut payload = vec![0_u8; payload_len];
        stream.read_exact(&mut payload).unwrap();
        (SocketAddr::new(destination_ip, destination_port), payload)
    }

    fn write_trusttunnel_udp_packet_frame_to_client(
        stream: &mut dyn Write,
        target: SocketAddr,
        payload: &[u8],
    ) {
        let length = u32::try_from(16 + 2 + 16 + 2 + payload.len()).unwrap();
        stream.write_all(&length.to_be_bytes()).unwrap();
        match target {
            SocketAddr::V4(addr) => {
                stream.write_all(&[0_u8; 12]).unwrap();
                stream.write_all(&addr.ip().octets()).unwrap();
            }
            SocketAddr::V6(addr) => {
                stream.write_all(&addr.ip().octets()).unwrap();
            }
        }
        stream.write_all(&target.port().to_be_bytes()).unwrap();
        stream.write_all(&[0_u8; 16]).unwrap();
        stream.write_all(&0_u16.to_be_bytes()).unwrap();
        stream.write_all(payload).unwrap();
    }

    fn read_tuic_v5_udp_packet_from_client(stream: &mut dyn Read) -> (SocketAddr, Vec<u8>) {
        let mut header = [0_u8; 2];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(header, [0x05, 0x02]);
        let mut assoc = [0_u8; 2];
        stream.read_exact(&mut assoc).unwrap();
        let _assoc = u16::from_be_bytes(assoc);
        let mut packet_id = [0_u8; 2];
        stream.read_exact(&mut packet_id).unwrap();
        let _ = packet_id;
        let mut frag = [0_u8; 2];
        stream.read_exact(&mut frag).unwrap();
        assert_eq!(frag, [1, 0]);
        let mut size = [0_u8; 2];
        stream.read_exact(&mut size).unwrap();
        let size = u16::from_be_bytes(size) as usize;
        let target = read_tuic_udp_socket_addr(stream);
        let mut payload = vec![0_u8; size];
        stream.read_exact(&mut payload).unwrap();
        (target, payload)
    }

    fn write_tuic_v5_udp_packet_to_client(
        stream: &mut dyn Write,
        source: SocketAddr,
        payload: &[u8],
    ) {
        stream.write_all(&[0x05, 0x02]).unwrap();
        stream.write_all(&1_u16.to_be_bytes()).unwrap();
        stream.write_all(&0_u16.to_be_bytes()).unwrap();
        stream.write_all(&[1, 0]).unwrap();
        stream.write_all(&(payload.len() as u16).to_be_bytes()).unwrap();
        write_tuic_udp_socket_addr(stream, source);
        stream.write_all(payload).unwrap();
    }

    fn read_tuic_v4_udp_packet_from_client(stream: &mut dyn Read) -> (SocketAddr, Vec<u8>) {
        let mut header = [0_u8; 2];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(header, [0x04, 0x02]);
        let mut assoc = [0_u8; 4];
        stream.read_exact(&mut assoc).unwrap();
        let _assoc = u32::from_be_bytes(assoc);
        let mut size = [0_u8; 2];
        stream.read_exact(&mut size).unwrap();
        let size = u16::from_be_bytes(size) as usize;
        let target = read_tuic_udp_socket_addr(stream);
        let mut payload = vec![0_u8; size];
        stream.read_exact(&mut payload).unwrap();
        (target, payload)
    }

    fn write_tuic_v4_udp_packet_to_client(
        stream: &mut dyn Write,
        source: SocketAddr,
        payload: &[u8],
    ) {
        stream.write_all(&[0x04, 0x02]).unwrap();
        stream.write_all(&1_u32.to_be_bytes()).unwrap();
        stream.write_all(&(payload.len() as u16).to_be_bytes()).unwrap();
        write_tuic_udp_socket_addr(stream, source);
        stream.write_all(payload).unwrap();
    }

    fn read_tuic_udp_socket_addr(stream: &mut dyn Read) -> SocketAddr {
        let mut atyp = [0_u8; 1];
        stream.read_exact(&mut atyp).unwrap();
        match atyp[0] {
            0x01 => {
                let mut octets = [0_u8; 4];
                stream.read_exact(&mut octets).unwrap();
                let mut port = [0_u8; 2];
                stream.read_exact(&mut port).unwrap();
                SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
                    u16::from_be_bytes(port),
                )
            }
            0x02 => {
                let mut octets = [0_u8; 16];
                stream.read_exact(&mut octets).unwrap();
                let mut port = [0_u8; 2];
                stream.read_exact(&mut port).unwrap();
                SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                    u16::from_be_bytes(port),
                )
            }
            other => panic!("unexpected tuic udp atyp {other}"),
        }
    }

    fn write_tuic_udp_socket_addr(stream: &mut dyn Write, addr: SocketAddr) {
        match addr {
            SocketAddr::V4(addr) => {
                stream.write_all(&[0x01]).unwrap();
                stream.write_all(&addr.ip().octets()).unwrap();
                stream.write_all(&addr.port().to_be_bytes()).unwrap();
            }
            SocketAddr::V6(addr) => {
                stream.write_all(&[0x02]).unwrap();
                stream.write_all(&addr.ip().octets()).unwrap();
                stream.write_all(&addr.port().to_be_bytes()).unwrap();
            }
        }
    }

    fn read_hy2_udp_varint(stream: &mut dyn Read) -> u64 {
        let mut first = [0_u8; 1];
        stream.read_exact(&mut first).unwrap();
        let tag = first[0] >> 6;
        let mut buf = [0_u8; 8];
        match tag {
            0 => (first[0] & 0x3f) as u64,
            1 => {
                buf[0] = first[0];
                stream.read_exact(&mut buf[1..2]).unwrap();
                u16::from_be_bytes(buf[..2].try_into().unwrap()) as u64 & 0x3fff
            }
            2 => {
                buf[0] = first[0];
                stream.read_exact(&mut buf[1..4]).unwrap();
                u32::from_be_bytes(buf[..4].try_into().unwrap()) as u64 & 0x3fff_ffff
            }
            _ => {
                buf[0] = first[0];
                stream.read_exact(&mut buf[1..8]).unwrap();
                u64::from_be_bytes(buf) & 0x3fff_ffff_ffff_ffff
            }
        }
    }

    fn write_hy2_udp_varint(stream: &mut dyn Write, value: u64) {
        if value < (1 << 6) {
            stream.write_all(&[value as u8]).unwrap();
        } else if value < (1 << 14) {
            let mut bytes = ((1_u16 << 14) | value as u16).to_be_bytes();
            bytes[0] |= 0b01 << 6;
            stream.write_all(&bytes).unwrap();
        } else if value < (1 << 30) {
            let mut bytes = ((1_u32 << 30) | value as u32).to_be_bytes();
            bytes[0] |= 0b10 << 6;
            stream.write_all(&bytes).unwrap();
        } else {
            let mut bytes = ((1_u64 << 62) | value).to_be_bytes();
            bytes[0] |= 0b11 << 6;
            stream.write_all(&bytes).unwrap();
        }
    }

    fn read_hy2_udp_packet_from_client(stream: &mut dyn Read) -> (SocketAddr, Vec<u8>) {
        let mut session = [0_u8; 4];
        stream.read_exact(&mut session).unwrap();
        let mut packet = [0_u8; 2];
        stream.read_exact(&mut packet).unwrap();
        let mut frag_id = [0_u8; 1];
        stream.read_exact(&mut frag_id).unwrap();
        let mut frag_total = [0_u8; 1];
        stream.read_exact(&mut frag_total).unwrap();
        assert_eq!(frag_id[0], 0);
        assert_eq!(frag_total[0], 1);
        let destination_len = read_hy2_udp_varint(stream) as usize;
        let mut destination = vec![0_u8; destination_len];
        stream.read_exact(&mut destination).unwrap();
        let destination = String::from_utf8(destination).unwrap();
        let target = destination.parse::<SocketAddr>().unwrap();
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).unwrap();
        (target, payload)
    }

    fn write_hy2_udp_packet_to_client(
        stream: &mut dyn Write,
        source: SocketAddr,
        payload: &[u8],
    ) {
        stream.write_all(&1_u32.to_be_bytes()).unwrap();
        stream.write_all(&1_u16.to_be_bytes()).unwrap();
        stream.write_all(&[0, 1]).unwrap();
        let destination = source.to_string();
        write_hy2_udp_varint(stream, destination.len() as u64);
        stream.write_all(destination.as_bytes()).unwrap();
        stream.write_all(payload).unwrap();
    }

    fn read_hysteria_udp_packet_from_client(stream: &mut dyn Read) -> (SocketAddr, Vec<u8>) {
        let mut session = [0_u8; 4];
        stream.read_exact(&mut session).unwrap();
        let mut host_len = [0_u8; 2];
        stream.read_exact(&mut host_len).unwrap();
        let host_len = u16::from_be_bytes(host_len) as usize;
        let mut host = vec![0_u8; host_len];
        stream.read_exact(&mut host).unwrap();
        let host = String::from_utf8(host).unwrap();
        let mut port = [0_u8; 2];
        stream.read_exact(&mut port).unwrap();
        let port = u16::from_be_bytes(port);
        let mut msg_id = [0_u8; 2];
        stream.read_exact(&mut msg_id).unwrap();
        let _msg_id = u16::from_be_bytes(msg_id);
        let mut frag_id = [0_u8; 1];
        stream.read_exact(&mut frag_id).unwrap();
        let mut frag_count = [0_u8; 1];
        stream.read_exact(&mut frag_count).unwrap();
        assert_eq!(frag_id[0], 0);
        assert_eq!(frag_count[0], 1);
        let mut payload_len = [0_u8; 2];
        stream.read_exact(&mut payload_len).unwrap();
        let payload_len = u16::from_be_bytes(payload_len) as usize;
        let mut payload = vec![0_u8; payload_len];
        stream.read_exact(&mut payload).unwrap();
        let target = format!("{host}:{port}").parse::<SocketAddr>().unwrap();
        (target, payload)
    }

    fn write_hysteria_udp_packet_to_client(
        stream: &mut dyn Write,
        source: SocketAddr,
        payload: &[u8],
    ) {
        stream.write_all(&1_u32.to_be_bytes()).unwrap();
        let host = source.ip().to_string();
        stream.write_all(&(host.len() as u16).to_be_bytes()).unwrap();
        stream.write_all(host.as_bytes()).unwrap();
        stream.write_all(&source.port().to_be_bytes()).unwrap();
        stream.write_all(&1_u16.to_be_bytes()).unwrap();
        stream.write_all(&[0, 1]).unwrap();
        stream.write_all(&(payload.len() as u16).to_be_bytes()).unwrap();
        stream.write_all(payload).unwrap();
    }

    const TEST_HYSTERIA_XPLUS_SALT_LEN: usize = 16;

    fn apply_test_hysteria_xplus_obfs(password: &[u8], salt: &[u8], payload: &mut [u8]) {
        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(salt);
        let key = hasher.finalize();
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[index % key.len()];
        }
    }

    #[derive(Debug)]
    struct TestHysteriaXPlusUdpSocket {
        io: tokio::net::UdpSocket,
        local_addr: SocketAddr,
        obfs_password: Vec<u8>,
    }

    impl TestHysteriaXPlusUdpSocket {
        fn new(socket: std::net::UdpSocket, obfs_password: Vec<u8>) -> io::Result<Self> {
            socket.set_nonblocking(true)?;
            let local_addr = socket.local_addr()?;
            Ok(Self {
                io: tokio::net::UdpSocket::from_std(socket)?,
                local_addr,
                obfs_password,
            })
        }

        fn maybe_decode_recv(&self, meta: &mut RecvMeta, buf: &mut [u8]) {
            if self.obfs_password.is_empty() || meta.len <= TEST_HYSTERIA_XPLUS_SALT_LEN {
                return;
            }
            let payload_len = meta.len - TEST_HYSTERIA_XPLUS_SALT_LEN;
            let salt = buf[..TEST_HYSTERIA_XPLUS_SALT_LEN].to_vec();
            buf.copy_within(TEST_HYSTERIA_XPLUS_SALT_LEN..meta.len, 0);
            let payload = &mut buf[..payload_len];
            apply_test_hysteria_xplus_obfs(&self.obfs_password, &salt, payload);
            meta.len = payload_len;
            meta.stride = payload_len;
        }
    }

    impl AsyncUdpSocket for TestHysteriaXPlusUdpSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(TestHysteriaXPlusUdpPoller { socket: self })
        }

        fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
            let mut owned;
            let tx = if self.obfs_password.is_empty() {
                transmit.clone()
            } else {
                let mut salt = [0_u8; TEST_HYSTERIA_XPLUS_SALT_LEN];
                rand_core::OsRng.fill_bytes(&mut salt);
                owned = Vec::with_capacity(TEST_HYSTERIA_XPLUS_SALT_LEN + transmit.contents.len());
                owned.extend_from_slice(&salt);
                owned.extend_from_slice(transmit.contents);
                apply_test_hysteria_xplus_obfs(
                    &self.obfs_password,
                    &salt,
                    &mut owned[TEST_HYSTERIA_XPLUS_SALT_LEN..],
                );
                Transmit {
                    destination: transmit.destination,
                    ecn: transmit.ecn,
                    contents: &owned,
                    segment_size: None,
                    src_ip: transmit.src_ip,
                }
            };
            self.io.try_send_to(tx.contents, tx.destination).map(|_| ())
        }

        fn poll_recv(
            &self,
            cx: &mut Context,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            loop {
                match self.io.poll_recv_ready(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
                let buf = match bufs.first_mut() {
                    Some(buf) => buf,
                    None => return Poll::Ready(Ok(0)),
                };
                let mut recv_buf = vec![0_u8; buf.len()];
                match self.io.try_recv_from(&mut recv_buf) {
                    Ok((len, addr)) => {
                        let dst = &mut buf[..len];
                        dst.copy_from_slice(&recv_buf[..len]);
                        meta[0] = RecvMeta {
                            addr,
                            len,
                            stride: len,
                            ecn: None,
                            dst_ip: None,
                        };
                        self.maybe_decode_recv(&mut meta[0], dst);
                        return Poll::Ready(Ok(1));
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(err) => return Poll::Ready(Err(err)),
                }
            }
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        fn may_fragment(&self) -> bool {
            true
        }
    }

    #[derive(Debug)]
    struct TestHysteriaXPlusUdpPoller {
        socket: Arc<TestHysteriaXPlusUdpSocket>,
    }

    impl UdpPoller for TestHysteriaXPlusUdpPoller {
        fn poll_writable(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.socket.io.poll_send_ready(cx)
        }
    }

    #[derive(Debug)]
    struct TestTokioQuinnRuntime;

    impl QuinnRuntime for TestTokioQuinnRuntime {
        fn new_timer(&self, i: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
            Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(i)))
        }

        fn spawn(&self, future: Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
            tokio::spawn(future);
        }

        fn wrap_udp_socket(
            &self,
            socket: std::net::UdpSocket,
        ) -> io::Result<Arc<dyn AsyncUdpSocket>> {
            Ok(Arc::new(TestHysteriaXPlusUdpSocket::new(socket, Vec::new())?))
        }
    }

    fn parse_socks_udp_response(packet: &[u8]) -> (SocketAddr, Vec<u8>) {
        assert!(packet.len() >= 10);
        assert_eq!(&packet[..3], &[0x00, 0x00, 0x00]);
        let atyp = packet[3];
        let mut offset = 4;
        let addr = match atyp {
            0x01 => {
                let ip = std::net::Ipv4Addr::new(
                    packet[offset],
                    packet[offset + 1],
                    packet[offset + 2],
                    packet[offset + 3],
                );
                offset += 4;
                std::net::IpAddr::V4(ip)
            }
            0x04 => {
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(&packet[offset..offset + 16]);
                offset += 16;
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
            }
            other => panic!("unexpected atyp {other}"),
        };
        let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        offset += 2;
        (SocketAddr::new(addr, port), packet[offset..].to_vec())
    }

    fn build_socks_udp_reply(bind_addr: SocketAddr) -> Vec<u8> {
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
        reply
    }

    fn build_socks_udp_reply_with_domain(host: &str, port: u16) -> Vec<u8> {
        let host = host.as_bytes();
        let mut reply = vec![0x05, 0x00, 0x00, 0x03, host.len() as u8];
        reply.extend_from_slice(host);
        reply.extend_from_slice(&port.to_be_bytes());
        reply
    }

    fn build_dns_query_packet(host: &str, qtype: u16, request_id: u16) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&request_id.to_be_bytes());
        payload.extend_from_slice(&0x0100_u16.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        for label in host.split('.') {
            payload.push(label.len() as u8);
            payload.extend_from_slice(label.as_bytes());
        }
        payload.push(0);
        payload.extend_from_slice(&qtype.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload
    }

    fn build_dns_response_packet(
        host: &str,
        ip: std::net::IpAddr,
        request_id: u16,
    ) -> Vec<u8> {
        let query_type = match ip {
            std::net::IpAddr::V4(_) => 1_u16,
            std::net::IpAddr::V6(_) => 28_u16,
        };
        let query = build_dns_query_packet(host, query_type, request_id);
        let mut payload = Vec::new();
        payload.extend_from_slice(&request_id.to_be_bytes());
        payload.extend_from_slice(&0x8180_u16.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&query[12..]);
        payload.extend_from_slice(&0xC00C_u16.to_be_bytes());
        payload.extend_from_slice(&query_type.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&60_u32.to_be_bytes());
        match ip {
            std::net::IpAddr::V4(ip) => {
                payload.extend_from_slice(&4_u16.to_be_bytes());
                payload.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                payload.extend_from_slice(&16_u16.to_be_bytes());
                payload.extend_from_slice(&ip.octets());
            }
        }
        payload
    }

    fn parse_first_a_answer(packet: &[u8]) -> Option<std::net::IpAddr> {
        if packet.len() < 12 {
            return None;
        }
        let answer_count = u16::from_be_bytes([packet[6], packet[7]]) as usize;
        if answer_count == 0 {
            return None;
        }
        let mut offset = 12;
        while let Some(length) = packet.get(offset).copied() {
            offset += 1;
            if length == 0 {
                break;
            }
            offset += length as usize;
        }
        offset += 4;
        if offset + 16 > packet.len() {
            return None;
        }
        offset += 2;
        let rr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        offset += 2;
        offset += 2;
        offset += 4;
        let rd_length = u16::from_be_bytes([packet[offset], packet[offset + 1]]) as usize;
        offset += 2;
        if rr_type != 1 || rd_length != 4 || offset + 4 > packet.len() {
            return None;
        }
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            packet[offset],
            packet[offset + 1],
            packet[offset + 2],
            packet[offset + 3],
        )))
    }
