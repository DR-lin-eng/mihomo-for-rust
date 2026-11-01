    #[test]
    fn udp_only_support_gaps_trigger_fallback_only_when_udp_surface_is_exposed() {
        let temp = unique_temp_dir();
        let tcp_only = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: http
    name: edge-http
    listen: 127.0.0.1
    port: "8080"
proxies:
  - type: hysteria2
    name: hy2
    server: 1.2.3.4
    port: 443
    password: secret
    sni: edge.example
rules:
  - MATCH,hy2
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&tcp_only, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(gaps.is_empty(), "{gaps:?}");

        let udp_exposed = BootOptions {
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
socks-port: 7891
proxies:
  - type: hysteria2
    name: hy2
    server: 1.2.3.4
    port: 443
    password: secret
    sni: edge.example
rules:
  - MATCH,hy2
"#,
            )),
            ..tcp_only
        };
        let mut state =
            bootstrap_from_boot_options(&udp_exposed, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "hy2"),
            "{gaps:?}"
        );
    }

    #[test]
    fn effective_native_support_gaps_do_not_flag_tuic_udp_runtime() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: edge-tuic
    target: 127.0.0.1:5353
proxies:
  - type: tuic
    name: edge-tuic
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: secret
    udp: true
    sni: localhost
    skip-cert-verify: true
rules:
  - MATCH,edge-tuic
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "edge-tuic"),
            "{gaps:?}"
        );
    }

    #[test]
    fn effective_native_support_gaps_do_not_flag_tuic_udp_over_outer_socks5() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: edge-tuic
    target: 127.0.0.1:5353
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
    udp: true
  - type: tuic
    name: edge-tuic
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: secret
    udp: true
    sni: localhost
    skip-cert-verify: true
    dialer-proxy: outer-socks
rules:
  - MATCH,edge-tuic
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "edge-tuic"),
            "{gaps:?}"
        );
    }

    #[test]
    fn effective_native_support_gaps_do_not_flag_hy2_udp_over_outer_socks5() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: edge-hy2
    target: 127.0.0.1:5353
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
    udp: true
  - type: hysteria2
    name: edge-hy2
    server: 1.2.3.4
    port: 443
    password: secret
    sni: localhost
    skip-cert-verify: true
    dialer-proxy: outer-socks
rules:
  - MATCH,edge-hy2
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "edge-hy2"),
            "{gaps:?}"
        );
    }

    #[test]
    fn effective_native_support_gaps_do_not_flag_hysteria_udp_over_outer_socks5() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: edge-hy
    target: 127.0.0.1:5353
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
    udp: true
  - type: hysteria
    name: edge-hy
    server: 1.2.3.4
    port: 443
    auth-str: secret
    up: 10 Mbps
    down: 50 Mbps
    skip-cert-verify: true
    dialer-proxy: outer-socks
rules:
  - MATCH,edge-hy
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "edge-hy"),
            "{gaps:?}"
        );
    }


    #[test]
    fn effective_native_support_gaps_do_not_flag_masque_h2_udp_runtime() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: edge-masque
    target: 127.0.0.1:5353
proxies:
  - type: masque
    name: edge-masque
    server: masque.example.com
    port: 443
    private-key: key
    public-key: pub
    ip: 10.10.0.2/32
    network: h2
    uri: https://masque.example.com/
    udp: true
rules:
  - MATCH,edge-masque
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "edge-masque"),
            "{gaps:?}"
        );
    }

    #[test]
    fn effective_native_support_gaps_do_not_flag_trusttunnel_quic_over_outer_socks5() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: tt-hop
    target: 127.0.0.1:5353
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
    udp: true
  - type: trusttunnel
    name: tt-hop
    server: 1.2.3.4
    port: 443
    username: demo
    password: secret
    udp: true
    quic: true
    tls: true
    sni: localhost
    skip-cert-verify: true
    dialer-proxy: outer-socks
rules:
  - MATCH,tt-hop
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "tt-hop"),
            "{gaps:?}"
        );
    }

    #[test]
    fn effective_native_support_gaps_do_not_flag_openvpn_udp_over_outer_socks5() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: ovpn-hop
    target: 8.8.8.8:53
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
    udp: true
  - type: openvpn
    name: ovpn-hop
    server: 1.2.3.4
    port: 1194
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: demo
    tls-crypt: demo
    username: demo
    password: secret
    dialer-proxy: outer-socks
rules:
  - MATCH,ovpn-hop
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "ovpn-hop"),
            "{gaps:?}"
        );
    }

    #[test]
    fn effective_native_support_gaps_do_not_flag_vless_packetaddr_udp_runtime() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: edge-vless
    target: 127.0.0.1:5353
proxies:
  - type: vless
    name: edge-vless
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    udp: true
    packet-addr: true
rules:
  - MATCH,edge-vless
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "edge-vless"),
            "{gaps:?}"
        );
    }

    #[test]
    fn effective_native_support_gaps_do_not_flag_vmess_packetaddr_udp_runtime() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: tunnel
    name: edge-udp
    listen: 127.0.0.1
    port: "0"
    network: [udp]
    proxy: edge-vmess
    target: 127.0.0.1:5353
proxies:
  - type: vmess
    name: edge-vmess
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: aes-128-gcm
    udp: true
    packet-addr: true
rules:
  - MATCH,edge-vmess
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "edge-vmess"),
            "{gaps:?}"
        );
    }

    #[test]
    fn top_level_vmess_surface_counts_as_udp_exposed_for_gap_detection() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
vmess-config: vmess://demo:b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:0
proxies:
  - type: wireguard
    name: wg-hop
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    udp: false
    allowed-ips: [0.0.0.0/0]
rules:
  - MATCH,wg-hop
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        assert_eq!(gaps[0].proxy_name, "wg-hop");
        assert!(gaps[0].reason.contains("udp"));
    }

    #[test]
    fn top_level_shadowsocks_surface_counts_as_udp_exposed_for_gap_detection() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
ss-config: ss://aes-128-gcm:secret@127.0.0.1:0
proxies:
  - type: wireguard
    name: wg-hop
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    udp: false
    allowed-ips: [0.0.0.0/0]
rules:
  - MATCH,wg-hop
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        assert_eq!(gaps[0].proxy_name, "wg-hop");
        assert!(gaps[0].reason.contains("udp"));
    }

    #[test]
    fn top_level_tuic_server_surface_counts_as_udp_exposed_for_gap_detection() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
tuic-server:
  enable: true
  listen: 127.0.0.1:0
  users:
    b831381d-6324-4d53-ad4f-8cda48b30811: secret
  certificate: cert
  private-key: key
proxies:
  - type: wireguard
    name: wg-hop
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    udp: false
    allowed-ips: [0.0.0.0/0]
rules:
  - MATCH,wg-hop
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        assert_eq!(gaps[0].proxy_name, "wg-hop");
        assert!(gaps[0].reason.contains("udp"));
    }

    #[test]
    fn tuic_tcp_only_only_triggers_gap_when_udp_surface_is_exposed() {
        let temp = unique_temp_dir();
        let tcp_only = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: http
    name: edge-http
    listen: 127.0.0.1
    port: "8080"
proxies:
  - type: tuic
    name: tuic-hop
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: secret
    alpn: [h3]
rules:
  - MATCH,tuic-hop
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&tcp_only, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "tuic-hop"),
            "{gaps:?}"
        );

        let udp_exposed = BootOptions {
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
socks-port: 7891
proxies:
  - type: tuic
    name: tuic-hop
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: secret
    alpn: [h3]
rules:
  - MATCH,tuic-hop
"#,
            )),
            ..tcp_only
        };
        let mut state =
            bootstrap_from_boot_options(&udp_exposed, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        assert_eq!(gaps[0].proxy_name, "tuic-hop");
        assert!(gaps[0].reason.contains("udp"));
    }

    #[test]
    fn openvpn_udp_flag_only_triggers_gap_when_udp_surface_is_exposed() {
        let temp = unique_temp_dir();
        let tcp_only = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: http
    name: edge-http
    listen: 127.0.0.1
    port: "8080"
proxies:
  - type: openvpn
    name: ovpn-hop
    server: 1.2.3.4
    port: 1194
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    udp: false
    ca: demo
    tls-crypt: demo
    username: demo
    password: secret
rules:
  - MATCH,ovpn-hop
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&tcp_only, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "ovpn-hop"),
            "{gaps:?}"
        );

        let udp_exposed = BootOptions {
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
socks-port: 7891
proxies:
  - type: openvpn
    name: ovpn-hop
    server: 1.2.3.4
    port: 1194
    proto: udp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    udp: false
    ca: demo
    tls-crypt: demo
    username: demo
    password: secret
rules:
  - MATCH,ovpn-hop
"#,
            )),
            ..tcp_only
        };
        let mut state =
            bootstrap_from_boot_options(&udp_exposed, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        assert_eq!(gaps[0].proxy_name, "ovpn-hop");
        assert!(gaps[0].reason.contains("udp"));
    }

    #[test]
    fn wireguard_udp_flag_only_triggers_gap_when_udp_surface_is_exposed() {
        let temp = unique_temp_dir();
        let tcp_only = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: http
    name: edge-http
    listen: 127.0.0.1
    port: "8080"
proxies:
  - type: wireguard
    name: wg-hop
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    udp: false
    allowed-ips: [0.0.0.0/0]
rules:
  - MATCH,wg-hop
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&tcp_only, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "wg-hop"),
            "{gaps:?}"
        );

        let udp_exposed = BootOptions {
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
socks-port: 7891
proxies:
  - type: wireguard
    name: wg-hop
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    udp: false
    allowed-ips: [0.0.0.0/0]
rules:
  - MATCH,wg-hop
"#,
            )),
            ..tcp_only
        };
        let mut state =
            bootstrap_from_boot_options(&udp_exposed, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        assert_eq!(gaps[0].proxy_name, "wg-hop");
        assert!(gaps[0].reason.contains("udp"));
    }

    #[test]
    fn tun_listener_with_file_descriptor_is_served_by_native_runtime() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: tun
    name: edge-tun
    file-descriptor: 9
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(!gaps.iter().any(|gap| gap.proxy_name == "listener:edge-tun"), "{gaps:?}");
    }

    #[test]
    fn top_level_tun_with_file_descriptor_is_served_by_native_runtime() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
tun:
  enable: true
  stack: system
  file-descriptor: 9
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(!gaps.iter().any(|gap| gap.proxy_name == "__top_level_tun__"), "{gaps:?}");
    }

    #[test]
    fn top_level_tun_auto_redirect_no_longer_triggers_native_support_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
tun:
  enable: true
  stack: system
  auto-route: true
  auto-redirect: true
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "__top_level_tun__"),
            "{gaps:?}"
        );
    }

    #[test]
    fn top_level_tun_route_address_set_no_longer_triggers_native_support_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
tun:
  enable: true
  stack: system
  route-address-set:
    - ruleset-1
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "__top_level_tun__"),
            "{gaps:?}"
        );
    }

    #[test]
    fn top_level_tun_mixed_stack_without_auto_redirect_uses_native_bridge() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
tun:
  enable: true
  stack: mixed
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "__top_level_tun__"),
            "{gaps:?}"
        );
    }

    #[test]
    fn top_level_tun_mixed_stack_with_auto_route_and_auto_redirect_no_longer_triggers_native_support_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
redir-port: 17891
tun:
  enable: true
  stack: mixed
  auto-route: true
  auto-redirect: true
  device: mihmixed0
  inet4-address:
    - 198.19.0.1/30
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "__top_level_tun__"),
            "{gaps:?}"
        );
    }

    #[test]
    fn top_level_tun_auto_detect_interface_no_longer_triggers_native_support_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
tun:
  enable: true
  stack: system
  auto-detect-interface: true
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "__top_level_tun__"),
            "{gaps:?}"
        );
    }

    #[test]
    fn top_level_tun_strict_route_no_longer_triggers_native_support_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
tun:
  enable: true
  stack: system
  strict-route: true
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "__top_level_tun__"),
            "{gaps:?}"
        );
    }

    #[test]
    fn linux_top_level_tun_accepts_inactive_android_template_filters() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
tun:
  enable: true
  stack: system
  include-package:
    - com.example.app
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "__top_level_tun__"),
            "{gaps:?}"
        );
    }

    #[test]
    fn top_level_tun_mac_filters_still_trigger_native_support_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
tun:
  enable: true
  stack: system
  include-mac-address:
    - 00:11:22:33:44:55
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            gaps.iter().any(|gap| gap.proxy_name == "__top_level_tun__"),
            "{gaps:?}"
        );
        let tun_reasons = gaps
            .iter()
            .filter(|gap| gap.proxy_name == "__top_level_tun__")
            .map(|gap| gap.reason.as_str())
            .collect::<Vec<_>>();
        assert!(
            tun_reasons
                .iter()
                .any(|reason| reason.contains("MAC address filters are not yet served")),
            "{gaps:?}"
        );
    }

    #[test]
    fn top_level_tun_endpoint_independent_nat_no_longer_triggers_native_support_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
tun:
  enable: true
  stack: system
  endpoint-independent-nat: true
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "__top_level_tun__"),
            "{gaps:?}"
        );
    }

    #[test]
    fn top_level_tun_gso_still_triggers_native_support_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
tun:
  enable: true
  stack: system
  gso: true
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            gaps.iter().any(|gap| gap.proxy_name == "__top_level_tun__"),
            "{gaps:?}"
        );
    }

    #[test]
    fn top_level_tun_recvmsgx_still_triggers_native_support_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
tun:
  enable: true
  stack: system
  recvmsgx: true
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            gaps.iter().any(|gap| gap.proxy_name == "__top_level_tun__"),
            "{gaps:?}"
        );
    }

    #[test]
    fn top_level_tun_loopback_address_still_triggers_native_support_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
tun:
  enable: true
  stack: system
  loopback-address:
    - 10.0.0.1
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            gaps.iter().any(|gap| gap.proxy_name == "__top_level_tun__"),
            "{gaps:?}"
        );
        let tun_reasons = gaps
            .iter()
            .filter(|gap| gap.proxy_name == "__top_level_tun__")
            .map(|gap| gap.reason.as_str())
            .collect::<Vec<_>>();
        assert!(
            tun_reasons
                .iter()
                .any(|reason| reason.contains("only a minimal TCP loopback bounce")),
            "{gaps:?}"
        );
    }

    #[test]
    fn top_level_tun_loopback_address_with_auto_redirect_mentions_command_layer_partial_in_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
redir-port: 17891
tun:
  enable: true
  stack: system
  auto-route: true
  auto-redirect: true
  loopback-address:
    - 10.0.0.1
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        let tun_reasons = gaps
            .iter()
            .filter(|gap| gap.proxy_name == "__top_level_tun__")
            .map(|gap| gap.reason.as_str())
            .collect::<Vec<_>>();
        assert!(
            tun_reasons
                .iter()
                .any(|reason| reason.contains("output-mark, conntrack-mark, and prerouting-mark rules")),
            "{gaps:?}"
        );
    }

    #[test]
    fn top_level_tun_disable_icmp_forwarding_no_longer_triggers_native_support_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
tun:
  enable: true
  stack: system
  disable-icmp-forwarding: true
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "__top_level_tun__"),
            "{gaps:?}"
        );
    }

    #[test]
    fn top_level_tun_advanced_auto_redirect_marks_still_trigger_native_support_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
redir-port: 17891
tun:
  enable: true
  stack: system
  auto-route: true
  auto-redirect: true
  auto-redirect-output-mark: 0x2024
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            gaps.iter().any(|gap| gap.proxy_name == "__top_level_tun__"),
            "{gaps:?}"
        );
        let tun_reasons = gaps
            .iter()
            .filter(|gap| gap.proxy_name == "__top_level_tun__")
            .map(|gap| gap.reason.as_str())
            .collect::<Vec<_>>();
        assert!(
            tun_reasons
                .iter()
                .any(|reason| reason.contains("now emits Linux iptables/ip rule command-layer mark-mode setup")),
            "{gaps:?}"
        );
    }

    #[test]
    fn top_level_tun_multiple_native_support_gaps_are_reported_together() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
tun:
  enable: true
  stack: mixed
  include-package:
    - com.example.app
  gso: true
  include-mac-address:
    - '02:00:00:00:00:01'
  loopback-address:
    - 10.0.0.1
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        let tun_reasons = gaps
            .iter()
            .filter(|gap| gap.proxy_name == "__top_level_tun__")
            .map(|gap| gap.reason.as_str())
            .collect::<Vec<_>>();
        assert!(
            tun_reasons.iter().any(|reason| reason.contains("GSO")),
            "{gaps:?}"
        );
        assert!(
            tun_reasons
                .iter()
                .any(|reason| reason.contains("MAC address filters")),
            "{gaps:?}"
        );
        assert!(
            tun_reasons
                .iter()
                .any(|reason| reason.contains("loopback-address")),
            "{gaps:?}"
        );
        assert!(tun_reasons.len() >= 3, "{gaps:?}");
    }

    #[test]
    fn top_level_tuic_verify_if_given_client_auth_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
tuic-server:
  enable: true
  listen: 127.0.0.1:0
  users:
    b831381d-6324-4d53-ad4f-8cda48b30811: secret
  certificate: cert
  private-key: key
  client-auth-type: verify-if-given
  client-auth-cert: client-cert
proxies:
  - type: direct
    name: direct
rules:
  - MATCH,direct
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let mut state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "__top_level_tuic__"),
            "{gaps:?}"
        );
    }
