    #[test]
    fn tcp_only_ssh_proxy_no_longer_triggers_legacy_fallback() {
        let temp = unique_temp_dir();
        let options = BootOptions {
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
  - type: ssh
    name: ssh-hop
    server: 1.2.3.4
    port: 22
    username: demo
    password: secret
rules:
  - MATCH,ssh-hop
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
            !gaps.iter().any(|gap| gap.proxy_name == "ssh-hop"),
            "{gaps:?}"
        );
    }

    #[test]
    fn tcp_only_tuic_proxy_no_longer_triggers_legacy_fallback() {
        let temp = unique_temp_dir();
        let options = BootOptions {
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
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "tuic-hop"),
            "{gaps:?}"
        );
    }

    #[test]
    fn tcp_only_tuic_v4_token_proxy_no_longer_triggers_legacy_fallback() {
        let temp = unique_temp_dir();
        let options = BootOptions {
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
    token: secret
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
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "tuic-hop"),
            "{gaps:?}"
        );
    }

    #[test]
    fn hy2_realm_proxy_no_longer_triggers_legacy_fallback() {
        let temp = unique_temp_dir();
        let options = BootOptions {
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
    realm-opts:
      enable: true
      server-url: https://realm.example.com
      realm-id: alpha
      stun-servers:
        - 1.1.1.1:3478
      proxy: socks5://127.0.0.1:1080
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
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(!gaps.iter().any(|gap| gap.proxy_name == "hy2"), "{gaps:?}");
    }

    #[test]
    fn hy2_realm_proxy_name_no_longer_triggers_legacy_fallback() {
        let temp = unique_temp_dir();
        let options = BootOptions {
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
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
  - type: hysteria2
    name: hy2
    server: 1.2.3.4
    port: 443
    password: secret
    realm-opts:
      enable: true
      server-url: https://realm.example.com
      realm-id: alpha
      stun-servers:
        - 1.1.1.1:3478
      proxy: outer-socks
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
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        mihomo_app::restore_selected_proxy_mapping(&mut state);
        let gaps = super::effective_native_support_gaps(&state);
        assert!(!gaps.iter().any(|gap| gap.proxy_name == "hy2"), "{gaps:?}");
    }

    #[test]
    fn tcp_only_anytls_proxy_no_longer_triggers_legacy_fallback() {
        let temp = unique_temp_dir();
        let options = BootOptions {
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
  - type: anytls
    name: anytls-hop
    server: anytls.example.com
    port: 443
    password: secret
rules:
  - MATCH,anytls-hop
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
            !gaps.iter().any(|gap| gap.proxy_name == "anytls-hop"),
            "{gaps:?}"
        );
    }

    #[test]
    fn tcp_only_openvpn_tcp_dialer_proxy_no_longer_triggers_legacy_fallback() {
        let temp = unique_temp_dir();
        let options = BootOptions {
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
  - type: http
    name: outer-http
    server: 127.0.0.1
    port: 8081
  - type: openvpn
    name: ovpn-hop
    server: 1.2.3.4
    port: 1194
    proto: tcp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: demo
    tls-crypt: demo
    username: demo
    password: secret
    dialer-proxy: outer-http
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
    fn tcp_only_openvpn_tcp_http_dialer_proxy_chain_no_longer_triggers_legacy_fallback() {
        let temp = unique_temp_dir();
        let options = BootOptions {
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
  - type: http
    name: outer-http
    server: 127.0.0.1
    port: 8081
  - type: http
    name: middle-http
    server: 127.0.0.1
    port: 8082
    dialer-proxy: outer-http
  - type: openvpn
    name: ovpn-hop
    server: 1.2.3.4
    port: 1194
    proto: tcp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: demo
    tls-crypt: demo
    username: demo
    password: secret
    dialer-proxy: middle-http
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
    fn tcp_only_openvpn_tcp_client_cert_http_dialer_proxy_no_longer_triggers_legacy_fallback() {
        let temp = unique_temp_dir();
        let options = BootOptions {
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
  - type: http
    name: outer-http
    server: 127.0.0.1
    port: 8081
  - type: openvpn
    name: ovpn-hop
    server: 1.2.3.4
    port: 1194
    proto: tcp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: demo
    cert: demo-cert
    key: demo-key
    tls-crypt: demo
    dialer-proxy: outer-http
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
    fn tcp_only_openvpn_tcp_client_cert_socks5_http_dialer_proxy_chain_no_longer_triggers_legacy_fallback() {
        let temp = unique_temp_dir();
        let options = BootOptions {
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
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
  - type: http
    name: middle-http
    server: 127.0.0.1
    port: 8081
    dialer-proxy: outer-socks
  - type: openvpn
    name: ovpn-hop
    server: 1.2.3.4
    port: 1194
    proto: tcp
    dev: tun
    cipher: AES-128-GCM
    auth: SHA256
    ca: demo
    cert: demo-cert
    key: demo-key
    tls-crypt: demo
    dialer-proxy: middle-http
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
    fn tcp_only_wireguard_workers_no_longer_triggers_legacy_fallback() {
        let temp = unique_temp_dir();
        let options = BootOptions {
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
    name: edge-wg
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    allowed-ips: [0.0.0.0/0]
    workers: 4
rules:
  - MATCH,edge-wg
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
            !gaps.iter().any(|gap| gap.proxy_name == "edge-wg"),
            "{gaps:?}"
        );
    }

    #[test]
    fn tcp_only_trojan_proxy_no_longer_triggers_legacy_fallback() {
        let temp = unique_temp_dir();
        let options = BootOptions {
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
  - type: trojan
    name: trojan-hop
    server: 1.2.3.4
    port: 443
    password: secret
rules:
  - MATCH,trojan-hop
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
            !gaps.iter().any(|gap| gap.proxy_name == "trojan-hop"),
            "{gaps:?}"
        );
    }

    #[test]
    fn tcp_only_trusttunnel_proxy_no_longer_triggers_legacy_fallback() {
        let temp = unique_temp_dir();
        let options = BootOptions {
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
  - type: trusttunnel
    name: tt-hop
    server: 1.2.3.4
    port: 443
    username: demo
    password: secret
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
    fn sudoku_ws_http_mask_over_dialer_proxy_does_not_trigger_legacy_fallback() {
        let temp = unique_temp_dir();
        let options = BootOptions {
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
  - type: socks5
    name: outer
    server: 127.0.0.1
    port: 1080
  - type: sudoku
    name: edge-sudoku
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 12
    http-mask: true
    http-mask-mode: ws
    dialer-proxy: outer
rules:
  - MATCH,edge-sudoku
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
            !gaps.iter().any(|gap| gap.proxy_name == "edge-sudoku"),
            "{gaps:?}"
        );
    }

    #[test]
    fn sudoku_stream_http_mask_over_dialer_proxy_no_longer_triggers_legacy_fallback() {
        let temp = unique_temp_dir();
        let options = BootOptions {
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
  - type: socks5
    name: outer
    server: 127.0.0.1
    port: 1080
  - type: sudoku
    name: edge-sudoku
    server: sudoku.example.com
    port: 443
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    padding-min: 12
    http-mask: true
    http-mask-mode: stream
    dialer-proxy: outer
rules:
  - MATCH,edge-sudoku
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
            !gaps.iter().any(|gap| gap.proxy_name == "edge-sudoku"),
            "{gaps:?}"
        );
    }

    #[test]
    fn top_level_tun_without_file_descriptor_still_requires_legacy_fallback() {
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
  mtu: 9000
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
        if cfg!(target_os = "linux") {
            assert!(!gaps.iter().any(|gap| gap.proxy_name == "__top_level_tun__"), "{gaps:?}");
        } else {
            assert!(gaps.iter().any(|gap| gap.proxy_name == "__top_level_tun__"), "{gaps:?}");
        }
    }
