    #[test]
    fn supported_tuic_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: tuic
    name: edge-tuic
    listen: 127.0.0.1
    port: "0"
    users:
      b831381d-6324-4d53-ad4f-8cda48b30811: secret
    certificate: cert
    private-key: key
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-tuic"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_hy2_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: hysteria2
    name: edge-hy2
    listen: 127.0.0.1
    port: "0"
    users:
      user-a: secret
    certificate: cert
    private-key: key
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-hy2"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_hy2_realm_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: hysteria2-realm
    name: edge-hy2-realm
    listen: 127.0.0.1
    port: "0"
    token: public
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-hy2-realm"),
            "{gaps:?}"
        );
    }

    #[test]
    fn udp_listener_surface_counts_as_udp_exposed_for_gap_detection() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
        alterId: 0
    network: ws
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
    fn sudoku_plain_listener_with_ech_surface_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    certificate: cert
    private-key: key
    ech-key: unsupported
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
            gaps.iter().any(|gap| gap.proxy_name == "listener:edge-sudoku"),
            "{gaps:?}"
        );
    }

    #[test]
    fn sudoku_plain_listener_with_tls_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    certificate: cert
    private-key: key
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-sudoku"),
            "{gaps:?}"
        );
    }

    #[test]
    fn sudoku_stream_http_mask_tls_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: sudoku
    name: edge-sudoku
    listen: 127.0.0.1
    port: "0"
    key: secret-seed
    aead-method: aes-128-gcm
    table-type: prefer_ascii
    certificate: cert
    private-key: key
    http-mask: true
    http-mask-mode: stream
    http-mask-tls: true
    http-mask-host: localhost:8443
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-sudoku"),
            "{gaps:?}"
        );
    }

    #[test]
    fn unsupported_listener_surface_triggers_legacy_fallback() {
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
            assert!(
                !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-tun"),
                "{gaps:?}"
            );
        } else {
            assert_eq!(gaps.len(), 1, "{gaps:?}");
            assert_eq!(gaps[0].proxy_name, "listener:edge-tun");
            assert!(gaps[0].reason.contains("tun"));
        }
    }

    #[test]
    fn http_listener_tls_surface_no_longer_triggers_listener_gap() {
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
    port: "0"
    certificate: cert
    private-key: key
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-http"),
            "{gaps:?}"
        );
    }

    #[test]
    fn http_listener_mtls_surface_no_longer_triggers_listener_gap() {
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
    port: "0"
    certificate: cert
    private-key: key
    client-auth-type: require
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-http"),
            "{gaps:?}"
        );
    }

    #[test]
    fn socks_listener_tls_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: socks
    name: edge-socks
    listen: 127.0.0.1
    port: "0"
    certificate: cert
    private-key: key
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-socks"),
            "{gaps:?}"
        );
    }

    #[test]
    fn socks_listener_mtls_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: socks
    name: edge-socks
    listen: 127.0.0.1
    port: "0"
    certificate: cert
    private-key: key
    client-auth-type: require
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-socks"),
            "{gaps:?}"
        );
    }

    #[test]
    fn mixed_listener_tls_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: mixed
    name: edge-mixed
    listen: 127.0.0.1
    port: "0"
    certificate: cert
    private-key: key
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-mixed"),
            "{gaps:?}"
        );
    }

    #[test]
    fn mixed_listener_mtls_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: mixed
    name: edge-mixed
    listen: 127.0.0.1
    port: "0"
    certificate: cert
    private-key: key
    client-auth-type: require
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-mixed"),
            "{gaps:?}"
        );
    }

    #[test]
    fn mixed_listener_reality_surface_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: mixed
    name: edge-mixed
    listen: 127.0.0.1
    port: "0"
    reality-config:
      dest: test.com:443
      private-key: key
      short-id:
        - 0123456789abcdef
      server-names:
        - test.com
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
            gaps.iter().any(|gap| gap.proxy_name == "listener:edge-mixed"),
            "{gaps:?}"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn supported_tproxy_listener_surface_with_udp_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: tproxy
    name: edge-tproxy
    listen: 127.0.0.1
    port: "0"
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-tproxy"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_vless_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: ws
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-vless"),
            "{gaps:?}"
        );
    }

    #[test]
    fn vless_listener_reality_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    reality-config:
      dest: test.com:443
      private-key: key
      short-id:
        - 0123456789abcdef
      server-names:
        - test.com
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-vless"),
            "{gaps:?}"
        );
    }

    #[test]
    fn vless_listener_reality_surface_missing_server_names_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    reality-config:
      dest: test.com:443
      private-key: key
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
            gaps.iter().any(|gap| gap.proxy_name == "listener:edge-vless"),
            "{gaps:?}"
        );
    }

    #[test]
    fn vless_listener_decryption_surface_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    decryption: mlkem768x25519plus.native.600s.example
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
            gaps.iter().any(|gap| gap.proxy_name == "listener:edge-vless"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_vless_xhttp_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: xhttp
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    xhttp-opts:
      path: /vx
      host: localhost
      mode: stream-one
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-vless"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_vless_xhttp_stream_up_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: xhttp
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    xhttp-opts:
      path: /vx
      host: localhost
      mode: stream-up
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-vless"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_vless_xhttp_packet_up_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: xhttp
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    xhttp-opts:
      path: /vx
      host: localhost
      mode: packet-up
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-vless"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_vmess_xhttp_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    network: xhttp
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    xhttp-opts:
      path: /vx
      host: localhost
      mode: stream-one
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-vmess"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_vmess_xhttp_stream_up_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    network: xhttp
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    xhttp-opts:
      path: /vx
      host: localhost
      mode: stream-up
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-vmess"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_vmess_xhttp_packet_up_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    network: xhttp
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    xhttp-opts:
      path: /vx
      host: localhost
      mode: packet-up
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-vmess"),
            "{gaps:?}"
        );
    }

    #[test]
    fn vmess_listener_ech_surface_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    certificate: cert
    private-key: key
    ech-key: ech
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
            gaps.iter().any(|gap| gap.proxy_name == "listener:edge-vmess"),
            "{gaps:?}"
        );
    }

    #[test]
    fn vmess_listener_reality_surface_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    reality-config:
      dest: test.com:443
      private-key: key
      short-id:
        - 0123456789abcdef
      server-names:
        - test.com
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
            gaps.iter().any(|gap| gap.proxy_name == "listener:edge-vmess"),
            "{gaps:?}"
        );
    }

    #[test]
    fn unsupported_vmess_xhttp_mode_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: vmess
    name: edge-vmess
    listen: 127.0.0.1
    port: "0"
    network: xhttp
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    xhttp-opts:
      path: /vx
      host: localhost
      mode: stream-mode-not-supported
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
            gaps.iter().any(|gap| gap.proxy_name == "listener:edge-vmess"),
            "{gaps:?}"
        );
    }

    #[test]
    fn unsupported_vless_xhttp_mode_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: vless
    name: edge-vless
    listen: 127.0.0.1
    port: "0"
    network: xhttp
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    xhttp-opts:
      path: /vx
      host: localhost
      mode: stream-mode-not-supported
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
            gaps.iter().any(|gap| gap.proxy_name == "listener:edge-vless"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_shadowsocks_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: shadowsocks
    name: edge-ss
    listen: 127.0.0.1
    port: "0"
    cipher: aes-128-gcm
    password: secret
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-ss"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_shadowsocks_http_obfs_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: shadowsocks
    name: edge-ss
    listen: 127.0.0.1
    port: "0"
    cipher: aes-128-gcm
    password: secret
    simple-obfs:
      enable: true
      mode: http
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-ss"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_trojan_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-trojan"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_trojan_ws_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    network: ws
    ws-opts:
      path: /tr
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-trojan"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_trojan_h2_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    network: h2
    certificate: cert
    private-key: key
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-trojan"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_trojan_xhttp_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    network: xhttp
    certificate: cert
    private-key: key
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-trojan"),
            "{gaps:?}"
        );
    }

    #[test]
    fn trojan_listener_reality_surface_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    reality-config:
      dest: test.com:443
      private-key: key
      short-id:
        - 0123456789abcdef
      server-names:
        - test.com
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
            gaps.iter().any(|gap| gap.proxy_name == "listener:edge-trojan"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_trojan_users_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    users:
      - username: alice
        password: secret-a
      - username: bob
        password: secret-b
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-trojan"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_shadowsocks_2022_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: shadowsocks
    name: edge-ss2022
    listen: 127.0.0.1
    port: "0"
    cipher: 2022-blake3-aes-256-gcm
    password: AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-ss2022"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_anytls_users_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: anytls
    name: edge-anytls
    listen: 127.0.0.1
    port: "0"
    users:
      username1: password1
      username2: password2
    certificate: ./server.crt
    private-key: ./server.key
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-anytls"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_trusttunnel_users_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: trusttunnel
    name: edge-trusttunnel
    listen: 127.0.0.1
    port: "0"
    users:
      - username: alice
        password: secret-a
    certificate: ./server.crt
    private-key: ./server.key
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-trusttunnel"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_trojan_xhttp_stream_up_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    network: xhttp
    xhttp-opts:
      path: /trx
      host: localhost
      mode: stream-up
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-trojan"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_trojan_xhttp_packet_up_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    network: xhttp
    xhttp-opts:
      path: /trx
      host: localhost
      mode: packet-up
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-trojan"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_trojan_ss_option_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: trojan
    name: edge-trojan
    listen: 127.0.0.1
    port: "0"
    password: secret
    ss-option:
      enabled: true
      method: aes-128-gcm
      password: inner
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-trojan"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_tuic_require_and_verify_client_auth_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: tuic
    name: edge-tuic
    listen: 127.0.0.1
    port: "0"
    users:
      b831381d-6324-4d53-ad4f-8cda48b30811: secret
    certificate: cert
    private-key: key
    client-auth-type: require-and-verify
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-tuic"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_anytls_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: anytls
    name: edge-anytls
    listen: 127.0.0.1
    port: "0"
    password: secret
    certificate: cert
    private-key: key
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-anytls"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_trusttunnel_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: trusttunnel
    name: edge-trust
    listen: 127.0.0.1
    port: "0"
    username: alice
    password: secret
    certificate: cert
    private-key: key
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-trust"),
            "{gaps:?}"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn supported_tproxy_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: tproxy
    name: edge-tproxy
    listen: 127.0.0.1
    port: "0"
    udp: false
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-tproxy"),
            "{gaps:?}"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn supported_redir_listener_surface_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
listeners:
  - type: redir
    name: edge-redir
    listen: 127.0.0.1
    port: "0"
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
            !gaps.iter().any(|gap| gap.proxy_name == "listener:edge-redir"),
            "{gaps:?}"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn supported_top_level_tproxy_port_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
tproxy-port: 7893
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
            !gaps.iter().any(|gap| gap.proxy_name == "__top_level_tproxy__"),
            "{gaps:?}"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn supported_top_level_redir_port_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
redir-port: 7892
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
            !gaps.iter().any(|gap| gap.proxy_name == "__top_level_redir__"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_top_level_vmess_config_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
vmess-config: vmess://test:b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:0
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
            !gaps.iter().any(|gap| gap.proxy_name == "__top_level_vmess__"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_top_level_shadowsocks_config_no_longer_triggers_listener_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
ss-config: ss://aes-128-gcm:secret@127.0.0.1:0
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
            !gaps.iter().any(|gap| gap.proxy_name == "__top_level_shadowsocks__"),
            "{gaps:?}"
        );
    }

    #[test]
    fn supported_top_level_tuic_server_no_longer_triggers_listener_gap() {
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
