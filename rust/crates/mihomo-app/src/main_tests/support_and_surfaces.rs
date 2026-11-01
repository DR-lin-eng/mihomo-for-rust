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
    fn sudoku_plain_listener_with_tls_surface_triggers_listener_gap() {
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
    fn vless_listener_reality_surface_triggers_listener_gap() {
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
