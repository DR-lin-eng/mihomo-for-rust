    #[test]
    fn legacy_runtime_args_assigns_writable_home_dir_when_home_dir_is_missing() {
        let options = BootOptions {
            home_dir: None,
            config_file: Some("/tmp/home/config.yaml".into()),
            config_base64: None,
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
        let gaps = vec![mihomo_runtime::NativeSupportGap {
            proxy_name: "edge-tuic".into(),
            kind: Some(mihomo_outbound::OutboundKind::Tuic),
            provider_name: String::new(),
            reason: "tuic is not yet implemented in the native Rust runtime".into(),
        }];
        let args = legacy_runtime_args(&options, &gaps)
            .into_iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args.windows(2).any(|window| window[0] == "-d"));
    }

    #[test]
    fn native_support_gap_error_mentions_proxy_kind_provider_and_fallback() {
        let rendered = render_native_support_gap_error(&[mihomo_runtime::NativeSupportGap {
            proxy_name: "edge-tuic".into(),
            kind: Some(mihomo_outbound::OutboundKind::Tuic),
            provider_name: "provider-a".into(),
            reason: "tuic is not yet implemented in the native Rust runtime".into(),
        }]);
        assert!(rendered.contains("proxy=edge-tuic"));
        assert!(rendered.contains("type=tuic"));
        assert!(rendered.contains("provider=provider-a"));
        assert!(rendered.contains("falling back to the legacy Go runtime"));
    }

    #[test]
    fn unsupported_dns_upstream_syntax_triggers_legacy_fallback() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
proxies:
  - type: direct
    name: direct-ok
dns:
  enable: true
  nameserver:
    - dhcp://en0
rules:
  - MATCH,direct-ok
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
            gaps.iter().any(|gap| {
                gap.proxy_name == "dns.nameserver"
                    && gap.reason.contains("not yet supported by the native Rust dns runtime")
            }),
            "{gaps:?}"
        );
        assert!(super::should_fallback_to_legacy(&options, &gaps));
    }

    #[test]
    fn udp_dns_upstream_syntax_does_not_trigger_dns_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
proxies:
  - type: direct
    name: direct-ok
dns:
  enable: true
  nameserver:
    - 8.8.8.8
    - udp://1.1.1.1
rules:
  - MATCH,direct-ok
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
            !gaps.iter().any(|gap| gap.proxy_name == "dns.nameserver"),
            "{gaps:?}"
        );
    }

    #[test]
    fn udp_dns_upstream_rules_fragment_does_not_trigger_dns_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
proxies:
  - type: direct
    name: direct-ok
dns:
  enable: true
  nameserver:
    - udp://1.1.1.1#RULES
rules:
  - MATCH,direct-ok
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
            !gaps.iter().any(|gap| gap.proxy_name == "dns.nameserver"),
            "{gaps:?}"
        );
    }

    #[test]
    fn udp_dns_upstream_named_proxy_fragment_does_not_trigger_dns_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
proxies:
  - type: direct
    name: direct-ok
  - type: socks5
    name: relay
    server: 127.0.0.1
    port: 1080
    udp: true
dns:
  enable: true
  nameserver:
    - udp://1.1.1.1#relay
rules:
  - MATCH,direct-ok
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
            !gaps.iter().any(|gap| gap.proxy_name == "dns.nameserver"),
            "{gaps:?}"
        );
    }

    #[test]
    fn tcp_dns_upstream_syntax_does_not_trigger_dns_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
proxies:
  - type: direct
    name: direct-ok
dns:
  enable: true
  nameserver:
    - tcp://1.1.1.1
rules:
  - MATCH,direct-ok
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
            !gaps.iter().any(|gap| gap.proxy_name == "dns.nameserver"),
            "{gaps:?}"
        );
    }

    #[test]
    fn tls_dns_upstream_syntax_does_not_trigger_dns_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
proxies:
  - type: direct
    name: direct-ok
dns:
  enable: true
  nameserver:
    - tls://1.1.1.1
rules:
  - MATCH,direct-ok
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
            !gaps.iter().any(|gap| gap.proxy_name == "dns.nameserver"),
            "{gaps:?}"
        );
    }

    #[test]
    fn https_dns_upstream_syntax_does_not_trigger_dns_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
proxies:
  - type: direct
    name: direct-ok
dns:
  enable: true
  nameserver:
    - https://dns.google/dns-query
rules:
  - MATCH,direct-ok
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
            !gaps.iter().any(|gap| gap.proxy_name == "dns.nameserver"),
            "{gaps:?}"
        );
    }

    #[test]
    fn rcode_dns_upstream_syntax_does_not_trigger_dns_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
proxies:
  - type: direct
    name: direct-ok
dns:
  enable: true
  nameserver:
    - rcode://success
rules:
  - MATCH,direct-ok
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
            !gaps.iter().any(|gap| gap.proxy_name == "dns.nameserver"),
            "{gaps:?}"
        );
    }

    #[test]
    fn quic_dns_upstream_syntax_does_not_trigger_dns_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
proxies:
  - type: direct
    name: direct-ok
dns:
  enable: true
  nameserver:
    - quic://dns.adguard.com:784
rules:
  - MATCH,direct-ok
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
            !gaps.iter().any(|gap| gap.proxy_name == "dns.nameserver"),
            "{gaps:?}"
        );
    }

    #[test]
    fn dns_respect_rules_no_longer_triggers_legacy_fallback() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
proxies:
  - type: direct
    name: direct-ok
dns:
  enable: true
  respect-rules: true
  proxy-server-nameserver:
    - 9.9.9.9
  nameserver:
    - 8.8.8.8
rules:
  - MATCH,direct-ok
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
            !gaps.iter().any(|gap| gap.proxy_name == "dns.respect-rules"),
            "{gaps:?}"
        );
        assert!(!super::should_fallback_to_legacy(&options, &gaps));
    }

    #[test]
    fn dns_proxy_server_policy_without_upstreams_triggers_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
proxies:
  - type: direct
    name: direct-ok
dns:
  enable: true
  nameserver:
    - 8.8.8.8
  proxy-server-nameserver-policy:
    "+.proxy.test":
      - 4.4.4.4
rules:
  - MATCH,direct-ok
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
            gaps.iter().any(|gap| gap.proxy_name == "dns.proxy-server-nameserver-policy"),
            "{gaps:?}"
        );
    }

    #[test]
    fn dns_rules_fragment_no_longer_triggers_dns_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
proxies:
  - type: direct
    name: direct-ok
dns:
  enable: true
  nameserver:
    - 9.9.9.9#RULES
rules:
  - MATCH,direct-ok
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
            !gaps.iter().any(|gap| gap.proxy_name == "dns.nameserver"),
            "{gaps:?}"
        );
    }

    #[test]
    fn dns_named_proxy_fragment_no_longer_triggers_dns_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
proxies:
  - type: socks5
    name: proxy-socks
    server: 127.0.0.1
    port: 1080
    udp: true
dns:
  enable: true
  nameserver:
    - 9.9.9.9#proxy-socks
rules:
  - MATCH,proxy-socks
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
            !gaps.iter().any(|gap| gap.proxy_name == "dns.nameserver"),
            "{gaps:?}"
        );
    }

    #[test]
    fn dns_quic_rules_fragment_no_longer_triggers_dns_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
proxies:
  - type: direct
    name: direct-ok
dns:
  enable: true
  nameserver:
    - quic://localhost:853#RULES
rules:
  - MATCH,direct-ok
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
            !gaps.iter().any(|gap| gap.proxy_name == "dns.nameserver"),
            "{gaps:?}"
        );
    }

    #[test]
    fn dns_quic_named_proxy_fragment_no_longer_triggers_dns_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
proxies:
  - type: direct
    name: direct-ok
dns:
  enable: true
  nameserver:
    - quic://localhost:853#direct-ok
rules:
  - MATCH,direct-ok
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
            !gaps.iter().any(|gap| gap.proxy_name == "dns.nameserver"),
            "{gaps:?}"
        );
    }

    #[test]
    fn dns_tls_rules_fragment_no_longer_triggers_dns_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
proxies:
  - type: direct
    name: direct-ok
dns:
  enable: true
  nameserver:
    - tls://localhost:853#RULES
rules:
  - MATCH,direct-ok
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
            !gaps.iter().any(|gap| gap.proxy_name == "dns.nameserver"),
            "{gaps:?}"
        );
    }

    #[test]
    fn dns_https_named_proxy_fragment_no_longer_triggers_dns_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
proxies:
  - type: http
    name: proxy-http
    server: 127.0.0.1
    port: 8080
dns:
  enable: true
  nameserver:
    - https://dns.google/dns-query#proxy-http
rules:
  - MATCH,proxy-http
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
            !gaps.iter().any(|gap| gap.proxy_name == "dns.nameserver"),
            "{gaps:?}"
        );
    }

    #[test]
    fn stdin_config_source_bootstraps_from_dash_file_option() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: Some("-".into()),
            config_base64: None,
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: true,
            command: Command::Run,
        };
        let yaml = br#"
proxies:
  - type: direct
    name: stdin-direct
"#;
        let mut stdin = Cursor::new(yaml.as_slice());
        let state = bootstrap_from_boot_options_with_stdin(
            &options,
            &temp,
            &BootEnvironment::default(),
            &mut stdin,
        )
        .unwrap();
        assert!(state.registry.proxies.contains_key("stdin-direct"));
        assert_eq!(
            state.resolved_boot.config_display_path(),
            temp.join("config.yaml")
        );
    }

    #[test]
    fn normalize_stdin_boot_options_inlines_dash_config_as_base64() {
        let options = BootOptions {
            home_dir: None,
            config_file: Some("-".into()),
            config_base64: None,
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
        let yaml = br#"proxies:
  - type: direct
    name: stdin-normalized
"#;
        let expected = base64::engine::general_purpose::STANDARD.encode(yaml);
        let mut reader = Cursor::new(yaml.as_slice());
        let normalized = normalize_stdin_boot_options_with_reader(options, &mut reader).unwrap();
        assert_eq!(normalized.config_base64.as_deref(), Some(expected.as_str()));
        assert!(normalized.config_file.is_none());
    }

    #[test]
    fn normalized_stdin_boot_options_can_bootstrap_again_without_reader() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: Some("-".into()),
            config_base64: None,
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
        let yaml = br#"
proxies:
  - type: direct
    name: stdin-reload-safe
"#;
        let mut reader = Cursor::new(yaml.as_slice());
        let normalized = normalize_stdin_boot_options_with_reader(options, &mut reader).unwrap();
        let state = bootstrap_from_boot_options_with_stdin(
            &normalized,
            &temp,
            &BootEnvironment::default(),
            &mut Cursor::new(Vec::<u8>::new()),
        )
        .unwrap();
        assert!(state.registry.proxies.contains_key("stdin-reload-safe"));
        assert_eq!(
            state.resolved_boot.config_display_path(),
            temp.join("config.yaml")
        );
    }

    #[test]
    #[cfg(unix)]
    fn run_loop_returns_restart_when_controller_requests_restart() {
        let temp = unique_temp_dir();
        let config_path = temp.join("config.yaml");
        fs::write(
            &config_path,
            r#"
external-controller: 127.0.0.1:0
secret: top-secret
proxies:
  - type: direct
    name: direct-a
"#,
        )
        .unwrap();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: Some(config_path.to_string_lossy().into_owned()),
            config_base64: None,
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
        let env = BootEnvironment::default();
        let app = RunningApp::start(&options, &temp, &env).unwrap();
        let addr = app.controller_addr().unwrap();

        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .write_all(
                b"POST /restart HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer top-secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.contains("HTTP/1.1 200 OK"), "{response}");

        let outcome = run_app_until_signal(app, &options, &temp, &env).unwrap();
        assert_eq!(outcome, RunLoopExit::Restart);
    }

    #[test]
    #[cfg(unix)]
    fn shell_hooks_execute_post_up_and_post_down_commands() {
        let temp = unique_temp_dir();
        let up_path = temp.join("post-up.txt");
        let down_path = temp.join("post-down.txt");
        let up_cmd = format!("printf up > {}", shell_quote(&up_path));
        exec_shell(&up_cmd).unwrap();
        assert_eq!(fs::read_to_string(&up_path).unwrap(), "up");

        {
            let down_cmd = format!("printf down > {}", shell_quote(&down_path));
            let _guard = PostDownGuard::new(Some(down_cmd));
        }
        assert_eq!(fs::read_to_string(&down_path).unwrap(), "down");
    }
