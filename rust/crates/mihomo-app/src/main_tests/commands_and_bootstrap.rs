    #[test]
    fn convert_ruleset_command_writes_mrs_and_round_trips_to_text() {
        let temp = unique_temp_dir();
        let source = temp.join("rules.txt");
        let mrs = temp.join("rules.mrs");
        let text = temp.join("rules.out.txt");
        fs::write(&source, ".example.com\nsub.test\n").unwrap();

        run_convert_ruleset_command(&[
            "domain".into(),
            "text".into(),
            source.to_string_lossy().into_owned(),
            mrs.to_string_lossy().into_owned(),
        ])
        .unwrap();
        let bytes = fs::read(&mrs).unwrap();
        assert!(!bytes.is_empty());

        run_convert_ruleset_command(&[
            "domain".into(),
            "mrs".into(),
            mrs.to_string_lossy().into_owned(),
            text.to_string_lossy().into_owned(),
        ])
        .unwrap();
        let output = fs::read_to_string(text).unwrap();
        assert!(output.contains("+.example.com"));
        assert!(output.contains("sub.test"));
    }

    #[test]
    fn generate_command_outputs_uuid_and_x25519_keypairs() {
        let uuid = run_generate_command(&["uuid".into()]).unwrap();
        assert!(uuid.trim().len() >= 32);

        let reality = run_generate_command(&["reality-keypair".into()]).unwrap();
        let mut reality_lines = reality.lines();
        let private = reality_lines.next().unwrap().strip_prefix("PrivateKey: ").unwrap();
        let public = reality_lines.next().unwrap().strip_prefix("PublicKey: ").unwrap();
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(private)
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(public)
                .unwrap()
                .len(),
            32
        );

        let wg = run_generate_command(&["wg-keypair".into()]).unwrap();
        let mut wg_lines = wg.lines();
        let private = wg_lines.next().unwrap().strip_prefix("PrivateKey: ").unwrap();
        let public = wg_lines.next().unwrap().strip_prefix("PublicKey: ").unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(private)
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(public)
                .unwrap()
                .len(),
            32
        );

        let vless = run_generate_command(&["vless-x25519".into()]).unwrap();
        let mut lines = vless.lines();
        let private = lines.next().unwrap().strip_prefix("PrivateKey: ").unwrap();
        let password = lines.next().unwrap().strip_prefix("Password: ").unwrap();
        let hash32 = lines.next().unwrap().strip_prefix("Hash32: ").unwrap();
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(private)
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(password)
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(hash32)
                .unwrap()
                .len(),
            32
        );
        assert!(vless.contains("[Server] decryption:"));
        assert!(vless.contains("[Client] encryption:"));

        let sudoku = run_generate_command(&["sudoku-keypair".into()]).unwrap();
        let mut lines = sudoku.lines();
        let private = lines.next().unwrap().strip_prefix("PrivateKey: ").unwrap();
        let public = lines.next().unwrap().strip_prefix("PublicKey: ").unwrap();
        assert_eq!(private.len(), 128);
        assert_eq!(public.len(), 64);
        assert!(private.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(public.chars().all(|c| c.is_ascii_hexdigit()));

        let ech = run_generate_command(&["ech-keypair".into(), "www.example.com".into()]).unwrap();
        let config = ech
            .lines()
            .next()
            .unwrap()
            .strip_prefix("Config: ")
            .unwrap();
        let public_name = parse_ech_public_name(config);
        assert_eq!(public_name, "www.example.com");
        assert!(ech.contains("-----BEGIN ECH KEYS-----"));
        assert!(ech.contains("-----END ECH KEYS-----"));

        let mlkem = run_generate_command(&["vless-mlkem768".into()]).unwrap();
        let mut lines = mlkem.lines();
        let seed = lines.next().unwrap().strip_prefix("Seed: ").unwrap();
        let client = lines.next().unwrap().strip_prefix("Client: ").unwrap();
        let hash32 = lines.next().unwrap().strip_prefix("Hash32: ").unwrap();
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(seed)
                .unwrap()
                .len(),
            64
        );
        assert!(!base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(client)
            .unwrap()
            .is_empty());
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(hash32)
                .unwrap()
                .len(),
            32
        );
        assert!(mlkem.contains("[Server] decryption:"));
        assert!(mlkem.contains("[Client] encryption:"));
    }

    #[test]
    fn version_output_matches_main_go_shape() {
        let output = render_version_output();
        assert!(output.starts_with("Mihomo Meta "));
        assert!(output.contains(" with rustc "));
        assert!(output.contains(" unknown time"));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn test_config_messages_follow_main_go_file_shape() {
        let temp = unique_temp_dir();
        let resolved = ResolvedBoot {
            home_dir: temp.clone(),
            config_source: ConfigSource::File(temp.join("config.yaml")),
            command: Command::Run,
            geodata_mode: false,
            show_version: false,
            test_config: true,
        };
        assert_eq!(
            render_test_config_success(&resolved, None),
            format!(
                "configuration file {} test is successful",
                temp.join("config.yaml").display()
            )
        );
        assert_eq!(
            render_test_config_failure(&resolved),
            format!(
                "configuration file {} test failed",
                temp.join("config.yaml").display()
            )
        );
    }

    #[test]
    fn test_config_success_message_can_include_native_support_notice() {
        let temp = unique_temp_dir();
        let resolved = ResolvedBoot {
            home_dir: temp.clone(),
            config_source: ConfigSource::File(temp.join("config.yaml")),
            command: Command::Run,
            geodata_mode: false,
            show_version: false,
            test_config: true,
        };
        let message = render_test_config_success(
            &resolved,
            Some("native Rust runtime does not yet support one or more configured proxy protocols or features:\n- proxy=__top_level_tun__ reason=tun MAC address filters are not yet served by the native Rust app"),
        );
        assert!(message.contains("configuration file"));
        assert!(message.contains("test is successful"));
        assert!(message.contains("native Rust runtime does not yet support"));
        assert!(message.contains("proxy=__top_level_tun__"));
    }

    #[test]
    fn top_level_tun_report_marks_disable_icmp_forwarding_as_partial_fake_echo() {
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

        let state = bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        let report = render_top_level_tun_support_report(&state).unwrap();
        assert!(
            report.contains("- icmp-data-plane=fake-echo-when-disable-icmp-forwarding=true status=partial"),
            "{report}"
        );
        assert!(
            report.contains("- disable-icmp-forwarding=true status=partial-fake-echo-only"),
            "{report}"
        );
    }

    #[test]
    fn top_level_tun_report_marks_endpoint_independent_nat_as_source_reuse_only() {
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

        let state = bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        let report = render_top_level_tun_support_report(&state).unwrap();
        assert!(
            report.contains("- udp-data-plane=source-port-session-reuse-direct-packet-relay status=closer-to-go-mixed-but-still-not-gvisor"),
            "{report}"
        );
        assert!(
            report.contains("- endpoint-independent-nat=true status=source-port-session-reuse-only"),
            "{report}"
        );
    }

    #[test]
    fn top_level_tun_support_report_summarizes_current_tun_state() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
redir-port: 7891
tun:
  enable: true
  stack: mixed
  auto-route: true
  auto-redirect: true
  strict-route: true
  route-address-set:
    - cn_ip
proxies:
  - type: direct
    name: direct
rule-providers:
  cn_ip:
    type: file
    behavior: ipcidr
    path: ./cn_ip.yaml
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
            test_config: true,
            command: Command::Run,
        };
        fs::create_dir_all(&temp).unwrap();
        fs::write(
            temp.join("cn_ip.yaml"),
            "payload:\n  - 1.1.1.0/24\n",
        )
        .unwrap();
        let state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        let report = render_top_level_tun_support_report(&state).unwrap();
        assert!(report.contains("tun field report:"), "{report}");
        assert!(
            report.contains("- platform-surface=linux-native-or-external-file-descriptor status=partial"),
            "{report}"
        );
        assert!(
            report.contains("- tcp-data-plane=transparent-listener-path-with-tun-tcp-bypass status=closer-to-go-system-but-still-partial"),
            "{report}"
        );
        assert!(
            report.contains("- udp-data-plane=source-port-session-reuse-direct-packet-relay status=closer-to-go-mixed-but-still-not-gvisor"),
            "{report}"
        );
        assert!(
            report.contains("- icmp-data-plane=missing status=gap"),
            "{report}"
        );
        assert!(
            report.contains("- stack=mixed status=partially-supported-linux-auto-route-auto-redirect"),
            "{report}"
        );
        assert!(report.contains("- dns-hijack=1 status=supported"), "{report}");
        assert!(report.contains("- auto-route=true status=supported"), "{report}");
        assert!(report.contains("- auto-redirect=true status=supported"), "{report}");
        assert!(report.contains("- strict-route=true status=supported"), "{report}");
        assert!(
            report.contains("- route-address-set=1 status=supported-restart-based"),
            "{report}"
        );
        assert!(
            report.contains(
                "tun native-support verdict: top-level tun is eligible for native startup"
            ),
            "{report}"
        );
    }

    #[test]
    fn top_level_tun_report_keeps_plain_mixed_udp_data_plane_at_direct_relay() {
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
        let state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        let report = render_top_level_tun_support_report(&state).unwrap();
        assert!(
            report.contains("- udp-data-plane=fixed-worker-queue-direct-packet-relay status=supported-but-not-go-gvisor"),
            "{report}"
        );
        assert!(report.contains("- stack=mixed status=supported-passive-tcp-and-packet-udp"), "{report}");
    }

    #[test]
    fn top_level_tun_support_report_marks_auto_redirect_mark_mode_as_partial_gap() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
redir-port: 7891
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
            test_config: true,
            command: Command::Run,
        };
        fs::create_dir_all(&temp).unwrap();
        let state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        let report = render_top_level_tun_support_report(&state).unwrap();
        assert!(
            report.contains("- auto-redirect=true status=partial-mark-mode-command-layer"),
            "{report}"
        );
        assert!(
            report.contains("- auto-redirect-output-mark=8228 status=partial-command-layer"),
            "{report}"
        );
        assert!(
            report.contains(
                "- auto-redirect-mark-mode-model=iptables-ip-rule-command-layer-with-global-routing-mark-missing-loopback-reroute-and-nftables-parity status=gap"
            ),
            "{report}"
        );
    }

    #[test]
    fn top_level_tun_support_report_marks_auto_redirect_fallback_rule_as_partial_command_layer() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
redir-port: 7891
tun:
  enable: true
  stack: system
  auto-route: true
  auto-redirect: true
  auto-redirect-iproute2-fallback-rule-index: 32768
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
            test_config: true,
            command: Command::Run,
        };
        fs::create_dir_all(&temp).unwrap();
        let state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        let report = render_top_level_tun_support_report(&state).unwrap();
        assert!(
            report.contains("- auto-redirect=true status=partial-mark-mode-command-layer"),
            "{report}"
        );
        assert!(
            report.contains(
                "- auto-redirect-iproute2-fallback-rule-index=32768 status=partial-command-layer"
            ),
            "{report}"
        );
    }

    #[test]
    fn top_level_tun_support_report_explains_loopback_address_gap_shape() {
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
            test_config: true,
            command: Command::Run,
        };
        fs::create_dir_all(&temp).unwrap();
        let state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        let report = render_top_level_tun_support_report(&state).unwrap();
        assert!(
            report.contains(
                "- loopback-address=1 status=partial-tcp-data-plane-only"
            ),
            "{report}"
        );
        assert!(
            report.contains(
                "- loopback-address-model=system-tcp-bounce-after-tun-ingress-missing-linux-reroute-command-layer-and-go-system-parity status=gap"
            ),
            "{report}"
        );
    }

    #[test]
    fn top_level_tun_support_report_marks_loopback_address_with_auto_redirect_as_command_layer_partial() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
redir-port: 7891
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
            test_config: true,
            command: Command::Run,
        };
        fs::create_dir_all(&temp).unwrap();
        let state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        let report = render_top_level_tun_support_report(&state).unwrap();
        assert!(
            report.contains(
                "- loopback-address=1 status=partial-tcp-data-plane-and-iptables-reroute-command-layer"
            ),
            "{report}"
        );
        assert!(
            report.contains(
                "- loopback-address-model=system-tcp-bounce-plus-iptables-output-prerouting-connmark-command-layer-missing-go-nftables-and-full-system-stack-parity status=gap"
            ),
            "{report}"
        );
    }

    #[test]
    fn test_config_failure_message_is_generic_for_non_file_sources() {
        let temp = unique_temp_dir();
        let stdin_resolved = ResolvedBoot {
            home_dir: temp.clone(),
            config_source: ConfigSource::Stdin,
            command: Command::Run,
            geodata_mode: false,
            show_version: false,
            test_config: true,
        };
        let base64_resolved = ResolvedBoot {
            home_dir: temp,
            config_source: ConfigSource::Base64("cHJveGllczogW10K".into()),
            command: Command::Run,
            geodata_mode: false,
            show_version: false,
            test_config: true,
        };
        assert_eq!(render_test_config_failure(&stdin_resolved), "configuration test failed");
        assert_eq!(render_test_config_failure(&base64_resolved), "configuration test failed");
    }

    #[test]
    fn legacy_runtime_args_prefers_base64_config_when_present() {
        let options = BootOptions {
            home_dir: Some("/tmp/home".into()),
            config_file: Some("/tmp/home/config.yaml".into()),
            config_base64: Some("YmFzZTY0".into()),
            external_ui: Some("/tmp/ui".into()),
            external_controller: Some("127.0.0.1:9090".into()),
            external_controller_unix: Some("/tmp/mihomo.sock".into()),
            external_controller_pipe: Some("mihomo-pipe".into()),
            secret: Some("secret".into()),
            post_up: Some("echo up".into()),
            post_down: Some("echo down".into()),
            geodata_mode: true,
            show_version: false,
            test_config: true,
            command: Command::Run,
        };
        let args = legacy_runtime_args(&options, &[])
            .into_iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args.windows(2).any(|window| window == ["-config", "YmFzZTY0"]));
        assert!(!args.iter().any(|value| value == "-f"));
        assert!(args.iter().any(|value| value == "-m"));
        assert!(args.iter().any(|value| value == "-t"));
    }

    #[test]
    fn legacy_runtime_args_preserves_file_config_when_no_base64_is_present() {
        let options = BootOptions {
            home_dir: Some("/tmp/home".into()),
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
        let args = legacy_runtime_args(&options, &[])
            .into_iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args.windows(2).any(|window| window == ["-f", "/tmp/home/config.yaml"]));
        assert!(!args.iter().any(|value| value == "-config"));
    }

    #[test]
    fn legacy_fallback_only_triggers_for_non_test_runs_with_gaps() {
        let run_options = BootOptions {
            home_dir: None,
            config_file: None,
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
        let test_options = BootOptions {
            test_config: true,
            ..run_options.clone()
        };
        let gaps = vec![mihomo_runtime::NativeSupportGap {
            proxy_name: "edge-tuic".into(),
            kind: Some(mihomo_outbound::OutboundKind::Tuic),
            provider_name: String::new(),
            reason: "tuic is not yet implemented in the native Rust runtime".into(),
        }];
        assert!(super::should_fallback_to_legacy(&run_options, &gaps));
        assert!(!super::should_fallback_to_legacy(&test_options, &gaps));
        assert!(!super::should_fallback_to_legacy(&run_options, &[]));
    }

    #[test]
    fn force_native_runtime_aborts_instead_of_falling_back_when_gaps_exist() {
        let run_options = BootOptions {
            home_dir: None,
            config_file: None,
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
            proxy_name: "__top_level_tun__".into(),
            kind: None,
            provider_name: String::new(),
            reason: "tun auto-redirect is not yet served by the native Rust app".into(),
        }];
        let previous = std::env::var("MIHOMO_FORCE_NATIVE_RUNTIME").ok();
        unsafe {
            std::env::set_var("MIHOMO_FORCE_NATIVE_RUNTIME", "1");
        }
        assert!(!super::should_fallback_to_legacy(&run_options, &gaps));
        assert!(super::should_abort_on_native_support_gaps(&run_options, &gaps));
        match previous {
            Some(value) => unsafe {
                std::env::set_var("MIHOMO_FORCE_NATIVE_RUNTIME", value);
            },
            None => unsafe {
                std::env::remove_var("MIHOMO_FORCE_NATIVE_RUNTIME");
            },
        }
    }

    #[test]
    fn startup_gap_scan_includes_non_default_protocols() {
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
  - type: tuic
    name: full-config-tuic
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: secret
proxy-groups:
  - name: reachable
    type: select
    proxies: [direct-ok]
  - name: manual-tuic
    type: select
    proxies: [full-config-tuic]
rules:
  - MATCH,reachable
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
        let gaps = detect_native_support_gaps(&state.registry);
        assert!(gaps.is_empty(), "{gaps:?}");
        assert!(!super::should_fallback_to_legacy(&options, &gaps));
    }

    #[test]
    fn effective_native_support_gaps_ignore_unsupported_unused_proxy() {
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
  - type: direct
    name: direct-ok
  - type: mieru
    name: unused-mieru
    server: 1.2.3.4
    port: 443
    transport: TCP
    username: demo
    password: secret
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
        let all_gaps = detect_native_support_gaps(&state.registry);
        assert!(
            all_gaps.iter().any(|gap| gap.proxy_name == "unused-mieru"),
            "{all_gaps:?}"
        );
        let gaps = super::effective_native_support_gaps(&state);
        assert!(
            !gaps.iter().any(|gap| gap.proxy_name == "unused-mieru"),
            "{gaps:?}"
        );
        assert!(!super::should_fallback_to_legacy(&options, &gaps));
    }

    #[test]
    fn effective_native_support_gaps_ignore_unused_vless_vision_member_even_with_udp_surface() {
        let temp = unique_temp_dir();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
mixed-port: 7890
proxy-groups:
  - name: manual
    type: select
    proxies: [DIRECT, vision]
proxies:
  - type: vless
    name: vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: xtls-rprx-vision
rules:
  - MATCH,manual
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
            !gaps.iter().any(|gap| gap.proxy_name == "vision"),
            "{gaps:?}"
        );
        assert!(!super::should_fallback_to_legacy(&options, &gaps));
    }

    #[test]
    fn invalid_vless_uuid_fails_bootstrap_validation() {
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
  - type: vless
    name: bad-vless
    server: 1.2.3.4
    port: 443
    uuid: not-a-uuid
rules:
  - MATCH,bad-vless
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
        let err = bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default())
            .unwrap_err();
        assert!(err.to_string().contains("invalid uuid"));
    }

    #[test]
    fn invalid_vmess_uuid_fails_bootstrap_validation() {
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
  - type: vmess
    name: bad-vmess
    server: 1.2.3.4
    port: 443
    uuid: not-a-uuid
rules:
  - MATCH,bad-vmess
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
        let err = bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default())
            .unwrap_err();
        assert!(err.to_string().contains("invalid uuid"));
    }

    #[test]
    fn invalid_tuic_uuid_fails_bootstrap_validation() {
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
    name: bad-tuic
    server: 1.2.3.4
    port: 443
    uuid: not-a-uuid
    password: secret
rules:
  - MATCH,bad-tuic
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
        let err = bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default())
            .unwrap_err();
        assert!(err.to_string().contains("invalid uuid"));
    }
