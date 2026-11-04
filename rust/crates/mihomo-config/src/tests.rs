#![cfg(test)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use mihomo_inbound::InboundDefinition;
use mihomo_outbound::{OutboundDefinition, OutboundGroupKind, ProxyProviderVehicleType};

use crate::{
    parse_args, parse_runtime_config_document, BootEnvironment, BootOptions, Command,
    ConfigSource, ConfigValidationError, ParseError, RuleProviderBehavior,
    RuleProviderFormat, RuleProviderVehicleType,
};

#[test]
fn mode_accepts_go_compatible_case_variants() {
    for (input, expected) in [("Rule", "rule"), ("GLOBAL", "global"), ("Direct", "direct")] {
        assert_eq!(parse_runtime_config_document(&format!("mode: {input}\n")).unwrap().mode, expected);
    }
}

#[test]
fn parses_main_run_flags() {
    let args = [
        "mihomo",
        "-d",
        "/tmp/home",
        "-f",
        "config.yaml",
        "-ext-ctl",
        "127.0.0.1:9090",
        "-m",
        "-t",
    ];
    let options = parse_args(args).unwrap();
    assert_eq!(
        options,
        BootOptions {
            home_dir: Some("/tmp/home".into()),
            config_file: Some("config.yaml".into()),
            config_base64: None,
            external_ui: None,
            external_controller: Some("127.0.0.1:9090".into()),
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: true,
            show_version: false,
            test_config: true,
            command: Command::Run,
        }
    );
}

#[test]
fn parses_builtin_subcommands() {
    let convert = parse_args(["mihomo", "convert-ruleset", "rules.yaml"]).unwrap();
    let generate = parse_args(["mihomo", "generate", "template"]).unwrap();
    assert_eq!(convert.command, Command::ConvertRuleset(vec!["rules.yaml".into()]));
    assert_eq!(generate.command, Command::Generate(vec!["template".into()]));
}

#[test]
fn rejects_unknown_flags() {
    let err = parse_args(["mihomo", "--unknown"]).unwrap_err();
    assert_eq!(err, ParseError::UnknownFlag("--unknown".into()));
}

#[test]
fn resolves_relative_paths_like_main_go() {
    let options = BootOptions {
        home_dir: Some("state".into()),
        config_file: Some("override.yaml".into()),
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
    let cwd = PathBuf::from("/tmp/mihomo-rs");
    let resolved = options.resolve(&cwd, &BootEnvironment::default());
    assert_eq!(resolved.home_dir, cwd.join("state"));
    assert_eq!(
        resolved.config_source,
        ConfigSource::File(cwd.join("override.yaml"))
    );
}

#[test]
fn defaults_config_file_under_resolved_home_dir() {
    let cwd = unique_temp_dir();
    fs::create_dir_all(cwd.join("home").join(".config").join("mihomo")).unwrap();
    let env = BootEnvironment {
        user_home: Some(cwd.join("home")),
        xdg_config_home: None,
    };
    let resolved = BootOptions::default().resolve(&cwd, &env);
    assert_eq!(
        resolved.config_source,
        ConfigSource::File(cwd.join("home").join(".config").join("mihomo").join("config.yaml"))
    );
}

#[test]
fn explicit_config_file_does_not_change_default_data_directory() {
    let cwd = PathBuf::from("/tmp/mihomo-rs");
    let config_path = PathBuf::from("/data/kano_plugins/clash/Proxy/config.yaml");
    let resolved = BootOptions {
        home_dir: None,
        config_file: Some(config_path.to_string_lossy().into_owned()),
        ..BootOptions::default()
    }
    .resolve(&cwd, &BootEnvironment::default());
    assert_eq!(resolved.config_source, ConfigSource::File(config_path.clone()));
    assert_eq!(
        resolved.home_dir,
        cwd.join(".config").join("mihomo")
    );
}

#[test]
fn config_base64_has_priority_over_file_source() {
    let options = BootOptions {
        home_dir: None,
        config_file: Some("-".into()),
        config_base64: Some("YmFzZTY0".into()),
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
    let resolved = options.resolve(Path::new("/tmp"), &BootEnvironment::default());
    assert_eq!(resolved.config_source, ConfigSource::Base64("YmFzZTY0".into()));
}

#[test]
fn xdg_home_is_used_when_default_home_is_missing() {
    let cwd = unique_temp_dir();
    let env = BootEnvironment {
        user_home: Some(cwd.join("home")),
        xdg_config_home: Some(cwd.join("xdg")),
    };
    let resolved = BootOptions::default().resolve(&cwd, &env);
    assert_eq!(resolved.home_dir, cwd.join("xdg").join("mihomo"));
}

#[test]
fn runtime_config_document_defaults_mode_to_rule() {
    let document = parse_runtime_config_document(
        r#"
proxies:
  - type: direct
    name: direct-a
"#,
    )
    .unwrap();

    assert_eq!(document.mode, "rule");
}

#[test]
fn runtime_config_document_parses_listeners_key() {
    let document = parse_runtime_config_document(
        r#"
mode: rule
log-level: debug
mixed-port: 7890
allow-lan: true
bind-address: "*"
external-controller: 0.0.0.0:9093
external-ui: ./ui
proxies:
  - type: direct
    name: direct-a
proxy-groups:
  - name: auto
    type: url-test
    proxies: [direct-a]
    url: https://cp.cloudflare.com/generate_204
    interval: 300
proxy-providers:
  provider1:
    type: inline
    payload:
      - type: direct
        name: provider-direct
rule-providers:
  rule1:
    type: inline
    behavior: domain
    payload:
      - '.example.org'
listeners:
  - type: socks
    name: edge-socks
    listen: 127.0.0.1
    port: "1080"
  - type: tun
    name: edge-tun
rules:
  - DOMAIN-SUFFIX,example.com,direct-a
  - MATCH,auto
sub-rules:
  edge:
    - DOMAIN,edge.example.com,direct-a
tun:
  enable: true
  stack: system
  dns-hijack:
    - 0.0.0.0:53
hosts:
  example.com:
    - 1.1.1.1
    - 1.0.0.1
  alias.local: target.local
dns:
  enable: true
  use-hosts: true
  use-system-hosts: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-range6: fdfe:dcba:9876::1/64
  fake-ip-filter:
    - '*.lan'
  fallback-filter:
    domain:
      - '+.fallback.test'
    ipcidr:
      - 240.0.0.0/4
  nameserver:
    - 8.8.8.8
  proxy-server-nameserver:
    - 9.9.9.9
  proxy-server-nameserver-policy:
    "+.proxy.test":
      - 4.4.4.4
  direct-nameserver:
    - 1.1.1.1
  direct-nameserver-follow-policy: true
  default-nameserver:
    - 1.1.1.1
"#,
    )
    .unwrap();

    assert_eq!(document.proxies.len(), 1);
    assert_eq!(document.proxy_groups.len(), 1);
    assert_eq!(document.proxy_providers.len(), 1);
    assert_eq!(document.rule_providers.len(), 1);
    assert_eq!(document.listeners.len(), 2);
    assert_eq!(document.rules.len(), 2);
    assert_eq!(document.sub_rules.len(), 1);
    assert!(document.tun.enable);
    assert!(document.dns.enable);
    assert_eq!(document.hosts.len(), 2);
    assert_eq!(document.mode, "rule");
    assert_eq!(document.log_level, "debug");
    assert_eq!(document.mixed_port, 7890);
    assert!(document.allow_lan);
    assert_eq!(document.bind_address, "*");
    assert_eq!(document.external_controller, "0.0.0.0:9093");
    assert_eq!(document.external_ui, "./ui");
    match &document.proxies[0] {
        OutboundDefinition::Direct(config) => {
            assert_eq!(config.base.name, "direct-a");
        }
        _ => panic!("expected direct proxy"),
    }
    assert_eq!(document.proxy_groups[0].kind(), Some(OutboundGroupKind::UrlTest));
    assert_eq!(
        document.proxy_providers["provider1"].vehicle_type(),
        Some(ProxyProviderVehicleType::Inline)
    );
    assert_eq!(
        document.rule_providers["rule1"].vehicle_type(),
        Some(RuleProviderVehicleType::Inline)
    );
    assert_eq!(
        document.rule_providers["rule1"].behavior_kind(),
        Some(RuleProviderBehavior::Domain)
    );
    assert_eq!(
        document.rule_providers["rule1"].format_kind(),
        Some(RuleProviderFormat::Yaml)
    );
    match &document.listeners[0] {
        InboundDefinition::Socks(config) => {
            assert_eq!(config.base.name, "edge-socks");
        }
        _ => panic!("expected socks listener"),
    }
    match &document.listeners[1] {
        InboundDefinition::Tun(config) => {
            assert_eq!(config.base.name, "edge-tun");
        }
        _ => panic!("expected tun listener"),
    }
    assert_eq!(document.rules[0], "DOMAIN-SUFFIX,example.com,direct-a");
    assert_eq!(document.rules[1], "MATCH,auto");
    assert_eq!(document.sub_rules["edge"][0], "DOMAIN,edge.example.com,direct-a");
    assert_eq!(document.tun.config.dns_hijack, vec!["0.0.0.0:53"]);
    assert_eq!(document.hosts["example.com"].values, vec!["1.1.1.1", "1.0.0.1"]);
    assert_eq!(document.hosts["alias.local"].values, vec!["target.local"]);
    assert_eq!(document.dns.enhanced_mode, "fake-ip");
    assert_eq!(document.dns.fake_ip_range, "198.18.0.1/16");
    assert_eq!(document.dns.fake_ip_range6, "fdfe:dcba:9876::1/64");
    assert_eq!(document.dns.fake_ip_filter, vec!["*.lan"]);
    assert!(document.dns.use_system_hosts);
    assert_eq!(document.dns.fallback_filter.domain, vec!["+.fallback.test"]);
    assert_eq!(document.dns.fallback_filter.ipcidr, vec!["240.0.0.0/4"]);
    assert_eq!(document.dns.nameserver, vec!["8.8.8.8"]);
    assert_eq!(document.dns.proxy_server_nameserver, vec!["9.9.9.9"]);
    assert_eq!(
        document.dns.proxy_server_nameserver_policy["+.proxy.test"].values,
        vec!["4.4.4.4"]
    );
    assert_eq!(document.dns.direct_nameserver, vec!["1.1.1.1"]);
    assert!(document.dns.direct_nameserver_follow_policy);
    assert_eq!(document.dns.default_nameserver, vec!["1.1.1.1"]);
    assert!(document.extra.is_empty());
    document.validate().unwrap();
}

#[test]
fn validation_rejects_duplicate_proxy_names() {
    let document = parse_runtime_config_document(
        r#"
proxies:
  - type: direct
    name: same
  - type: reject
    name: same
"#,
    )
    .unwrap();
    assert_eq!(
        document.validate().unwrap_err(),
        ConfigValidationError::DuplicateProxyName("same".into())
    );
}

#[test]
fn validation_rejects_reserved_provider_name() {
    let document = parse_runtime_config_document(
        r#"
proxy-providers:
  default:
    type: inline
    payload:
      - type: direct
        name: direct-a
"#,
    )
    .unwrap();
    assert_eq!(
        document.validate().unwrap_err(),
        ConfigValidationError::ReservedProviderName("default".into())
    );
}

#[test]
fn validation_rejects_missing_group_reference() {
    let document = parse_runtime_config_document(
        r#"
proxy-groups:
  - name: auto
    type: select
    proxies: [missing-proxy]
"#,
    )
    .unwrap();
    assert_eq!(
        document.validate().unwrap_err(),
        ConfigValidationError::ProxyGroupReferenceNotFound {
            group: "auto".into(),
            reference: "missing-proxy".into()
        }
    );
}

#[test]
fn validation_rejects_removed_relay_group_type() {
    let document = parse_runtime_config_document(
        r#"
proxy-groups:
  - name: relay
    type: relay
    proxies: [DIRECT]
"#,
    )
    .unwrap();
    assert_eq!(
        document.validate().unwrap_err(),
        ConfigValidationError::UnsupportedProxyGroupType("relay".into())
    );
}

#[test]
fn validation_accepts_smart_group_type() {
    let document = parse_runtime_config_document(
        r#"
proxy-groups:
  - name: auto
    type: smart
    proxies: [DIRECT]
    strategy: sticky-sessions
    uselightgbm: true
proxies:
  - type: direct
    name: leaf-a
"#,
    )
    .unwrap();
    document.validate().unwrap();
}

#[test]
fn validation_rejects_invalid_proxy_uuid_fields() {
    let document = parse_runtime_config_document(
        r#"
proxies:
  - type: vless
    name: bad-vless
    server: 1.2.3.4
    port: 443
    uuid: not-a-uuid
"#,
    )
    .unwrap();
    match document.validate().unwrap_err() {
        ConfigValidationError::InvalidProxyUuid {
            proxy, protocol, ..
        } => {
            assert_eq!(proxy, "bad-vless");
            assert_eq!(protocol, "vless");
        }
        other => panic!("unexpected validation error: {other:?}"),
    }

    let document = parse_runtime_config_document(
        r#"
proxies:
  - type: vmess
    name: bad-vmess
    server: 1.2.3.4
    port: 443
    uuid: not-a-uuid
"#,
    )
    .unwrap();
    match document.validate().unwrap_err() {
        ConfigValidationError::InvalidProxyUuid {
            proxy, protocol, ..
        } => {
            assert_eq!(proxy, "bad-vmess");
            assert_eq!(protocol, "vmess");
        }
        other => panic!("unexpected validation error: {other:?}"),
    }

    let document = parse_runtime_config_document(
        r#"
proxies:
  - type: tuic
    name: bad-tuic
    server: 1.2.3.4
    port: 443
    uuid: not-a-uuid
    password: secret
"#,
    )
    .unwrap();
    match document.validate().unwrap_err() {
        ConfigValidationError::InvalidProxyUuid {
            proxy, protocol, ..
        } => {
            assert_eq!(proxy, "bad-tuic");
            assert_eq!(protocol, "tuic");
        }
        other => panic!("unexpected validation error: {other:?}"),
    }
}

#[test]
fn validation_rejects_invalid_listener_uuid_fields() {
    let document = parse_runtime_config_document(
        r#"
listeners:
  - type: vless
    name: bad-vless-listener
    listen: 127.0.0.1
    port: "0"
    users:
      - uuid: not-a-uuid
"#,
    )
    .unwrap();
    match document.validate().unwrap_err() {
        ConfigValidationError::InvalidListenerUuid {
            listener,
            protocol,
            ..
        } => {
            assert_eq!(listener, "bad-vless-listener");
            assert_eq!(protocol, "vless");
        }
        other => panic!("unexpected validation error: {other:?}"),
    }

    let document = parse_runtime_config_document(
        r#"
listeners:
  - type: vmess
    name: bad-vmess-listener
    listen: 127.0.0.1
    port: "0"
    users:
      - uuid: not-a-uuid
"#,
    )
    .unwrap();
    match document.validate().unwrap_err() {
        ConfigValidationError::InvalidListenerUuid {
            listener,
            protocol,
            ..
        } => {
            assert_eq!(listener, "bad-vmess-listener");
            assert_eq!(protocol, "vmess");
        }
        other => panic!("unexpected validation error: {other:?}"),
    }
}

#[test]
fn runtime_config_document_expands_yaml_merge_keys() {
    let document = parse_runtime_config_document(
        r#"
p: &p
  type: http
  interval: 86400

rule-anchor:
  IPCIDR: &IPCIDR
    type: http
    behavior: ipcidr
    format: mrs

proxy-providers:
  airport1:
    <<: *p
    url: https://example.com/sub
    path: ./providers/airport1.yaml

rule-providers:
  cn_ip:
    <<: *IPCIDR
    path: ./rules/cn_ip.mrs
    url: https://example.com/cn_ip.mrs
"#,
    )
    .unwrap();

    assert_eq!(document.proxy_providers["airport1"].provider_type, "http");
    assert_eq!(document.proxy_providers["airport1"].interval, 86400);
    assert_eq!(document.rule_providers["cn_ip"].provider_type, "http");
    assert_eq!(document.rule_providers["cn_ip"].behavior, "ipcidr");
    assert_eq!(document.rule_providers["cn_ip"].format, "mrs");
}

#[test]
fn sniffer_ports_accept_numbers_and_strings() {
    let document = parse_runtime_config_document(
        r#"
sniffer:
  sniff:
    HTTP:
      ports: [80, "8080-8880"]
"#,
    )
    .unwrap();

    assert_eq!(document.sniffer.sniff["HTTP"].ports, vec!["80", "8080-8880"]);
}

fn unique_temp_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("mihomo-config-test-{nanos}"));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn accepts_go_flag_forms_and_explicit_false() {
    let options = parse_args(["mihomo", "--d=/tmp/data", "-f=config.yaml", "--ext-ctl", "127.0.0.1:9090", "-m=false", "--t=true"]).unwrap();
    assert_eq!(options.home_dir.as_deref(), Some("/tmp/data"));
    assert_eq!(options.config_file.as_deref(), Some("config.yaml"));
    assert!(!options.geodata_mode);
    assert!(options.test_config);
    assert_eq!(parse_args(["mihomo", "--help"]), Err(ParseError::HelpRequested));
}

#[test]
fn smart_group_validates_boolean_options_and_retains_collector_size(){
 let document=parse_runtime_config_document("profile:\n  smart-collector-size: 0.5\nproxy-groups:\n  - name: auto\n    type: smart\n    proxies: [DIRECT]\n    uselightgbm: true\n    collectdata: false\n    prefer-asn: true\n").unwrap();
 document.validate().unwrap();assert_eq!(document.profile.extra["smart-collector-size"].as_f64(),Some(0.5));
 let bad=parse_runtime_config_document("proxy-groups:\n  - name: auto\n    type: smart\n    proxies: [DIRECT]\n    uselightgbm: yes-please\n").unwrap();
 assert!(matches!(bad.validate(),Err(ConfigValidationError::InvalidSmartConfig(_))));
}

#[test]
fn ebpf_configuration_keeps_legacy_names_and_defaults_auto_redir_port(){
 let document=parse_runtime_config_document("allow-lan: true\nebpf:\n  auto-redir: [br-lan]\n").unwrap();
 document.validate().unwrap();assert_eq!(document.ebpf.auto_redir,["br-lan"]);assert_eq!(document.redir_port,29810);assert_eq!(document.ebpf.effective_bypass_mark(),0x636c746d);
 let off=parse_runtime_config_document("ebpf: {}\n").unwrap();assert!(!off.ebpf.enabled());assert_eq!(off.redir_port,0);
}

#[test]
fn kernel_direct_requires_named_tun_and_valid_lan_interfaces() {
 let text="allow-lan: true\ntun:\n  enable: true\n  device: Meta\n  auto-redirect: false\nebpf:\n  direct-offload: [br-lan]\n";
 let d=parse_runtime_config_document(text).unwrap();d.validate().unwrap();assert!(d.ebpf.enabled());
 for invalid in [text.replace("allow-lan: true","allow-lan: false"),text.replace("device: Meta","device: ''"),text.replace("auto-redirect: false","auto-redirect: true"),text.replace("[br-lan]","[Meta]"),text.replace("[br-lan]","[br-lan, br-lan]")] {
  assert!(parse_runtime_config_document(&invalid).unwrap().validate().is_err());
 }
}
#[test]
fn ebpf_rejects_capture_conflicts_and_invalid_interfaces(){
 for yaml in [
  "ebpf: {auto-redir: ['bad/name']}",
  "ebpf: {auto-redir: [eth0, eth0]}",
  "ebpf: {auto-redir: [eth0], redirect-to-tun: [eth0]}",
  "ebpf: {redirect-to-tun: [eth0]}",
  "tun: {enable: true, device: eth0}\nebpf: {redirect-to-tun: [eth0]}",
  "tun: {enable: true, device: tun0, auto-redirect: true}\nebpf: {redirect-to-tun: [eth0]}",
  "routing-mark: 123\nebpf: {auto-redir: [eth0]}",
 ] {
  let document=parse_runtime_config_document(yaml).unwrap();assert!(matches!(document.validate(),Err(ConfigValidationError::InvalidEbpfConfig(_))),"{yaml}");
 }
 let document=parse_runtime_config_document("allow-lan: true\nrouting-mark: 123\nebpf: {auto-redir: [eth0], bypass-mark: 123}").unwrap();document.validate().unwrap();
}
