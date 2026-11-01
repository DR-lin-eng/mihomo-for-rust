use std::fs;

use mihomo_config::parse_runtime_config_document;
use mihomo_runtime::bootstrap_from_yaml;

use super::{build_api_snapshot, build_api_snapshot_from_bootstrap};

#[test]
fn api_snapshot_summarizes_runtime_surface() {
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
rules:
  - DOMAIN-SUFFIX,example.com,direct-a
  - MATCH,auto
listeners:
  - type: socks
    name: edge-socks
    listen: 127.0.0.1
    port: "1080"
tun:
  enable: true
  stack: system
  dns-hijack:
    - 0.0.0.0:53
dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  nameserver:
    - 8.8.8.8
  default-nameserver:
    - 1.1.1.1
"#,
    )
    .unwrap();
    let snapshot = build_api_snapshot(&document).unwrap();
    assert_eq!(snapshot.general.mode, "rule");
    assert!(snapshot.general.tun.stack == mihomo_inbound::TunStack::System);
    assert_eq!(snapshot.general.listener_count, 2);
    assert!(snapshot.proxies.iter().any(|proxy| proxy.name == "direct-a"));
    assert!(snapshot.groups.iter().any(|group| group.name == "auto"));
    assert_eq!(snapshot.rules.len(), 2);
    assert!(snapshot.tun.enabled);
    assert_eq!(snapshot.dns.nameserver_count, 1);
}

#[test]
fn api_snapshot_can_be_built_from_bootstrap_state() {
    let (document, _, _) = bootstrap_from_yaml(
        r#"
proxies:
  - type: direct
    name: direct-a
"#,
        std::path::Path::new("/tmp"),
    )
    .unwrap();
    let state = mihomo_runtime::BootstrapState {
        resolved_boot: mihomo_config::BootOptions::default()
            .resolve(std::path::Path::new("/tmp"), &mihomo_config::BootEnvironment::default()),
        document,
        provider_sources: Default::default(),
        registry: mihomo_runtime::build_runtime_registry(&parse_runtime_config_document(
            "proxies:\n  - type: direct\n    name: direct-a\n",
        )
        .unwrap())
        .unwrap(),
    };
    let snapshot = build_api_snapshot_from_bootstrap(&state).unwrap();
    assert!(snapshot.proxies.iter().any(|proxy| proxy.name == "direct-a"));
}

#[test]
fn bootstrap_snapshot_uses_loaded_rule_provider_payloads() {
    let temp = unique_temp_dir("mihomo-api-bootstrap-rule-provider");
    fs::create_dir_all(&temp).unwrap();
    fs::write(
        temp.join("rule-provider.yaml"),
        "payload:\n  - DOMAIN-SUFFIX,example.com\n  - DOMAIN,example.org\n",
    )
    .unwrap();

    let (document, provider_sources, registry) = bootstrap_from_yaml(
        r#"
rule-providers:
  rule1:
    type: file
    behavior: classical
    format: yaml
    path: rule-provider.yaml
proxies:
  - type: direct
    name: direct-a
"#,
        &temp,
    )
    .unwrap();
    let state = mihomo_runtime::BootstrapState {
        resolved_boot: mihomo_config::BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            ..mihomo_config::BootOptions::default()
        }
        .resolve(&temp, &mihomo_config::BootEnvironment::default()),
        document,
        provider_sources,
        registry,
    };

    let snapshot = build_api_snapshot_from_bootstrap(&state).unwrap();
    assert_eq!(snapshot.rule_providers.len(), 1);
    assert_eq!(snapshot.rule_providers[0].name, "rule1");
    assert_eq!(snapshot.rule_providers[0].rule_count, 2);
}

fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nanos}"))
}
