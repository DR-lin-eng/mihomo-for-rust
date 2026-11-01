use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use mihomo_config::parse_runtime_config_document;
use mihomo_core::{DnsMode, Metadata};
use quinn::Endpoint;
use rcgen::generate_simple_self_signed;
use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection, StreamOwned};
use rustls023::crypto::aws_lc_rs;
use rustls023::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use super::packet::{build_dns_query, parse_dns_response};
use super::upstream::register_test_root_certificate;
use super::{
    DnsPacketTransport, DnsRecordType, DnsRuntime, DnsUpstream, EnhancedMode,
    FakeIpFilterMode, NetworkDnsUpstream,
};

#[derive(Default)]
struct StaticUpstream {
    answers: HashMap<(String, String), Vec<IpAddr>>,
    calls: Vec<(Vec<String>, String)>,
    raw_calls: Vec<Vec<u8>>,
}

impl StaticUpstream {
    fn with_answer(mut self, server: &str, host: &str, answers: Vec<IpAddr>) -> Self {
        self.answers
            .insert((server.to_owned(), host.to_owned()), answers);
        self
    }
}

impl DnsUpstream for StaticUpstream {
    fn resolve(&mut self, servers: &[String], host: &str) -> Result<Vec<IpAddr>, super::DnsError> {
        self.calls.push((servers.to_vec(), host.to_owned()));
        for server in servers {
            if let Some(answer) = self.answers.get(&(server.clone(), host.to_owned())) {
                return Ok(answer.clone());
            }
        }
        Ok(Vec::new())
    }

    fn exchange(&mut self, _servers: &[String], packet: &[u8]) -> Result<Vec<u8>, super::DnsError> {
        self.raw_calls.push(packet.to_vec());
        let mut response = packet.to_vec();
        response[2] |= 0x80;
        response[3] |= 0x80;
        Ok(response)
    }
}

#[derive(Default)]
struct FakePacketTransport {
    calls: Vec<String>,
    responses: HashMap<String, Vec<u8>>,
}

impl FakePacketTransport {
    fn with_response(mut self, server: &str, response: Vec<u8>) -> Self {
        self.responses.insert(server.to_owned(), response);
        self
    }
}

impl DnsPacketTransport for FakePacketTransport {
    fn exchange(&mut self, server: &str, _payload: &[u8]) -> Result<Vec<u8>, super::DnsError> {
        self.calls.push(server.to_owned());
        Ok(self.responses.get(server).cloned().unwrap_or_default())
    }
}

#[test]
fn hosts_exact_and_alias_resolution_work() {
    let document = parse_runtime_config_document(
        r#"
hosts:
  example.com: 1.1.1.1
  alias.local: example.com
dns:
  use-hosts: true
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    assert_eq!(
        runtime.resolve_host("example.com").unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
    );
    assert_eq!(
        runtime.resolve_host("alias.local").unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
    );
}

#[test]
fn system_hosts_entries_are_loaded_when_enabled() {
    let document = parse_runtime_config_document(
        r#"
dns:
  use-system-hosts: true
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document_with_rule_providers_and_system_hosts(
        &document,
        &BTreeMap::new(),
        &BTreeMap::new(),
        Some(
            r#"
127.0.0.1 localhost custom.local
10.0.0.2 service.internal
"#,
        ),
    )
    .unwrap();
    assert_eq!(
        runtime.resolve_host("service.internal").unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
    );
    assert_eq!(
        runtime.resolve_host("custom.local").unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
    );
}

#[test]
fn explicit_hosts_override_system_hosts_entries() {
    let document = parse_runtime_config_document(
        r#"
hosts:
  custom.local: 1.1.1.1
dns:
  use-system-hosts: true
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document_with_rule_providers_and_system_hosts(
        &document,
        &BTreeMap::new(),
        &BTreeMap::new(),
        Some("127.0.0.1 custom.local"),
    )
    .unwrap();
    assert_eq!(
        runtime.resolve_host("custom.local").unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
    );
}

#[test]
fn hosts_sequence_returns_all_ip_answers_in_order() {
    let document = parse_runtime_config_document(
        r#"
hosts:
  dualstack.local:
    - "::1"
    - "127.0.0.1"
dns:
  use-hosts: true
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    let mut upstream = StaticUpstream::default();

    let resolved = runtime
        .resolve_host_addrs_with_upstream("dualstack.local", &mut upstream)
        .unwrap();

    assert_eq!(
        resolved,
        vec![
            IpAddr::V6("::1".parse().unwrap()),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        ]
    );
}

#[test]
fn resolve_host_addrs_via_system_style_upstream_keeps_all_answers_in_order() {
    let document = parse_runtime_config_document(
        r#"
dns:
  nameserver:
    - 1.1.1.1
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    let mut upstream = StaticUpstream::default().with_answer(
        "1.1.1.1",
        "multi.example",
        vec![
            IpAddr::V6("2001:db8::10".parse().unwrap()),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        ],
    );

    let resolved = runtime
        .resolve_host_addrs_with_upstream("multi.example", &mut upstream)
        .unwrap();

    assert_eq!(
        resolved,
        vec![
            IpAddr::V6("2001:db8::10".parse().unwrap()),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        ]
    );
}

#[test]
fn select_nameservers_defaults_to_system_when_unconfigured() {
    let document = parse_runtime_config_document(
        r#"
dns:
  enable: true
"#,
    )
    .unwrap();
    let runtime = DnsRuntime::from_document(&document).unwrap();
    assert_eq!(runtime.select_nameservers("www.gstatic.com"), vec!["system://"]);
}

#[test]
fn resolve_direct_server_host_addrs_via_system_works_without_explicit_nameserver() {
    let document = parse_runtime_config_document(
        r#"
dns:
  enable: true
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    let resolved = runtime
        .resolve_direct_server_host_addrs_via_system("localhost")
        .unwrap();
    assert!(
        !resolved.is_empty(),
        "system resolver returned no localhost addresses"
    );
}

#[test]
fn fake_ip_assignment_and_reverse_lookup_work() {
    let document = parse_runtime_config_document(
        r#"
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    let fake_ip = runtime.resolve_host("example.com").unwrap().unwrap();
    assert!(runtime.reverse_lookup(fake_ip).is_some());
    let mut metadata = Metadata {
        dst_ip: Some(fake_ip),
        ..Metadata::default()
    };
    runtime.resolve_metadata(&mut metadata).unwrap();
    assert_eq!(metadata.host.as_deref(), Some("example.com"));
    assert_eq!(metadata.dns_mode, DnsMode::FakeIp);
}

#[test]
fn fake_ip_pool_starts_from_reserved_four_and_is_case_insensitive() {
    let document = parse_runtime_config_document(
        r#"
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    let first = runtime.resolve_host("Foo.Com").unwrap().unwrap();
    let second = runtime.resolve_host("bar.com").unwrap().unwrap();
    let third = runtime.resolve_host("foo.com").unwrap().unwrap();
    assert_eq!(first, "198.18.0.4".parse::<IpAddr>().unwrap());
    assert_eq!(second, "198.18.0.5".parse::<IpAddr>().unwrap());
    assert_eq!(third, first);
    assert_eq!(runtime.reverse_lookup(first), Some("foo.com"));
}

#[test]
fn fake_ip_mode_real_resolution_uses_upstream_answer_instead_of_fake_ip() {
    let document = parse_runtime_config_document(
        r#"
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 1.1.1.1
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    let mut upstream = StaticUpstream::default().with_answer(
        "1.1.1.1",
        "real.example",
        vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))],
    );
    let resolved = runtime
        .resolve_host_with_upstream("real.example", &mut upstream)
        .unwrap();
    assert_eq!(resolved, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))));
    assert_eq!(runtime.reverse_lookup(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))), None);
}

#[test]
fn fake_ip_state_persists_when_store_fake_ip_is_enabled() {
    let temp = unique_temp_dir();
    let empty_sources = BTreeMap::<String, String>::new();
    let document = parse_runtime_config_document(
        r#"
profile:
  store-fake-ip: true
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
"#,
    )
    .unwrap();
    let runtime = DnsRuntime::from_document_with_rule_providers_and_home_bytes(
        &document,
        &empty_sources,
        &empty_sources,
        &temp,
    )
    .unwrap();
    let mut runtime = runtime;
    let first = runtime.resolve_host("persist.example").unwrap().unwrap();
    drop(runtime);
    let runtime = DnsRuntime::from_document_with_rule_providers_and_home_bytes(
        &document,
        &empty_sources,
        &empty_sources,
        &temp,
    )
    .unwrap();
    let mut runtime = runtime;
    let restored = runtime.resolve_host("persist.example").unwrap().unwrap();
    assert_eq!(restored, first);
    let _ = fs::remove_dir_all(temp);
}

#[test]
fn fake_ip_range6_answers_aaaa_queries_and_reverse_lookup_work() {
    let document = parse_runtime_config_document(
        r#"
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range6: fdfe:dcba:9876::1/64
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    let query = build_dns_query("example.com", DnsRecordType::Aaaa, 0x4321).unwrap();
    let response = runtime
        .handle_query_packet(&query, &mut StaticUpstream::default())
        .unwrap()
        .unwrap();
    let ips = parse_dns_response(&response, 0x4321, DnsRecordType::Aaaa).unwrap();
    assert_eq!(ips.len(), 1);
    assert!(matches!(ips[0], IpAddr::V6(_)));
    assert_eq!(runtime.reverse_lookup(ips[0]), Some("example.com"));
}

#[test]
fn dns_listener_forwards_https_query_type_65_without_protocol_error() {
    let document = parse_runtime_config_document(
        r#"
dns:
  enable: true
  nameserver:
    - 127.0.0.1:53
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    let query = build_dns_query("example.com", DnsRecordType::Other(65), 0x6501).unwrap();
    let mut upstream = StaticUpstream::default();
    let response = runtime.handle_query_packet(&query, &mut upstream).unwrap().unwrap();
    assert_eq!(response, {
        let mut expected = query.clone();
        expected[2] |= 0x80;
        expected[3] |= 0x80;
        expected
    });
    assert_eq!(upstream.raw_calls, vec![query]);
}

#[test]
fn resolve_metadata_recovers_host_from_ipv6_fake_ip() {
    let document = parse_runtime_config_document(
        r#"
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range6: fdfe:dcba:9876::1/64
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    let query = build_dns_query("example.com", DnsRecordType::Aaaa, 0x4321).unwrap();
    let response = runtime
        .handle_query_packet(&query, &mut StaticUpstream::default())
        .unwrap()
        .unwrap();
    let fake_ip = parse_dns_response(&response, 0x4321, DnsRecordType::Aaaa).unwrap()[0];
    let mut metadata = Metadata {
        dst_ip: Some(fake_ip),
        ..Metadata::default()
    };
    runtime.resolve_metadata(&mut metadata).unwrap();
    assert_eq!(metadata.host.as_deref(), Some("example.com"));
    assert_eq!(metadata.dns_mode, DnsMode::FakeIp);
}

#[test]
fn fake_ip_filter_blacklist_and_whitelist_modes_apply() {
    let blacklist = parse_runtime_config_document(
        r#"
dns:
  enhanced-mode: fake-ip
  fake-ip-filter:
    - '*.lan'
"#,
    )
    .unwrap();
    let runtime = DnsRuntime::from_document(&blacklist).unwrap();
    assert_eq!(runtime.config.enhanced_mode, EnhancedMode::FakeIp);
    assert_eq!(runtime.config.fake_ip_filter_mode, FakeIpFilterMode::Blacklist);
    assert!(!runtime.should_use_fake_ip("router.lan"));

    let whitelist = parse_runtime_config_document(
        r#"
dns:
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
  fake-ip-filter:
    - '*.allowed'
"#,
    )
    .unwrap();
    let runtime = DnsRuntime::from_document(&whitelist).unwrap();
    assert!(runtime.should_use_fake_ip("app.allowed"));
    assert!(!runtime.should_use_fake_ip("blocked.example"));
}

#[test]
fn fake_ip_filter_rule_mode_uses_rule_targets() {
    let document = parse_runtime_config_document(
        r#"
dns:
  enhanced-mode: fake-ip
  fake-ip-filter-mode: rule
  fake-ip-filter:
    - DOMAIN-SUFFIX,example.com,fake-ip
    - MATCH,real-ip
"#,
    )
    .unwrap();
    let runtime = DnsRuntime::from_document(&document).unwrap();
    assert!(runtime.should_use_fake_ip("www.example.com"));
    assert!(!runtime.should_use_fake_ip("other.test"));
}

#[test]
fn fake_ip_filter_rule_mode_supports_rule_set_provider() {
    let document = parse_runtime_config_document(
        r#"
rule-providers:
  rule1:
    type: inline
    behavior: domain
    payload:
      - .example.net
dns:
  enhanced-mode: fake-ip
  fake-ip-filter-mode: rule
  fake-ip-filter:
    - RULE-SET,rule1,fake-ip
    - MATCH,real-ip
"#,
    )
    .unwrap();
    let runtime =
        DnsRuntime::from_document_with_rule_providers(&document, &BTreeMap::new(), &BTreeMap::new())
            .unwrap();
    assert!(runtime.should_use_fake_ip("api.example.net"));
    assert!(!runtime.should_use_fake_ip("other.test"));
}

#[test]
fn fake_ip_filter_rule_mode_rejects_ipcidr_rule_set_provider() {
    let document = parse_runtime_config_document(
        r#"
rule-providers:
  rule1:
    type: inline
    behavior: ipcidr
    payload:
      - 1.1.1.0/24
dns:
  enhanced-mode: fake-ip
  fake-ip-filter-mode: rule
  fake-ip-filter:
    - RULE-SET,rule1,fake-ip
"#,
    )
    .unwrap();
    assert!(
        DnsRuntime::from_document_with_rule_providers(&document, &BTreeMap::new(), &BTreeMap::new())
            .is_err()
    );
}

#[test]
fn fake_ip_filter_blacklist_and_whitelist_support_rule_set_provider() {
    let blacklist = parse_runtime_config_document(
        r#"
rule-providers:
  rule1:
    type: inline
    behavior: domain
    payload:
      - .blocked.net
dns:
  enhanced-mode: fake-ip
  fake-ip-filter:
    - rule-set:rule1
"#,
    )
    .unwrap();
    let blacklist_runtime =
        DnsRuntime::from_document_with_rule_providers(&blacklist, &BTreeMap::new(), &BTreeMap::new())
            .unwrap();
    assert!(!blacklist_runtime.should_use_fake_ip("api.blocked.net"));
    assert!(blacklist_runtime.should_use_fake_ip("other.test"));

    let whitelist = parse_runtime_config_document(
        r#"
rule-providers:
  rule1:
    type: inline
    behavior: domain
    payload:
      - .allowed.net
dns:
  enhanced-mode: fake-ip
  fake-ip-filter-mode: whitelist
  fake-ip-filter:
    - rule-set:rule1
"#,
    )
    .unwrap();
    let whitelist_runtime =
        DnsRuntime::from_document_with_rule_providers(&whitelist, &BTreeMap::new(), &BTreeMap::new())
            .unwrap();
    assert!(whitelist_runtime.should_use_fake_ip("api.allowed.net"));
    assert!(!whitelist_runtime.should_use_fake_ip("other.test"));
}

#[test]
fn fake_ip_filter_blacklist_supports_geosite_provider_shortcut() {
    let document = parse_runtime_config_document(
        r#"
rule-providers:
  fakeip-filter:
    type: inline
    behavior: domain
    payload:
      - .blocked.net
dns:
  enhanced-mode: fake-ip
  fake-ip-filter:
    - geosite:fakeip-filter
"#,
    )
    .unwrap();
    let runtime =
        DnsRuntime::from_document_with_rule_providers(&document, &BTreeMap::new(), &BTreeMap::new())
            .unwrap();
    assert!(!runtime.should_use_fake_ip("api.blocked.net"));
    assert!(runtime.should_use_fake_ip("other.test"));
}

#[test]
fn fake_ip_filter_blacklist_and_whitelist_reject_ipcidr_rule_set_provider() {
    let document = parse_runtime_config_document(
        r#"
rule-providers:
  rule1:
    type: inline
    behavior: ipcidr
    payload:
      - 1.1.1.0/24
dns:
  enhanced-mode: fake-ip
  fake-ip-filter:
    - rule-set:rule1
"#,
    )
    .unwrap();
    assert!(
        DnsRuntime::from_document_with_rule_providers(&document, &BTreeMap::new(), &BTreeMap::new())
            .is_err()
    );
}

#[test]
fn resolve_metadata_prefers_hosts_before_fake_ip() {
    let document = parse_runtime_config_document(
        r#"
hosts:
  service.local: 10.0.0.10
dns:
  use-hosts: true
  enhanced-mode: fake-ip
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    let mut metadata = Metadata {
        host: Some("service.local".into()),
        ..Metadata::default()
    };
    runtime.resolve_metadata(&mut metadata).unwrap();
    assert_eq!(metadata.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10))));
    assert_eq!(metadata.dns_mode, DnsMode::Hosts);
}

#[test]
fn nameserver_policy_and_fallback_with_cache_work() {
    let document = parse_runtime_config_document(
        r#"
dns:
  nameserver:
    - 8.8.8.8
  fallback:
    - 1.1.1.1
  nameserver-policy:
    "+.cn":
      - 223.5.5.5
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    assert_eq!(runtime.select_nameservers("www.test.cn"), vec!["223.5.5.5"]);

    let mut upstream = StaticUpstream::default()
        .with_answer(
            "1.1.1.1",
            "fallback.test",
            vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
        )
        .with_answer(
            "223.5.5.5",
            "www.test.cn",
            vec![IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5))],
        );

    assert_eq!(
        runtime.resolve_host_with_upstream("www.test.cn", &mut upstream).unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)))
    );
    assert_eq!(
        runtime.resolve_host_with_upstream("fallback.test", &mut upstream).unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
    );
    let calls_before_cache = upstream.calls.len();
    assert_eq!(
        runtime.resolve_host_with_upstream("fallback.test", &mut upstream).unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
    );
    assert_eq!(upstream.calls.len(), calls_before_cache);
    assert_eq!(
        runtime.cached_answer("fallback.test").unwrap().ips,
        vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]
    );
}

#[test]
fn fallback_filter_domain_forces_fallback_nameserver() {
    let document = parse_runtime_config_document(
        r#"
dns:
  nameserver:
    - 8.8.8.8
  fallback:
    - 1.1.1.1
  fallback-filter:
    domain:
      - '+.blocked.test'
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    let mut upstream = StaticUpstream::default()
        .with_answer(
            "8.8.8.8",
            "api.blocked.test",
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
        )
        .with_answer(
            "1.1.1.1",
            "api.blocked.test",
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
        );

    assert_eq!(
        runtime
            .resolve_host_with_upstream("api.blocked.test", &mut upstream)
            .unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
    );
}

#[test]
fn fallback_filter_ipcidr_switches_to_fallback_nameserver() {
    let document = parse_runtime_config_document(
        r#"
dns:
  nameserver:
    - 8.8.8.8
  fallback:
    - 1.1.1.1
  fallback-filter:
    ipcidr:
      - 240.0.0.0/4
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    let mut upstream = StaticUpstream::default()
        .with_answer(
            "8.8.8.8",
            "fallback.test",
            vec![IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))],
        )
        .with_answer(
            "1.1.1.1",
            "fallback.test",
            vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
        );

    assert_eq!(
        runtime
            .resolve_host_with_upstream("fallback.test", &mut upstream)
            .unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
    );
}

#[test]
fn fallback_filter_supports_rule_set_providers() {
    let document = parse_runtime_config_document(
        r#"
rule-providers:
  domain-rule:
    type: inline
    behavior: domain
    payload:
      - .domain.test
  ip-rule:
    type: inline
    behavior: ipcidr
    payload:
      - 240.0.0.0/4
dns:
  nameserver:
    - 8.8.8.8
  fallback:
    - 1.1.1.1
  fallback-filter:
    domain:
      - rule-set:domain-rule
    ipcidr:
      - rule-set:ip-rule
"#,
    )
    .unwrap();
    let mut runtime =
        DnsRuntime::from_document_with_rule_providers(&document, &BTreeMap::new(), &BTreeMap::new())
            .unwrap();
    let mut upstream = StaticUpstream::default()
        .with_answer(
            "8.8.8.8",
            "api.domain.test",
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
        )
        .with_answer(
            "1.1.1.1",
            "api.domain.test",
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
        )
        .with_answer(
            "8.8.8.8",
            "fallback.test",
            vec![IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))],
        )
        .with_answer(
            "1.1.1.1",
            "fallback.test",
            vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
        );

    assert_eq!(
        runtime
            .resolve_host_with_upstream("api.domain.test", &mut upstream)
            .unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
    );
    assert_eq!(
        runtime
            .resolve_host_with_upstream("fallback.test", &mut upstream)
            .unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
    );
}

#[test]
fn fallback_filter_supports_geosite_and_geoip_shortcuts() {
    let document = parse_runtime_config_document(
        r#"
rule-providers:
  gfw:
    type: inline
    behavior: domain
    payload:
      - .blocked.test
  CN_IP:
    type: inline
    behavior: ipcidr
    payload:
      - 240.0.0.0/4
dns:
  nameserver:
    - 8.8.8.8
  fallback:
    - 1.1.1.1
  fallback-filter:
    domain:
      - geosite:gfw
    ipcidr:
      - geoip:cn
"#,
    )
    .unwrap();
    let mut runtime =
        DnsRuntime::from_document_with_rule_providers(&document, &BTreeMap::new(), &BTreeMap::new())
            .unwrap();
    let mut upstream = StaticUpstream::default()
        .with_answer(
            "8.8.8.8",
            "api.blocked.test",
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
        )
        .with_answer(
            "1.1.1.1",
            "api.blocked.test",
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
        )
        .with_answer(
            "8.8.8.8",
            "fallback.test",
            vec![IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))],
        )
        .with_answer(
            "1.1.1.1",
            "fallback.test",
            vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
        );

    assert_eq!(
        runtime
            .resolve_host_with_upstream("api.blocked.test", &mut upstream)
            .unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
    );
    assert_eq!(
        runtime
            .resolve_host_with_upstream("fallback.test", &mut upstream)
            .unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
    );
}

#[test]
fn nameserver_policy_supports_rule_set_provider() {
    let document = parse_runtime_config_document(
        r#"
rule-providers:
  rule1:
    type: inline
    behavior: domain
    payload:
      - .example.net
dns:
  nameserver:
    - 8.8.8.8
  nameserver-policy:
    "rule-set:rule1":
      - 9.9.9.9
"#,
    )
    .unwrap();
    let runtime =
        DnsRuntime::from_document_with_rule_providers(&document, &BTreeMap::new(), &BTreeMap::new())
            .unwrap();
    assert_eq!(runtime.select_nameservers("api.example.net"), vec!["9.9.9.9"]);
    assert_eq!(runtime.select_nameservers("other.test"), vec!["8.8.8.8"]);
}

#[test]
fn nameserver_policy_supports_geosite_shortcut() {
    let document = parse_runtime_config_document(
        r#"
rule-providers:
  cn:
    type: inline
    behavior: domain
    payload:
      - .example.net
dns:
  nameserver:
    - 8.8.8.8
  nameserver-policy:
    "geosite:cn":
      - 9.9.9.9
"#,
    )
    .unwrap();
    let runtime =
        DnsRuntime::from_document_with_rule_providers(&document, &BTreeMap::new(), &BTreeMap::new())
            .unwrap();
    assert_eq!(runtime.select_nameservers("api.example.net"), vec!["9.9.9.9"]);
    assert_eq!(runtime.select_nameservers("other.test"), vec!["8.8.8.8"]);
}

#[test]
fn proxy_server_nameserver_policy_is_used() {
    let document = parse_runtime_config_document(
        r#"
dns:
  nameserver:
    - 8.8.8.8
  proxy-server-nameserver:
    - 9.9.9.9
  proxy-server-nameserver-policy:
    "+.proxy.test":
      - 4.4.4.4
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    assert_eq!(
        runtime.select_proxy_server_nameservers("api.proxy.test"),
        vec!["4.4.4.4"]
    );
    assert_eq!(
        runtime.select_proxy_server_nameservers("other.test"),
        vec!["9.9.9.9"]
    );

    let mut upstream = StaticUpstream::default()
        .with_answer(
            "4.4.4.4",
            "api.proxy.test",
            vec![IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4))],
        )
        .with_answer(
            "9.9.9.9",
            "other.test",
            vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
        )
        .with_answer(
            "8.8.8.8",
            "api.proxy.test",
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
        );

    assert_eq!(
        runtime
            .resolve_proxy_server_host_with_upstream("api.proxy.test", &mut upstream)
            .unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4)))
    );
    assert_eq!(
        runtime
            .resolve_proxy_server_host_with_upstream("other.test", &mut upstream)
            .unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
    );
    assert_eq!(
        upstream.calls,
        vec![
            (vec!["4.4.4.4".into()], "api.proxy.test".into()),
            (vec!["9.9.9.9".into()], "other.test".into()),
        ]
    );
}

#[test]
fn relay_query_packet_uses_proxy_server_nameserver_when_primary_nameserver_is_empty() {
    let document = parse_runtime_config_document(
        r#"
dns:
  proxy-server-nameserver:
    - 9.9.9.9
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    let query = build_dns_query("relay.proxy.test", DnsRecordType::A, 0x4321).unwrap();
    let mut upstream = StaticUpstream::default().with_answer(
        "9.9.9.9",
        "relay.proxy.test",
        vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
    );

    let relayed = runtime
        .relay_query_packet(&query, &mut upstream)
        .unwrap()
        .unwrap();
    let ips = parse_dns_response(&relayed, 0x4321, DnsRecordType::A).unwrap();
    assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
    assert_eq!(
        upstream.calls,
        vec![(vec!["9.9.9.9".into()], "relay.proxy.test".into())]
    );
}

#[test]
fn direct_nameserver_follow_policy_controls_selection() {
    let document = parse_runtime_config_document(
        r#"
dns:
  nameserver:
    - 8.8.8.8
  nameserver-policy:
    "+.cn":
      - 223.5.5.5
  direct-nameserver:
    - 1.1.1.1
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    assert_eq!(runtime.select_direct_nameservers("www.test.cn"), vec!["1.1.1.1"]);
    let mut upstream = StaticUpstream::default().with_answer(
        "1.1.1.1",
        "www.test.cn",
        vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
    );
    assert_eq!(
        runtime
            .resolve_direct_server_host_with_upstream("www.test.cn", &mut upstream)
            .unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
    );
    assert_eq!(
        upstream.calls,
        vec![(vec!["1.1.1.1".into()], "www.test.cn".into())]
    );

    let document = parse_runtime_config_document(
        r#"
dns:
  nameserver:
    - 8.8.8.8
  nameserver-policy:
    "+.cn":
      - 223.5.5.5
  direct-nameserver:
    - 1.1.1.1
  direct-nameserver-follow-policy: true
"#,
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    assert_eq!(runtime.select_direct_nameservers("www.test.cn"), vec!["223.5.5.5"]);
    assert_eq!(runtime.select_direct_nameservers("other.test"), vec!["8.8.8.8"]);
    let mut upstream = StaticUpstream::default()
        .with_answer(
            "223.5.5.5",
            "www.test.cn",
            vec![IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5))],
        )
        .with_answer(
            "8.8.8.8",
            "other.test",
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
        );
    assert_eq!(
        runtime
            .resolve_direct_server_host_with_upstream("www.test.cn", &mut upstream)
            .unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)))
    );
    assert_eq!(
        runtime
            .resolve_direct_server_host_with_upstream("other.test", &mut upstream)
            .unwrap(),
        Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
    );
    assert_eq!(
        upstream.calls,
        vec![
            (vec!["223.5.5.5".into()], "www.test.cn".into()),
            (vec!["8.8.8.8".into()], "other.test".into()),
        ]
    );
}

#[test]
fn nameserver_policy_rejects_ipcidr_rule_set_provider() {
    let document = parse_runtime_config_document(
        r#"
rule-providers:
  rule1:
    type: inline
    behavior: ipcidr
    payload:
      - 1.1.1.0/24
dns:
  nameserver-policy:
    "rule-set:rule1":
      - 9.9.9.9
"#,
    )
    .unwrap();
    assert!(
        DnsRuntime::from_document_with_rule_providers(&document, &BTreeMap::new(), &BTreeMap::new())
            .is_err()
    );
}

#[test]
fn dns_query_codec_round_trips_a_record_answers() {
    let query = build_dns_query("example.com", DnsRecordType::A, 0x1234).unwrap();
    assert!(query.ends_with(&[0, 0x00, 0x01, 0x00, 0x01]));

    let response = [
        vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        query[12..].to_vec(),
        vec![
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 1, 1, 1,
            1,
        ],
    ]
    .concat();
    let ips = parse_dns_response(&response, 0x1234, DnsRecordType::A).unwrap();
    assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
}

#[test]
fn network_dns_upstream_queries_plain_udp_servers() {
    let query_a = build_dns_query("example.com", DnsRecordType::A, 1).unwrap();
    let query_aaaa = build_dns_query("example.com", DnsRecordType::Aaaa, 2).unwrap();
    let response_a = [
        vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ],
        query_a[12..].to_vec(),
        vec![
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 8, 8, 8,
            8,
        ],
    ]
    .concat();
    let response_aaaa = [
        vec![
            0x00, 0x02, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        query_aaaa[12..].to_vec(),
    ]
    .concat();
    let transport = FakePacketTransport::default()
        .with_response("8.8.8.8", response_a)
        .with_response("8.8.8.8#aaaa", response_aaaa);
    let mut upstream = NetworkDnsUpstream::new(SequencedTransport::new(transport));
    let result = upstream.resolve(&["8.8.8.8".into()], "example.com").unwrap();
    assert_eq!(result, vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]);
}

#[test]
fn system_dns_packet_transport_supports_tcp_nameservers() {
    let query_a = build_dns_query("example.com", DnsRecordType::A, 1).unwrap();
    let query_aaaa = build_dns_query("example.com", DnsRecordType::Aaaa, 2).unwrap();
    let response_a = [
        vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ],
        query_a[12..].to_vec(),
        vec![
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 9, 9, 9, 9,
        ],
    ]
    .concat();
    let response_aaaa = [
        vec![
            0x00, 0x02, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        query_aaaa[12..].to_vec(),
    ]
    .concat();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        for response in [response_a, response_aaaa] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut header = [0_u8; 2];
            stream.read_exact(&mut header).unwrap();
            let length = u16::from_be_bytes(header) as usize;
            let mut body = vec![0_u8; length];
            stream.read_exact(&mut body).unwrap();
            let response_len = u16::try_from(response.len()).unwrap();
            stream.write_all(&response_len.to_be_bytes()).unwrap();
            stream.write_all(&response).unwrap();
            stream.flush().unwrap();
        }
    });

    let mut upstream = NetworkDnsUpstream::new(super::SystemDnsPacketTransport);
    let result = upstream
        .resolve(&[format!("tcp://{}", addr)], "example.com")
        .unwrap();
    assert_eq!(result, vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
    worker.join().unwrap();
}

#[test]
fn system_dns_packet_transport_supports_system_nameserver_alias() {
    let mut upstream = NetworkDnsUpstream::new(super::SystemDnsPacketTransport);
    let result = upstream.resolve(&["system://".into()], "localhost").unwrap();
    assert!(!result.is_empty());
    assert!(result.iter().all(IpAddr::is_loopback), "{result:?}");
}

#[test]
fn system_dns_packet_transport_supports_tls_nameservers() {
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    register_test_root_certificate(&cert.cert.pem()).unwrap();

    let certs = vec![Certificate(cert.cert.der().to_vec())];
    let key = PrivateKey(cert.key_pair.serialize_der());
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    );

    let query_a = build_dns_query("example.com", DnsRecordType::A, 1).unwrap();
    let query_aaaa = build_dns_query("example.com", DnsRecordType::Aaaa, 2).unwrap();
    let response_a = [
        vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ],
        query_a[12..].to_vec(),
        vec![
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 6, 6, 6, 6,
        ],
    ]
    .concat();
    let response_aaaa = [
        vec![
            0x00, 0x02, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        query_aaaa[12..].to_vec(),
    ]
    .concat();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        for response in [response_a, response_aaaa] {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(Arc::clone(&server_config)).unwrap();
            let mut tls = StreamOwned::new(conn, stream);
            let mut header = [0_u8; 2];
            tls.read_exact(&mut header).unwrap();
            let length = u16::from_be_bytes(header) as usize;
            let mut body = vec![0_u8; length];
            tls.read_exact(&mut body).unwrap();
            let response_len = u16::try_from(response.len()).unwrap();
            tls.write_all(&response_len.to_be_bytes()).unwrap();
            tls.write_all(&response).unwrap();
            tls.flush().unwrap();
        }
    });

    let mut upstream = NetworkDnsUpstream::new(super::SystemDnsPacketTransport);
    let result = upstream
        .resolve(&[format!("tls://localhost:{}", addr.port())], "example.com")
        .unwrap();
    assert_eq!(result, vec![IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6))]);
    worker.join().unwrap();
}

#[test]
fn system_dns_packet_transport_supports_http_nameservers() {
    let query_a = build_dns_query("example.com", DnsRecordType::A, 1).unwrap();
    let query_aaaa = build_dns_query("example.com", DnsRecordType::Aaaa, 2).unwrap();
    let response_a = [
        vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ],
        query_a[12..].to_vec(),
        vec![
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 5, 5, 5, 5,
        ],
    ]
    .concat();
    let response_aaaa = [
        vec![
            0x00, 0x02, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        query_aaaa[12..].to_vec(),
    ]
    .concat();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        for response in [response_a, response_aaaa] {
            let (mut stream, _) = listener.accept().unwrap();
            let body = read_http_request_body(&mut stream);
            assert!(!body.is_empty());
            write_http_response(&mut stream, &response);
        }
    });

    let mut upstream = NetworkDnsUpstream::new(super::SystemDnsPacketTransport);
    let result = upstream
        .resolve(&[format!("http://127.0.0.1:{}/dns-query", addr.port())], "example.com")
        .unwrap();
    assert_eq!(result, vec![IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5))]);
    worker.join().unwrap();
}

#[test]
fn system_dns_packet_transport_supports_https_nameservers() {
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    register_test_root_certificate(&cert.cert.pem()).unwrap();

    let certs = vec![Certificate(cert.cert.der().to_vec())];
    let key = PrivateKey(cert.key_pair.serialize_der());
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    );

    let query_a = build_dns_query("example.com", DnsRecordType::A, 1).unwrap();
    let query_aaaa = build_dns_query("example.com", DnsRecordType::Aaaa, 2).unwrap();
    let response_a = [
        vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ],
        query_a[12..].to_vec(),
        vec![
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 4, 4, 4, 4,
        ],
    ]
    .concat();
    let response_aaaa = [
        vec![
            0x00, 0x02, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        query_aaaa[12..].to_vec(),
    ]
    .concat();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        for response in [response_a, response_aaaa] {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(Arc::clone(&server_config)).unwrap();
            let mut tls = StreamOwned::new(conn, stream);
            let body = read_http_request_body(&mut tls);
            assert!(!body.is_empty());
            write_http_response(&mut tls, &response);
        }
    });

    let mut upstream = NetworkDnsUpstream::new(super::SystemDnsPacketTransport);
    let result = upstream
        .resolve(&[format!("https://localhost:{}/dns-query", addr.port())], "example.com")
        .unwrap();
    assert_eq!(result, vec![IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4))]);
    worker.join().unwrap();
}

#[test]
fn system_dns_packet_transport_supports_rcode_nameservers() {
    let query = build_dns_query("example.com", DnsRecordType::A, 0x2222).unwrap();
    let response = super::SystemDnsPacketTransport
        .exchange("rcode://refused", &query)
        .unwrap();
    assert!(response.len() >= 12);
    assert_eq!(response[0], 0x22);
    assert_eq!(response[1], 0x22);
    assert_eq!(response[3] & 0x0F, 5);
    assert_eq!(response[6], 0);
    assert_eq!(response[7], 0);
}

#[test]
fn system_dns_packet_transport_supports_quic_nameservers() {
    let _ = aws_lc_rs::default_provider().install_default();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    register_test_root_certificate(&cert.cert.pem()).unwrap();
    let certs = vec![CertificateDer::from(cert.cert.der().to_vec())];
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into();
    let mut server_crypto = rustls023::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    server_crypto.alpn_protocols = vec![b"doq".to_vec()];
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
    ));
    let transport = Arc::get_mut(&mut server_config.transport).unwrap();
    transport.max_concurrent_bidi_streams(8u32.into());

    let query_a = build_dns_query("example.com", DnsRecordType::A, 1).unwrap();
    let query_aaaa = build_dns_query("example.com", DnsRecordType::Aaaa, 2).unwrap();
    let response_a = [
        vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ],
        query_a[12..].to_vec(),
        vec![
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 3, 3, 3, 3,
        ],
    ]
    .concat();
    let response_aaaa = [
        vec![
            0x00, 0x02, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        query_aaaa[12..].to_vec(),
    ]
    .concat();

    let (addr_tx, addr_rx) = std::sync::mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async move {
            let server = Endpoint::server(
                server_config,
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            )
            .unwrap();
            addr_tx.send(server.local_addr().unwrap()).unwrap();
            for response in [response_a, response_aaaa] {
                let incoming = server.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                let mut header = [0_u8; 2];
                recv.read_exact(&mut header).await.unwrap();
                let length = u16::from_be_bytes(header) as usize;
                let mut body = vec![0_u8; length];
                recv.read_exact(&mut body).await.unwrap();
                let response_len = u16::try_from(response.len()).unwrap();
                send.write_all(&response_len.to_be_bytes()).await.unwrap();
                send.write_all(&response).await.unwrap();
                send.finish().unwrap();
                let _ = send.stopped().await;
            }
        });
    });
    let addr = addr_rx.recv().unwrap();

    let mut upstream = NetworkDnsUpstream::new(super::SystemDnsPacketTransport);
    let result = upstream
        .resolve(&[format!("quic://localhost:{}", addr.port())], "example.com")
        .unwrap();
    assert_eq!(result, vec![IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3))]);
    worker.join().unwrap();
}

#[test]
fn invalid_fake_ip_range_is_reported() {
    let document = parse_runtime_config_document(
        r#"
dns:
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/99
"#,
    )
    .unwrap();
    assert!(DnsRuntime::from_document(&document).is_err());
}

fn unique_temp_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("mihomo-dns-{nanos}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

struct SequencedTransport {
    transport: FakePacketTransport,
    counts: HashMap<String, usize>,
}

impl SequencedTransport {
    fn new(transport: FakePacketTransport) -> Self {
        Self {
            transport,
            counts: HashMap::new(),
        }
    }
}

impl DnsPacketTransport for SequencedTransport {
    fn exchange(&mut self, server: &str, _payload: &[u8]) -> Result<Vec<u8>, super::DnsError> {
        let count = self.counts.entry(server.to_owned()).or_insert(0);
        *count += 1;
        let key = if *count == 1 {
            server.to_owned()
        } else {
            format!("{server}#aaaa")
        };
        self.transport.exchange(&key, &[])
    }
}

fn read_http_request_body(stream: &mut dyn Read) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buf = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buf).unwrap();
        assert!(read > 0);
        request.extend_from_slice(&buf[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    let header_text = String::from_utf8_lossy(&request[..header_end]);
    let content_length = header_text
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
        })
        .unwrap_or(0);
    while request.len() < header_end + content_length {
        let read = stream.read(&mut buf).unwrap();
        assert!(read > 0);
        request.extend_from_slice(&buf[..read]);
    }
    request[header_end..header_end + content_length].to_vec()
}

fn write_http_response(stream: &mut dyn Write, body: &[u8]) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();
}

#[test]
fn https_query_upstream_failure_is_not_a_successful_empty_answer() {
    struct Failed;
    impl DnsUpstream for Failed {
        fn resolve(&mut self, _: &[String], _: &str) -> Result<Vec<IpAddr>, super::DnsError> { Ok(vec![]) }
    }
    let document = parse_runtime_config_document("dns:\n  enable: true\n  nameserver: [127.0.0.1:1]\n").unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    let query = build_dns_query("failure.test", DnsRecordType::Other(65), 7).unwrap();
    assert!(runtime.handle_query_packet(&query, &mut Failed).is_err());
    let response = super::build_servfail_response(&query).unwrap();
    assert_eq!(response[3] & 15, 2);
    assert_eq!(&response[12..], &query[12..]);
}

#[test]
fn wire_exchange_rejects_wrong_question_and_tries_next_configured_server() {
    let query = build_dns_query("service.test", DnsRecordType::Other(65), 9).unwrap();
    let mut valid = query.clone(); valid[2] |= 0x80;
    let mut wrong = valid.clone(); wrong[1] = 8;
    let transport = FakePacketTransport::default().with_response("first", wrong).with_response("second", valid.clone());
    let mut upstream = NetworkDnsUpstream::new(transport);
    let actual = upstream.exchange(&["first".into(), "second".into()], &query).unwrap();
    assert_eq!(actual, valid);
    assert_eq!(upstream.transport().calls, ["first", "second"]);
}

#[test]
fn cloned_resolver_shares_storage_but_keeps_fake_ip_and_cache_mutations_isolated(){
    let document=parse_runtime_config_document("dns:\n  enable: true\n  enhanced-mode: fake-ip\n  cache-size: 2\n").unwrap();
    let mut original=DnsRuntime::from_document(&document).unwrap();
    let first=original.resolve_host("one.test").unwrap().unwrap();
    original.store_cached_answer("one.real".into(),super::CachedAnswer{ips:vec!["1.2.3.4".parse().unwrap()],servers:vec![]});
    let mut cloned=original.clone();
    assert!(Arc::ptr_eq(&original.hosts,&cloned.hosts));
    assert!(Arc::ptr_eq(&original.cache,&cloned.cache));
    let second=cloned.resolve_host("two.test").unwrap().unwrap();
    assert_ne!(first,second);assert_eq!(original.reverse_lookup(first),Some("one.test"));assert_eq!(original.reverse_lookup(second),None);
    cloned.clear_cache();assert!(original.cached_answer("one.real").is_some());assert!(cloned.cached_answer("one.real").is_none());
    original.flush_fake_ip();assert_eq!(cloned.reverse_lookup(first),Some("one.test"));
}

#[test]
fn dns_cache_capacity_is_enforced_during_insertion_and_merge(){
    let document=parse_runtime_config_document("dns:\n  enable: true\n  cache-size: 2\n").unwrap();let mut runtime=DnsRuntime::from_document(&document).unwrap();
    let answer=super::CachedAnswer{ips:vec!["1.2.3.4".parse().unwrap()],servers:vec![]};
    runtime.store_cached_answer("first".into(),answer.clone());runtime.store_cached_answer("second".into(),answer.clone());
    let mut clone=runtime.clone();clone.store_cached_answer("third".into(),answer.clone());
    assert_eq!(clone.cache.len(),2);assert!(clone.cached_answer("first").is_none());assert!(runtime.cached_answer("first").is_some());
    runtime.merge_cache_from(&clone);assert_eq!(runtime.cache.len(),2);assert!(runtime.cached_answer("third").is_some());
    runtime.clear_cache();assert!(runtime.cache.is_empty());assert!(runtime.cache_order.is_empty());
}
