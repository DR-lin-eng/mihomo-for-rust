use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::{
    DnsError, DnsPacketTransport, DnsRecordType, DnsRuntime, DnsUpstream, NetworkDnsUpstream,
};

#[derive(Clone, Default)]
struct Resolver {
    calls: Arc<Mutex<Vec<(String, u16)>>>,
}
impl DnsPacketTransport for Resolver {
    fn fork(&self) -> Option<Box<dyn DnsPacketTransport + Send>> {
        Some(Box::new(self.clone()))
    }
    fn exchange(&mut self, server: &str, packet: &[u8]) -> Result<Vec<u8>, DnsError> {
        let query = crate::packet::parse_dns_query_packet(packet)?;
        self.calls
            .lock()
            .unwrap()
            .push((server.into(), query.query_type.code()));
        match server {
            "slow" => std::thread::sleep(Duration::from_millis(500)),
            "broken" => return Err(DnsError::Io("fixture unavailable".into())),
            _ => {}
        }
        if query.query_type == DnsRecordType::Aaaa && server == "ipv4-only" {
            return Err(DnsError::Io("AAAA timed out".into()));
        }
        let ips: Vec<IpAddr> = if query.query_type == DnsRecordType::A {
            vec!["203.0.113.20".parse().unwrap()]
        } else {
            Vec::new()
        };
        let mut response = crate::packet::build_dns_response(&query, 60, &ips);
        if server == "servfail" {
            response[3] = (response[3] & 0xf0) | 2;
        }
        if server == "nxdomain" {
            response[3] = (response[3] & 0xf0) | 3;
        }
        Ok(response)
    }
}

#[test]
fn ipv4_only_resolution_does_not_query_aaaa() {
    let document = mihomo_config::parse_runtime_config_document(
        "dns:\n  enable: true\n  ipv6: false\n  enhanced-mode: fake-ip\n  nameserver: [ipv4-only]\n"
    ).unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    let transport = Resolver::default();
    let calls = transport.calls.clone();
    let mut upstream = NetworkDnsUpstream::new(transport);
    assert_eq!(
        runtime
            .resolve_host_addrs_with_upstream("cold.test", &mut upstream)
            .unwrap(),
        vec!["203.0.113.20".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(*calls.lock().unwrap(), [("ipv4-only".into(), 1)]);
}

#[test]
fn dual_stack_resolution_keeps_a_when_aaaa_fails() {
    let mut upstream = NetworkDnsUpstream::new(Resolver::default());
    assert_eq!(
        upstream
            .resolve(&["ipv4-only".into()], "cold.test")
            .unwrap(),
        vec!["203.0.113.20".parse::<IpAddr>().unwrap()]
    );
}

#[test]
fn healthy_second_resolver_does_not_wait_for_slow_first() {
    let mut upstream = NetworkDnsUpstream::new(Resolver::default());
    let started = Instant::now();
    let ips = upstream
        .resolve_for_type(
            &["slow".into(), "fast".into()],
            "cold.test",
            DnsRecordType::A,
        )
        .unwrap();
    assert_eq!(ips.len(), 1);
    assert!(started.elapsed() < Duration::from_millis(300));
}

#[test]
fn servfail_is_retried_but_nxdomain_and_explicit_rcode_are_preserved() {
    let packet = crate::packet::build_dns_query("cold.test", DnsRecordType::Other(65), 9).unwrap();
    let mut upstream = NetworkDnsUpstream::new(Resolver::default());
    assert_eq!(
        upstream
            .exchange(&["servfail".into(), "fast".into()], &packet)
            .unwrap()[3]
            & 15,
        0
    );
    assert_eq!(
        upstream.exchange(&["nxdomain".into()], &packet).unwrap()[3] & 15,
        3
    );
    let mut system = NetworkDnsUpstream::new(crate::SystemDnsPacketTransport);
    assert_eq!(
        system
            .exchange(
                &["rcode://refused".into(), "rcode://success".into()],
                &packet
            )
            .unwrap()[3]
            & 15,
        5
    );
}

#[test]
fn upstream_transport_error_can_use_configured_fallback() {
    let document = mihomo_config::parse_runtime_config_document(
        "dns:\n  enable: true\n  ipv6: false\n  nameserver: [broken]\n  fallback: [fast]\n",
    )
    .unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    let mut upstream = NetworkDnsUpstream::new(Resolver::default());
    assert!(runtime
        .resolve_host_with_upstream("cold.test", &mut upstream)
        .unwrap()
        .is_some());
}

#[derive(Default)]
struct EmptyPrimaryRawFallback {
    calls: Vec<Vec<String>>,
    primary_rcode: u8,
    fail_fallback: bool,
}

impl DnsUpstream for EmptyPrimaryRawFallback {
    fn resolve(&mut self, _servers: &[String], _host: &str) -> Result<Vec<IpAddr>, DnsError> {
        Ok(Vec::new())
    }

    fn exchange(&mut self, servers: &[String], packet: &[u8]) -> Result<Vec<u8>, DnsError> {
        self.calls.push(servers.to_vec());
        let query = crate::packet::parse_dns_query_packet(packet)?;
        let fallback = servers.iter().any(|server| server == "fallback");
        if fallback && self.fail_fallback {
            return Err(DnsError::Io("fallback unavailable".into()));
        }
        let ips = if fallback {
            vec![match query.query_type {
                DnsRecordType::Aaaa => "2001:db8::42".parse().unwrap(),
                _ => "203.0.113.42".parse().unwrap(),
            }]
        } else {
            Vec::new()
        };
        let mut response = crate::packet::build_dns_response(&query, 37, &ips);
        response[3] |= if fallback { 0x20 } else { self.primary_rcode };
        Ok(response)
    }
}

#[test]
fn redir_host_empty_primary_answer_uses_fallback_on_cold_lookup() {
    let document = mihomo_config::parse_runtime_config_document(
        "dns:\n  enable: true\n  ipv6: false\n  enhanced-mode: redir-host\n  nameserver: [primary]\n  fallback: [fallback]\n",
    )
    .unwrap();
    for kind in [DnsRecordType::A, DnsRecordType::Aaaa] {
        for rcode in [0, 3] {
            let mut runtime = DnsRuntime::from_document(&document).unwrap();
            let mut upstream = EmptyPrimaryRawFallback {
                primary_rcode: rcode,
                ..Default::default()
            };
            let query = crate::packet::build_dns_query("cold-redir.test", kind, 17).unwrap();
            let mut expected_upstream = EmptyPrimaryRawFallback::default();
            let expected = expected_upstream
                .exchange(&["fallback".into()], &query)
                .unwrap();
            let response = runtime
                .exchange_query_packet(&query, &mut upstream)
                .unwrap();
            assert_eq!(response, expected, "record {kind:?}, primary rcode {rcode}");
            let ips = crate::packet::parse_dns_response(&response, 17, kind).unwrap();
            assert_eq!(ips.len(), 1);
            assert_eq!(
                runtime.domain_for_ip(ips[0]).as_deref(),
                Some("cold-redir.test")
            );
            assert_eq!(
                upstream.calls,
                vec![vec!["primary".to_owned()], vec!["fallback".to_owned()]]
            );
        }
    }
}

#[test]
fn redir_host_negative_and_non_address_replies_keep_wire_bytes_without_fallback() {
    for kind in [
        DnsRecordType::A,
        DnsRecordType::Aaaa,
        DnsRecordType::Other(65),
        DnsRecordType::Other(16),
    ] {
        for rcode in [0, 3] {
            let extra = if matches!(kind, DnsRecordType::Other(_)) {
                "  fallback: [fallback]\n"
            } else {
                ""
            };
            let document = mihomo_config::parse_runtime_config_document(&format!(
                "dns:\n  enable: true\n  enhanced-mode: redir-host\n  nameserver: [primary]\n{extra}"
            )).unwrap();
            let mut runtime = DnsRuntime::from_document(&document).unwrap();
            let mut upstream = EmptyPrimaryRawFallback {
                primary_rcode: rcode,
                ..Default::default()
            };
            let query = crate::packet::build_dns_query("negative.test", kind, 99).unwrap();
            let mut expected = crate::packet::build_dns_response(
                &crate::packet::parse_dns_query_packet(&query).unwrap(),
                37,
                &[],
            );
            expected[3] |= rcode;
            assert_eq!(
                runtime
                    .exchange_query_packet(&query, &mut upstream)
                    .unwrap(),
                expected
            );
            assert_eq!(upstream.calls, vec![vec!["primary".to_owned()]]);
        }
    }
}

#[test]
fn redir_host_nameserver_policy_keeps_precedence_over_fallback() {
    let document = mihomo_config::parse_runtime_config_document(
        "dns:\n  enable: true\n  enhanced-mode: redir-host\n  nameserver: [primary]\n  fallback: [fallback]\n  fallback-filter:\n    domain: ['+.internal.test']\n  nameserver-policy:\n    '+.internal.test': [private]\n"
    ).unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    let query =
        crate::packet::build_dns_query("service.internal.test", DnsRecordType::A, 17).unwrap();
    let mut upstream = EmptyPrimaryRawFallback::default();
    let response = runtime
        .exchange_query_packet(&query, &mut upstream)
        .unwrap();
    assert_eq!(response[6..8], [0, 0]);
    assert_eq!(upstream.calls, vec![vec!["private".to_owned()]]);
}

#[test]
fn redir_host_explicit_rcode_policy_is_not_overridden_by_fallback() {
    for policy in ["success", "name_error", "refused"] {
        let document = mihomo_config::parse_runtime_config_document(&format!(
            "dns:\n  enable: true\n  enhanced-mode: redir-host\n  nameserver: ['rcode://{policy}']\n  fallback: ['rcode://success']\n"
        )).unwrap();
        let mut runtime = DnsRuntime::from_document(&document).unwrap();
        let query = crate::packet::build_dns_query("blocked.test", DnsRecordType::A, 17).unwrap();
        let mut upstream = NetworkDnsUpstream::new(crate::SystemDnsPacketTransport);
        let expected = upstream
            .exchange(&[format!("rcode://{policy}")], &query)
            .unwrap();
        assert_eq!(
            runtime
                .exchange_query_packet(&query, &mut upstream)
                .unwrap(),
            expected
        );
    }
}

#[test]
fn redir_host_failed_fallback_is_not_fabricated_as_successful_empty_answer() {
    let document = mihomo_config::parse_runtime_config_document(
        "dns:\n  enable: true\n  enhanced-mode: redir-host\n  nameserver: [primary]\n  fallback: [fallback]\n"
    ).unwrap();
    let mut runtime = DnsRuntime::from_document(&document).unwrap();
    let mut upstream = EmptyPrimaryRawFallback {
        fail_fallback: true,
        ..Default::default()
    };
    let query = crate::packet::build_dns_query("failure.test", DnsRecordType::A, 17).unwrap();
    assert!(runtime
        .exchange_query_packet(&query, &mut upstream)
        .is_err());
    assert_eq!(runtime.domain_for_ip("203.0.113.42".parse().unwrap()), None);
}
