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
