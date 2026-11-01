use super::*;
use advanced::{pair, AdvancedState, ExitInfo};
use response::{Action, Headers};
const NOW: u64 = 1800000000;
fn headers(values: &[(&str, &str)]) -> Headers {
    values
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn response_classification_preserves_challenge_rate_region_and_redirect_order() {
    let cases = [
        (200, vec![], "Hello", Action::Reachable, "answered", 0, true),
        (
            200,
            vec![],
            "This service is not available in your country",
            Action::Record,
            "region unavailable",
            1800,
            false,
        ),
        (
            403,
            vec![("cf-mitigated", "challenge")],
            "region unavailable",
            Action::Record,
            "challenge",
            600,
            false,
        ),
        (
            403,
            vec![("x-amzn-waf-action", "captcha")],
            "",
            Action::Record,
            "challenge",
            600,
            false,
        ),
        (403, vec![], "", Action::Record, "forbidden", 600, false),
        (
            451,
            vec![],
            "",
            Action::Record,
            "unavailable for legal reasons",
            1800,
            false,
        ),
        (
            302,
            vec![("location", "https://login.example.com/")],
            "",
            Action::Ignore,
            "redirect",
            0,
            false,
        ),
        (
            302,
            vec![("location", "/welcome/unavailable")],
            "",
            Action::Record,
            "region unavailable",
            1800,
            false,
        ),
        (
            429,
            vec![("retry-after", "1")],
            "",
            Action::Record,
            "rate limited",
            60,
            false,
        ),
        (
            429,
            vec![("retry-after", "9999")],
            "",
            Action::Record,
            "rate limited",
            1800,
            false,
        ),
        (
            403,
            vec![("x-ratelimit-remaining", "0")],
            "",
            Action::Record,
            "rate limited",
            600,
            false,
        ),
        (
            200,
            vec![("x-ratelimit-remaining", "0")],
            "",
            Action::Record,
            "quota exhausted",
            600,
            false,
        ),
        (
            503,
            vec![("retry-after", "120")],
            "cf-error-details",
            Action::Record,
            "overloaded",
            120,
            false,
        ),
        (
            502,
            vec![],
            "cf-error-details",
            Action::Record,
            "edge error",
            300,
            false,
        ),
        (
            503,
            vec![],
            "server broken",
            Action::Record,
            "origin error",
            300,
            false,
        ),
        (
            405,
            vec![],
            "",
            Action::Ignore,
            "method not allowed",
            0,
            false,
        ),
        (
            501,
            vec![],
            "",
            Action::Ignore,
            "method not allowed",
            0,
            false,
        ),
        (
            421,
            vec![],
            "",
            Action::Ignore,
            "misdirected request",
            0,
            false,
        ),
        (404, vec![], "", Action::Reachable, "answered", 0, false),
    ];
    for (status, head, body, action, reason, ttl, control) in cases {
        let actual = response::classify(status, &headers(&head), body.as_bytes(), NOW);
        assert_eq!(
            (
                actual.action,
                actual.reason,
                actual.ttl,
                actual.control_success
            ),
            (action, reason.into(), ttl, control),
            "HTTP {status}: {body}"
        );
    }
}
#[test]
fn retry_dates_and_tls_errors_remain_distinct() {
    let date = httpdate::fmt_http_date(UNIX_EPOCH + std::time::Duration::from_secs(NOW + 245));
    assert_eq!(
        response::classify(429, &headers(&[("retry-after", &date)]), b"", NOW).ttl,
        245
    );
    let reset = (NOW + 400).to_string();
    assert_eq!(
        response::classify(429, &headers(&[("x-ratelimit-reset", &reset)]), b"", NOW).ttl,
        400
    );
    assert_eq!(
        response::classify_error("invalid peer certificate: UnknownIssuer", false).reason,
        "unknown certificate authority"
    );
    assert_eq!(
        response::classify_error("invalid peer certificate: NotValidForName", false).reason,
        "certificate hostname mismatch"
    );
    assert_eq!(response::classify_error("network timeout", true).ttl, 300);
    let other = response::classify_error("connection reset by peer", false);
    assert_eq!(other.action, Action::Ignore);
    assert!(other.unproven);
}
fn exit(region: &str, key: &str) -> ExitInfo {
    ExitInfo {
        region: region.into(),
        asn: if region == "US" { "111" } else { "222" }.into(),
        key: key.into(),
        updated: NOW,
        ..Default::default()
    }
}
fn record(state: &mut AdvancedState, node: &str, status: u16) {
    state.apply_verdict(
        "target.test",
        node,
        status,
        response::classify(status, &Headers::new(), b"", NOW),
        true,
        NOW,
    );
}
#[test]
fn regional_suspicion_requires_independent_exits_and_a_cross_region_control() {
    let mut state = AdvancedState::default();
    state.exits.insert("a".into(), exit("US", "ip-a"));
    state.exits.insert("b".into(), exit("US", "ip-a"));
    state.exits.insert("c".into(), exit("JP", "ip-c"));
    state.exits.insert("d".into(), exit("US", "ip-d"));
    record(&mut state, "a", 403);
    record(&mut state, "b", 403);
    assert!(state.suspects.is_empty());
    record(&mut state, "c", 200);
    assert!(
        state.suspects.is_empty(),
        "two node names sharing an IP are one exit"
    );
    state.exits.insert("b".into(), exit("US", "ip-b"));
    state.confirm("target.test", true, NOW);
    assert!(state.suspected("target.test", "d", true, NOW));
    assert!(!state.suspected("other.test", "d", true, NOW));
    assert!(!state.suspected("target.test", "c", true, NOW));
    assert!(!state.suspected("target.test", "d", true, NOW + 1801));
    record(&mut state, "d", 200);
    assert!(!state.suspected("target.test", "d", true, NOW));
}
#[test]
fn challenge_or_redirect_does_not_create_regional_evidence() {
    let mut state = AdvancedState::default();
    for (node, region) in [("a", "US"), ("b", "US"), ("c", "JP")] {
        state.exits.insert(node.into(), exit(region, node));
    }
    let challenge = response::classify(403, &headers(&[("cf-mitigated", "challenge")]), b"", NOW);
    for node in ["a", "b"] {
        state.apply_verdict("target.test", node, 403, challenge.clone(), true, NOW);
    }
    record(&mut state, "c", 200);
    assert!(state.suspects.is_empty());
    let before = state.probes[&pair("target.test", "a")].clone();
    state.apply_verdict(
        "target.test",
        "a",
        302,
        response::classify(302, &Headers::new(), b"", NOW),
        true,
        NOW,
    );
    assert_eq!(
        state.probes[&pair("target.test", "a")],
        before,
        "generic redirect neither sets nor clears a refusal"
    );
}
#[test]
fn target_trace_overrides_global_and_expired_metadata_is_unknown() {
    let mut state = AdvancedState::default();
    state.exits.insert("a".into(), exit("US", "one"));
    state
        .target_exits
        .insert(pair("target.test", "a"), exit("JP", "two"));
    assert_eq!(state.exit("target.test", "a", NOW).unwrap().region, "JP");
    assert_eq!(state.exit("other.test", "a", NOW).unwrap().region, "US");
    assert!(state.exit("target.test", "a", NOW + 21601).is_none());
}

#[test]
fn unknown_control_region_cannot_confirm_a_region_block() {
    let mut state = AdvancedState::default();
    state.exits.insert("a".into(), exit("US", "a"));
    state.exits.insert("b".into(), exit("US", "b"));
    state.exits.insert("control".into(), exit("", "control"));
    record(&mut state, "a", 403);
    record(&mut state, "b", 403);
    record(&mut state, "control", 200);
    assert!(!state.suspects.contains_key("target.test\u{1f}region:US"));
}
#[test]
fn probes_and_half_open_leases_are_bounded_and_back_off() {
    let mut state = AdvancedState::default();
    assert!(state.allow_probe("t", "n", NOW));
    assert!(!state.allow_probe("t", "n", NOW + 119));
    assert!(state.allow_probe("t", "n", NOW + 120));
    for n in 0..6 {
        assert!(state.allow_probe("limited", &n.to_string(), NOW));
    }
    assert!(!state.allow_probe("limited", "seventh", NOW));
    assert!(state.allow_probe("limited", "seventh", NOW + 60));
    let candidates = vec![ProxyCandidate {
        name: "a".into(),
        alive: true,
        last_delay_ms: 0,
        supports_udp: true,
    }];
    let meta = Metadata {
        host: Some("half.test".into()),
        ..Default::default()
    };
    assert_eq!(
        state.half_open_candidate(&meta, &candidates, NOW),
        Some("a".into())
    );
    assert!(state
        .half_open_candidate(&meta, &candidates, NOW + 1)
        .is_none());
    assert!(state
        .half_open_candidate(&meta, &candidates, NOW + 31)
        .is_some());
    for node in ["a", "b", "c"] {
        record(&mut state, node, 403);
    }
    assert!(!state.allow_probe("target.test", "d", NOW + 1));
    assert!(state.allow_probe("target.test", "d", NOW + 1801));
}
#[test]
fn unknown_exit_data_is_not_fabricated_and_raw_exit_ip_is_not_saved() {
    let parsed = probe::parse_exit(b"ip=203.0.113.8\nloc=US\n", None, NOW).unwrap();
    assert_eq!(parsed.region, "US");
    assert_eq!(parsed.key.len(), 12);
    assert!(!serde_json::to_string(&parsed)
        .unwrap()
        .contains("203.0.113.8"));
    assert!(probe::parse_exit(b"loc=US\n", None, NOW).is_none());
    assert!(probe::parse_exit(b"<html>captcha</html>", None, NOW).is_none());
    let parsed = probe::parse_exit(
        br#"{"ip":"2001:db8::5","country_code":"jp","connection":{"asn":1234}}"#,
        None,
        NOW,
    )
    .unwrap();
    assert_eq!(
        (parsed.region.as_str(), parsed.asn.as_str()),
        ("JP", "1234")
    );
}
#[test]
fn service_keys_use_public_suffixes_and_do_not_claim_shared_or_ambiguous_asns() {
    assert_eq!(target::site("a.b.example.co.uk", ""), "*.b.example.co.uk");
    assert_eq!(
        target::site("a.deadbeef.example.co.uk", ""),
        "*.example.co.uk"
    );
    let mut evidence = BTreeMap::<String, BTreeMap<String, u32>>::new();
    let mut meta = Metadata {
        host: Some("www.example.com".into()),
        dst_ip_asn: "AS1234 service".into(),
        smart_rule: Some(("RuleSet [media]".into(), 25)),
        ..Default::default()
    };
    assert_eq!(target::key(true, &meta, &evidence), "RuleSet [media]");
    meta.smart_rule = Some(("RuleSet [category-media]".into(), 25));
    assert_eq!(target::key(true, &meta, &evidence), "asn:1234");
    meta.dst_ip_asn = "AS13335 Cloudflare".into();
    assert_eq!(target::key(true, &meta, &evidence), "*.example.com");
    evidence.insert(
        "RuleSet [media]".into(),
        BTreeMap::from([("1234".into(), 4)]),
    );
    meta.dst_ip_asn = "AS1234 service".into();
    assert_eq!(target::key(true, &meta, &evidence), "RuleSet [media]");
    evidence.insert(
        "RuleSet [other]".into(),
        BTreeMap::from([("1234".into(), 4)]),
    );
    assert_eq!(target::key(true, &meta, &evidence), "asn:1234");
    meta.smart_rule = Some(("RuleSet [provider]".into(), 10000));
    assert_eq!(target::key(true, &meta, &evidence), "asn:1234");
}
#[test]
fn loss_windows_accumulate_and_do_not_reconsume_or_invent_samples() {
    let mut loss = loss::LossSampler::default();
    let sample = |sent, retrans| {
        Some(mihomo_core::TcpStats {
            segments_out: sent,
            retransmissions: retrans,
            rtt_us: 1000,
        })
    };
    loss.sample(None);
    assert_eq!(loss.windows, 0);
    loss.sample(sample(63, 10));
    assert_eq!(loss.windows, 0);
    loss.sample(sample(64, 10));
    assert_eq!(
        (loss.windows, loss.segments, loss.retransmissions),
        (1, 64, 10)
    );
    loss.sample(sample(64, 10));
    assert_eq!(loss.windows, 1);
    loss.sample(sample(120, 10));
    assert_eq!(loss.windows, 1);
    loss.sample(sample(128, 10));
    assert_eq!(
        (loss.windows, loss.segments, loss.retransmissions),
        (2, 128, 10)
    );
    loss.sample(sample(1, 0));
    loss.sample(sample(64, 0));
    assert_eq!(loss.windows, 3, "source counter reset opens a fresh window");
}
#[test]
fn loss_exclusion_requires_repeated_measured_evidence() {
    let def = mihomo_outbound::parse_group_yaml("name: smart\ntype: smart\n").unwrap();
    let mut smart = SmartGroup::new(&def);
    let meta = Metadata::default();
    let observation = Observation {
        success: true,
        tcp_segments: 64,
        tcp_retransmissions: 10,
        tcp_loss_windows: 1,
        tcp_loss_ema: 0.15,
        tcp_loss_strikes: 1,
        tcp_loss_last: 0.15,
        ..Default::default()
    };
    smart.observe("smart", "a", &meta, &observation);
    let key = smart.record_key(&meta, "a");
    assert_eq!(smart.state.records[&key].loss_block_until, 0);
    smart.observe(
        "smart",
        "a",
        &meta,
        &Observation {
            success: true,
            ..Default::default()
        },
    );
    assert_eq!(
        smart.state.records[&key].loss_block_until, 0,
        "missing TCP_INFO is not another strike"
    );
    smart.observe("smart", "a", &meta, &observation);
    assert!(smart.state.records[&key].loss_block_until > now_seconds());
}
#[test]
fn legacy_cache_loads_and_flush_invalidates_queued_probes() {
    let old = r#"{"nodes":{},"records":{},"selections":1,"observations":2,"last_used":3}"#;
    let state: SmartState = serde_json::from_str(old).unwrap();
    assert_eq!(state.observations, 2);
    assert!(state.advanced.exits.is_empty());
    let runtime = advanced::AdvancedRuntime::default();
    let generation = runtime
        .generation
        .load(std::sync::atomic::Ordering::Acquire);
    runtime.invalidate();
    assert_ne!(
        generation,
        runtime
            .generation
            .load(std::sync::atomic::Ordering::Acquire)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn actual_tcp_info_reads_the_physical_socket() {
    use mihomo_core::TcpStream;
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut data = vec![0u8; 1024 * 1024];
        stream.read_exact(&mut data).unwrap();
        stream.write_all(b"ok").unwrap();
    });
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    stream.write_all(&vec![1; 1024 * 1024]).unwrap();
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).unwrap();
    let stats = stream.tcp_stats().expect("modern Linux supplies TCP_INFO");
    assert!(stats.segments_out > 0);
    assert!(stats.retransmissions <= stats.segments_out);
    server.join().unwrap();
}

#[test]
fn smart_protocol_deadline_closes_a_stalled_connect_socket() {
    use std::io::Read;
    use std::time::{Duration, Instant};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let start = Instant::now();
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && start.elapsed() < Duration::from_secs(3) =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(e) => panic!("accept: {e}"),
            }
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        socket
            .read_to_end(&mut request)
            .expect("cancelled underlay closes");
        assert!(request.starts_with(b"CONNECT deadline.test:443 HTTP/1.1\r\n"));
    });
    let document=mihomo_config::parse_runtime_config_document(&format!("proxies:\n  - {{name: stalled, type: http, server: 127.0.0.1, port: {port}}}\nproxy-groups:\n  - {{name: smart, type: smart, proxies: [stalled]}}\nrules:\n  - MATCH,smart\n")).unwrap();
    let registry = crate::build_runtime_registry(&document).unwrap();
    let tunnel = crate::RuntimeTunnel::new("rule", registry)
        .with_rule_set(mihomo_rules::compile_rule_set(&document.rules).unwrap());
    let start = Instant::now();
    assert!(tunnel
        .connect_tcp_with_system_dialer_with_timeout(
            &Metadata {
                kind: mihomo_core::SessionKind::Http,
                host: Some("deadline.test".into()),
                dst_port: Some(443),
                ..Default::default()
            },
            Some(80)
        )
        .is_err());
    assert!(start.elapsed() < Duration::from_secs(2));
    server.join().unwrap();
}

#[test]
fn matched_geodata_identity_keeps_country_collections_separate_from_services() {
    let document=mihomo_config::parse_runtime_config_document("rule-providers:\n  cn:\n    type: inline\n    behavior: classical\n    payload: ['DOMAIN-SUFFIX,example.com']\n  US_IP:\n    type: inline\n    behavior: ipcidr\n    payload: ['203.0.113.0/24']\nrules:\n  - GEOSITE,cn,DIRECT\n  - GEOIP,US,DIRECT\n  - MATCH,DIRECT\n").unwrap();
    let empty = BTreeMap::<String, String>::new();
    let rules = mihomo_rules::compile_rule_table_with_providers(
        &document.rules,
        &document.sub_rules,
        &document.rule_providers,
        &empty,
        &empty,
    )
    .unwrap();
    let host = Metadata {
        host: Some("www.example.com".into()),
        ..Default::default()
    };
    let ip = Metadata {
        dst_ip: Some("203.0.113.4".parse().unwrap()),
        ..Default::default()
    };
    assert_eq!(
        rules.smart_rule_identity(&host),
        Some(("GeoSite [cn]".into(), 1))
    );
    assert_eq!(
        rules.smart_rule_identity(&ip),
        Some(("GeoIP [US]".into(), 1))
    );
    let mut metadata = ip.clone();
    metadata.smart_rule = rules.smart_rule_identity(&ip);
    metadata.dst_ip_asn = "AS1234 service".into();
    assert_eq!(target::key(true, &metadata, &BTreeMap::new()), "asn:1234");
    rules.set_rule_disabled(0, true);
    assert_eq!(rules.smart_rule_identity(&host), Some(("Match".into(), 0)));
}
