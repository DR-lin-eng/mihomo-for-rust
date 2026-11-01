use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use mihomo_config::RuleProviderDefinition;
use mihomo_core::{Metadata, NetworkKind, SessionKind};

use crate::{
    compile_rule_set, compile_rule_table, compile_rule_table_with_providers,
    convert_ruleset_content, parse_rule, RuleDefinition, RuleError, RuleSet, RuleType,
};

#[test]
fn parse_rule_supports_match_without_payload() {
    assert_eq!(
        parse_rule("MATCH,DIRECT").unwrap(),
        RuleDefinition {
            rule_type: RuleType::Match,
            payload: String::new(),
            target: "DIRECT".into(),
        }
    );
}

#[test]
fn parse_rule_preserves_regex_payload_with_commas() {
    assert_eq!(
        parse_rule(r#"DOMAIN-REGEX,^api,(v1|v2)\.example\.com$,PROXY"#).unwrap(),
        RuleDefinition {
            rule_type: RuleType::DomainRegex,
            payload: r#"^api,(v1|v2)\.example\.com$"#.into(),
            target: "PROXY".into(),
        }
    );
}

#[test]
fn parse_geoip_cn_rule_maps_to_cn_ip_ruleset() {
    assert_eq!(
        parse_rule("GEOIP,CN,DIRECT").unwrap(),
        RuleDefinition {
            rule_type: RuleType::RuleSet,
            payload: "CN_IP".into(),
            target: "DIRECT".into(),
        }
    );
}

#[test]
fn parse_geoip_rule_maps_generic_region_to_ruleset_name() {
    assert_eq!(
        parse_rule("GEOIP,US,DIRECT").unwrap(),
        RuleDefinition {
            rule_type: RuleType::RuleSet,
            payload: "US_IP".into(),
            target: "DIRECT".into(),
        }
    );
}

#[test]
fn parse_geosite_rule_maps_to_ruleset_name() {
    assert_eq!(
        parse_rule("GEOSITE,gfw,PROXY").unwrap(),
        RuleDefinition {
            rule_type: RuleType::RuleSet,
            payload: "gfw".into(),
            target: "PROXY".into(),
        }
    );
}

#[test]
fn rule_set_matches_domain_and_match_fallback_in_order() {
    let rules = compile_rule_set(&[
        "DOMAIN-SUFFIX,example.com,DIRECT".into(),
        "MATCH,REJECT".into(),
    ])
    .unwrap();

    let domain = Metadata {
        host: Some("www.example.com".into()),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&domain), Some("DIRECT"));

    let other = Metadata {
        host: Some("openai.com".into()),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&other), Some("REJECT"));
}

#[test]
fn rule_set_matches_ip_and_network_variants() {
    let rules = compile_rule_set(&[
        "SRC-IP-CIDR,10.0.0.0/8,DIRECT".into(),
        "IP-CIDR,1.1.1.0/24,PROXY".into(),
        "NETWORK,UDP,UDP-OUT".into(),
        "MATCH,REJECT".into(),
    ])
    .unwrap();

    let src_match = Metadata {
        src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&src_match), Some("DIRECT"));

    let dst_match = Metadata {
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&dst_match), Some("PROXY"));

    let udp_match = Metadata {
        network: NetworkKind::Udp,
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&udp_match), Some("UDP-OUT"));
}

#[test]
fn rule_set_matches_ports_uid_and_dscp_variants() {
    let rules = compile_rule_set(&[
        "SRC-PORT,10000-10010,LAN".into(),
        "DST-PORT,443/8443,TLS".into(),
        "IN-PORT,7890,MIXED".into(),
        "UID,1000-2000,UID-OUT".into(),
        "DSCP,46/48-50,QOS".into(),
        "MATCH,REJECT".into(),
    ])
    .unwrap();

    let src_port = Metadata {
        src_port: Some(10005),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&src_port), Some("LAN"));

    let dst_port = Metadata {
        dst_port: Some(8443),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&dst_port), Some("TLS"));

    let in_port = Metadata {
        inbound_port: Some(7890),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&in_port), Some("MIXED"));

    let uid = Metadata {
        uid: Some(1500),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&uid), Some("UID-OUT"));

    let dscp = Metadata {
        dscp: Some(48),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&dscp), Some("QOS"));
}

#[test]
fn rule_set_matches_process_and_inbound_variants() {
    let rules = compile_rule_set(&[
        "IN-NAME,edge/tproxy-in,IN-NAME-OUT".into(),
        "IN-USER,alice/bob,IN-USER-OUT".into(),
        "IN-TYPE,SOCKS/TUNNEL,IN-TYPE-OUT".into(),
        "PROCESS-NAME,Firefox,PROC-NAME-OUT".into(),
        "PROCESS-PATH,/Applications/Firefox.app,PROC-PATH-OUT".into(),
        "MATCH,REJECT".into(),
    ])
    .unwrap();

    let in_name = Metadata {
        inbound_name: "tproxy-in".into(),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&in_name), Some("IN-NAME-OUT"));

    let in_user = Metadata {
        inbound_user: "bob".into(),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&in_user), Some("IN-USER-OUT"));

    let in_type = Metadata {
        kind: SessionKind::Socks5,
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&in_type), Some("IN-TYPE-OUT"));

    let process_name = Metadata {
        process: "firefox".into(),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&process_name), Some("PROC-NAME-OUT"));

    let process_path = Metadata {
        process_path: "/applications/firefox.app".into(),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&process_path), Some("PROC-PATH-OUT"));
}

#[test]
fn rule_set_matches_regex_and_wildcard_variants() {
    let rules = compile_rule_set(&[
        r#"DOMAIN-REGEX,^api,(v1|v2)\.example\.com$,DOMAIN-REGEX-OUT"#.into(),
        "DOMAIN-WILDCARD,*.internal.example.com,DOMAIN-WILDCARD-OUT".into(),
        r#"PROCESS-NAME-REGEX,^fire.*x$,PROC-REGEX-OUT"#.into(),
        "PROCESS-PATH-WILDCARD,*/firefox.app/*,PROC-WILDCARD-OUT".into(),
        "MATCH,REJECT".into(),
    ])
    .unwrap();

    let domain_regex = Metadata {
        host: Some("api,v2.example.com".into()),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&domain_regex), Some("DOMAIN-REGEX-OUT"));

    let domain_wildcard = Metadata {
        host: Some("foo.internal.example.com".into()),
        ..Metadata::default()
    };
    assert_eq!(
        rules.target_for(&domain_wildcard),
        Some("DOMAIN-WILDCARD-OUT")
    );

    let proc_regex = Metadata {
        process: "firefox".into(),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&proc_regex), Some("PROC-REGEX-OUT"));

    let proc_wildcard = Metadata {
        process_path: "/applications/firefox.app/contents/macos/firefox".into(),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&proc_wildcard), Some("PROC-WILDCARD-OUT"));
}

#[test]
fn rule_set_matches_logic_variants() {
    let and_rules = compile_rule_set(&[
        "AND,((DOMAIN,baidu.com),(NETWORK,TCP),(DST-PORT,10001-65535)),DIRECT".into(),
    ])
    .unwrap();
    let and_match = Metadata {
        host: Some("baidu.com".into()),
        network: NetworkKind::Tcp,
        dst_port: Some(20000),
        ..Metadata::default()
    };
    assert_eq!(and_rules.target_for(&and_match), Some("DIRECT"));

    let or_rules = compile_rule_set(&[
        "OR,((DOMAIN,baidu.com),(NETWORK,TCP),(DST-PORT,10001-65535)),DIRECT".into(),
    ])
    .unwrap();
    let or_match = Metadata {
        network: NetworkKind::Tcp,
        ..Metadata::default()
    };
    assert_eq!(or_rules.target_for(&or_match), Some("DIRECT"));

    let not_rules = compile_rule_set(&["NOT,((DST-PORT,6000-6500)),REJECT".into()]).unwrap();
    let blocked = Metadata {
        dst_port: Some(6100),
        ..Metadata::default()
    };
    assert_eq!(not_rules.target_for(&blocked), None);

    let allowed = Metadata {
        dst_port: Some(7000),
        ..Metadata::default()
    };
    assert_eq!(not_rules.target_for(&allowed), Some("REJECT"));
}

#[test]
fn rule_set_matches_nested_logic_variants() {
    let rules = compile_rule_set(&[
        "AND,((OR,((DOMAIN,example.com),(DOMAIN,example.org))),(NETWORK,TCP)),DIRECT".into(),
    ])
    .unwrap();
    let match_metadata = Metadata {
        host: Some("example.org".into()),
        network: NetworkKind::Tcp,
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&match_metadata), Some("DIRECT"));
}

#[test]
fn rule_set_matches_sub_rule_variants() {
    let rules = compile_rule_table(
        &[
            "DOMAIN-SUFFIX,example.com,DIRECT".into(),
            "SUB-RULE,(OR,((NETWORK,TCP),(NETWORK,UDP))),branch-a".into(),
            "MATCH,REJECT".into(),
        ],
        &BTreeMap::from([(
            "branch-a".into(),
            vec![
                "DOMAIN,google.com,PROXY".into(),
                "DOMAIN,baidu.com,DIRECT".into(),
            ],
        )]),
    )
    .unwrap();

    let from_default = Metadata {
        host: Some("foo.example.com".into()),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&from_default), Some("DIRECT"));

    let from_branch = Metadata {
        host: Some("google.com".into()),
        network: NetworkKind::Tcp,
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&from_branch), Some("PROXY"));
}

#[test]
fn rule_set_uses_special_rules_when_present() {
    let rules = compile_rule_table(
        &["DOMAIN,default.com,DIRECT".into()],
        &BTreeMap::from([("custom".into(), vec!["DOMAIN,branch.com,PROXY".into()])]),
    )
    .unwrap();

    let mut metadata = Metadata {
        host: Some("branch.com".into()),
        ..Metadata::default()
    };
    metadata.special_rules = "custom".into();
    assert_eq!(rules.target_for(&metadata), Some("PROXY"));

    let missing = Metadata {
        host: Some("default.com".into()),
        special_rules: "missing".into(),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&missing), Some("DIRECT"));
}

#[test]
fn rule_set_matches_rule_set_provider_variants() {
    let providers = BTreeMap::from([(
        "rule1".into(),
        RuleProviderDefinition {
            provider_type: "inline".into(),
            behavior: "domain".into(),
            payload: vec![".example.com".into()],
            ..RuleProviderDefinition::default()
        },
    )]);
    let empty_sources = BTreeMap::<String, String>::new();
    let rules = compile_rule_table_with_providers(
        &["RULE-SET,rule1,PROXY".into(), "MATCH,DIRECT".into()],
        &BTreeMap::new(),
        &providers,
        &empty_sources,
        &empty_sources,
    )
    .unwrap();

    let metadata = Metadata {
        host: Some("api.example.com".into()),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&metadata), Some("PROXY"));
}

#[test]
fn rule_set_matches_geosite_rule_via_existing_provider_name() {
    let providers = BTreeMap::from([(
        "gfw".into(),
        RuleProviderDefinition {
            provider_type: "inline".into(),
            behavior: "domain".into(),
            payload: vec!["+.example.com".into()],
            ..RuleProviderDefinition::default()
        },
    )]);
    let empty_sources = BTreeMap::<String, String>::new();
    let rules = compile_rule_table_with_providers(
        &["GEOSITE,gfw,PROXY".into(), "MATCH,DIRECT".into()],
        &BTreeMap::new(),
        &providers,
        &empty_sources,
        &empty_sources,
    )
    .unwrap();

    let metadata = Metadata {
        host: Some("api.example.com".into()),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&metadata), Some("PROXY"));
}

#[test]
fn rule_set_matches_geoip_rule_via_existing_provider_name() {
    let providers = BTreeMap::from([(
        "US_IP".into(),
        RuleProviderDefinition {
            provider_type: "inline".into(),
            behavior: "ipcidr".into(),
            payload: vec!["8.8.8.0/24".into()],
            ..RuleProviderDefinition::default()
        },
    )]);
    let empty_sources = BTreeMap::<String, String>::new();
    let rules = compile_rule_table_with_providers(
        &["GEOIP,US,PROXY".into(), "MATCH,DIRECT".into()],
        &BTreeMap::new(),
        &providers,
        &empty_sources,
        &empty_sources,
    )
    .unwrap();

    let metadata = Metadata {
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&metadata), Some("PROXY"));
}

#[test]
fn rule_set_matches_classical_rule_provider_variants() {
    let providers = BTreeMap::from([(
        "rule1".into(),
        RuleProviderDefinition {
            provider_type: "inline".into(),
            behavior: "classical".into(),
            payload: vec!["DOMAIN-KEYWORD,google".into(), "NETWORK,UDP".into()],
            ..RuleProviderDefinition::default()
        },
    )]);
    let empty_sources = BTreeMap::<String, String>::new();
    let rules = compile_rule_table_with_providers(
        &["RULE-SET,rule1,PROXY".into(), "MATCH,DIRECT".into()],
        &BTreeMap::new(),
        &providers,
        &empty_sources,
        &empty_sources,
    )
    .unwrap();

    let metadata = Metadata {
        host: Some("www.google.com".into()),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&metadata), Some("PROXY"));
}

#[test]
fn rule_set_loads_text_rule_provider_content() {
    let providers = BTreeMap::from([(
        "rule1".into(),
        RuleProviderDefinition {
            provider_type: "file".into(),
            behavior: "ipcidr".into(),
            format: "text".into(),
            path: "rule1.txt".into(),
            ..RuleProviderDefinition::default()
        },
    )]);
    let rules = compile_rule_table_with_providers(
        &["RULE-SET,rule1,PROXY".into()],
        &BTreeMap::new(),
        &providers,
        &BTreeMap::from([("rule1.txt".into(), "1.1.1.0/24\n".into())]),
        &BTreeMap::<String, String>::new(),
    )
    .unwrap();

    let metadata = Metadata {
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&metadata), Some("PROXY"));
}

#[test]
fn rule_set_loads_mrs_ip_rule_provider_content_without_expanding_cidrs() {
    let mrs = convert_ruleset_content(
        b"1.1.1.0/24\n2001:db8::/126\n",
        mihomo_config::RuleProviderBehavior::IpCidr,
        mihomo_config::RuleProviderFormat::Text,
    )
    .unwrap();
    let providers = BTreeMap::from([(
        "rule1".into(),
        RuleProviderDefinition {
            provider_type: "file".into(),
            behavior: "ipcidr".into(),
            format: "mrs".into(),
            path: "rule1.mrs".into(),
            ..RuleProviderDefinition::default()
        },
    )]);
    let rules = compile_rule_table_with_providers(
        &["RULE-SET,rule1,PROXY".into(), "MATCH,DIRECT".into()],
        &BTreeMap::new(),
        &providers,
        &BTreeMap::from([("rule1.mrs".into(), mrs)]),
        &BTreeMap::<String, Vec<u8>>::new(),
    )
    .unwrap();

    let ipv4 = Metadata {
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 8))),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&ipv4), Some("PROXY"));

    let ipv6 = Metadata {
        dst_ip: Some("2001:db8::2".parse().unwrap()),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&ipv6), Some("PROXY"));

    let miss = Metadata {
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&miss), Some("DIRECT"));
}

#[test]
fn rule_set_loads_mrs_domain_rule_provider_content() {
    let mrs = convert_ruleset_content(
        b"example.com\n+.suffix.test\n",
        mihomo_config::RuleProviderBehavior::Domain,
        mihomo_config::RuleProviderFormat::Text,
    )
    .unwrap();
    let providers = BTreeMap::from([(
        "rule1".into(),
        RuleProviderDefinition {
            provider_type: "file".into(),
            behavior: "domain".into(),
            format: "mrs".into(),
            path: "rule1.mrs".into(),
            ..RuleProviderDefinition::default()
        },
    )]);
    let rules = compile_rule_table_with_providers(
        &["RULE-SET,rule1,PROXY".into(), "MATCH,DIRECT".into()],
        &BTreeMap::new(),
        &providers,
        &BTreeMap::from([("rule1.mrs".into(), mrs)]),
        &BTreeMap::<String, Vec<u8>>::new(),
    )
    .unwrap();

    let exact = Metadata {
        host: Some("example.com".into()),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&exact), Some("PROXY"));

    let suffix = Metadata {
        host: Some("api.suffix.test".into()),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&suffix), Some("PROXY"));

    let miss = Metadata {
        host: Some("other.test".into()),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&miss), Some("DIRECT"));
}

#[test]
fn rule_set_loads_mrs_domain_rule_provider_with_wildcards_via_fallback_path() {
    let mrs = convert_ruleset_content(
        b"*.wild.example\n",
        mihomo_config::RuleProviderBehavior::Domain,
        mihomo_config::RuleProviderFormat::Text,
    )
    .unwrap();
    let providers = BTreeMap::from([(
        "rule1".into(),
        RuleProviderDefinition {
            provider_type: "file".into(),
            behavior: "domain".into(),
            format: "mrs".into(),
            path: "rule1.mrs".into(),
            ..RuleProviderDefinition::default()
        },
    )]);
    let rules = compile_rule_table_with_providers(
        &["RULE-SET,rule1,PROXY".into(), "MATCH,DIRECT".into()],
        &BTreeMap::new(),
        &providers,
        &BTreeMap::from([("rule1.mrs".into(), mrs)]),
        &BTreeMap::<String, Vec<u8>>::new(),
    )
    .unwrap();

    let wildcard = Metadata {
        host: Some("api.wild.example".into()),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&wildcard), Some("PROXY"));

    let miss = Metadata {
        host: Some("wild.example".into()),
        ..Metadata::default()
    };
    assert_eq!(rules.target_for(&miss), Some("DIRECT"));
}

#[test]
fn convert_ruleset_content_round_trips_mrs_formats() {
    let domain_mrs = convert_ruleset_content(
        b".example.com\nsub.test\n",
        mihomo_config::RuleProviderBehavior::Domain,
        mihomo_config::RuleProviderFormat::Text,
    )
    .unwrap();
    let domain_text = String::from_utf8(
        convert_ruleset_content(
            &domain_mrs,
            mihomo_config::RuleProviderBehavior::Domain,
            mihomo_config::RuleProviderFormat::Mrs,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(domain_text.contains("+.example.com"));
    assert!(domain_text.contains("sub.test"));

    let ip_mrs = convert_ruleset_content(
        b"1.1.1.0/24\n2001:db8::/126\n",
        mihomo_config::RuleProviderBehavior::IpCidr,
        mihomo_config::RuleProviderFormat::Text,
    )
    .unwrap();
    let ip_text = String::from_utf8(
        convert_ruleset_content(
            &ip_mrs,
            mihomo_config::RuleProviderBehavior::IpCidr,
            mihomo_config::RuleProviderFormat::Mrs,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(ip_text.contains("1.1.1.0/24"));
    assert!(ip_text.contains("2001:db8::/126"));
}

#[test]
fn invalid_cidr_is_reported() {
    assert_eq!(
        compile_rule_set(&["IP-CIDR,1.1.1.1/99,DIRECT".into()]).unwrap_err(),
        RuleError::InvalidCidr("1.1.1.1/99".into())
    );
}

#[test]
fn invalid_local_metadata_rules_are_reported() {
    assert_eq!(
        compile_rule_set(&["DST-PORT,70000,DIRECT".into()]).unwrap_err(),
        RuleError::InvalidPort("70000".into())
    );
    assert_eq!(
        compile_rule_set(&["DSCP,64,DIRECT".into()]).unwrap_err(),
        RuleError::InvalidDscp("64".into())
    );
    assert_eq!(
        compile_rule_set(&["IN-TYPE,SOCKS/UNKNOWN,DIRECT".into()]).unwrap_err(),
        RuleError::InvalidInType("SOCKS/UNKNOWN".into())
    );
    assert_eq!(
        compile_rule_set(&["IN-USER,/,DIRECT".into()]).unwrap_err(),
        RuleError::InvalidInUser("/".into())
    );
}

#[test]
fn invalid_logic_rules_are_reported() {
    assert_eq!(
        compile_rule_set(&["NOT,(DST-PORT,5600-6666),DIRECT".into()]).unwrap_err(),
        RuleError::InvalidLogic("(DST-PORT,5600-6666)".into())
    );
    assert_eq!(
        compile_rule_set(&["NOT,((DST-PORT,5600-6666),(DOMAIN,baidu.com)),DIRECT".into()])
            .unwrap_err(),
        RuleError::InvalidLogic("((DST-PORT,5600-6666),(DOMAIN,baidu.com))".into())
    );
}

#[test]
fn invalid_sub_rules_are_reported() {
    assert_eq!(
        compile_rule_table(
            &["SUB-RULE,(DOMAIN,google.com),branch-a".into()],
            &BTreeMap::new(),
        )
        .unwrap_err(),
        RuleError::SubRuleNotFound("branch-a".into())
    );

    assert_eq!(
        compile_rule_table(
            &["MATCH,DIRECT".into()],
            &BTreeMap::from([("".into(), vec!["MATCH,DIRECT".into()])]),
        )
        .unwrap_err(),
        RuleError::EmptySubRuleName
    );

    assert_eq!(
        compile_rule_table(
            &["MATCH,DIRECT".into()],
            &BTreeMap::from([
                ("a".into(), vec!["SUB-RULE,(DOMAIN,foo.com),b".into()]),
                ("b".into(), vec!["SUB-RULE,(DOMAIN,bar.com),a".into()]),
            ]),
        )
        .unwrap_err(),
        RuleError::CircularSubRule("a->b->a".into())
    );
}

#[test]
fn empty_rule_set_is_supported() {
    let rules = RuleSet::default();
    assert!(rules.is_empty());
    assert_eq!(rules.len(), 0);
    assert_eq!(rules.target_for(&Metadata::default()), None);
}
