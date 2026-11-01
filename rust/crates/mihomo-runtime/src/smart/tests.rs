use super::*;
#[test]
fn smart_ranks_live_candidates_and_honors_priority() {
    let definition = mihomo_outbound::parse_group_yaml(
        "name: test\ntype: smart\npolicy-priority: 'preferred:2'\n",
    )
    .unwrap();
    let mut smart = SmartGroup::new(&definition);
    let candidates = vec![
        ProxyCandidate {
            name: "other".into(),
            alive: true,
            last_delay_ms: 20,
            supports_udp: true,
        },
        ProxyCandidate {
            name: "preferred".into(),
            alive: true,
            last_delay_ms: 30,
            supports_udp: false,
        },
    ];
    assert_eq!(
        smart
            .choose(&candidates, Some(&Metadata::default()), None)
            .unwrap()
            .name,
        "preferred"
    );
    let metadata = Metadata {
        network: NetworkKind::Udp,
        ..Default::default()
    };
    assert_eq!(
        smart
            .choose(&candidates, Some(&metadata), None)
            .unwrap()
            .name,
        "other"
    );
}

fn model_text(decision: u32, threshold: &str, extra: &str) -> String {
    format!("tree\nversion=v4\nnum_class=1\nnum_tree_per_iteration=1\nmax_feature_idx=0\nobjective=regression\nfeature_names=success\n\nTree=0\nnum_leaves=2\nsplit_feature=0\nthreshold={threshold}\ndecision_type={decision}\nleft_child=-1\nright_child=-2\nleaf_value=0.25 0.75\n{extra}\nend of trees\n")
}
#[test]
fn lightgbm_numeric_missing_and_categorical_splits() {
    let numeric = LightGbmModel::parse(&model_text(10, "1.5", "")).unwrap();
    assert_eq!(numeric.predict(&[1.0]).unwrap(), 0.25);
    assert_eq!(numeric.predict(&[2.0]).unwrap(), 0.75);
    assert_eq!(numeric.predict(&[f64::NAN]).unwrap(), 0.25);
    let category =
        LightGbmModel::parse(&model_text(1, "0", "cat_boundaries=0 1\ncat_threshold=10")).unwrap();
    assert_eq!(category.predict(&[1.0]).unwrap(), 0.25);
    assert_eq!(category.predict(&[3.0]).unwrap(), 0.25);
    assert_eq!(category.predict(&[2.0]).unwrap(), 0.75);
    assert_eq!(category.predict(&[-1.0]).unwrap(), 0.75);
}
#[test]
fn lightgbm_applies_feature_scalers_and_rejects_invalid_graphs() {
    let text=model_text(2,"0","")+"[transforms]\ntransform=true\n[order]\n0=success\n[/order]\n[definitions]\nstd_type=StandardScaler\nstd_features=0\nstd_mean=4\nstd_scale=2\n[/definitions]\n[/transforms]\n";
    let model = LightGbmModel::parse(&text).unwrap();
    assert_eq!(model.predict(&[3.0]).unwrap(), 0.25);
    assert_eq!(model.predict(&[6.0]).unwrap(), 0.75);
    assert!(
        LightGbmModel::parse(&model_text(2, "0", "").replace("left_child=-1", "left_child=0"))
            .is_err()
    );
    assert!(LightGbmModel::parse(
        &model_text(2, "0", "").replace("right_child=-2", "right_child=-999")
    )
    .is_err());
    assert!(LightGbmModel::parse(&text.replace("std_scale=2", "std_scale=0")).is_err());
}
#[test]
fn smart_learns_failures_per_target_without_poisoning_other_destinations() {
    let definition = mihomo_outbound::parse_group_yaml("name: test\ntype: smart\n").unwrap();
    let mut smart = SmartGroup::new(&definition);
    let candidates = vec![
        ProxyCandidate {
            name: "a".into(),
            alive: true,
            last_delay_ms: 10,
            supports_udp: true,
        },
        ProxyCandidate {
            name: "b".into(),
            alive: true,
            last_delay_ms: 100,
            supports_udp: true,
        },
    ];
    let first = Metadata {
        host: Some("one.test".into()),
        ..Default::default()
    };
    let second = Metadata {
        host: Some("two.test".into()),
        ..Default::default()
    };
    smart.observe(
        "test",
        "a",
        &first,
        &Observation {
            success: false,
            ..Default::default()
        },
    );
    assert_eq!(
        smart.choose(&candidates, Some(&first), None).unwrap().name,
        "b"
    );
    assert_eq!(
        smart
            .choose(&candidates, Some(&second), Some("a"))
            .unwrap()
            .name,
        "a"
    );
    assert_eq!(
        smart.choose(&candidates, Some(&second), None).unwrap().name,
        "a"
    );
    // A target-specific observation overrides the aggregate score once enough evidence exists.
    for _ in 0..3 {
        smart.observe(
            "test",
            "a",
            &second,
            &Observation {
                success: true,
                connect_ms: 10,
                ..Default::default()
            },
        );
    }
    assert_eq!(
        smart.choose(&candidates, Some(&second), None).unwrap().name,
        "a"
    );
    assert!(!smart.ranking(&candidates).is_empty());
    smart.flush();
    assert!(smart.ranking(&candidates).is_empty());
}
#[test]
fn smart_uses_lightgbm_scores_after_minimum_sample_count() {
    let definition =
        mihomo_outbound::parse_group_yaml("name: test\ntype: smart\nuselightgbm: true\n").unwrap();
    let mut smart = SmartGroup::new(&definition);
    smart.model = Some(Arc::new(
        LightGbmModel::parse(&model_text(2, "1.5", "")).unwrap(),
    ));
    let metadata = Metadata {
        host: Some("model.test".into()),
        ..Default::default()
    };
    smart.observe(
        "test",
        "node",
        &metadata,
        &Observation {
            success: true,
            connect_ms: 10,
            ..Default::default()
        },
    );
    assert!(!smart.state.nodes["node"].model_predicted);
    smart.observe(
        "test",
        "node",
        &metadata,
        &Observation {
            success: true,
            connect_ms: 10,
            ..Default::default()
        },
    );
    assert!(smart.state.nodes["node"].model_predicted);
    assert_eq!(smart.state.nodes["node"].weight, 0.75);
}
#[test]
fn smart_csv_collection_honors_enable_size_and_escapes_fields() {
    let temp = std::env::temp_dir().join(format!(
        "smart-csv-{}-{}",
        std::process::id(),
        now_seconds()
    ));
    let _ = fs::remove_dir_all(&temp);
    fs::create_dir_all(&temp).unwrap();
    let definition = mihomo_outbound::parse_group_yaml(
        "name: test\ntype: smart\ncollectdata: true\nsample-rate: 1\n",
    )
    .unwrap();
    let mut smart = SmartGroup::new(&definition);
    smart.collector = Some(Arc::new(Collector::new(&temp, 0.01)));
    let metadata = Metadata {
        host: Some("quoted,\"host".into()),
        ..Default::default()
    };
    for _ in 0..100 {
        smart.observe(
            "test",
            "node",
            &metadata,
            &Observation {
                success: true,
                ..Default::default()
            },
        );
    }
    let path = temp.join("smart_weight_data.csv");
    let bytes = fs::read(&path).unwrap();
    assert!(bytes.len() <= 10486);
    assert!(String::from_utf8(bytes)
        .unwrap()
        .contains("\"quoted,\"\"host\""));
    let _ = fs::remove_dir_all(temp);
}
#[test]
fn feature_slots_match_upstream_hash_and_special_port_precedence() {
    let input = ModelInput {
        success: 2,
        connect_time: 19.0,
        latency: 49.0,
        host: "dns.google".into(),
        port: 853,
        asn: "AS15169 Google".into(),
        geoip: vec!["US".into()],
        is_udp: true,
        ..Default::default()
    };
    let features = input.features(now_seconds());
    assert_eq!(features[2], 20f64.ln());
    assert_eq!(features[15], 1.0);
    assert_eq!(features[16], 0.0);
    assert_eq!(features[19], 100.0);
    assert_eq!(features[20], 106.0);
    assert_eq!(features[21], 104.0);
    assert_eq!(features[22], 7.0);
    assert_eq!(features[25], 7.0);
    assert!(features[27] >= 1.0 && features[27] <= 1000.0);
}
#[test]
fn smart_state_persists_by_configuration_and_flush_does_not_affect_other_configs() {
    use crate::{build_runtime_registry, RuntimeTunnel};
    let temp = std::env::temp_dir().join(format!(
        "smart-state-{}-{}",
        std::process::id(),
        now_seconds()
    ));
    let _ = fs::remove_dir_all(&temp);
    fs::create_dir_all(&temp).unwrap();
    let document = mihomo_config::parse_runtime_config_document(
        "proxy-groups:\n  - name: learn\n    type: smart\n    proxies: [DIRECT]\n",
    )
    .unwrap();
    let registry = build_runtime_registry(&document).unwrap();
    let tunnel = RuntimeTunnel::new("rule", registry.clone());
    tunnel.configure_smart(&temp, "profile", 100.0);
    let metadata = Metadata {
        host: Some("target.test".into()),
        ..Default::default()
    };
    for _ in 0..2 {
        tunnel
            .registry
            .lock()
            .unwrap()
            .groups
            .get_mut("learn")
            .unwrap()
            .runtime
            .smart
            .as_mut()
            .unwrap()
            .observe(
                "learn",
                "DIRECT",
                &metadata,
                &Observation {
                    success: true,
                    connect_ms: 25,
                    ..Default::default()
                },
            );
    }
    tunnel.persist_smart_state().unwrap();
    let restored = RuntimeTunnel::new("rule", registry.clone());
    restored.configure_smart(&temp, "profile", 100.0);
    assert_eq!(
        restored.registry.lock().unwrap().groups["learn"]
            .runtime
            .smart
            .as_ref()
            .unwrap()
            .state
            .observations,
        2
    );
    let other = RuntimeTunnel::new("rule", registry.clone());
    other.configure_smart(&temp, "other", 100.0);
    other.persist_smart_state().unwrap();
    let other_path = other
        .smart_context
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .state_path
        .clone();
    assert!(other_path.is_file());
    restored.flush_smart_cache(Some("other")).unwrap();
    assert!(!other_path.exists());
    assert!(!restored.smart_rankings(Some("learn"))["learn"].is_empty());
    restored.flush_smart_cache(Some("profile")).unwrap();
    assert!(restored.smart_rankings(Some("learn"))["learn"].is_empty());
    other.persist_smart_state().unwrap();
    assert!(other_path.is_file());
    restored.flush_smart_cache(None).unwrap();
    assert!(!other_path.exists());
    let _ = fs::remove_dir_all(temp);
}

#[test]
#[ignore = "requires SMART_MMDB_FIXTURES with the public MaxMind test databases"]
fn smart_enriches_metadata_from_real_mmdb_files() {
    let root = std::env::var("SMART_MMDB_FIXTURES").unwrap();
    let geo = super::geodata::SmartGeoData::load(Path::new(&root));
    let mut asn = Metadata {
        dst_ip: Some("1.0.0.1".parse().unwrap()),
        ..Default::default()
    };
    geo.enrich(&mut asn);
    assert!(asn.dst_ip_asn.starts_with("AS"), "{:?}", asn);
    let mut country = Metadata {
        dst_ip: Some("81.2.69.142".parse().unwrap()),
        ..Default::default()
    };
    geo.enrich(&mut country);
    assert_eq!(country.dst_geoip, Some(vec!["GB".into()]));
    let mut domain = Metadata {
        host: Some("unresolved.example".into()),
        ..Default::default()
    };
    geo.enrich(&mut domain);
    assert!(domain.dst_ip_asn.is_empty());
    assert!(domain.dst_ip.is_none());
}
