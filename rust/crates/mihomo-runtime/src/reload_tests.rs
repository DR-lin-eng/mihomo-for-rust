use std::sync::Arc;

use mihomo_core::Metadata;

use crate::{build_runtime_registry, RuntimeTunnel};

fn policy(name: &str) -> RuntimeTunnel {
    let document = mihomo_config::parse_runtime_config_document(&format!(
        "mode: rule\nproxies:\n  - {{name: {name}, type: direct}}\nrules: ['MATCH,{name}']\n"
    ))
    .unwrap();
    RuntimeTunnel::new(
        document.mode.clone(),
        build_runtime_registry(&document).unwrap(),
    )
    .with_rule_set(mihomo_rules::compile_rule_set(&document.rules).unwrap())
}

#[test]
fn concurrent_reload_never_matches_a_rule_against_another_registry() {
    let tunnel = Arc::new(policy("first"));
    let reading = tunnel.clone();
    let worker = std::thread::spawn(move || {
        for _ in 0..5000 {
            let (target, resolved) = reading
                .selected_target_for_metadata(&Metadata::default())
                .unwrap();
            assert_eq!(target, resolved.leaf_name);
            assert!(matches!(target.as_str(), "first" | "second"));
        }
    });
    let first = policy("first");
    let second = policy("second");
    for _ in 0..300 {
        tunnel.apply_prepared_policy(&second);
        tunnel.apply_prepared_policy(&first);
    }
    worker.join().unwrap();
}
