use std::collections::{BTreeMap, BTreeSet};

use mihomo_core::Metadata;
use mihomo_outbound::OutboundDefinition;

use crate::{
    native_support_gap_for_outbound_with_registry, outbound_supports_udp, ProxyRegistration,
    ProxySource, RuntimeRegistry,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateState {
    pub name: String,
    pub alive: bool,
    pub last_delay_ms: u16,
    pub supports_udp: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedProxyPath {
    pub requested: String,
    pub selected_path: Vec<String>,
    pub leaf_name: String,
    pub leaf_source: ProxySource,
    pub leaf_kind: Option<mihomo_outbound::OutboundKind>,
    pub dialer_path: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolveError {
    ProxyNotFound(String),
    GroupResolutionLoop(Vec<String>),
    DialerResolutionLoop(Vec<String>),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProxyNotFound(name) => write!(f, "proxy not found: {name}"),
            Self::GroupResolutionLoop(path) => {
                write!(f, "proxy group resolution loop: {}", path.join("->"))
            }
            Self::DialerResolutionLoop(path) => {
                write!(f, "dialer-proxy resolution loop: {}", path.join("->"))
            }
        }
    }
}

impl std::error::Error for ResolveError {}

pub fn resolve_proxy_path(
    registry: &mut RuntimeRegistry,
    target: &str,
    metadata: Option<&Metadata>,
    states: &BTreeMap<String, CandidateState>,
) -> Result<ResolvedProxyPath, ResolveError> {
    resolve_proxy_path_internal(registry, target, metadata, states, false)
}

pub fn resolve_proxy_path_preferring_selected(
    registry: &mut RuntimeRegistry,
    target: &str,
    metadata: Option<&Metadata>,
    states: &BTreeMap<String, CandidateState>,
) -> Result<ResolvedProxyPath, ResolveError> {
    resolve_proxy_path_internal(registry, target, metadata, states, true)
}

fn resolve_proxy_path_internal(
    registry: &mut RuntimeRegistry,
    target: &str,
    metadata: Option<&Metadata>,
    states: &BTreeMap<String, CandidateState>,
    prefer_selected: bool,
) -> Result<ResolvedProxyPath, ResolveError> {
    let mut visited = Vec::new();
    let (leaf_name, selected_path) =
        resolve_target(registry, target, metadata, states, &mut visited, prefer_selected)?;
    let (leaf_source, leaf_kind, mut current) = {
        let leaf_registration = get_registration(registry, &leaf_name)?;
        (
            leaf_registration.source.clone(),
            leaf_registration.kind,
            leaf_registration.dialer_proxy.clone(),
        )
    };
    let mut dialer_path = Vec::new();
    let mut dialer_visited = BTreeSet::new();
    while let Some(dialer_target) = current {
        if !dialer_visited.insert(dialer_target.clone()) {
            let mut path = dialer_visited.into_iter().collect::<Vec<_>>();
            path.push(dialer_target);
            return Err(ResolveError::DialerResolutionLoop(path));
        }
        let (dialer_leaf, _) =
            resolve_target(
                registry,
                &dialer_target,
                metadata,
                states,
                &mut Vec::new(),
                prefer_selected,
            )?;
        current = get_registration(registry, &dialer_leaf)?.dialer_proxy.clone();
        dialer_path.push(dialer_leaf);
    }

    Ok(ResolvedProxyPath {
        requested: target.to_owned(),
        selected_path,
        leaf_name: leaf_name.clone(),
        leaf_source,
        leaf_kind,
        dialer_path,
    })
}

fn resolve_target(
    registry: &mut RuntimeRegistry,
    target: &str,
    metadata: Option<&Metadata>,
    states: &BTreeMap<String, CandidateState>,
    visited_groups: &mut Vec<String>,
    prefer_selected: bool,
) -> Result<(String, Vec<String>), ResolveError> {
    if let Some(position) = visited_groups.iter().position(|name| name == target) {
        let mut path = visited_groups[position..].to_vec();
        path.push(target.to_owned());
        return Err(ResolveError::GroupResolutionLoop(path));
    }

    if let Some(candidate_names) = registry.groups.get(target).map(|view| view.candidate_names.clone()) {
        visited_groups.push(target.to_owned());
        let candidate_states = candidate_names
            .iter()
            .map(|candidate| {
                let state = derive_candidate_state(
                    registry,
                    candidate,
                    metadata,
                    states,
                    visited_groups,
                    prefer_selected,
                )?;
                Ok(crate::ProxyCandidate {
                    name: candidate.clone(),
                    alive: state.alive,
                    last_delay_ms: state.last_delay_ms,
                    supports_udp: state.supports_udp,
                })
            })
            .collect::<Result<Vec<_>, ResolveError>>()?;

        let chosen_name = {
            let view = registry.groups.get_mut(target).expect("group should still exist");
            if prefer_selected {
                if let Some(selected) = view
                    .runtime
                    .selected()
                    .filter(|selected| view.candidate_names.iter().any(|candidate| candidate == *selected))
                {
                    selected.to_owned()
                } else {
                    view.runtime
                        .choose(&candidate_states, metadata)
                        .map(|proxy| proxy.name.clone())
                        .ok_or_else(|| ResolveError::ProxyNotFound(target.to_owned()))?
                }
            } else {
                view.runtime
                    .choose(&candidate_states, metadata)
                    .map(|proxy| proxy.name.clone())
                    .ok_or_else(|| ResolveError::ProxyNotFound(target.to_owned()))?
            }
        };

        let (leaf, mut path) =
            resolve_target(registry, &chosen_name, metadata, states, visited_groups, prefer_selected)?;
        visited_groups.pop();
        let mut selected_path = vec![target.to_owned()];
        selected_path.append(&mut path);
        Ok((leaf, selected_path))
    } else {
        get_registration(registry, target)?;
        Ok((target.to_owned(), vec![target.to_owned()]))
    }
}

fn derive_candidate_state(
    registry: &mut RuntimeRegistry,
    target: &str,
    metadata: Option<&Metadata>,
    states: &BTreeMap<String, CandidateState>,
    visited_groups: &mut Vec<String>,
    prefer_selected: bool,
) -> Result<CandidateState, ResolveError> {
    if let Some(existing) = states.get(target) {
        return Ok(existing.clone());
    }

    if registry.groups.contains_key(target) {
        let (leaf, _) =
            resolve_target(registry, target, metadata, states, visited_groups, prefer_selected)?;
        if let Some(existing) = states.get(&leaf) {
            return Ok(CandidateState {
                name: target.to_owned(),
                alive: existing.alive,
                last_delay_ms: existing.last_delay_ms,
                supports_udp: existing.supports_udp,
            });
        }
        let registration = get_registration(registry, &leaf)?;
        return Ok(CandidateState {
            name: target.to_owned(),
            alive: default_alive(registration, registry.proxy_definitions.get(&leaf), registry),
            last_delay_ms: 0,
            supports_udp: default_supports_udp(
                registration,
                registry.proxy_definitions.get(&leaf),
            ),
        });
    }

    let registration = get_registration(registry, target)?;
    Ok(CandidateState {
        name: target.to_owned(),
        alive: default_alive(registration, registry.proxy_definitions.get(target), registry),
        last_delay_ms: 0,
        supports_udp: default_supports_udp(
            registration,
            registry.proxy_definitions.get(target),
        ),
    })
}

fn default_alive(
    registration: &ProxyRegistration,
    definition: Option<&mihomo_outbound::OutboundDefinition>,
    registry: &RuntimeRegistry,
) -> bool {
    if registration.source == crate::ProxySource::Builtin {
        return true;
    }

    definition
        .map(|definition| native_support_gap_for_outbound_with_registry(definition, registry))
        .is_none_or(|gap| gap.is_none())
}

fn default_supports_udp(
    registration: &ProxyRegistration,
    definition: Option<&OutboundDefinition>,
) -> bool {
    match registration.name.as_str() {
        "REJECT" | "REJECT-DROP" => false,
        _ => definition.map_or(true, outbound_supports_udp),
    }
}

fn get_registration<'a>(
    registry: &'a RuntimeRegistry,
    name: &str,
) -> Result<&'a ProxyRegistration, ResolveError> {
    registry
        .proxies
        .get(name)
        .ok_or_else(|| ResolveError::ProxyNotFound(name.to_owned()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use mihomo_config::parse_runtime_config_document;

    use super::{resolve_proxy_path, resolve_proxy_path_preferring_selected, CandidateState, ResolveError};
    use crate::build_runtime_registry;

    #[test]
    fn resolves_nested_group_to_provider_leaf() {
        let document = parse_runtime_config_document(
            r#"
proxy-providers:
  provider1:
    type: inline
    payload:
      - type: ss
        name: ss-hk
        server: server
        port: 443
        cipher: chacha20-ietf-poly1305
        password: password
proxy-groups:
  - name: inner
    type: select
    use: [provider1]
  - name: outer
    type: select
    proxies: [inner]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let resolved = resolve_proxy_path(&mut registry, "outer", None, &BTreeMap::new()).unwrap();
        assert_eq!(resolved.leaf_name, "ss-hk");
        assert_eq!(resolved.selected_path, vec!["outer", "inner", "ss-hk"]);
    }

    #[test]
    fn resolves_url_test_group_to_fastest_leaf() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: direct
    name: a
  - type: direct
    name: b
proxy-groups:
  - name: auto
    type: url-test
    proxies: [a, b]
    tolerance: 0
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let states = BTreeMap::from([
            (
                "a".into(),
                CandidateState {
                    name: "a".into(),
                    alive: true,
                    last_delay_ms: 50,
                    supports_udp: true,
                },
            ),
            (
                "b".into(),
                CandidateState {
                    name: "b".into(),
                    alive: true,
                    last_delay_ms: 20,
                    supports_udp: true,
                },
            ),
        ]);
        let resolved = resolve_proxy_path(&mut registry, "auto", None, &states).unwrap();
        assert_eq!(resolved.leaf_name, "b");
    }

    #[test]
    fn group_candidate_state_respects_outbound_udp_flag() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: udp-off
    server: 1.2.3.4
    port: 1080
    udp: false
  - type: socks5
    name: udp-on
    server: 1.2.3.5
    port: 1080
    udp: true
proxy-groups:
  - name: selector
    type: select
    proxies: [udp-off, udp-on]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let resolved = resolve_proxy_path(&mut registry, "selector", None, &BTreeMap::new()).unwrap();
        assert_eq!(resolved.leaf_name, "udp-off");

        let off = super::derive_candidate_state(
            &mut registry,
            "udp-off",
            None,
            &BTreeMap::new(),
            &mut Vec::new(),
            false,
        )
        .unwrap();
        assert!(!off.supports_udp);

        let on = super::derive_candidate_state(
            &mut registry,
            "udp-on",
            None,
            &BTreeMap::new(),
            &mut Vec::new(),
            false,
        )
        .unwrap();
        assert!(on.supports_udp);
    }

    #[test]
    fn unresolved_hysteria2_candidates_are_not_treated_as_alive_by_default() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria2
    name: hy2
    server: 1.2.3.4
    port: 443
  - type: vless
    name: vless
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
proxy-groups:
  - name: auto
    type: fallback
    proxies: [hy2, vless]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let resolved = resolve_proxy_path(&mut registry, "auto", None, &BTreeMap::new()).unwrap();
        assert_eq!(resolved.leaf_name, "hy2");
        assert_eq!(resolved.selected_path, vec!["auto", "hy2"]);
    }

    #[test]
    fn plain_hysteria2_candidates_are_treated_as_alive_by_default() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria2
    name: hy2
    server: 1.2.3.4
    port: 443
    password: secret
    sni: edge.example
proxy-groups:
  - name: auto
    type: fallback
    proxies: [hy2]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let resolved = resolve_proxy_path(&mut registry, "auto", None, &BTreeMap::new()).unwrap();
        assert_eq!(resolved.leaf_name, "hy2");
        assert_eq!(resolved.selected_path, vec!["auto", "hy2"]);
    }

    #[test]
    fn wireguard_over_outer_socks5_udp_is_treated_as_alive_by_default() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: socks5
    name: outer-socks
    server: 127.0.0.1
    port: 1080
    udp: true
  - type: wireguard
    name: edge-wg
    server: 1.2.3.4
    port: 51820
    private-key: cHJpdmF0ZS1rZXktMzItYnl0ZXMtcHJpdmF0ZS1rZXk=
    public-key: cHVibGljLWtleS0zMi1ieXRlcy1wdWJsaWMta2V5LQ==
    ip: 10.0.0.2/32
    allowed-ips: [0.0.0.0/0]
    dialer-proxy: outer-socks
proxy-groups:
  - name: auto
    type: select
    proxies: [edge-wg]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let state = super::derive_candidate_state(
            &mut registry,
            "edge-wg",
            None,
            &BTreeMap::new(),
            &mut Vec::new(),
            false,
        )
        .unwrap();
        assert!(state.alive);
    }

    #[test]
    fn non_salamander_hysteria2_obfs_candidates_are_not_treated_as_alive_by_default() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria2
    name: hy2-obfs
    server: 1.2.3.4
    port: 443
    password: secret
    sni: edge.example
    obfs: custom-obfs
    obfs-password: hidden
  - type: vless
    name: vless
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
proxy-groups:
  - name: auto
    type: fallback
    proxies: [hy2-obfs, vless]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let resolved = resolve_proxy_path(&mut registry, "auto", None, &BTreeMap::new()).unwrap();
        assert_eq!(resolved.leaf_name, "vless");
        assert_eq!(resolved.selected_path, vec!["auto", "vless"]);
    }

    #[test]
    fn salamander_hysteria2_candidates_are_treated_as_alive_by_default() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: hysteria2
    name: hy2-obfs
    server: 1.2.3.4
    port: 443
    password: secret
    sni: edge.example
    obfs: salamander
    obfs-password: hidden
proxy-groups:
  - name: auto
    type: fallback
    proxies: [hy2-obfs]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let resolved = resolve_proxy_path(&mut registry, "auto", None, &BTreeMap::new()).unwrap();
        assert_eq!(resolved.leaf_name, "hy2-obfs");
        assert_eq!(resolved.selected_path, vec!["auto", "hy2-obfs"]);
    }

    #[test]
    fn vless_vision_reality_candidates_are_alive_by_default() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: xtls-rprx-vision
    reality-opts:
      public-key: abc
      short-id: def
  - type: vmess
    name: vmess
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: none
proxy-groups:
  - name: auto
    type: fallback
    proxies: [vision, vmess]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let resolved = resolve_proxy_path(&mut registry, "auto", None, &BTreeMap::new()).unwrap();
        assert_eq!(resolved.leaf_name, "vision");
        assert_eq!(resolved.selected_path, vec!["auto", "vision"]);
    }

    #[test]
    fn vless_vision_without_reality_candidates_stay_dead_by_default() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: xtls-rprx-vision
  - type: direct
    name: direct
proxy-groups:
  - name: auto
    type: fallback
    proxies: [vision, direct]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let resolved = resolve_proxy_path(&mut registry, "auto", None, &BTreeMap::new()).unwrap();
        assert_eq!(resolved.leaf_name, "vision");
        assert_eq!(resolved.selected_path, vec!["auto", "vision"]);
    }

    #[test]
    fn vless_vision_tls_tcp_without_reality_candidates_are_alive_by_default() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: xtls-rprx-vision
proxy-groups:
  - name: auto
    type: fallback
    proxies: [vision]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let resolved = resolve_proxy_path(&mut registry, "auto", None, &BTreeMap::new()).unwrap();
        assert_eq!(resolved.leaf_name, "vision");
        assert_eq!(resolved.selected_path, vec!["auto", "vision"]);
    }

    #[test]
    fn vless_vision_tls_h2_without_reality_candidates_are_alive_by_default() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    network: h2
    flow: xtls-rprx-vision
proxy-groups:
  - name: auto
    type: fallback
    proxies: [vision]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let resolved = resolve_proxy_path(&mut registry, "auto", None, &BTreeMap::new()).unwrap();
        assert_eq!(resolved.leaf_name, "vision");
        assert_eq!(resolved.selected_path, vec!["auto", "vision"]);
    }

    #[test]
    fn vless_vision_tls_grpc_without_reality_candidates_are_alive_by_default() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    network: grpc
    flow: xtls-rprx-vision
proxy-groups:
  - name: auto
    type: fallback
    proxies: [vision]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let resolved = resolve_proxy_path(&mut registry, "auto", None, &BTreeMap::new()).unwrap();
        assert_eq!(resolved.leaf_name, "vision");
        assert_eq!(resolved.selected_path, vec!["auto", "vision"]);
    }

    #[test]
    fn vless_vision_tls_ws_without_reality_candidates_are_alive_by_default() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    network: ws
    flow: xtls-rprx-vision
proxy-groups:
  - name: auto
    type: fallback
    proxies: [vision]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let resolved = resolve_proxy_path(&mut registry, "auto", None, &BTreeMap::new()).unwrap();
        assert_eq!(resolved.leaf_name, "vision");
        assert_eq!(resolved.selected_path, vec!["auto", "vision"]);
    }

    #[test]
    fn resolves_dialer_proxy_chain_after_group_selection() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: direct
    name: base
    dialer-proxy: upstream
  - type: direct
    name: upstream
proxy-groups:
  - name: selector
    type: select
    proxies: [base]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        let resolved = resolve_proxy_path(&mut registry, "selector", None, &BTreeMap::new()).unwrap();
        assert_eq!(resolved.leaf_name, "base");
        assert_eq!(resolved.dialer_path, vec!["upstream"]);
    }

    #[test]
    fn preferring_selected_path_honors_fixed_url_test_member_even_when_default_alive_would_skip_it() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: vless
    name: vision
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: xtls-rprx-vision
    reality-opts:
      public-key: abc
      short-id: def
  - type: hysteria2
    name: hy2
    server: 1.2.3.4
    port: 443
    password: secret
    sni: edge.example
proxy-groups:
  - name: auto
    type: url-test
    proxies: [vision, hy2]
"#,
        )
        .unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        registry
            .groups
            .get_mut("auto")
            .expect("runtime group")
            .runtime
            .set_selected("vision");
        let resolved = resolve_proxy_path_preferring_selected(&mut registry, "auto", None, &BTreeMap::new())
            .unwrap();
        assert_eq!(resolved.leaf_name, "vision");
        assert_eq!(resolved.selected_path, vec!["auto", "vision"]);
    }

    #[test]
    fn detects_runtime_missing_proxy_target() {
        let document = parse_runtime_config_document("proxies: []").unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        assert_eq!(
            resolve_proxy_path(&mut registry, "missing", None, &BTreeMap::new()).unwrap_err(),
            ResolveError::ProxyNotFound("missing".into())
        );
    }
}
