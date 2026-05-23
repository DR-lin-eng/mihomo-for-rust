use std::collections::{BTreeMap, BTreeSet};

use mihomo_core::Metadata;

use crate::{ProxyRegistration, ProxySource, RuntimeRegistry};

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
    let mut visited = Vec::new();
    let (leaf_name, selected_path) = resolve_target(registry, target, metadata, states, &mut visited)?;
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
            resolve_target(registry, &dialer_target, metadata, states, &mut Vec::new())?;
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
                let state = derive_candidate_state(registry, candidate, metadata, states, visited_groups)?;
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
            view.runtime
                .choose(&candidate_states, metadata)
                .map(|proxy| proxy.name.clone())
                .ok_or_else(|| ResolveError::ProxyNotFound(target.to_owned()))?
        };

        let (leaf, mut path) = resolve_target(registry, &chosen_name, metadata, states, visited_groups)?;
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
) -> Result<CandidateState, ResolveError> {
    if let Some(existing) = states.get(target) {
        return Ok(existing.clone());
    }

    if registry.groups.contains_key(target) {
        let (leaf, _) = resolve_target(registry, target, metadata, states, visited_groups)?;
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
            alive: true,
            last_delay_ms: 0,
            supports_udp: default_supports_udp(registration),
        });
    }

    let registration = get_registration(registry, target)?;
    Ok(CandidateState {
        name: target.to_owned(),
        alive: true,
        last_delay_ms: 0,
        supports_udp: default_supports_udp(registration),
    })
}

fn default_supports_udp(registration: &ProxyRegistration) -> bool {
    match registration.name.as_str() {
        "REJECT" | "REJECT-DROP" => false,
        _ => true,
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

    use super::{resolve_proxy_path, CandidateState, ResolveError};
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
    fn detects_runtime_missing_proxy_target() {
        let document = parse_runtime_config_document("proxies: []").unwrap();
        let mut registry = build_runtime_registry(&document).unwrap();
        assert_eq!(
            resolve_proxy_path(&mut registry, "missing", None, &BTreeMap::new()).unwrap_err(),
            ResolveError::ProxyNotFound("missing".into())
        );
    }
}
