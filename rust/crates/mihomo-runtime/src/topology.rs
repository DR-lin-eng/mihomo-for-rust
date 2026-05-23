use std::collections::{BTreeMap, BTreeSet};

use mihomo_config::RuntimeConfigDocument;
use mihomo_outbound::{GroupDefinition, OutboundDefinition};

const BUILTIN_PROXY_NAMES: &[&str] = &["DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE", "PASS"];
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedGroup {
    pub name: String,
    pub group_type: String,
    pub proxies: Vec<String>,
    pub use_providers: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssembledProxyTopology {
    pub builtin_proxy_names: Vec<String>,
    pub user_proxy_names_in_order: Vec<String>,
    pub all_proxy_names_sorted: Vec<String>,
    pub all_provider_names_sorted: Vec<String>,
    pub group_names_in_original_order: Vec<String>,
    pub group_names_in_dependency_order: Vec<String>,
    pub resolved_groups_in_dependency_order: Vec<ResolvedGroup>,
    pub proxy_list_order: Vec<String>,
    pub synthetic_default_provider_members: Vec<String>,
    pub final_proxy_names: BTreeSet<String>,
    pub injected_global: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TopologyError {
    GroupDependencyLoop(Vec<String>),
    ProxyGroupMembersMissing(String),
    ProxyGroupReferenceNotFound { group: String, reference: String },
    DialerProxyNotFound { proxy: String, dialer_proxy: String },
    DialerProxyCycle(String),
}

impl std::fmt::Display for TopologyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GroupDependencyLoop(groups) => write!(
                f,
                "loop is detected in ProxyGroup, please check following ProxyGroups: {:?}",
                groups
            ),
            Self::ProxyGroupMembersMissing(group) => {
                write!(f, "{group}: `use` or `proxies` missing")
            }
            Self::ProxyGroupReferenceNotFound { group, reference } => {
                write!(f, "proxy group {group}: '{reference}' not found")
            }
            Self::DialerProxyNotFound { proxy, dialer_proxy } => {
                write!(f, "proxy [{proxy}] dialer-proxy [{dialer_proxy}] not found")
            }
            Self::DialerProxyCycle(proxy) => {
                write!(f, "proxy [{proxy}] has circular dialer-proxy dependency")
            }
        }
    }
}

impl std::error::Error for TopologyError {}

pub fn assemble_proxy_topology(
    document: &RuntimeConfigDocument,
) -> Result<AssembledProxyTopology, TopologyError> {
    let builtin_proxy_names = BUILTIN_PROXY_NAMES
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    let user_proxy_names_in_order = document
        .proxies
        .iter()
        .map(|proxy| proxy.name().to_owned())
        .collect::<Vec<_>>();
    let group_names_in_original_order = document
        .proxy_groups
        .iter()
        .map(|group| group.name.clone())
        .collect::<Vec<_>>();

    let mut all_proxy_names_sorted = user_proxy_names_in_order.clone();
    all_proxy_names_sorted.sort();

    let mut all_provider_names_sorted = document
        .proxy_providers
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    all_provider_names_sorted.sort();

    let group_index = document
        .proxy_groups
        .iter()
        .map(|group| (group.name.clone(), group))
        .collect::<BTreeMap<_, _>>();

    let mut topo_state = BTreeMap::<String, VisitState>::new();
    let mut group_names_in_dependency_order = Vec::new();
    let mut stack = Vec::new();
    for group in &document.proxy_groups {
        visit_group(
            group,
            &group_index,
            &mut topo_state,
            &mut stack,
            &mut group_names_in_dependency_order,
        )?;
    }

    let mut available_proxy_refs = builtin_proxy_names
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    available_proxy_refs.extend(user_proxy_names_in_order.iter().cloned());

    let mut resolved_groups_in_dependency_order = Vec::new();
    for group_name in &group_names_in_dependency_order {
        let group = group_index[group_name];
        let resolved = resolve_group(group, &available_proxy_refs, &all_proxy_names_sorted, &all_provider_names_sorted)?;
        available_proxy_refs.insert(group.name.clone());
        resolved_groups_in_dependency_order.push(resolved);
    }

    let mut proxy_list_order = vec!["DIRECT".to_owned(), "REJECT".to_owned()];
    proxy_list_order.extend(user_proxy_names_in_order.iter().cloned());
    proxy_list_order.extend(group_names_in_original_order.iter().cloned());
    let synthetic_default_provider_members = proxy_list_order
        .iter()
        .filter(|name| name.as_str() != "PASS")
        .cloned()
        .collect::<Vec<_>>();

    let has_global = group_names_in_original_order.iter().any(|name| name == "GLOBAL");
    let injected_global = !has_global;
    let mut final_proxy_names = available_proxy_refs;
    if injected_global {
        final_proxy_names.insert("GLOBAL".to_owned());
    }

    validate_dialer_proxies(&document.proxies, &final_proxy_names)?;

    Ok(AssembledProxyTopology {
        builtin_proxy_names,
        user_proxy_names_in_order,
        all_proxy_names_sorted,
        all_provider_names_sorted,
        group_names_in_original_order,
        group_names_in_dependency_order,
        resolved_groups_in_dependency_order,
        proxy_list_order,
        synthetic_default_provider_members,
        final_proxy_names,
        injected_global,
    })
}

fn resolve_group(
    group: &GroupDefinition,
    available_proxy_refs: &BTreeSet<String>,
    all_proxy_names_sorted: &[String],
    all_provider_names_sorted: &[String],
) -> Result<ResolvedGroup, TopologyError> {
    let mut resolved_proxies = group.proxies.clone();
    let mut resolved_use = group.use_providers.clone();
    let include_all_proxies = group.include_all || group.include_all_proxies;
    let include_all_providers = group.include_all || group.include_all_providers;

    if include_all_providers {
        resolved_use = all_provider_names_sorted.to_vec();
    }
    if include_all_proxies {
        resolved_proxies = all_proxy_names_sorted.to_vec();
    }
    if include_all_proxies && resolved_proxies.is_empty() && resolved_use.is_empty() {
        resolved_proxies = vec!["COMPATIBLE".to_owned()];
    }
    if resolved_proxies.is_empty() && resolved_use.is_empty() {
        return Err(TopologyError::ProxyGroupMembersMissing(group.name.clone()));
    }
    for reference in &resolved_proxies {
        if !available_proxy_refs.contains(reference) {
            return Err(TopologyError::ProxyGroupReferenceNotFound {
                group: group.name.clone(),
                reference: reference.clone(),
            });
        }
    }
    Ok(ResolvedGroup {
        name: group.name.clone(),
        group_type: group.group_type.clone(),
        proxies: resolved_proxies,
        use_providers: resolved_use,
    })
}

fn validate_dialer_proxies(
    proxies: &[OutboundDefinition],
    final_proxy_names: &BTreeSet<String>,
) -> Result<(), TopologyError> {
    let dialer_graph = proxies
        .iter()
        .filter_map(|proxy| {
            let dialer_proxy = proxy.dialer_proxy();
            (!dialer_proxy.is_empty()).then(|| (proxy.name().to_owned(), dialer_proxy.to_owned()))
        })
        .collect::<BTreeMap<_, _>>();

    for (proxy_name, dialer_proxy) in &dialer_graph {
        if !final_proxy_names.contains(dialer_proxy) {
            return Err(TopologyError::DialerProxyNotFound {
                proxy: proxy_name.clone(),
                dialer_proxy: dialer_proxy.clone(),
            });
        }
    }

    for proxy_name in dialer_graph.keys() {
        let mut path = BTreeSet::new();
        if has_dialer_proxy_cycle(proxy_name, &dialer_graph, &mut path) {
            return Err(TopologyError::DialerProxyCycle(proxy_name.clone()));
        }
    }

    Ok(())
}

fn has_dialer_proxy_cycle(
    current: &str,
    graph: &BTreeMap<String, String>,
    path: &mut BTreeSet<String>,
) -> bool {
    if !path.insert(current.to_owned()) {
        return true;
    }
    let has_cycle = graph
        .get(current)
        .is_some_and(|next| has_dialer_proxy_cycle(next, graph, path));
    path.remove(current);
    has_cycle
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VisitState {
    Visiting,
    Done,
}

fn visit_group(
    group: &GroupDefinition,
    group_index: &BTreeMap<String, &GroupDefinition>,
    state: &mut BTreeMap<String, VisitState>,
    stack: &mut Vec<String>,
    ordered: &mut Vec<String>,
) -> Result<(), TopologyError> {
    match state.get(&group.name) {
        Some(VisitState::Done) => return Ok(()),
        Some(VisitState::Visiting) => {
            let loop_start = stack
                .iter()
                .position(|name| name == &group.name)
                .unwrap_or(0);
            return Err(TopologyError::GroupDependencyLoop(stack[loop_start..].to_vec()));
        }
        None => {}
    }

    state.insert(group.name.clone(), VisitState::Visiting);
    stack.push(group.name.clone());
    for dependency in &group.proxies {
        if let Some(child_group) = group_index.get(dependency) {
            visit_group(child_group, group_index, state, stack, ordered)?;
        }
    }
    stack.pop();
    state.insert(group.name.clone(), VisitState::Done);
    ordered.push(group.name.clone());
    Ok(())
}

#[cfg(test)]
mod tests {
    use mihomo_config::parse_runtime_config_document;

    use super::{assemble_proxy_topology, TopologyError};

    #[test]
    fn assembles_dependency_order_and_injects_global() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: direct
    name: direct-a
proxy-providers:
  provider1:
    type: inline
    payload:
      - type: direct
        name: provider-direct
proxy-groups:
  - name: outer
    type: select
    proxies: [inner, DIRECT]
  - name: inner
    type: url-test
    proxies: [direct-a]
    url: https://cp.cloudflare.com/generate_204
    interval: 300
"#,
        )
        .unwrap();

        let topology = assemble_proxy_topology(&document).unwrap();
        assert_eq!(topology.group_names_in_dependency_order, vec!["inner", "outer"]);
        assert_eq!(topology.group_names_in_original_order, vec!["outer", "inner"]);
        assert!(topology.injected_global);
        assert!(topology.final_proxy_names.contains("GLOBAL"));
        assert_eq!(topology.synthetic_default_provider_members, vec!["DIRECT", "REJECT", "direct-a", "outer", "inner"]);
        assert_eq!(topology.all_provider_names_sorted, vec!["provider1"]);
    }

    #[test]
    fn include_all_proxies_and_providers_expand_during_assembly() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: direct
    name: b
  - type: direct
    name: a
proxy-providers:
  provider2:
    type: inline
    payload:
      - type: direct
        name: provider-direct
proxy-groups:
  - name: all
    type: select
    include-all: true
"#,
        )
        .unwrap();

        let topology = assemble_proxy_topology(&document).unwrap();
        assert_eq!(topology.resolved_groups_in_dependency_order.len(), 1);
        assert_eq!(topology.resolved_groups_in_dependency_order[0].proxies, vec!["a", "b"]);
        assert_eq!(topology.resolved_groups_in_dependency_order[0].use_providers, vec!["provider2"]);
    }

    #[test]
    fn detects_group_dependency_loop() {
        let document = parse_runtime_config_document(
            r#"
proxy-groups:
  - name: a
    type: select
    proxies: [b]
  - name: b
    type: select
    proxies: [a]
"#,
        )
        .unwrap();

        assert_eq!(
            assemble_proxy_topology(&document).unwrap_err(),
            TopologyError::GroupDependencyLoop(vec!["a".into(), "b".into()])
        );
    }

    #[test]
    fn detects_dialer_proxy_cycle() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: direct
    name: a
    dialer-proxy: b
  - type: direct
    name: b
    dialer-proxy: a
"#,
        )
        .unwrap();

        assert_eq!(
            assemble_proxy_topology(&document).unwrap_err(),
            TopologyError::DialerProxyCycle("a".into())
        );
    }

    #[test]
    fn detects_missing_dialer_proxy_reference() {
        let document = parse_runtime_config_document(
            r#"
proxies:
  - type: direct
    name: a
    dialer-proxy: missing
"#,
        )
        .unwrap();

        assert_eq!(
            assemble_proxy_topology(&document).unwrap_err(),
            TopologyError::DialerProxyNotFound {
                proxy: "a".into(),
                dialer_proxy: "missing".into()
            }
        );
    }
}
