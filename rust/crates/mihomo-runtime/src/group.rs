use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};

use mihomo_outbound::{GroupDefinition, ProxyProviderDefinition};
use mihomo_core::Metadata;

use crate::ResolvedGroup;

const DEFAULT_TEST_URL: &str = "https://www.gstatic.com/generate_204";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyCandidate {
    pub name: String,
    pub alive: bool,
    pub last_delay_ms: u16,
    pub supports_udp: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadBalanceStrategy {
    ConsistentHashing,
    RoundRobin,
    StickySessions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeGroup {
    pub group: ResolvedGroup,
    pub disable_udp: bool,
    pub tolerance_ms: u16,
    pub load_balance_strategy: LoadBalanceStrategy,
    pub test_url: String,
    pub expected_status: String,
    selected: Option<String>,
    fast_node: Option<String>,
    round_robin_index: usize,
    sticky_sessions: BTreeMap<String, String>,
}

impl RuntimeGroup {
    pub fn new(group: ResolvedGroup) -> Self {
        Self {
            group,
            disable_udp: false,
            tolerance_ms: 0,
            load_balance_strategy: LoadBalanceStrategy::ConsistentHashing,
            test_url: String::new(),
            expected_status: String::new(),
            selected: None,
            fast_node: None,
            round_robin_index: 0,
            sticky_sessions: BTreeMap::new(),
        }
    }

    pub fn set_selected(&mut self, name: impl Into<String>) {
        self.selected = Some(name.into());
    }

    pub fn clear_selected(&mut self) {
        self.selected = None;
    }

    pub fn selected(&self) -> Option<&str> {
        self.selected.as_deref()
    }

    pub fn choose<'a>(
        &'a mut self,
        proxies: &'a [ProxyCandidate],
        metadata: Option<&Metadata>,
    ) -> Option<&'a ProxyCandidate> {
        if proxies.is_empty() {
            return None;
        }
        match self.group.group_type.as_str() {
            "select" => self.choose_select(proxies),
            "url-test" => self.choose_url_test(proxies),
            "fallback" => self.choose_fallback(proxies),
            "load-balance" => self.choose_load_balance(proxies, metadata),
            _ => proxies.first(),
        }
    }

    pub fn supports_udp(
        &mut self,
        proxies: &[ProxyCandidate],
        metadata: Option<&Metadata>,
    ) -> bool {
        if self.disable_udp {
            return false;
        }
        self.choose(proxies, metadata)
            .is_some_and(|proxy| proxy.supports_udp)
    }

    fn choose_select<'a>(&'a mut self, proxies: &'a [ProxyCandidate]) -> Option<&'a ProxyCandidate> {
        if let Some(selected) = &self.selected {
            if let Some(proxy) = proxies.iter().find(|proxy| proxy.name == *selected) {
                return Some(proxy);
            }
        }
        proxies.first()
    }

    fn choose_fallback<'a>(&'a mut self, proxies: &'a [ProxyCandidate]) -> Option<&'a ProxyCandidate> {
        if let Some(selected) = &self.selected {
            if let Some(proxy) = proxies.iter().find(|proxy| proxy.name == *selected && proxy.alive) {
                return Some(proxy);
            }
            self.selected = None;
        }
        proxies.iter().find(|proxy| proxy.alive).or_else(|| proxies.first())
    }

    fn choose_url_test<'a>(&'a mut self, proxies: &'a [ProxyCandidate]) -> Option<&'a ProxyCandidate> {
        if let Some(selected) = &self.selected {
            if let Some(proxy) = proxies.iter().find(|proxy| proxy.name == *selected && proxy.alive) {
                return Some(proxy);
            }
        }

        let fastest = proxies
            .iter()
            .filter(|proxy| proxy.alive)
            .min_by_key(|proxy| proxy.last_delay_ms)
            .or_else(|| proxies.first())?;

        match &self.fast_node {
            Some(current_name) => {
                if let Some(current) = proxies.iter().find(|proxy| proxy.name == *current_name && proxy.alive) {
                    if current.last_delay_ms <= fastest.last_delay_ms.saturating_add(self.tolerance_ms) {
                        return Some(current);
                    }
                }
            }
            None => {}
        }

        self.fast_node = Some(fastest.name.clone());
        Some(fastest)
    }

    fn choose_load_balance<'a>(
        &'a mut self,
        proxies: &'a [ProxyCandidate],
        metadata: Option<&Metadata>,
    ) -> Option<&'a ProxyCandidate> {
        match self.load_balance_strategy {
            LoadBalanceStrategy::ConsistentHashing => self.choose_consistent_hashing(proxies, metadata),
            LoadBalanceStrategy::RoundRobin => self.choose_round_robin(proxies),
            LoadBalanceStrategy::StickySessions => self.choose_sticky_sessions(proxies, metadata),
        }
    }

    fn choose_round_robin<'a>(&'a mut self, proxies: &'a [ProxyCandidate]) -> Option<&'a ProxyCandidate> {
        if proxies.is_empty() {
            return None;
        }
        let length = proxies.len();
        for step in 0..length {
            let index = (self.round_robin_index + step) % length;
            if proxies[index].alive {
                self.round_robin_index = (index + 1) % length;
                return Some(&proxies[index]);
            }
        }
        let proxy = &proxies[self.round_robin_index % length];
        self.round_robin_index = (self.round_robin_index + 1) % length;
        Some(proxy)
    }

    fn choose_consistent_hashing<'a>(
        &'a mut self,
        proxies: &'a [ProxyCandidate],
        metadata: Option<&Metadata>,
    ) -> Option<&'a ProxyCandidate> {
        if proxies.is_empty() {
            return None;
        }
        let mut key = stable_hash(&load_balance_key(metadata));
        let buckets = proxies.len() as i32;
        for _ in 0..5 {
            let index = jump_hash(key, buckets) as usize;
            let proxy = &proxies[index];
            if proxy.alive {
                return Some(proxy);
            }
            key = key.wrapping_add(1);
        }
        proxies.iter().find(|proxy| proxy.alive).or_else(|| proxies.first())
    }

    fn choose_sticky_sessions<'a>(
        &'a mut self,
        proxies: &'a [ProxyCandidate],
        metadata: Option<&Metadata>,
    ) -> Option<&'a ProxyCandidate> {
        if proxies.is_empty() {
            return None;
        }
        let key = sticky_key(metadata);
        if let Some(name) = self.sticky_sessions.get(&key) {
            if let Some(proxy) = proxies.iter().find(|proxy| proxy.name == *name && proxy.alive) {
                return Some(proxy);
            }
        }

        let chosen_name = self
            .choose_consistent_hashing(proxies, metadata)
            .or_else(|| proxies.first())
            .map(|proxy| proxy.name.clone())?;
        self.sticky_sessions.insert(key, chosen_name.clone());
        proxies.iter().find(|proxy| proxy.name == chosen_name)
    }
}

pub fn build_runtime_groups(
    resolved_groups: &[ResolvedGroup],
    group_definitions: &[GroupDefinition],
    proxy_providers: &BTreeMap<String, ProxyProviderDefinition>,
) -> Vec<RuntimeGroup> {
    let group_index = group_definitions
        .iter()
        .map(|definition| (definition.name.clone(), definition))
        .collect::<BTreeMap<_, _>>();

    resolved_groups
        .iter()
        .filter_map(|resolved| {
            let definition = group_index.get(&resolved.name)?;
            let mut runtime_group = RuntimeGroup::new(resolved.clone());
            runtime_group.disable_udp = definition.disable_udp;
            runtime_group.tolerance_ms = definition.tolerance.max(0) as u16;
            runtime_group.load_balance_strategy = parse_load_balance_strategy(&definition.strategy);
            runtime_group.test_url =
                determine_group_test_url(definition, resolved, proxy_providers).to_owned();
            runtime_group.expected_status = if definition.expected_status.trim().is_empty() {
                "*".to_owned()
            } else {
                definition.expected_status.clone()
            };
            Some(runtime_group)
        })
        .collect()
}

fn determine_group_test_url<'a>(
    definition: &'a GroupDefinition,
    resolved: &ResolvedGroup,
    proxy_providers: &'a BTreeMap<String, ProxyProviderDefinition>,
) -> &'a str {
    if !definition.url.trim().is_empty() {
        return &definition.url;
    }
    if !resolved.use_providers.is_empty() {
        for provider_name in &resolved.use_providers {
            if let Some(provider) = proxy_providers.get(provider_name) {
                if !provider.health_check.url.trim().is_empty() {
                    return &provider.health_check.url;
                }
            }
        }
    }
    match resolved.group_type.as_str() {
        "url-test" | "fallback" | "load-balance" => DEFAULT_TEST_URL,
        _ => "",
    }
}

fn parse_load_balance_strategy(strategy: &str) -> LoadBalanceStrategy {
    match strategy {
        "round-robin" => LoadBalanceStrategy::RoundRobin,
        "sticky-sessions" => LoadBalanceStrategy::StickySessions,
        _ => LoadBalanceStrategy::ConsistentHashing,
    }
}

fn load_balance_key(metadata: Option<&Metadata>) -> String {
    let Some(metadata) = metadata else {
        return String::new();
    };
    if let Some(host) = metadata.host.as_ref().filter(|host| !host.is_empty()) {
        return host.clone();
    }
    if let Some(dst_ip) = metadata.dst_ip {
        return dst_ip.to_string();
    }
    String::new()
}

fn sticky_key(metadata: Option<&Metadata>) -> String {
    let Some(metadata) = metadata else {
        return String::new();
    };
    format!(
        "{}|{}",
        metadata
            .src_ip
            .map(|ip| ip.to_string())
            .unwrap_or_default(),
        load_balance_key(Some(metadata))
    )
}

fn stable_hash(input: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    input.hash(&mut hasher);
    hasher.finish()
}

fn jump_hash(mut key: u64, buckets: i32) -> i32 {
    let mut b: i64 = -1;
    let mut j: i64 = 0;
    while j < i64::from(buckets) {
        b = j;
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        j = (((b + 1) as f64) * ((1_u64 << 31) as f64 / ((key >> 33) + 1) as f64)) as i64;
    }
    b as i32
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};

    use mihomo_core::Metadata;

    use mihomo_outbound::{GroupDefinition, ProxyProviderDefinition};

    use super::{
        build_runtime_groups, LoadBalanceStrategy, ProxyCandidate, RuntimeGroup, DEFAULT_TEST_URL,
    };
    use crate::ResolvedGroup;

    fn group(name: &str, group_type: &str, proxies: &[&str]) -> RuntimeGroup {
        RuntimeGroup::new(ResolvedGroup {
            name: name.into(),
            group_type: group_type.into(),
            proxies: proxies.iter().map(|value| (*value).into()).collect(),
            use_providers: vec![],
        })
    }

    fn candidate(name: &str, alive: bool, delay: u16) -> ProxyCandidate {
        ProxyCandidate {
            name: name.into(),
            alive,
            last_delay_ms: delay,
            supports_udp: true,
        }
    }

    #[test]
    fn select_group_honors_selected_proxy_when_present() {
        let mut group = group("selector", "select", &["a", "b"]);
        group.set_selected("b");
        let proxies = vec![candidate("a", true, 10), candidate("b", true, 20)];
        assert_eq!(group.choose(&proxies, None).unwrap().name, "b");
    }

    #[test]
    fn url_test_group_keeps_current_fast_node_within_tolerance() {
        let mut group = group("auto", "url-test", &["a", "b"]);
        group.tolerance_ms = 15;
        let first = vec![candidate("a", true, 40), candidate("b", true, 50)];
        assert_eq!(group.choose(&first, None).unwrap().name, "a");

        let second = vec![candidate("a", true, 50), candidate("b", true, 45)];
        assert_eq!(group.choose(&second, None).unwrap().name, "a");
    }

    #[test]
    fn fallback_group_chooses_first_alive_proxy() {
        let mut group = group("fallback", "fallback", &["a", "b", "c"]);
        let proxies = vec![
            candidate("a", false, 10),
            candidate("b", true, 20),
            candidate("c", true, 5),
        ];
        assert_eq!(group.choose(&proxies, None).unwrap().name, "b");
    }

    #[test]
    fn round_robin_load_balance_rotates_alive_nodes() {
        let mut group = group("lb", "load-balance", &["a", "b"]);
        group.load_balance_strategy = LoadBalanceStrategy::RoundRobin;
        let proxies = vec![candidate("a", true, 10), candidate("b", true, 20)];
        assert_eq!(group.choose(&proxies, None).unwrap().name, "a");
        assert_eq!(group.choose(&proxies, None).unwrap().name, "b");
        assert_eq!(group.choose(&proxies, None).unwrap().name, "a");
    }

    #[test]
    fn sticky_sessions_reuses_session_key() {
        let mut group = group("lb", "load-balance", &["a", "b"]);
        group.load_balance_strategy = LoadBalanceStrategy::StickySessions;
        let proxies = vec![candidate("a", true, 10), candidate("b", true, 20)];
        let metadata = Metadata {
            host: Some("example.com".into()),
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            ..Metadata::default()
        };
        let first = group.choose(&proxies, Some(&metadata)).unwrap().name.clone();
        let second = group.choose(&proxies, Some(&metadata)).unwrap().name.clone();
        assert_eq!(first, second);
    }

    #[test]
    fn runtime_groups_pick_provider_healthcheck_url_when_group_url_is_empty() {
        let resolved = vec![ResolvedGroup {
            name: "auto".into(),
            group_type: "url-test".into(),
            proxies: vec!["DIRECT".into()],
            use_providers: vec!["provider1".into()],
        }];
        let definitions = vec![GroupDefinition {
            name: "auto".into(),
            group_type: "url-test".into(),
            proxies: vec![],
            use_providers: vec!["provider1".into()],
            url: String::new(),
            interval: 0,
            timeout: 0,
            max_failed_times: 0,
            lazy: true,
            disable_udp: false,
            filter: String::new(),
            exclude_filter: String::new(),
            exclude_type: String::new(),
            expected_status: String::new(),
            include_all: false,
            include_all_proxies: false,
            include_all_providers: false,
            hidden: false,
            icon: String::new(),
            strategy: String::new(),
            tolerance: 25,
            extra: BTreeMap::new(),
        }];
        let providers = BTreeMap::from([(
            "provider1".into(),
            ProxyProviderDefinition {
                provider_type: "http".into(),
                health_check: mihomo_outbound::ProviderHealthCheckConfig {
                    enable: true,
                    url: "https://cp.cloudflare.com/generate_204".into(),
                    interval: 600,
                    timeout: 0,
                    lazy: true,
                    expected_status: String::new(),
                },
                ..ProxyProviderDefinition::default()
            },
        )]);

        let groups = build_runtime_groups(&resolved, &definitions, &providers);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].test_url, "https://cp.cloudflare.com/generate_204");
        assert_eq!(groups[0].expected_status, "*");
        assert_eq!(groups[0].tolerance_ms, 25);
    }

    #[test]
    fn load_balance_strategy_defaults_and_overrides_are_applied() {
        let resolved = vec![ResolvedGroup {
            name: "lb".into(),
            group_type: "load-balance".into(),
            proxies: vec!["DIRECT".into()],
            use_providers: vec![],
        }];
        let mut definitions = vec![GroupDefinition {
            name: "lb".into(),
            group_type: "load-balance".into(),
            proxies: vec!["DIRECT".into()],
            use_providers: vec![],
            url: String::new(),
            interval: 0,
            timeout: 0,
            max_failed_times: 0,
            lazy: true,
            disable_udp: false,
            filter: String::new(),
            exclude_filter: String::new(),
            exclude_type: String::new(),
            expected_status: String::new(),
            include_all: false,
            include_all_proxies: false,
            include_all_providers: false,
            hidden: false,
            icon: String::new(),
            strategy: String::new(),
            tolerance: 0,
            extra: BTreeMap::new(),
        }];

        let default_group = build_runtime_groups(&resolved, &definitions, &BTreeMap::new());
        assert_eq!(
            default_group[0].load_balance_strategy,
            LoadBalanceStrategy::ConsistentHashing
        );
        assert_eq!(default_group[0].test_url, DEFAULT_TEST_URL);

        definitions[0].strategy = "round-robin".into();
        let rr_group = build_runtime_groups(&resolved, &definitions, &BTreeMap::new());
        assert_eq!(rr_group[0].load_balance_strategy, LoadBalanceStrategy::RoundRobin);
    }
}
