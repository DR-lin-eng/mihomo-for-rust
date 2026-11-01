mod common;
mod dns;
mod legacy;
mod listener_surface;
mod udp;

use std::collections::{BTreeMap, BTreeSet};

use mihomo_config::BootOptions;
use mihomo_core::Metadata;
use mihomo_inbound::InboundDefinition;
use mihomo_rules::{parse_rule, RuleType};
use mihomo_runtime::{
    detect_native_support_gaps, resolve_proxy_path_preferring_selected, BootstrapState,
    CandidateState, NativeSupportGap,
};

use mihomo_tun::TunUdpRuntimeMode;

use self::common::filter_support_gaps_for_default_path;
pub(crate) use self::legacy::{hand_off_to_legacy_runtime, render_native_support_gap_error};
#[cfg(test)]
pub(crate) use self::legacy::legacy_runtime_args;

const LOW_MEMORY_RULE_MODE_AVAILABLE_KIB: u64 = 1024 * 1024;
const LOW_MEMORY_RULE_MODE_TOTAL_KIB: u64 = 2048 * 1024;

struct TunSupportReport {
    lines: Vec<String>,
}

pub(crate) fn effective_native_support_gaps(state: &BootstrapState) -> Vec<NativeSupportGap> {
    // Startup should only fall back for proxies that are actually reachable from the startup
    // root path or from explicitly pinned listener/provider targets. Avoid compiling the full
    // rule table here: on constrained OpenWrt devices that can OOM the process before the
    // runtime even starts listening.
    let default_path_names = Some(startup_root_proxy_names(state));
    let mut gaps = filter_support_gaps_for_default_path(
        detect_native_support_gaps(&state.registry),
        default_path_names.as_ref(),
    );
    gaps.extend(listener_surface::listener_surface_support_gaps(
        &state.document,
    ));
    gaps.extend(dns::dns_runtime_support_gaps(&state.document));
    if listener_surface::config_exposes_udp_surface(&state.document) {
        gaps.extend(filter_support_gaps_for_default_path(
            udp::udp_runtime_support_gaps(&state.registry),
            default_path_names.as_ref(),
        ));
    }
    if let Some(gap) = runtime_tunnel_memory_support_gap(state) {
        gaps.push(gap);
    }
    gaps.sort_by(|left, right| {
        left.provider_name
            .cmp(&right.provider_name)
            .then_with(|| left.proxy_name.cmp(&right.proxy_name))
            .then_with(|| left.reason.cmp(&right.reason))
    });
    gaps.dedup_by(|left, right| {
        left.proxy_name == right.proxy_name
            && left.kind == right.kind
            && left.provider_name == right.provider_name
            && left.reason == right.reason
    });
    gaps
}

pub(crate) fn should_fallback_to_legacy(options: &BootOptions, gaps: &[NativeSupportGap]) -> bool {
    !options.test_config && !gaps.is_empty() && !force_native_runtime_requested()
}

pub(crate) fn should_abort_on_native_support_gaps(
    options: &BootOptions,
    gaps: &[NativeSupportGap],
) -> bool {
    !options.test_config && !gaps.is_empty() && force_native_runtime_requested()
}

pub(crate) fn render_top_level_tun_support_report(state: &BootstrapState) -> Option<String> {
    let tun = &state.document.tun;
    if !tun.enable {
        return None;
    }

    Some(build_top_level_tun_support_report(state).lines.join("\n"))
}

fn build_top_level_tun_support_report(state: &BootstrapState) -> TunSupportReport {
    let tun = &state.document.tun;

    let stack = match &tun.config.stack {
        mihomo_inbound::TunStack::Gvisor => "gvisor",
        mihomo_inbound::TunStack::System => "system",
        mihomo_inbound::TunStack::Mixed => "mixed",
        mihomo_inbound::TunStack::Unknown(raw) => raw.as_str(),
    };

    let mut lines = vec!["tun field report:".to_owned()];
    lines.push("- platform-surface=linux-native-or-external-file-descriptor status=partial".to_owned());
    let tcp_data_plane = if tun.config.auto_route && tun.config.auto_redirect {
        "- tcp-data-plane=transparent-listener-path-with-tun-tcp-bypass status=closer-to-go-system-but-still-partial"
    } else {
        "- tcp-data-plane=passive-smoltcp-bridge status=supported-but-not-go-system"
    };
    lines.push(tcp_data_plane.to_owned());
    let spec = mihomo_tun::TunRuntimeSpec::new("__top_level_tun__", tun.config.clone());
    let udp_data_plane = match spec.udp_runtime_mode() {
        TunUdpRuntimeMode::DirectRelay => {
            if tun.config.endpoint_independent_nat {
                "- udp-data-plane=source-port-session-reuse-direct-packet-relay status=closer-to-go-mixed-but-still-not-gvisor"
            } else {
                "- udp-data-plane=fixed-worker-queue-direct-packet-relay status=supported-but-not-go-gvisor"
            }
        }
        TunUdpRuntimeMode::MixedLikeRelay => {
            "- udp-data-plane=source-port-session-reuse-direct-packet-relay status=closer-to-go-mixed-but-still-not-gvisor"
        }
    };
    lines.push(udp_data_plane.to_owned());
    if tun.config.disable_icmp_forwarding {
        lines.push("- icmp-data-plane=fake-echo-when-disable-icmp-forwarding=true status=partial".to_owned());
    } else {
        lines.push("- icmp-data-plane=missing status=gap".to_owned());
    }
    lines.push(format!(
        "- stack={} status={}",
        stack,
        match stack {
            "system" => "supported-but-not-go-1:1",
            "mixed" => {
                if tun.config.auto_route && tun.config.auto_redirect {
                    "partially-supported-linux-auto-route-auto-redirect"
                } else {
                    "supported-passive-tcp-and-packet-udp"
                }
            }
            "gvisor" => "gap",
            _ => "gap",
        }
    ));
    if !tun.config.dns_hijack.is_empty() {
        lines.push(format!(
            "- dns-hijack={} status=supported",
            tun.config.dns_hijack.len()
        ));
    }
    if tun.config.mtu != 0 {
        lines.push(format!("- mtu={} status=supported", tun.config.mtu));
    }
    if !tun.config.inet4_address.is_empty() {
        lines.push(format!(
            "- inet4-address={} status=supported",
            tun.config.inet4_address.len()
        ));
    }
    if !tun.config.inet6_address.is_empty() {
        lines.push(format!(
            "- inet6-address={} status=supported",
            tun.config.inet6_address.len()
        ));
    }
    if tun.config.auto_route {
        lines.push("- auto-route=true status=supported".to_owned());
    }
    if tun.config.auto_redirect {
        let status = if tun.config.auto_redirect_output_mark != 0
            || tun.config.auto_redirect_iproute2_fallback_rule_index > 0
        {
            "partial-mark-mode-command-layer"
        } else {
            "supported"
        };
        lines.push(format!("- auto-redirect=true status={status}"));
    }
    if tun.config.auto_redirect_input_mark != 0 {
        lines.push(format!(
            "- auto-redirect-input-mark={} status=supported",
            tun.config.auto_redirect_input_mark
        ));
    }
    if tun.config.strict_route {
        lines.push("- strict-route=true status=supported".to_owned());
    }
    if tun.config.auto_detect_interface {
        lines.push("- auto-detect-interface=true status=supported".to_owned());
    }
    if !tun.config.route_address.is_empty() {
        lines.push(format!(
            "- route-address={} status=supported",
            tun.config.route_address.len()
        ));
    }
    if !tun.config.route_exclude_address.is_empty() {
        lines.push(format!(
            "- route-exclude-address={} status=supported",
            tun.config.route_exclude_address.len()
        ));
    }
    if !tun.config.route_address_set.is_empty() {
        lines.push(format!(
            "- route-address-set={} status=supported-restart-based",
            tun.config.route_address_set.len()
        ));
    }
    if !tun.config.route_exclude_address_set.is_empty() {
        lines.push(format!(
            "- route-exclude-address-set={} status=supported-static-load",
            tun.config.route_exclude_address_set.len()
        ));
    }
    if !tun.config.include_interface.is_empty() || !tun.config.exclude_interface.is_empty() {
        lines.push(format!(
            "- interface-filters include={} exclude={} status=supported",
            tun.config.include_interface.len(),
            tun.config.exclude_interface.len()
        ));
    }
    if !tun.config.include_uid.is_empty()
        || !tun.config.include_uid_range.is_empty()
        || !tun.config.exclude_uid.is_empty()
        || !tun.config.exclude_uid_range.is_empty()
    {
        lines.push(format!(
            "- uid-filters include={} include-range={} exclude={} exclude-range={} status=supported",
            tun.config.include_uid.len(),
            tun.config.include_uid_range.len(),
            tun.config.exclude_uid.len(),
            tun.config.exclude_uid_range.len()
        ));
    }
    if !tun.config.exclude_src_port.is_empty()
        || !tun.config.exclude_src_port_range.is_empty()
        || !tun.config.exclude_dst_port.is_empty()
        || !tun.config.exclude_dst_port_range.is_empty()
    {
        lines.push(format!(
            "- port-filters exclude-src={} exclude-src-range={} exclude-dst={} exclude-dst-range={} status=supported",
            tun.config.exclude_src_port.len(),
            tun.config.exclude_src_port_range.len(),
            tun.config.exclude_dst_port.len(),
            tun.config.exclude_dst_port_range.len()
        ));
    }
    if !tun.config.include_package.is_empty() || !tun.config.exclude_package.is_empty() {
        lines.push(format!(
            "- package-filters include={} exclude={} status=inactive-on-linux",
            tun.config.include_package.len(),
            tun.config.exclude_package.len()
        ));
    }
    if !tun.config.include_mac_address.is_empty() || !tun.config.exclude_mac_address.is_empty() {
        lines.push(format!(
            "- mac-filters include={} exclude={} status=gap",
            tun.config.include_mac_address.len(),
            tun.config.exclude_mac_address.len()
        ));
    }
    if tun.config.endpoint_independent_nat {
        lines.push("- endpoint-independent-nat=true status=source-port-session-reuse-only".to_owned());
    }
    if tun.config.disable_icmp_forwarding {
        lines.push("- disable-icmp-forwarding=true status=partial-fake-echo-only".to_owned());
    }
    if tun.config.gso || tun.config.gso_max_size > 0 {
        lines.push(format!(
            "- gso={} gso-max-size={} status=gap",
            tun.config.gso,
            tun.config.gso_max_size
        ));
    }
    if tun.config.recvmsgx || tun.config.sendmsgx {
        lines.push(format!(
            "- recvmsgx={} sendmsgx={} status=gap",
            tun.config.recvmsgx,
            tun.config.sendmsgx
        ));
    }
    if tun.config.auto_redirect_output_mark != 0 {
        lines.push(format!(
            "- auto-redirect-output-mark={} status=partial-command-layer",
            tun.config.auto_redirect_output_mark
        ));
        lines.push(
            "- auto-redirect-mark-mode-model=iptables-ip-rule-command-layer-with-global-routing-mark-missing-loopback-reroute-and-nftables-parity status=gap"
                .to_owned(),
        );
    }
    if tun.config.auto_redirect_iproute2_fallback_rule_index > 0 {
        lines.push(format!(
            "- auto-redirect-iproute2-fallback-rule-index={} status=partial-command-layer",
            tun.config.auto_redirect_iproute2_fallback_rule_index
        ));
    }
    if !tun.config.loopback_address.is_empty() {
        let (status, model) = if tun.config.auto_redirect {
            (
                "partial-tcp-data-plane-and-iptables-reroute-command-layer",
                "system-tcp-bounce-plus-iptables-output-prerouting-connmark-command-layer-missing-go-nftables-and-full-system-stack-parity",
            )
        } else {
            (
                "partial-tcp-data-plane-only",
                "system-tcp-bounce-after-tun-ingress-missing-linux-reroute-command-layer-and-go-system-parity",
            )
        };
        lines.push(format!(
            "- loopback-address={} status={status}",
            tun.config.loopback_address.len(),
        ));
        lines.push(format!("- loopback-address-model={model} status=gap"));
    }

    let tun_gaps = effective_native_support_gaps(state)
        .into_iter()
        .filter(|gap| gap.proxy_name == "__top_level_tun__")
        .map(|gap| gap.reason)
        .collect::<Vec<_>>();
    if tun_gaps.is_empty() {
        lines.push(
            "tun native-support verdict: top-level tun is eligible for native startup".to_owned(),
        );
    } else {
        lines.push(
            "tun native-support verdict: normal startup would fall back to legacy; forcing native startup would abort"
                .to_owned(),
        );
        for reason in &tun_gaps {
            lines.push(format!("- {reason}"));
        }
    }
    TunSupportReport {
        lines,
    }
}

pub(crate) fn force_native_runtime_requested() -> bool {
    std::env::var("MIHOMO_FORCE_NATIVE_RUNTIME")
        .ok()
        .is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
}

fn startup_root_proxy_names(state: &BootstrapState) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut registry = state.registry.clone();
    for target in startup_root_targets(state) {
        match resolve_proxy_path_preferring_selected(
            &mut registry,
            &target,
            Some(&Metadata::default()),
            &BTreeMap::<String, CandidateState>::new(),
        ) {
            Ok(resolved) => {
                names.extend(resolved.selected_path);
                names.extend(resolved.dialer_path);
            }
            Err(err) => startup_trace(&format!(
                "native-support:skip-startup-root target={target} error={err}"
            )),
        }
    }
    names
}

fn startup_root_targets(state: &BootstrapState) -> BTreeSet<String> {
    let mut targets = BTreeSet::new();
    let mode = state.document.mode.trim().to_ascii_lowercase();
    match mode.as_str() {
        "global" => {
            if state.registry.groups.contains_key("GLOBAL") || state.registry.proxies.contains_key("GLOBAL")
            {
                targets.insert("GLOBAL".to_owned());
            }
        }
        "rule" => {
            if let Some(target) = default_rule_mode_target(&state.document.rules) {
                targets.insert(target);
            }
        }
        _ => {}
    }
    targets.extend(explicit_listener_targets(state));
    targets.extend(explicit_provider_proxy_targets(state));
    targets
}

fn default_rule_mode_target(rules: &[String]) -> Option<String> {
    rules.iter().rev().find_map(|raw| {
        let definition = parse_rule(raw).ok()?;
        if definition.rule_type != RuleType::Match {
            return None;
        }
        let target = definition.target.trim();
        if target.is_empty() || is_builtin_target(target) {
            None
        } else {
            Some(target.to_owned())
        }
    })
}

fn explicit_listener_targets(state: &BootstrapState) -> Vec<String> {
    let mut targets = Vec::new();
    if state.document.tun.enable {
        targets.push(state.document.tun.config.base.special_proxy.clone());
    }
    for listener in &state.document.listeners {
        let target = match listener {
            InboundDefinition::Socks(config) => &config.base.special_proxy,
            InboundDefinition::Http(config) => &config.base.special_proxy,
            InboundDefinition::Mixed(config) => &config.base.special_proxy,
            InboundDefinition::Redir(config) => &config.base.special_proxy,
            InboundDefinition::TProxy(config) => &config.base.special_proxy,
            InboundDefinition::Tunnel(config) => &config.base.special_proxy,
            InboundDefinition::Tun(config) => &config.base.special_proxy,
            _ => continue,
        };
        if !target.trim().is_empty() && !is_builtin_target(target.trim()) {
            targets.push(target.trim().to_owned());
        }
    }
    targets
}

fn explicit_provider_proxy_targets(state: &BootstrapState) -> Vec<String> {
    state
        .document
        .proxy_providers
        .values()
        .map(|provider| provider.proxy.as_str())
        .chain(
            state
                .document
                .rule_providers
                .values()
                .map(|provider| provider.proxy.as_str()),
        )
        .map(str::trim)
        .filter(|target| !target.is_empty() && !is_builtin_target(target))
        .map(ToOwned::to_owned)
        .collect()
}

fn is_builtin_target(target: &str) -> bool {
    matches!(
        target,
        "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS" | "GLOBAL" | "COMPATIBLE" | "dns"
    )
}

fn runtime_tunnel_memory_support_gap(state: &BootstrapState) -> Option<NativeSupportGap> {
    if force_native_runtime_requested() {
        return None;
    }
    if !state.document.mode.trim().eq_ignore_ascii_case("rule") {
        return None;
    }
    if state.document.rule_providers.is_empty() {
        return None;
    }
    let available_kib = mem_available_kib().unwrap_or(u64::MAX);
    let total_kib = mem_total_kib().unwrap_or(u64::MAX);
    if available_kib >= LOW_MEMORY_RULE_MODE_AVAILABLE_KIB
        && total_kib >= LOW_MEMORY_RULE_MODE_TOTAL_KIB
    {
        return None;
    }
    Some(NativeSupportGap {
        proxy_name: "runtime.rule-compiler".to_owned(),
        kind: None,
        provider_name: String::new(),
        reason: format!(
            "available memory {} KiB or total memory {} KiB is below the native rule runtime startup threshold (available {} KiB, total {} KiB)",
            available_kib,
            total_kib,
            LOW_MEMORY_RULE_MODE_AVAILABLE_KIB,
            LOW_MEMORY_RULE_MODE_TOTAL_KIB
        ),
    })
}

fn mem_available_kib() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_mem_available_kib(&text)
}

fn mem_total_kib() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_mem_total_kib(&text)
}

fn parse_mem_available_kib(text: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let rest = line.strip_prefix("MemAvailable:")?;
        rest.split_whitespace().next()?.parse::<u64>().ok()
    })
}

fn parse_mem_total_kib(text: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let rest = line.strip_prefix("MemTotal:")?;
        rest.split_whitespace().next()?.parse::<u64>().ok()
    })
}

fn startup_trace(stage: &str) {
    if std::env::var_os("MIHOMO_STARTUP_TRACE").is_some() {
        eprintln!("[startup-trace] {stage}");
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::Engine;
    use mihomo_config::{BootEnvironment, BootOptions, Command};
    use mihomo_runtime::bootstrap_from_boot_options;

    use super::{
        force_native_runtime_requested, parse_mem_available_kib,
        runtime_tunnel_memory_support_gap,
    };

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nanos}"))
    }

    #[test]
    fn parses_mem_available_from_proc_meminfo() {
        let text = "\
MemTotal:        2048000 kB
MemFree:          512000 kB
MemAvailable:     426600 kB
Buffers:           16000 kB
";
        assert_eq!(parse_mem_available_kib(text), Some(426600));
    }

    #[test]
    fn force_native_runtime_requested_recognizes_truthy_values() {
        let previous = std::env::var("MIHOMO_FORCE_NATIVE_RUNTIME").ok();
        unsafe {
            std::env::set_var("MIHOMO_FORCE_NATIVE_RUNTIME", "1");
        }
        assert!(force_native_runtime_requested());
        match previous {
            Some(value) => unsafe {
                std::env::set_var("MIHOMO_FORCE_NATIVE_RUNTIME", value);
            },
            None => unsafe {
                std::env::remove_var("MIHOMO_FORCE_NATIVE_RUNTIME");
            },
        }
    }

    #[test]
    fn force_native_runtime_skips_low_memory_rule_runtime_gap() {
        let temp = unique_temp_dir("mihomo-native-force-memory-gap");
        fs::create_dir_all(&temp).unwrap();
        fs::write(
            temp.join("rule-provider.yaml"),
            r#"
payload:
  - .example.com
"#,
        )
        .unwrap();
        let options = BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(base64::engine::general_purpose::STANDARD.encode(
                r#"
mode: rule
rule-providers:
  rule1:
    type: file
    behavior: domain
    path: rule-provider.yaml
proxies:
  - type: direct
    name: direct-a
rules:
  - RULE-SET,rule1,direct-a
"#,
            )),
            external_ui: None,
            external_controller: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            secret: None,
            post_up: None,
            post_down: None,
            geodata_mode: false,
            show_version: false,
            test_config: false,
            command: Command::Run,
        };
        let state =
            bootstrap_from_boot_options(&options, &temp, &BootEnvironment::default()).unwrap();
        let previous = std::env::var("MIHOMO_FORCE_NATIVE_RUNTIME").ok();
        unsafe {
            std::env::set_var("MIHOMO_FORCE_NATIVE_RUNTIME", "1");
        }
        assert!(runtime_tunnel_memory_support_gap(&state).is_none());
        match previous {
            Some(value) => unsafe {
                std::env::set_var("MIHOMO_FORCE_NATIVE_RUNTIME", value);
            },
            None => unsafe {
                std::env::remove_var("MIHOMO_FORCE_NATIVE_RUNTIME");
            },
        }
    }
}
