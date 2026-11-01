use std::io;
use std::net::{IpAddr, SocketAddr};
use std::process::Command;

use mihomo_config::{RuleProviderBehavior, RuntimeConfigDocument};
use mihomo_rules::load_rule_provider_payload_from_sources;
use mihomo_runtime::ProviderContentSources;
use mihomo_tun::TunRuntimeSpec;
use mihomo_runtime::build_tun_runtime_specs;

const DEFAULT_AUTO_REDIRECT_INPUT_MARK: u32 = 0x2023;
const DEFAULT_AUTO_REDIRECT_OUTPUT_MARK: u32 = 0x2024;
const DEFAULT_AUTO_REDIRECT_FALLBACK_RULE_INDEX: i32 = 32768;
const DNS_LISTENER_DPORT_RULE_PRIORITY: i32 = 8998;
const DNS_LISTENER_SPORT_RULE_PRIORITY: i32 = 8999;
pub(crate) struct TunAutoRedirectGuard {
    commands: Vec<Vec<String>>,
    default_routing_mark: Option<i32>,
}

impl TunAutoRedirectGuard {
    pub(crate) fn install(
        document: &RuntimeConfigDocument,
        provider_sources: Option<&ProviderContentSources>,
    ) -> io::Result<Option<Self>> {
        if !cfg!(target_os = "linux") {
            return Ok(None);
        }
        let specs = build_tun_runtime_specs(document);
        let Some(spec) = specs.iter().find(|spec| spec.config.auto_redirect) else {
            return Ok(None);
        };
        if !spec.config.auto_route {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tun auto-redirect requires auto-route=true",
            ));
        }
        if document.redir_port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tun auto-redirect requires redir-port to be configured for TCP interception",
            ));
        }
        let device = spec.config.device.trim();
        if device.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tun auto-redirect requires a stable tun device name",
            ));
        }

        let input_mark = if spec.config.auto_redirect_input_mark != 0 {
            spec.config.auto_redirect_input_mark
        } else {
            DEFAULT_AUTO_REDIRECT_INPUT_MARK
        };
        let output_mark = if spec.config.auto_redirect_output_mark != 0 {
            spec.config.auto_redirect_output_mark
        } else {
            DEFAULT_AUTO_REDIRECT_OUTPUT_MARK
        };
        let fallback_rule = if spec.config.auto_redirect_iproute2_fallback_rule_index > 0 {
            spec.config.auto_redirect_iproute2_fallback_rule_index
        } else {
            DEFAULT_AUTO_REDIRECT_FALLBACK_RULE_INDEX
        };
        let table = if spec.config.iproute2_table_index > 0 {
            spec.config.iproute2_table_index
        } else {
            2022
        };
        let dns_redirect_port = document
            .dns
            .listen
            .trim()
            .parse::<SocketAddr>()
            .ok()
            .map(|addr| addr.port())
            .filter(|_| document.dns.enable);
        let mark_mode = auto_redirect_mark_mode_enabled(spec);

        let commands = render_setup_commands(
            document,
            provider_sources,
            spec,
            document.redir_port,
            dns_redirect_port,
            input_mark,
            output_mark,
            fallback_rule,
            table,
        )?;
        for command in &commands {
            run_command(command)?;
        }
        if mark_mode {
            mihomo_transport::set_default_routing_mark(output_mark as i32);
        }

        Ok(Some(Self {
            commands: render_cleanup_commands(
                dns_redirect_port,
                input_mark,
                output_mark,
                fallback_rule,
                table,
            ),
            default_routing_mark: if mark_mode {
                Some(output_mark as i32)
            } else {
                None
            },
        }))
    }

    pub(crate) fn uninstall(&mut self) {
        if self.default_routing_mark.take().is_some() {
            mihomo_transport::clear_default_routing_mark();
        }
        for command in self.commands.iter().rev() {
            let _ = run_command_allow_missing(command);
        }
    }
}

impl Drop for TunAutoRedirectGuard {
    fn drop(&mut self) {
        self.uninstall();
    }
}

fn auto_redirect_mark_mode_enabled(spec: &TunRuntimeSpec) -> bool {
    spec.config.auto_redirect_output_mark != 0
        || spec.config.auto_redirect_iproute2_fallback_rule_index > 0
}

fn render_setup_commands(
    document: &RuntimeConfigDocument,
    provider_sources: Option<&ProviderContentSources>,
    spec: &TunRuntimeSpec,
    redir_port: u16,
    dns_redirect_port: Option<u16>,
    input_mark: u32,
    output_mark: u32,
    fallback_rule: i32,
    table: i32,
) -> io::Result<Vec<Vec<String>>> {
    let device = spec.config.device.trim();
    let mut route_address = collect_family_prefixes(
        &spec.config.route_address,
        &spec.config.inet4_route_address,
        &spec.config.inet6_route_address,
    );
    route_address.extend(resolve_route_set_prefixes(
        document,
        provider_sources,
        &spec.config.route_address_set,
    )?);
    let mut route_exclude_address = collect_family_prefixes(
        &spec.config.route_exclude_address,
        &spec.config.inet4_route_exclude_address,
        &spec.config.inet6_route_exclude_address,
    );
    route_exclude_address.extend(resolve_route_set_prefixes(
        document,
        provider_sources,
        &spec.config.route_exclude_address_set,
    )?);
    let loopback_addresses = collect_loopback_addresses(&spec.config.loopback_address);
    let mark_mode = auto_redirect_mark_mode_enabled(spec);

        let mut commands = vec![
        ];
    if let Some(dns_port) = dns_redirect_port {
        commands.extend([
            vec![
                "ip".into(),
                "rule".into(),
                "add".into(),
                "dport".into(),
                dns_port.to_string(),
                "lookup".into(),
                "main".into(),
                "suppress_prefixlength".into(),
                "0".into(),
                "priority".into(),
                DNS_LISTENER_DPORT_RULE_PRIORITY.to_string(),
            ],
            vec![
                "ip".into(),
                "rule".into(),
                "add".into(),
                "sport".into(),
                dns_port.to_string(),
                "lookup".into(),
                "main".into(),
                "suppress_prefixlength".into(),
                "0".into(),
                "priority".into(),
                DNS_LISTENER_SPORT_RULE_PRIORITY.to_string(),
            ],
        ]);
    }
    commands.extend(vec![
        vec![
            "iptables".into(),
            "-t".into(),
            "nat".into(),
            "-N".into(),
            "MIHOMO_AUTO_OUTPUT".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "nat".into(),
            "-A".into(),
            "MIHOMO_AUTO_OUTPUT".into(),
            "-p".into(),
            "tcp".into(),
            "-o".into(),
            device.into(),
            "-j".into(),
            "REDIRECT".into(),
            "--to-ports".into(),
            redir_port.to_string(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "nat".into(),
            "-A".into(),
            "MIHOMO_AUTO_OUTPUT".into(),
            "-m".into(),
            "mark".into(),
            "--mark".into(),
            output_mark.to_string(),
            "-j".into(),
            "RETURN".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "nat".into(),
            "-I".into(),
            "OUTPUT".into(),
            "-j".into(),
            "MIHOMO_AUTO_OUTPUT".into(),
        ],
        vec![
            "iptables".into(),
            "-N".into(),
            "MIHOMO_AUTO_INPUT".into(),
        ],
        vec![
            "iptables".into(),
            "-A".into(),
            "MIHOMO_AUTO_INPUT".into(),
            "-i".into(),
            device.into(),
            "-j".into(),
            "ACCEPT".into(),
        ],
        vec![
            "iptables".into(),
            "-A".into(),
            "MIHOMO_AUTO_INPUT".into(),
            "-o".into(),
            device.into(),
            "-j".into(),
            "ACCEPT".into(),
        ],
        vec![
            "iptables".into(),
            "-I".into(),
            "INPUT".into(),
            "-j".into(),
            "MIHOMO_AUTO_INPUT".into(),
        ],
        vec![
            "iptables".into(),
            "-N".into(),
            "MIHOMO_AUTO_FORWARD".into(),
        ],
        vec![
            "iptables".into(),
            "-A".into(),
            "MIHOMO_AUTO_FORWARD".into(),
            "-i".into(),
            device.into(),
            "-j".into(),
            "ACCEPT".into(),
        ],
        vec![
            "iptables".into(),
            "-A".into(),
            "MIHOMO_AUTO_FORWARD".into(),
            "-o".into(),
            device.into(),
            "-j".into(),
            "ACCEPT".into(),
        ],
        vec![
            "iptables".into(),
            "-I".into(),
            "FORWARD".into(),
            "-j".into(),
            "MIHOMO_AUTO_FORWARD".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "nat".into(),
            "-N".into(),
            "MIHOMO_AUTO_REDIRECT".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "nat".into(),
            "-A".into(),
            "MIHOMO_AUTO_REDIRECT".into(),
            "-i".into(),
            device.into(),
            "-j".into(),
            "RETURN".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "nat".into(),
            "-I".into(),
            "PREROUTING".into(),
            "-j".into(),
            "MIHOMO_AUTO_REDIRECT".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "mangle".into(),
            "-N".into(),
            "MIHOMO_AUTO_MARK".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "mangle".into(),
            "-A".into(),
            "MIHOMO_AUTO_MARK".into(),
            "-i".into(),
            device.into(),
            "-j".into(),
            "RETURN".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "mangle".into(),
            "-I".into(),
            "PREROUTING".into(),
            "-j".into(),
            "MIHOMO_AUTO_MARK".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "mangle".into(),
            "-N".into(),
            "MIHOMO_AUTO_LOOPBACK".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "mangle".into(),
            "-A".into(),
            "MIHOMO_AUTO_LOOPBACK".into(),
            "-m".into(),
            "mark".into(),
            "--mark".into(),
            input_mark.to_string(),
            "-j".into(),
            "RETURN".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "mangle".into(),
            "-I".into(),
            "OUTPUT".into(),
            "-j".into(),
            "MIHOMO_AUTO_LOOPBACK".into(),
        ],
        vec![
            "ip".into(),
            "rule".into(),
            "add".into(),
            "fwmark".into(),
            input_mark.to_string(),
            "lookup".into(),
            table.to_string(),
            "priority".into(),
            "9000".into(),
        ],
    ]);
    if mark_mode {
        commands.extend([
            vec![
                "ip".into(),
                "rule".into(),
                "add".into(),
                "fwmark".into(),
                output_mark.to_string(),
                "goto".into(),
                "9002".into(),
                "priority".into(),
                "9000".into(),
            ],
            vec![
                "ip".into(),
                "rule".into(),
                "add".into(),
                "lookup".into(),
                table.to_string(),
                "priority".into(),
                fallback_rule.to_string(),
            ],
        ]);
    }

    if spec
        .config
        .inet6_address
        .iter()
        .any(|address| !address.trim().is_empty())
    {
        commands.extend(render_ipv6_setup_commands(
            spec,
            redir_port,
            dns_redirect_port,
            input_mark,
            output_mark,
            fallback_rule,
            table,
            &route_address,
            &route_exclude_address,
        ));
    }

    append_redirect_filters(
        &mut commands,
        "nat",
        "MIHOMO_AUTO_REDIRECT",
        spec,
        &route_exclude_address,
    );
    if let Some(dns_port) = dns_redirect_port {
        append_dns_redirect_targets_v4(&mut commands, "MIHOMO_AUTO_REDIRECT", dns_port);
    }
    append_return_local(&mut commands, "nat", "MIHOMO_AUTO_REDIRECT");
    append_redirect_targets(
        &mut commands,
        "MIHOMO_AUTO_REDIRECT",
        spec,
        &route_address,
        |commands, destination| {
            commands.push(build_tcp_redirect_command(
                "MIHOMO_AUTO_REDIRECT",
                redir_port,
                destination,
            ));
        },
    );

    append_redirect_filters(
        &mut commands,
        "mangle",
        "MIHOMO_AUTO_MARK",
        spec,
        &route_exclude_address,
    );
    if let Some(dns_port) = dns_redirect_port {
        append_dns_mark_bypass_v4(&mut commands, "MIHOMO_AUTO_MARK", dns_port);
    }
    append_loopback_prerouting_mark_targets(
        &mut commands,
        "MIHOMO_AUTO_MARK",
        input_mark,
        &loopback_addresses,
    );
    append_redirect_targets(
        &mut commands,
        "MIHOMO_AUTO_MARK",
        spec,
        &route_address,
        |commands, destination| {
            commands.push(build_udp_mark_command(
                "MIHOMO_AUTO_MARK",
                input_mark,
                destination,
            ));
        },
    );
    append_loopback_mark_targets(
        &mut commands,
        "MIHOMO_AUTO_LOOPBACK",
        input_mark,
        &loopback_addresses,
    );

    Ok(commands)
}

fn render_ipv6_setup_commands(
    spec: &TunRuntimeSpec,
    redir_port: u16,
    dns_redirect_port: Option<u16>,
    input_mark: u32,
    output_mark: u32,
    fallback_rule: i32,
    table: i32,
    route_address: &[String],
    route_exclude_address: &[String],
) -> Vec<Vec<String>> {
    let device = spec.config.device.trim();
    let mark_mode = auto_redirect_mark_mode_enabled(spec);
    let loopback_addresses = collect_loopback_addresses(&spec.config.loopback_address);
    let mut commands = vec![
        vec![
            "ip6tables".into(),
            "-t".into(),
            "nat".into(),
            "-N".into(),
            "MIHOMO6_AUTO_OUTPUT".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "nat".into(),
            "-A".into(),
            "MIHOMO6_AUTO_OUTPUT".into(),
            "-p".into(),
            "tcp".into(),
            "-o".into(),
            device.into(),
            "-j".into(),
            "REDIRECT".into(),
            "--to-ports".into(),
            redir_port.to_string(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "nat".into(),
            "-A".into(),
            "MIHOMO6_AUTO_OUTPUT".into(),
            "-m".into(),
            "mark".into(),
            "--mark".into(),
            output_mark.to_string(),
            "-j".into(),
            "RETURN".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "nat".into(),
            "-I".into(),
            "OUTPUT".into(),
            "-j".into(),
            "MIHOMO6_AUTO_OUTPUT".into(),
        ],
        vec![
            "ip6tables".into(),
            "-N".into(),
            "MIHOMO6_AUTO_INPUT".into(),
        ],
        vec![
            "ip6tables".into(),
            "-A".into(),
            "MIHOMO6_AUTO_INPUT".into(),
            "-i".into(),
            device.into(),
            "-j".into(),
            "ACCEPT".into(),
        ],
        vec![
            "ip6tables".into(),
            "-A".into(),
            "MIHOMO6_AUTO_INPUT".into(),
            "-o".into(),
            device.into(),
            "-j".into(),
            "ACCEPT".into(),
        ],
        vec![
            "ip6tables".into(),
            "-I".into(),
            "INPUT".into(),
            "-j".into(),
            "MIHOMO6_AUTO_INPUT".into(),
        ],
        vec![
            "ip6tables".into(),
            "-N".into(),
            "MIHOMO6_AUTO_FORWARD".into(),
        ],
        vec![
            "ip6tables".into(),
            "-A".into(),
            "MIHOMO6_AUTO_FORWARD".into(),
            "-i".into(),
            device.into(),
            "-j".into(),
            "ACCEPT".into(),
        ],
        vec![
            "ip6tables".into(),
            "-A".into(),
            "MIHOMO6_AUTO_FORWARD".into(),
            "-o".into(),
            device.into(),
            "-j".into(),
            "ACCEPT".into(),
        ],
        vec![
            "ip6tables".into(),
            "-I".into(),
            "FORWARD".into(),
            "-j".into(),
            "MIHOMO6_AUTO_FORWARD".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "nat".into(),
            "-N".into(),
            "MIHOMO6_AUTO_REDIRECT".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "nat".into(),
            "-A".into(),
            "MIHOMO6_AUTO_REDIRECT".into(),
            "-i".into(),
            device.into(),
            "-j".into(),
            "RETURN".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "nat".into(),
            "-I".into(),
            "PREROUTING".into(),
            "-j".into(),
            "MIHOMO6_AUTO_REDIRECT".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "mangle".into(),
            "-N".into(),
            "MIHOMO6_AUTO_MARK".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "mangle".into(),
            "-A".into(),
            "MIHOMO6_AUTO_MARK".into(),
            "-i".into(),
            device.into(),
            "-j".into(),
            "RETURN".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "mangle".into(),
            "-I".into(),
            "PREROUTING".into(),
            "-j".into(),
            "MIHOMO6_AUTO_MARK".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "mangle".into(),
            "-N".into(),
            "MIHOMO6_AUTO_LOOPBACK".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "mangle".into(),
            "-A".into(),
            "MIHOMO6_AUTO_LOOPBACK".into(),
            "-m".into(),
            "mark".into(),
            "--mark".into(),
            input_mark.to_string(),
            "-j".into(),
            "RETURN".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "mangle".into(),
            "-I".into(),
            "OUTPUT".into(),
            "-j".into(),
            "MIHOMO6_AUTO_LOOPBACK".into(),
        ],
        vec![
            "ip".into(),
            "-6".into(),
            "rule".into(),
            "add".into(),
            "fwmark".into(),
            input_mark.to_string(),
            "lookup".into(),
            table.to_string(),
            "priority".into(),
            "9000".into(),
        ],
    ];
    if mark_mode {
        commands.extend([
            vec![
                "ip".into(),
                "-6".into(),
                "rule".into(),
                "add".into(),
                "fwmark".into(),
                output_mark.to_string(),
                "goto".into(),
                "9002".into(),
                "priority".into(),
                "9000".into(),
            ],
            vec![
                "ip".into(),
                "-6".into(),
                "rule".into(),
                "add".into(),
                "lookup".into(),
                table.to_string(),
                "priority".into(),
                fallback_rule.to_string(),
            ],
        ]);
    }

    append_redirect_filters_ipv6(
        &mut commands,
        "nat",
        "MIHOMO6_AUTO_REDIRECT",
        spec,
        route_exclude_address,
    );
    append_return_local_ipv6(&mut commands, "nat", "MIHOMO6_AUTO_REDIRECT");
    append_redirect_targets_ipv6(
        &mut commands,
        "MIHOMO6_AUTO_REDIRECT",
        spec,
        route_address,
        |commands, destination| {
            commands.push(build_tcp_redirect_command_v6(
                "MIHOMO6_AUTO_REDIRECT",
                redir_port,
                destination,
            ));
        },
    );

    append_redirect_filters_ipv6(
        &mut commands,
        "mangle",
        "MIHOMO6_AUTO_MARK",
        spec,
        route_exclude_address,
    );
    if let Some(dns_port) = dns_redirect_port {
        append_dns_mark_bypass_v6(&mut commands, "MIHOMO6_AUTO_MARK", dns_port);
    }
    append_loopback_prerouting_mark_targets_ipv6(
        &mut commands,
        "MIHOMO6_AUTO_MARK",
        input_mark,
        &loopback_addresses,
    );
    append_redirect_targets_ipv6(
        &mut commands,
        "MIHOMO6_AUTO_MARK",
        spec,
        route_address,
        |commands, destination| {
            commands.push(build_udp_mark_command_v6(
                "MIHOMO6_AUTO_MARK",
                input_mark,
                destination,
            ));
        },
    );
    append_loopback_mark_targets_ipv6(
        &mut commands,
        "MIHOMO6_AUTO_LOOPBACK",
        input_mark,
        &loopback_addresses,
    );

    if let Some(dns_port) = dns_redirect_port {
        append_dns_redirect_targets_v6(&mut commands, "MIHOMO6_AUTO_REDIRECT", dns_port);
    }

    commands
}

fn append_dns_redirect_targets_v4(
    commands: &mut Vec<Vec<String>>,
    chain: &str,
    dns_port: u16,
) {
    commands.extend([
        vec![
            "iptables".into(),
            "-t".into(),
            "nat".into(),
            "-A".into(),
            chain.into(),
            "-p".into(),
            "udp".into(),
            "--dport".into(),
            "53".into(),
            "-j".into(),
            "REDIRECT".into(),
            "--to-ports".into(),
            dns_port.to_string(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "nat".into(),
            "-A".into(),
            chain.into(),
            "-p".into(),
            "tcp".into(),
            "--dport".into(),
            "53".into(),
            "-j".into(),
            "REDIRECT".into(),
            "--to-ports".into(),
            dns_port.to_string(),
        ],
    ]);
}

fn append_dns_redirect_targets_v6(
    commands: &mut Vec<Vec<String>>,
    chain: &str,
    dns_port: u16,
) {
    commands.extend([
        vec![
            "ip6tables".into(),
            "-t".into(),
            "nat".into(),
            "-A".into(),
            chain.into(),
            "-p".into(),
            "udp".into(),
            "--dport".into(),
            "53".into(),
            "-j".into(),
            "REDIRECT".into(),
            "--to-ports".into(),
            dns_port.to_string(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "nat".into(),
            "-A".into(),
            chain.into(),
            "-p".into(),
            "tcp".into(),
            "--dport".into(),
            "53".into(),
            "-j".into(),
            "REDIRECT".into(),
            "--to-ports".into(),
            dns_port.to_string(),
        ],
    ]);
}

fn append_dns_mark_bypass_v4(commands: &mut Vec<Vec<String>>, chain: &str, dns_port: u16) {
    append_dns_mark_bypass_rules(commands, "iptables", chain, dns_port);
}

fn append_dns_mark_bypass_v6(commands: &mut Vec<Vec<String>>, chain: &str, dns_port: u16) {
    append_dns_mark_bypass_rules(commands, "ip6tables", chain, dns_port);
}

fn append_dns_mark_bypass_rules(
    commands: &mut Vec<Vec<String>>,
    binary: &str,
    chain: &str,
    dns_port: u16,
) {
    for port in [53_u16, dns_port] {
        for protocol in ["udp", "tcp"] {
            commands.push(vec![
                binary.into(),
                "-t".into(),
                "mangle".into(),
                "-A".into(),
                chain.into(),
                "-p".into(),
                protocol.into(),
                "--dport".into(),
                port.to_string(),
                "-j".into(),
                "RETURN".into(),
            ]);
        }
    }
}

fn render_cleanup_commands(
    dns_redirect_port: Option<u16>,
    input_mark: u32,
    output_mark: u32,
    fallback_rule: i32,
    table: i32,
) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    if let Some(dns_port) = dns_redirect_port {
        commands.push(vec![
            "ip".into(),
            "rule".into(),
            "del".into(),
            "dport".into(),
            dns_port.to_string(),
            "lookup".into(),
            "main".into(),
            "suppress_prefixlength".into(),
            "0".into(),
            "priority".into(),
            DNS_LISTENER_DPORT_RULE_PRIORITY.to_string(),
        ]);
        commands.push(vec![
            "ip".into(),
            "rule".into(),
            "del".into(),
            "sport".into(),
            dns_port.to_string(),
            "lookup".into(),
            "main".into(),
            "suppress_prefixlength".into(),
            "0".into(),
            "priority".into(),
            DNS_LISTENER_SPORT_RULE_PRIORITY.to_string(),
        ]);
    }
    commands.extend(vec![
        vec![
            "ip".into(),
            "rule".into(),
            "del".into(),
            "fwmark".into(),
            input_mark.to_string(),
            "lookup".into(),
            table.to_string(),
            "priority".into(),
            "9000".into(),
        ],
        vec![
            "ip".into(),
            "rule".into(),
            "del".into(),
            "fwmark".into(),
            output_mark.to_string(),
            "goto".into(),
            "9002".into(),
            "priority".into(),
            "9000".into(),
        ],
        vec![
            "ip".into(),
            "rule".into(),
            "del".into(),
            "lookup".into(),
            table.to_string(),
            "priority".into(),
            fallback_rule.to_string(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "nat".into(),
            "-D".into(),
            "OUTPUT".into(),
            "-j".into(),
            "MIHOMO_AUTO_OUTPUT".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "nat".into(),
            "-F".into(),
            "MIHOMO_AUTO_OUTPUT".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "nat".into(),
            "-X".into(),
            "MIHOMO_AUTO_OUTPUT".into(),
        ],
        vec![
            "iptables".into(),
            "-D".into(),
            "FORWARD".into(),
            "-j".into(),
            "MIHOMO_AUTO_FORWARD".into(),
        ],
        vec![
            "iptables".into(),
            "-F".into(),
            "MIHOMO_AUTO_FORWARD".into(),
        ],
        vec![
            "iptables".into(),
            "-X".into(),
            "MIHOMO_AUTO_FORWARD".into(),
        ],
        vec![
            "iptables".into(),
            "-D".into(),
            "INPUT".into(),
            "-j".into(),
            "MIHOMO_AUTO_INPUT".into(),
        ],
        vec![
            "iptables".into(),
            "-F".into(),
            "MIHOMO_AUTO_INPUT".into(),
        ],
        vec![
            "iptables".into(),
            "-X".into(),
            "MIHOMO_AUTO_INPUT".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "mangle".into(),
            "-D".into(),
            "OUTPUT".into(),
            "-j".into(),
            "MIHOMO_AUTO_LOOPBACK".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "mangle".into(),
            "-F".into(),
            "MIHOMO_AUTO_LOOPBACK".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "mangle".into(),
            "-X".into(),
            "MIHOMO_AUTO_LOOPBACK".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "mangle".into(),
            "-D".into(),
            "PREROUTING".into(),
            "-j".into(),
            "MIHOMO_AUTO_MARK".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "mangle".into(),
            "-F".into(),
            "MIHOMO_AUTO_MARK".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "mangle".into(),
            "-X".into(),
            "MIHOMO_AUTO_MARK".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "nat".into(),
            "-D".into(),
            "PREROUTING".into(),
            "-j".into(),
            "MIHOMO_AUTO_REDIRECT".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "nat".into(),
            "-F".into(),
            "MIHOMO_AUTO_REDIRECT".into(),
        ],
        vec![
            "iptables".into(),
            "-t".into(),
            "nat".into(),
            "-X".into(),
            "MIHOMO_AUTO_REDIRECT".into(),
        ],
    ]);
    commands.extend(render_ipv6_cleanup_commands(
        dns_redirect_port,
        input_mark,
        output_mark,
        fallback_rule,
        table,
    ));
    commands
}

fn render_ipv6_cleanup_commands(
    dns_redirect_port: Option<u16>,
    input_mark: u32,
    output_mark: u32,
    fallback_rule: i32,
    table: i32,
) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    if let Some(dns_port) = dns_redirect_port {
        commands.push(vec![
            "ip".into(),
            "-6".into(),
            "rule".into(),
            "del".into(),
            "dport".into(),
            dns_port.to_string(),
            "lookup".into(),
            "main".into(),
            "suppress_prefixlength".into(),
            "0".into(),
            "priority".into(),
            DNS_LISTENER_DPORT_RULE_PRIORITY.to_string(),
        ]);
        commands.push(vec![
            "ip".into(),
            "-6".into(),
            "rule".into(),
            "del".into(),
            "sport".into(),
            dns_port.to_string(),
            "lookup".into(),
            "main".into(),
            "suppress_prefixlength".into(),
            "0".into(),
            "priority".into(),
            DNS_LISTENER_SPORT_RULE_PRIORITY.to_string(),
        ]);
    }
    commands.extend(vec![
        vec![
            "ip".into(),
            "-6".into(),
            "rule".into(),
            "del".into(),
            "fwmark".into(),
            input_mark.to_string(),
            "lookup".into(),
            table.to_string(),
            "priority".into(),
            "9000".into(),
        ],
        vec![
            "ip".into(),
            "-6".into(),
            "rule".into(),
            "del".into(),
            "fwmark".into(),
            output_mark.to_string(),
            "goto".into(),
            "9002".into(),
            "priority".into(),
            "9000".into(),
        ],
        vec![
            "ip".into(),
            "-6".into(),
            "rule".into(),
            "del".into(),
            "lookup".into(),
            table.to_string(),
            "priority".into(),
            fallback_rule.to_string(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "nat".into(),
            "-D".into(),
            "OUTPUT".into(),
            "-j".into(),
            "MIHOMO6_AUTO_OUTPUT".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "nat".into(),
            "-F".into(),
            "MIHOMO6_AUTO_OUTPUT".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "nat".into(),
            "-X".into(),
            "MIHOMO6_AUTO_OUTPUT".into(),
        ],
        vec![
            "ip6tables".into(),
            "-D".into(),
            "FORWARD".into(),
            "-j".into(),
            "MIHOMO6_AUTO_FORWARD".into(),
        ],
        vec![
            "ip6tables".into(),
            "-F".into(),
            "MIHOMO6_AUTO_FORWARD".into(),
        ],
        vec![
            "ip6tables".into(),
            "-X".into(),
            "MIHOMO6_AUTO_FORWARD".into(),
        ],
        vec![
            "ip6tables".into(),
            "-D".into(),
            "INPUT".into(),
            "-j".into(),
            "MIHOMO6_AUTO_INPUT".into(),
        ],
        vec![
            "ip6tables".into(),
            "-F".into(),
            "MIHOMO6_AUTO_INPUT".into(),
        ],
        vec![
            "ip6tables".into(),
            "-X".into(),
            "MIHOMO6_AUTO_INPUT".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "mangle".into(),
            "-D".into(),
            "OUTPUT".into(),
            "-j".into(),
            "MIHOMO6_AUTO_LOOPBACK".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "mangle".into(),
            "-F".into(),
            "MIHOMO6_AUTO_LOOPBACK".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "mangle".into(),
            "-X".into(),
            "MIHOMO6_AUTO_LOOPBACK".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "mangle".into(),
            "-D".into(),
            "PREROUTING".into(),
            "-j".into(),
            "MIHOMO6_AUTO_MARK".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "mangle".into(),
            "-F".into(),
            "MIHOMO6_AUTO_MARK".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "mangle".into(),
            "-X".into(),
            "MIHOMO6_AUTO_MARK".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "nat".into(),
            "-D".into(),
            "PREROUTING".into(),
            "-j".into(),
            "MIHOMO6_AUTO_REDIRECT".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "nat".into(),
            "-F".into(),
            "MIHOMO6_AUTO_REDIRECT".into(),
        ],
        vec![
            "ip6tables".into(),
            "-t".into(),
            "nat".into(),
            "-X".into(),
            "MIHOMO6_AUTO_REDIRECT".into(),
        ],
    ]);
    commands
}

fn append_return_local(commands: &mut Vec<Vec<String>>, table: &str, chain: &str) {
    commands.push(vec![
        "iptables".into(),
        "-t".into(),
        table.into(),
        "-A".into(),
        chain.into(),
        "-m".into(),
        "addrtype".into(),
        "--dst-type".into(),
        "LOCAL".into(),
        "-j".into(),
        "RETURN".into(),
    ]);
}

fn append_return_local_ipv6(commands: &mut Vec<Vec<String>>, table: &str, chain: &str) {
    commands.push(vec![
        "ip6tables".into(),
        "-t".into(),
        table.into(),
        "-A".into(),
        chain.into(),
        "-m".into(),
        "addrtype".into(),
        "--dst-type".into(),
        "LOCAL".into(),
        "-j".into(),
        "RETURN".into(),
    ]);
}

fn append_redirect_filters(
    commands: &mut Vec<Vec<String>>,
    table: &str,
    chain: &str,
    spec: &TunRuntimeSpec,
    route_excludes: &[String],
) {
    for prefix in route_excludes {
        commands.push(vec![
            "iptables".into(),
            "-t".into(),
            table.into(),
            "-A".into(),
            chain.into(),
            "-d".into(),
            prefix.clone(),
            "-j".into(),
            "RETURN".into(),
        ]);
    }
    for interface in &spec.config.exclude_interface {
        commands.push(vec![
            "iptables".into(),
            "-t".into(),
            table.into(),
            "-A".into(),
            chain.into(),
            "-i".into(),
            interface.clone(),
            "-j".into(),
            "RETURN".into(),
        ]);
    }
}

fn append_redirect_filters_ipv6(
    commands: &mut Vec<Vec<String>>,
    table: &str,
    chain: &str,
    spec: &TunRuntimeSpec,
    route_excludes: &[String],
) {
    for prefix in route_excludes
        .iter()
        .filter(|prefix| prefix.contains(':'))
    {
        commands.push(vec![
            "ip6tables".into(),
            "-t".into(),
            table.into(),
            "-A".into(),
            chain.into(),
            "-d".into(),
            prefix.clone(),
            "-j".into(),
            "RETURN".into(),
        ]);
    }
    for interface in &spec.config.exclude_interface {
        commands.push(vec![
            "ip6tables".into(),
            "-t".into(),
            table.into(),
            "-A".into(),
            chain.into(),
            "-i".into(),
            interface.clone(),
            "-j".into(),
            "RETURN".into(),
        ]);
    }
}

fn append_redirect_targets<F>(
    commands: &mut Vec<Vec<String>>,
    chain: &str,
    spec: &TunRuntimeSpec,
    route_address: &[String],
    mut emit_terminal: F,
) where
    F: FnMut(&mut Vec<Vec<String>>, Option<&str>),
{
    if !route_address.is_empty() {
        let table = if chain == "MIHOMO_AUTO_REDIRECT" {
            "nat"
        } else {
            "mangle"
        };
        for prefix in route_address {
            emit_terminal(commands, Some(prefix));
        }
        commands.push(vec![
            "iptables".into(),
            "-t".into(),
            table.into(),
            "-A".into(),
            chain.into(),
            "-j".into(),
            "RETURN".into(),
        ]);
        return;
    }

    if !spec.config.include_interface.is_empty() {
        for interface in &spec.config.include_interface {
            emit_terminal_with_interface(commands, chain, interface, &mut emit_terminal);
        }
        return;
    }

    emit_terminal(commands, None);
}

fn append_redirect_targets_ipv6<F>(
    commands: &mut Vec<Vec<String>>,
    chain: &str,
    spec: &TunRuntimeSpec,
    route_address: &[String],
    mut emit_terminal: F,
) where
    F: FnMut(&mut Vec<Vec<String>>, Option<&str>),
{
    let ipv6_routes = route_address
        .iter()
        .filter(|prefix| prefix.contains(':'))
        .cloned()
        .collect::<Vec<_>>();
    if !ipv6_routes.is_empty() {
        let table = if chain == "MIHOMO6_AUTO_REDIRECT" {
            "nat"
        } else {
            "mangle"
        };
        for prefix in &ipv6_routes {
            emit_terminal(commands, Some(prefix));
        }
        commands.push(vec![
            "ip6tables".into(),
            "-t".into(),
            table.into(),
            "-A".into(),
            chain.into(),
            "-j".into(),
            "RETURN".into(),
        ]);
        return;
    }

    if !spec.config.include_interface.is_empty() {
        for interface in &spec.config.include_interface {
            emit_terminal_with_interface_ipv6(commands, chain, interface, &mut emit_terminal);
        }
        return;
    }

    emit_terminal(commands, None);
}

fn build_tcp_redirect_command(chain: &str, redir_port: u16, destination: Option<&str>) -> Vec<String> {
    let mut command = vec![
        "iptables".into(),
        "-t".into(),
        "nat".into(),
        "-A".into(),
        chain.into(),
    ];
    if let Some(destination) = destination {
        command.extend(["-d".into(), destination.to_owned()]);
    }
    command.extend([
        "-p".into(),
        "tcp".into(),
        "-j".into(),
        "REDIRECT".into(),
        "--to-ports".into(),
        redir_port.to_string(),
    ]);
    command
}

fn build_tcp_redirect_command_v6(
    chain: &str,
    redir_port: u16,
    destination: Option<&str>,
) -> Vec<String> {
    let mut command = vec![
        "ip6tables".into(),
        "-t".into(),
        "nat".into(),
        "-A".into(),
        chain.into(),
    ];
    if let Some(destination) = destination {
        command.extend(["-d".into(), destination.to_owned()]);
    }
    command.extend([
        "-p".into(),
        "tcp".into(),
        "-j".into(),
        "REDIRECT".into(),
        "--to-ports".into(),
        redir_port.to_string(),
    ]);
    command
}

fn build_udp_mark_command(
    chain: &str,
    input_mark: u32,
    destination: Option<&str>,
) -> Vec<String> {
    let mut command = vec![
        "iptables".into(),
        "-t".into(),
        "mangle".into(),
        "-A".into(),
        chain.into(),
    ];
    if let Some(destination) = destination {
        command.extend(["-d".into(), destination.to_owned()]);
    }
    command.extend([
        "-p".into(),
        "udp".into(),
        "-j".into(),
        "MARK".into(),
        "--set-mark".into(),
        input_mark.to_string(),
    ]);
    command
}

fn build_udp_mark_command_v6(
    chain: &str,
    input_mark: u32,
    destination: Option<&str>,
) -> Vec<String> {
    let mut command = vec![
        "ip6tables".into(),
        "-t".into(),
        "mangle".into(),
        "-A".into(),
        chain.into(),
    ];
    if let Some(destination) = destination {
        command.extend(["-d".into(), destination.to_owned()]);
    }
    command.extend([
        "-p".into(),
        "udp".into(),
        "-j".into(),
        "MARK".into(),
        "--set-mark".into(),
        input_mark.to_string(),
    ]);
    command
}

fn emit_terminal_with_interface<F>(
    commands: &mut Vec<Vec<String>>,
    _chain: &str,
    interface: &str,
    emit_terminal: &mut F,
) where
    F: FnMut(&mut Vec<Vec<String>>, Option<&str>),
{
    let before = commands.len();
    emit_terminal(commands, None);
    if let Some(command) = commands.get_mut(before) {
        command.splice(5..5, ["-i".to_owned(), interface.to_owned()]);
    }
}

fn emit_terminal_with_interface_ipv6<F>(
    commands: &mut Vec<Vec<String>>,
    chain: &str,
    interface: &str,
    emit_terminal: &mut F,
) where
    F: FnMut(&mut Vec<Vec<String>>, Option<&str>),
{
    let before = commands.len();
    emit_terminal(commands, None);
    if let Some(command) = commands.get_mut(before) {
        let _ = chain;
        command.splice(5..5, ["-i".to_owned(), interface.to_owned()]);
    }
}

fn collect_family_prefixes(
    common: &[String],
    ipv4: &[String],
    ipv6: &[String],
) -> Vec<String> {
    let mut prefixes = Vec::new();
    prefixes.extend(
        common
            .iter()
            .filter_map(|prefix| non_empty_prefix(prefix))
            .map(ToOwned::to_owned),
    );
    prefixes.extend(
        ipv4.iter()
            .filter_map(|prefix| non_empty_prefix(prefix))
            .map(ToOwned::to_owned),
    );
    prefixes.extend(
        ipv6.iter()
            .filter_map(|prefix| non_empty_prefix(prefix))
            .map(ToOwned::to_owned),
    );
    prefixes
}

fn collect_loopback_addresses(values: &[String]) -> Vec<IpAddr> {
    values
        .iter()
        .filter_map(|value| value.trim().parse::<IpAddr>().ok())
        .collect()
}

fn append_loopback_mark_targets(
    commands: &mut Vec<Vec<String>>,
    chain: &str,
    input_mark: u32,
    addresses: &[IpAddr],
) {
    for address in addresses {
        let IpAddr::V4(address) = address else {
            continue;
        };
        commands.push(vec![
            "iptables".into(),
            "-t".into(),
            "mangle".into(),
            "-A".into(),
            chain.into(),
            "-p".into(),
            "tcp".into(),
            "-d".into(),
            address.to_string(),
            "-j".into(),
            "MARK".into(),
            "--set-mark".into(),
            input_mark.to_string(),
        ]);
        commands.push(vec![
            "iptables".into(),
            "-t".into(),
            "mangle".into(),
            "-A".into(),
            chain.into(),
            "-p".into(),
            "tcp".into(),
            "-d".into(),
            address.to_string(),
            "-j".into(),
            "CONNMARK".into(),
            "--save-mark".into(),
        ]);
    }
}

fn append_loopback_mark_targets_ipv6(
    commands: &mut Vec<Vec<String>>,
    chain: &str,
    input_mark: u32,
    addresses: &[IpAddr],
) {
    for address in addresses {
        let IpAddr::V6(address) = address else {
            continue;
        };
        commands.push(vec![
            "ip6tables".into(),
            "-t".into(),
            "mangle".into(),
            "-A".into(),
            chain.into(),
            "-p".into(),
            "tcp".into(),
            "-d".into(),
            address.to_string(),
            "-j".into(),
            "MARK".into(),
            "--set-mark".into(),
            input_mark.to_string(),
        ]);
        commands.push(vec![
            "ip6tables".into(),
            "-t".into(),
            "mangle".into(),
            "-A".into(),
            chain.into(),
            "-p".into(),
            "tcp".into(),
            "-d".into(),
            address.to_string(),
            "-j".into(),
            "CONNMARK".into(),
            "--save-mark".into(),
        ]);
    }
}

fn append_loopback_prerouting_mark_targets(
    commands: &mut Vec<Vec<String>>,
    chain: &str,
    input_mark: u32,
    addresses: &[IpAddr],
) {
    for address in addresses {
        let IpAddr::V4(address) = address else {
            continue;
        };
        commands.push(vec![
            "iptables".into(),
            "-t".into(),
            "mangle".into(),
            "-A".into(),
            chain.into(),
            "-p".into(),
            "tcp".into(),
            "-d".into(),
            address.to_string(),
            "-m".into(),
            "mark".into(),
            "!".into(),
            "--mark".into(),
            input_mark.to_string(),
            "-j".into(),
            "MARK".into(),
            "--set-mark".into(),
            input_mark.to_string(),
        ]);
    }
}

fn append_loopback_prerouting_mark_targets_ipv6(
    commands: &mut Vec<Vec<String>>,
    chain: &str,
    input_mark: u32,
    addresses: &[IpAddr],
) {
    for address in addresses {
        let IpAddr::V6(address) = address else {
            continue;
        };
        commands.push(vec![
            "ip6tables".into(),
            "-t".into(),
            "mangle".into(),
            "-A".into(),
            chain.into(),
            "-p".into(),
            "tcp".into(),
            "-d".into(),
            address.to_string(),
            "-m".into(),
            "mark".into(),
            "!".into(),
            "--mark".into(),
            input_mark.to_string(),
            "-j".into(),
            "MARK".into(),
            "--set-mark".into(),
            input_mark.to_string(),
        ]);
    }
}

fn non_empty_prefix(prefix: &str) -> Option<&str> {
    let trimmed = prefix.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn resolve_route_set_prefixes(
    document: &RuntimeConfigDocument,
    provider_sources: Option<&ProviderContentSources>,
    names: &[String],
) -> io::Result<Vec<String>> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let Some(provider_sources) = provider_sources else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "route-address-set requires loaded rule-provider sources",
        ));
    };
    let mut prefixes = Vec::new();
    for name in names {
        let provider = document.rule_providers.get(name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("route-address-set rule provider not found: {name}"),
            )
        })?;
        if provider.behavior_kind() != Some(RuleProviderBehavior::IpCidr) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("route-address-set rule provider `{name}` must use ipcidr behavior"),
            ));
        }
        let payload = load_rule_provider_payload_from_sources(
            provider,
            &provider_sources.file_blobs,
            &provider_sources.http_blobs,
        )
        .map_err(|err| io::Error::other(err.to_string()))?;
        prefixes.extend(
            payload
                .into_iter()
                .filter_map(|prefix| non_empty_prefix(&prefix).map(ToOwned::to_owned)),
        );
    }
    Ok(prefixes)
}

fn run_command(args: &[String]) -> io::Result<()> {
    let Some((binary, rest)) = args.split_first() else {
        return Ok(());
    };
    let output = Command::new(binary).args(rest).output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(io::Error::other(format!(
        "command `{}` failed: {}",
        args.join(" "),
        stderr.trim()
    )))
}

fn run_command_allow_missing(args: &[String]) -> io::Result<()> {
    match run_command(args) {
        Ok(()) => Ok(()),
        Err(err)
            if err.to_string().contains("No chain/target/match by that name")
                || err.to_string().contains("Bad rule")
                || err.to_string().contains("No such file or directory")
                || err.to_string().contains("No such process") =>
        {
            Ok(())
        }
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use super::{render_cleanup_commands, render_setup_commands, resolve_route_set_prefixes};
    use mihomo_config::{parse_runtime_config_document, RuleProviderBehavior};
    use mihomo_runtime::ProviderContentSources;
    use mihomo_runtime::build_tun_runtime_specs;

    #[test]
    fn route_address_set_loads_ipcidr_provider_prefixes() {
        let document = parse_runtime_config_document(
            r#"
tun:
  enable: true
  auto-route: true
  auto-redirect: true
  device: utun-test
  route-address-set:
    - set1
rule-providers:
  set1:
    type: file
    behavior: ipcidr
    format: text
    path: set1.txt
"#,
        )
        .unwrap();
        let prefixes = resolve_route_set_prefixes(
            &document,
            Some(&ProviderContentSources {
                file_blobs: std::collections::BTreeMap::from([(
                    "set1.txt".to_owned(),
                    b"1.1.1.0/24\n8.8.8.8/32\n".to_vec(),
                )]),
                ..ProviderContentSources::default()
            }),
            &["set1".to_owned()],
        )
        .unwrap();
        assert_eq!(prefixes, vec!["1.1.1.0/24".to_owned(), "8.8.8.8/32".to_owned()]);
    }

    #[test]
    fn route_address_set_rejects_non_ipcidr_provider() {
        let document = parse_runtime_config_document(
            r#"
rule-providers:
  set1:
    type: file
    behavior: domain
    format: text
    path: set1.txt
"#,
        )
        .unwrap();
        let err = resolve_route_set_prefixes(
            &document,
            Some(&ProviderContentSources::default()),
            &["set1".to_owned()],
        )
        .unwrap_err();
        assert!(err.to_string().contains("ipcidr"));
        assert_eq!(
            document.rule_providers["set1"].behavior_kind(),
            Some(RuleProviderBehavior::Domain)
        );
    }

    #[test]
    fn auto_redirect_setup_commands_include_provider_prefixes() {
        let document = parse_runtime_config_document(
            r#"
redir-port: 17891
tun:
  enable: true
  auto-route: true
  auto-redirect: true
  device: utun-test
  route-address-set:
    - set1
rule-providers:
  set1:
    type: file
    behavior: ipcidr
    format: text
    path: set1.txt
"#,
        )
        .unwrap();
        let specs = build_tun_runtime_specs(&document);
        let commands = render_setup_commands(
            &document,
            Some(&ProviderContentSources {
                file_blobs: std::collections::BTreeMap::from([(
                    "set1.txt".to_owned(),
                    b"1.1.1.0/24\n".to_vec(),
                )]),
                ..ProviderContentSources::default()
            }),
            &specs[0],
            17891,
            None,
            0x2023,
            0x2024,
            32768,
            2022,
        )
        .unwrap();
        let rendered = commands
            .iter()
            .map(|parts| parts.join(" "))
            .collect::<Vec<_>>();
        assert!(rendered
            .iter()
            .any(|line| line.contains("-d 1.1.1.0/24") && line.contains("REDIRECT")));
        assert!(rendered
            .iter()
            .any(|line| line.contains("-d 1.1.1.0/24") && line.contains("MARK")));
    }

    #[test]
    fn route_address_set_uses_runtime_provider_source_shape() {
        let temp = std::env::temp_dir().join(format!(
            "mihomo-auto-redirect-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::write(temp.join("set1.txt"), b"9.9.9.0/24\n").unwrap();

        let options = mihomo_config::BootOptions {
            home_dir: Some(temp.to_string_lossy().into_owned()),
            config_file: None,
            config_base64: Some(
                base64::engine::general_purpose::STANDARD.encode(
                    r#"
redir-port: 17891
tun:
  enable: true
  auto-route: true
  auto-redirect: true
  device: utun-test
  route-address-set:
    - set1
rule-providers:
  set1:
    type: file
    behavior: ipcidr
    format: text
    path: set1.txt
"#,
                ),
            ),
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
            command: mihomo_config::Command::Run,
        };
        let state = mihomo_runtime::bootstrap_from_boot_options(
            &options,
            &temp,
            &mihomo_config::BootEnvironment::default(),
        )
        .unwrap();
        let sources = state.provider_sources_for_snapshot().unwrap();
        let specs = build_tun_runtime_specs(&state.document);
        let commands = render_setup_commands(
            &state.document,
            Some(&sources),
            &specs[0],
            17891,
            None,
            0x2023,
            0x2024,
            32768,
            2022,
        )
        .unwrap();
        let rendered = commands
            .iter()
            .map(|parts| parts.join(" "))
            .collect::<Vec<_>>();
        assert!(rendered
            .iter()
            .any(|line| line.contains("-d 9.9.9.0/24") && line.contains("REDIRECT")));
    }

    #[test]
    fn auto_redirect_mark_mode_options_translate_to_runtime_commands() {
        let document = parse_runtime_config_document(
            r#"
redir-port: 17891
tun:
  enable: true
  auto-route: true
  auto-redirect: true
  device: utun-test
  auto-redirect-output-mark: 0x2024
  auto-redirect-iproute2-fallback-rule-index: 32768
"#,
        )
        .unwrap();
        let specs = build_tun_runtime_specs(&document);
        let commands = render_setup_commands(
            &document,
            Some(&ProviderContentSources::default()),
            &specs[0],
            17891,
            None,
            0x2023,
            0x2024,
            32768,
            2022,
        )
        .unwrap();
        let rendered = commands
            .iter()
            .map(|parts| parts.join(" "))
            .collect::<Vec<_>>();

        assert!(
            rendered
                .iter()
                .any(|line| line.contains("fwmark 8228") && line.contains("goto 9002")),
            "{rendered:?}"
        );
        assert!(
            rendered
                .iter()
                .any(|line| line.contains("lookup 2022") && line.contains("priority 32768")),
            "{rendered:?}"
        );
        assert!(
            rendered
                .iter()
                .any(|line| line.contains("MIHOMO_AUTO_OUTPUT") && line.contains("--mark 8228")),
            "{rendered:?}"
        );
    }

    #[test]
    fn auto_redirect_loopback_address_generates_output_mark_rules() {
        let document = parse_runtime_config_document(
            r#"
redir-port: 17891
tun:
  enable: true
  auto-route: true
  auto-redirect: true
  device: utun-test
  inet6-address:
    - fd00::1/126
  loopback-address:
    - 10.0.0.1
    - fd00::1
"#,
        )
        .unwrap();
        let specs = build_tun_runtime_specs(&document);
        let commands = render_setup_commands(
            &document,
            Some(&ProviderContentSources::default()),
            &specs[0],
            17891,
            None,
            0x2023,
            0x2024,
            32768,
            2022,
        )
        .unwrap();
        let rendered = commands
            .iter()
            .map(|parts| parts.join(" "))
            .collect::<Vec<_>>();

        assert!(
            rendered
                .iter()
                .any(|line| line.contains("MIHOMO_AUTO_LOOPBACK") && line.contains("-d 10.0.0.1") && line.contains("--set-mark 8227")),
            "{rendered:?}"
        );
        assert!(
            rendered
                .iter()
                .any(|line| line.contains("MIHOMO_AUTO_LOOPBACK") && line.contains("-d 10.0.0.1") && line.contains("CONNMARK --save-mark")),
            "{rendered:?}"
        );
        assert!(
            rendered
                .iter()
                .any(|line| line.contains("MIHOMO_AUTO_MARK") && line.contains("-d 10.0.0.1") && line.contains("--set-mark 8227")),
            "{rendered:?}"
        );
        assert!(
            rendered
                .iter()
                .any(|line| line.contains("MIHOMO6_AUTO_LOOPBACK") && line.contains("-d fd00::1") && line.contains("--set-mark 8227")),
            "{rendered:?}"
        );
        assert!(
            rendered
                .iter()
                .any(|line| line.contains("MIHOMO6_AUTO_LOOPBACK") && line.contains("-d fd00::1") && line.contains("CONNMARK --save-mark")),
            "{rendered:?}"
        );
        assert!(
            rendered
                .iter()
                .any(|line| line.contains("MIHOMO6_AUTO_MARK") && line.contains("-d fd00::1") && line.contains("--set-mark 8227")),
            "{rendered:?}"
        );
    }

    #[test]
    fn auto_redirect_dns_listen_generates_prerouting_dns_redirect_rules() {
        let document = parse_runtime_config_document(
            r#"
redir-port: 17891
tun:
  enable: true
  auto-route: true
  auto-redirect: true
  device: utun-test
dns:
  enable: true
  listen: 127.0.0.1:1053
"#,
        )
        .unwrap();
        let specs = build_tun_runtime_specs(&document);
        let commands = render_setup_commands(
            &document,
            Some(&ProviderContentSources::default()),
            &specs[0],
            17891,
            Some(1053),
            0x2023,
            0x2024,
            32768,
            2022,
        )
        .unwrap();
        let rendered = commands
            .iter()
            .map(|parts| parts.join(" "))
            .collect::<Vec<_>>();
        let udp_index = rendered
            .iter()
            .position(|line| line.contains("MIHOMO_AUTO_REDIRECT") && line.contains("-p udp") && line.contains("--dport 53") && line.contains("--to-ports 1053"))
            .expect("missing udp dns redirect");
        let tcp_index = rendered
            .iter()
            .position(|line| line.contains("MIHOMO_AUTO_REDIRECT") && line.contains("-p tcp") && line.contains("--dport 53") && line.contains("--to-ports 1053"))
            .expect("missing tcp dns redirect");
        let local_return_index = rendered
            .iter()
            .position(|line| line.contains("MIHOMO_AUTO_REDIRECT") && line.contains("--dst-type LOCAL") && line.contains("RETURN"))
            .expect("missing local return");
        assert!(
            udp_index < local_return_index,
            "{rendered:?}"
        );
        assert!(
            tcp_index < local_return_index,
            "{rendered:?}"
        );
        assert!(
            rendered
                .iter()
                .any(|line| line.contains("rule add dport 1053") && line.contains("priority 8998")),
            "{rendered:?}"
        );
        assert!(
            rendered
                .iter()
                .any(|line| line.contains("rule add sport 1053") && line.contains("priority 8999")),
            "{rendered:?}"
        );
        assert!(
            rendered
                .iter()
                .any(|line| line.contains("MIHOMO_AUTO_MARK") && line.contains("-p udp") && line.contains("--dport 53") && line.contains("RETURN")),
            "{rendered:?}"
        );
        assert!(
            rendered
                .iter()
                .any(|line| line.contains("MIHOMO_AUTO_MARK") && line.contains("-p tcp") && line.contains("--dport 53") && line.contains("RETURN")),
            "{rendered:?}"
        );
        assert!(
            rendered
                .iter()
                .any(|line| line.contains("MIHOMO_AUTO_MARK") && line.contains("-p udp") && line.contains("--dport 1053") && line.contains("RETURN")),
            "{rendered:?}"
        );
        assert!(
            rendered
                .iter()
                .any(|line| line.contains("MIHOMO_AUTO_MARK") && line.contains("-p tcp") && line.contains("--dport 1053") && line.contains("RETURN")),
            "{rendered:?}"
        );

        let cleanup = render_cleanup_commands(Some(1053), 0x2023, 0x2024, 32768, 2022);
        let rendered_cleanup = cleanup
            .iter()
            .map(|parts| parts.join(" "))
            .collect::<Vec<_>>();
        assert!(
            rendered_cleanup
                .iter()
                .any(|line| line.contains("rule del dport 1053") && line.contains("priority 8998")),
            "{rendered_cleanup:?}"
        );
        assert!(
            rendered_cleanup
                .iter()
                .any(|line| line.contains("rule del sport 1053") && line.contains("priority 8999")),
            "{rendered_cleanup:?}"
        );
    }
}
