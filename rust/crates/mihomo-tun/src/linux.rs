use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::process::Command;

use ipnet::IpNet;

use crate::runtime_spec::TunRuntimeSpec;

const LINUX_TUN_DEVICE_PATH: &str = "/dev/net/tun";
const LINUX_TUN_IOCTL_SET_IFF: libc::Ioctl = 0x4004_54ca as libc::Ioctl;
const LINUX_IFF_TUN: libc::c_short = 0x0001;
const LINUX_IFF_NO_PI: libc::c_short = 0x1000;
const LINUX_IFNAMSIZ: usize = 16;
const DEFAULT_IPROUTE2_TABLE_INDEX: i32 = 2022;
const DEFAULT_IPROUTE2_RULE_INDEX: i32 = 9000;

#[repr(C)]
union LinuxIfReqData {
    flags: libc::c_short,
    pad: [u8; 24],
}

#[repr(C)]
struct LinuxIfReq {
    name: [libc::c_char; LINUX_IFNAMSIZ],
    data: LinuxIfReqData,
}

pub fn open_linux_tun_device(spec: &TunRuntimeSpec) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(LINUX_TUN_DEVICE_PATH)
        .map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "linux tun device `{}` is unavailable; ensure /dev/net/tun exists and the process has CAP_NET_ADMIN",
                        LINUX_TUN_DEVICE_PATH
                    ),
                )
            } else {
                err
            }
        })?;
    let mut ifreq = LinuxIfReq {
        name: [0; LINUX_IFNAMSIZ],
        data: LinuxIfReqData { pad: [0; 24] },
    };
    let requested_name = requested_linux_tun_name(spec)?;
    for (index, byte) in requested_name.bytes().enumerate() {
        ifreq.name[index] = byte as libc::c_char;
    }
    ifreq.data.flags = LINUX_IFF_TUN | LINUX_IFF_NO_PI;
    let result = unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            LINUX_TUN_IOCTL_SET_IFF,
            &mut ifreq as *mut LinuxIfReq,
        )
    };
    if result < 0 {
        let err = io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) {
            return Err(io::Error::new(
                err.kind(),
                format!(
                    "failed to configure linux tun device `{}`; CAP_NET_ADMIN is required",
                    LINUX_TUN_DEVICE_PATH
                ),
            ));
        }
        return Err(err);
    }
    let actual_name = linux_ifreq_name(&ifreq);
    if !actual_name.is_empty() {
        configure_linux_tun_interface(spec, &actual_name)?;
        let message = format!(
            "[TUN] interface {actual_name} started ipv4={:?} ipv6={:?} auto-route={}",
            spec.config.inet4_address, spec.config.inet6_address, spec.config.auto_route);
        eprintln!("{message}");
        mihomo_core::push_log(mihomo_core::LogLevel::Info, message);
    }
    Ok(file)
}

pub fn requested_linux_tun_name(spec: &TunRuntimeSpec) -> io::Result<String> {
    let requested_name = if !spec.config.device.trim().is_empty() {
        spec.config.device.trim().to_owned()
    } else if spec.name.starts_with("__") {
        String::new()
    } else {
        spec.name.clone()
    };
    if requested_name.len() >= LINUX_IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tun device name too long: {requested_name}"),
        ));
    }
    Ok(requested_name)
}

pub fn linux_tun_setup_commands(spec: &TunRuntimeSpec, device_name: &str) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    if spec.config.mtu > 0 {
        commands.push(vec![
            "link".into(),
            "set".into(),
            "dev".into(),
            device_name.into(),
            "mtu".into(),
            spec.config.mtu.to_string(),
        ]);
    }
    for address in &spec.config.inet4_address {
        if !address.trim().is_empty() {
            commands.push(vec![
                "addr".into(),
                "add".into(),
                address.trim().to_owned(),
                "dev".into(),
                device_name.into(),
            ]);
        }
    }
    for address in &spec.config.inet6_address {
        if !address.trim().is_empty() {
            commands.push(vec![
                "-6".into(),
                "addr".into(),
                "add".into(),
                address.trim().to_owned(),
                "dev".into(),
                device_name.into(),
            ]);
        }
    }
    commands.push(vec![
        "link".into(),
        "set".into(),
        "dev".into(),
        device_name.into(),
        "up".into(),
    ]);
    commands.extend(linux_tun_auto_route_commands(spec, device_name));
    commands
}

fn linux_ifreq_name(ifreq: &LinuxIfReq) -> String {
    let bytes = ifreq
        .name
        .iter()
        .copied()
        .map(|value| value as u8)
        .take_while(|value| *value != 0)
        .collect::<Vec<_>>();
    String::from_utf8_lossy(&bytes).trim().to_owned()
}

fn configure_linux_tun_interface(spec: &TunRuntimeSpec, device_name: &str) -> io::Result<()> {
    for command in linux_tun_setup_commands(spec, device_name) {
        run_linux_ip_command(&command)?;
    }
    Ok(())
}

pub fn cleanup_linux_tun_interface(spec: &TunRuntimeSpec, device_name: &str) -> io::Result<()> {
    let mut first_err = None;
    for command in linux_tun_cleanup_commands(spec, device_name) {
        if let Err(err) = run_linux_ip_command_allow_missing(&command) {
            if first_err.is_none() {
                first_err = Some(err);
            }
        }
    }
    if let Some(err) = first_err {
        return Err(err);
    }
    Ok(())
}

fn linux_tun_auto_route_commands(spec: &TunRuntimeSpec, device_name: &str) -> Vec<Vec<String>> {
    if !spec.config.auto_route {
        return Vec::new();
    }

    let table = iproute2_table_index(spec);
    let rule = iproute2_rule_index(spec);
    let mut commands = Vec::new();

    for prefix in auto_route_ranges(spec) {
        let prefix_text = prefix.to_string();
        if prefix.addr().is_ipv6() {
            commands.push(vec![
                "-6".into(),
                "route".into(),
                "replace".into(),
                prefix_text,
                "dev".into(),
                device_name.into(),
                "table".into(),
                table.to_string(),
            ]);
        } else {
            commands.push(vec![
                "route".into(),
                "replace".into(),
                prefix_text,
                "dev".into(),
                device_name.into(),
                "table".into(),
                table.to_string(),
            ]);
        }
    }

    commands.extend(linux_tun_auto_route_rule_commands(
        spec,
        device_name,
        table,
        rule,
        true,
    ));

    commands
}

fn linux_tun_cleanup_commands(spec: &TunRuntimeSpec, device_name: &str) -> Vec<Vec<String>> {
    if !spec.config.auto_route {
        return Vec::new();
    }

    let table = iproute2_table_index(spec);
    let rule = iproute2_rule_index(spec);
    let mut commands = Vec::new();

    for prefix in auto_route_ranges(spec) {
        let prefix_text = prefix.to_string();
        if prefix.addr().is_ipv6() {
            commands.push(vec![
                "-6".into(),
                "route".into(),
                "del".into(),
                prefix_text,
                "dev".into(),
                device_name.into(),
                "table".into(),
                table.to_string(),
            ]);
        } else {
            commands.push(vec![
                "route".into(),
                "del".into(),
                prefix_text,
                "dev".into(),
                device_name.into(),
                "table".into(),
                table.to_string(),
            ]);
        }
    }

    commands.extend(linux_tun_auto_route_rule_commands(
        spec,
        device_name,
        table,
        rule,
        false,
    ));

    commands
}

fn linux_tun_auto_route_rule_commands(
    spec: &TunRuntimeSpec,
    device_name: &str,
    table: i32,
    rule: i32,
    replace: bool,
) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    let action = if replace { "add" } else { "del" };

    let inet4_subnets = interface_subnets(&spec.config.inet4_address);
    if !inet4_subnets.is_empty() {
        let mut priority = rule;
        let nop_priority = rule + 10;
        emit_linux_rule_filters(
            &mut commands,
            RuleFilterFamily::Ipv4,
            action,
            &mut priority,
            nop_priority,
            &spec.config.include_interface,
            &spec.config.exclude_interface,
            &collect_u32_ranges(&spec.config.include_uid, &spec.config.include_uid_range),
            &collect_u32_ranges(&spec.config.exclude_uid, &spec.config.exclude_uid_range),
            &collect_u16_ranges(
                &spec.config.exclude_src_port,
                &spec.config.exclude_src_port_range,
            ),
            &collect_u16_ranges(
                &spec.config.exclude_dst_port,
                &spec.config.exclude_dst_port_range,
            ),
        );
        if spec.config.strict_route && spec.config.inet4_address.is_empty() {
            commands.push(vec![
                "rule".into(),
                action.into(),
                "type".into(),
                "unreachable".into(),
                "priority".into(),
                priority.to_string(),
            ]);
            priority += 1;
        }
        for subnet in &inet4_subnets {
            commands.push(vec![
                "rule".into(),
                action.into(),
                "to".into(),
                subnet.to_string(),
                "lookup".into(),
                table.to_string(),
                "priority".into(),
                priority.to_string(),
            ]);
            priority += 1;
        }
        commands.push(vec![
            "rule".into(),
            action.into(),
            "not".into(),
            "dport".into(),
            "53".into(),
            "lookup".into(),
            "main".into(),
            "suppress_prefixlength".into(),
            "0".into(),
            "priority".into(),
            priority.to_string(),
        ]);
        priority += 1;
        commands.push(vec![
            "rule".into(),
            action.into(),
            "lookup".into(),
            "main".into(),
            "iif".into(),
            device_name.into(),
            "priority".into(),
            priority.to_string(),
        ]);
        priority += 1;
        commands.push(vec![
            "rule".into(),
            action.into(),
            "not".into(),
            "iif".into(),
            "lo".into(),
            "lookup".into(),
            table.to_string(),
            "priority".into(),
            priority.to_string(),
        ]);
        priority += 1;
        commands.push(vec![
            "rule".into(),
            action.into(),
            "iif".into(),
            "lo".into(),
            "from".into(),
            "0.0.0.0/32".into(),
            "lookup".into(),
            table.to_string(),
            "priority".into(),
            priority.to_string(),
        ]);
        priority += 1;
        for subnet in &inet4_subnets {
            commands.push(vec![
                "rule".into(),
                action.into(),
                "iif".into(),
                "lo".into(),
                "from".into(),
                subnet.to_string(),
                "lookup".into(),
                table.to_string(),
                "priority".into(),
                priority.to_string(),
            ]);
            priority += 1;
        }
        commands.push(vec![
            "rule".into(),
            action.into(),
            "priority".into(),
            nop_priority.to_string(),
        ]);
    }

    let inet6_subnets = interface_subnets(&spec.config.inet6_address);
    if !inet6_subnets.is_empty() {
        let mut priority = rule;
        let nop_priority = rule + 10;
        emit_linux_rule_filters(
            &mut commands,
            RuleFilterFamily::Ipv6,
            action,
            &mut priority,
            nop_priority,
            &spec.config.include_interface,
            &spec.config.exclude_interface,
            &collect_u32_ranges(&spec.config.include_uid, &spec.config.include_uid_range),
            &collect_u32_ranges(&spec.config.exclude_uid, &spec.config.exclude_uid_range),
            &collect_u16_ranges(
                &spec.config.exclude_src_port,
                &spec.config.exclude_src_port_range,
            ),
            &collect_u16_ranges(
                &spec.config.exclude_dst_port,
                &spec.config.exclude_dst_port_range,
            ),
        );
        if spec.config.strict_route && spec.config.inet6_address.is_empty() {
            commands.push(vec![
                "-6".into(),
                "rule".into(),
                action.into(),
                "type".into(),
                "unreachable".into(),
                "priority".into(),
                priority.to_string(),
            ]);
            priority += 1;
        }
        for subnet in &inet6_subnets {
            commands.push(vec![
                "-6".into(),
                "rule".into(),
                action.into(),
                "to".into(),
                subnet.to_string(),
                "lookup".into(),
                table.to_string(),
                "priority".into(),
                priority.to_string(),
            ]);
            priority += 1;
        }
        commands.push(vec![
            "-6".into(),
            "rule".into(),
            action.into(),
            "not".into(),
            "dport".into(),
            "53".into(),
            "lookup".into(),
            "main".into(),
            "suppress_prefixlength".into(),
            "0".into(),
            "priority".into(),
            priority.to_string(),
        ]);
        priority += 1;
        commands.push(vec![
            "-6".into(),
            "rule".into(),
            action.into(),
            "lookup".into(),
            "main".into(),
            "iif".into(),
            device_name.into(),
            "priority".into(),
            priority.to_string(),
        ]);
        priority += 1;
        commands.push(vec![
            "-6".into(),
            "rule".into(),
            action.into(),
            "iif".into(),
            "lo".into(),
            "from".into(),
            "::/1".into(),
            "lookup".into(),
            "main".into(),
            "priority".into(),
            priority.to_string(),
        ]);
        priority += 1;
        commands.push(vec![
            "-6".into(),
            "rule".into(),
            action.into(),
            "iif".into(),
            "lo".into(),
            "from".into(),
            "8000::/1".into(),
            "lookup".into(),
            "main".into(),
            "priority".into(),
            priority.to_string(),
        ]);
        priority += 1;
        for subnet in &inet6_subnets {
            commands.push(vec![
                "-6".into(),
                "rule".into(),
                action.into(),
                "iif".into(),
                "lo".into(),
                "from".into(),
                subnet.to_string(),
                "lookup".into(),
                table.to_string(),
                "priority".into(),
                priority.to_string(),
            ]);
            priority += 1;
        }
        commands.push(vec![
            "-6".into(),
            "rule".into(),
            action.into(),
            "lookup".into(),
            table.to_string(),
            "priority".into(),
            priority.to_string(),
        ]);
        commands.push(vec![
            "-6".into(),
            "rule".into(),
            action.into(),
            "priority".into(),
            nop_priority.to_string(),
        ]);
    }

    commands
}

#[derive(Clone, Copy)]
enum RuleFilterFamily {
    Ipv4,
    Ipv6,
}

fn emit_linux_rule_filters(
    commands: &mut Vec<Vec<String>>,
    family: RuleFilterFamily,
    action: &str,
    priority: &mut i32,
    nop_priority: i32,
    include_interfaces: &[String],
    exclude_interfaces: &[String],
    include_uid_ranges: &[(u32, u32)],
    exclude_uid_ranges: &[(u32, u32)],
    exclude_src_ports: &[(u16, u16)],
    exclude_dst_ports: &[(u16, u16)],
) {
    for (start, end) in exclude_src_ports {
        commands.push(build_rule_command(
            family,
            action,
            &[
                "sport",
                &render_u16_range(*start, *end),
                "goto",
                &nop_priority.to_string(),
                "priority",
                &priority.to_string(),
            ],
        ));
    }
    if !exclude_src_ports.is_empty() {
        *priority += 1;
    }

    for (start, end) in exclude_dst_ports {
        commands.push(build_rule_command(
            family,
            action,
            &[
                "dport",
                &render_u16_range(*start, *end),
                "goto",
                &nop_priority.to_string(),
                "priority",
                &priority.to_string(),
            ],
        ));
    }
    if !exclude_dst_ports.is_empty() {
        *priority += 1;
    }

    for (start, end) in exclude_uid_ranges {
        commands.push(build_rule_command(
            family,
            action,
            &[
                "uidrange",
                &render_u32_range(*start, *end),
                "goto",
                &nop_priority.to_string(),
                "priority",
                &priority.to_string(),
            ],
        ));
    }
    if !exclude_uid_ranges.is_empty() {
        *priority += 1;
    }

    if !include_interfaces.is_empty() {
        let match_priority = *priority + 2;
        for interface in include_interfaces {
            commands.push(build_rule_command(
                family,
                action,
                &[
                    "iif",
                    interface,
                    "goto",
                    &match_priority.to_string(),
                    "priority",
                    &priority.to_string(),
                ],
            ));
        }
        *priority += 1;
        commands.push(build_rule_command(
            family,
            action,
            &[
                "goto",
                &nop_priority.to_string(),
                "priority",
                &priority.to_string(),
            ],
        ));
        *priority += 1;
        commands.push(build_rule_command(
            family,
            action,
            &["priority", &match_priority.to_string()],
        ));
        *priority += 1;
    } else if !exclude_interfaces.is_empty() {
        for interface in exclude_interfaces {
            commands.push(build_rule_command(
                family,
                action,
                &[
                    "iif",
                    interface,
                    "goto",
                    &nop_priority.to_string(),
                    "priority",
                    &priority.to_string(),
                ],
            ));
        }
        *priority += 1;
    }

    if !include_uid_ranges.is_empty() {
        let match_priority = *priority + 2;
        for (start, end) in include_uid_ranges {
            commands.push(build_rule_command(
                family,
                action,
                &[
                    "uidrange",
                    &render_u32_range(*start, *end),
                    "goto",
                    &match_priority.to_string(),
                    "priority",
                    &priority.to_string(),
                ],
            ));
        }
        *priority += 1;
        commands.push(build_rule_command(
            family,
            action,
            &[
                "goto",
                &nop_priority.to_string(),
                "priority",
                &priority.to_string(),
            ],
        ));
        *priority += 1;
        commands.push(build_rule_command(
            family,
            action,
            &["priority", &match_priority.to_string()],
        ));
        *priority += 1;
    }
}

fn build_rule_command(family: RuleFilterFamily, action: &str, tokens: &[&str]) -> Vec<String> {
    let mut command = Vec::new();
    if matches!(family, RuleFilterFamily::Ipv6) {
        command.push("-6".into());
    }
    command.push("rule".into());
    command.push(action.into());
    command.extend(tokens.iter().map(|token| (*token).to_owned()));
    command
}

fn render_u16_range(start: u16, end: u16) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}

fn render_u32_range(start: u32, end: u32) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}

fn collect_u16_ranges(values: &[u16], ranges: &[String]) -> Vec<(u16, u16)> {
    let mut collected = values.iter().map(|value| (*value, *value)).collect::<Vec<_>>();
    collected.extend(parse_u16_ranges(ranges));
    collected
}

fn collect_u32_ranges(values: &[u32], ranges: &[String]) -> Vec<(u32, u32)> {
    let mut collected = values.iter().map(|value| (*value, *value)).collect::<Vec<_>>();
    collected.extend(parse_u32_ranges(ranges));
    collected
}

fn parse_u16_ranges(raw_ranges: &[String]) -> Vec<(u16, u16)> {
    raw_ranges
        .iter()
        .filter_map(|raw| parse_u16_range(raw))
        .collect()
}

fn parse_u32_ranges(raw_ranges: &[String]) -> Vec<(u32, u32)> {
    raw_ranges
        .iter()
        .filter_map(|raw| parse_u32_range(raw))
        .collect()
}

fn parse_u16_range(raw: &str) -> Option<(u16, u16)> {
    let (start, end) = raw.trim().split_once(':')?;
    Some((start.trim().parse().ok()?, end.trim().parse().ok()?))
}

fn parse_u32_range(raw: &str) -> Option<(u32, u32)> {
    let (start, end) = raw.trim().split_once(':')?;
    Some((start.trim().parse().ok()?, end.trim().parse().ok()?))
}

fn interface_subnets(addresses: &[String]) -> Vec<IpNet> {
    addresses
        .iter()
        .filter_map(|address| parse_ipnet(address))
        .map(|address| address.trunc())
        .collect()
}

fn auto_route_ranges(spec: &TunRuntimeSpec) -> Vec<IpNet> {
    let mut ranges = Vec::new();

    let mut inet4 = spec
        .config
        .route_address
        .iter()
        .filter_map(|prefix| parse_ipnet(prefix))
        .filter(|prefix| prefix.addr().is_ipv4())
        .collect::<Vec<_>>();
    inet4.extend(
        spec.config
            .inet4_route_address
            .iter()
            .filter_map(|prefix| parse_ipnet(prefix))
            .filter(|prefix| prefix.addr().is_ipv4()),
    );
    if inet4.is_empty() && !spec.config.inet4_address.is_empty() {
        inet4.push("0.0.0.0/0".parse().unwrap());
    }
    let inet4_excludes = spec
        .config
        .route_exclude_address
        .iter()
        .filter_map(|prefix| parse_ipnet(prefix))
        .filter(|prefix| prefix.addr().is_ipv4())
        .chain(
            spec.config
                .inet4_route_exclude_address
                .iter()
                .filter_map(|prefix| parse_ipnet(prefix))
                .filter(|prefix| prefix.addr().is_ipv4()),
        )
        .collect::<Vec<_>>();
    ranges.extend(filter_exact_excludes(inet4, &inet4_excludes));

    let mut inet6 = spec
        .config
        .route_address
        .iter()
        .filter_map(|prefix| parse_ipnet(prefix))
        .filter(|prefix| prefix.addr().is_ipv6())
        .collect::<Vec<_>>();
    inet6.extend(
        spec.config
            .inet6_route_address
            .iter()
            .filter_map(|prefix| parse_ipnet(prefix))
            .filter(|prefix| prefix.addr().is_ipv6()),
    );
    if inet6.is_empty() && !spec.config.inet6_address.is_empty() {
        inet6.push("::/0".parse().unwrap());
    }
    let inet6_excludes = spec
        .config
        .route_exclude_address
        .iter()
        .filter_map(|prefix| parse_ipnet(prefix))
        .filter(|prefix| prefix.addr().is_ipv6())
        .chain(
            spec.config
                .inet6_route_exclude_address
                .iter()
                .filter_map(|prefix| parse_ipnet(prefix))
                .filter(|prefix| prefix.addr().is_ipv6()),
        )
        .collect::<Vec<_>>();
    ranges.extend(filter_exact_excludes(inet6, &inet6_excludes));

    ranges
}

fn filter_exact_excludes(ranges: Vec<IpNet>, excludes: &[IpNet]) -> Vec<IpNet> {
    ranges
        .into_iter()
        .filter(|range| !excludes.iter().any(|exclude| exclude == range))
        .collect()
}

fn parse_ipnet(prefix: &str) -> Option<IpNet> {
    let trimmed = prefix.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<IpNet>().ok()
}

fn iproute2_table_index(spec: &TunRuntimeSpec) -> i32 {
    if spec.config.iproute2_table_index > 0 {
        spec.config.iproute2_table_index
    } else {
        DEFAULT_IPROUTE2_TABLE_INDEX
    }
}

fn iproute2_rule_index(spec: &TunRuntimeSpec) -> i32 {
    if spec.config.iproute2_rule_index > 0 {
        spec.config.iproute2_rule_index
    } else {
        DEFAULT_IPROUTE2_RULE_INDEX
    }
}

fn run_linux_ip_command(args: &[String]) -> io::Result<()> {
    let candidates = ["/sbin/ip", "/usr/sbin/ip", "ip"];
    let mut last_not_found = None;
    for candidate in candidates {
        let output = Command::new(candidate).args(args).output();
        match output {
            Ok(output) => {
                if output.status.success() {
                    return Ok(());
                }
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
                let detail = if stderr.is_empty() {
                    format!("exit status {}", output.status)
                } else {
                    stderr
                };
                return Err(io::Error::other(format!(
                    "failed to configure linux tun interface with `{candidate} {}`: {detail}",
                    args.join(" ")
                )));
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                last_not_found = Some(err);
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_not_found.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "linux ip command not found")
    }))
}

fn run_linux_ip_command_allow_missing(args: &[String]) -> io::Result<()> {
    match run_linux_ip_command(args) {
        Ok(()) => Ok(()),
        Err(err)
            if err
                .to_string()
                .contains("Cannot find device")
                || err.to_string().contains("No such process")
                || err.to_string().contains("No such file or directory") =>
        {
            Ok(())
        }
        Err(err) => Err(err),
    }
}
