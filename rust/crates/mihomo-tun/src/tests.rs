#[cfg(target_os = "linux")]
use std::io;
use std::net::SocketAddr;

use mihomo_core::{NetworkKind, SessionKind};
use mihomo_inbound::{TunInboundConfig, TunStack};

use crate::TunRuntimeSpec;
#[cfg(target_os = "linux")]
use crate::{linux_tun_setup_commands, requested_linux_tun_name};

fn spec() -> TunRuntimeSpec {
    TunRuntimeSpec::new(
        "tun0",
        TunInboundConfig {
            stack: TunStack::System,
            dns_hijack: vec!["0.0.0.0:53".into(), "198.18.0.2:1053".into()],
            include_interface: vec!["en0".into()],
            exclude_interface: vec!["utun2".into()],
            include_package: vec!["com.example.app".into()],
            exclude_package: vec!["com.example.blocked".into()],
            include_uid_range: vec!["1000:1999".into()],
            exclude_uid: vec![1500],
            ..TunInboundConfig::default()
        },
    )
}

#[test]
fn dns_hijack_matches_wildcard_and_exact_targets() {
    let spec = spec();
    assert!(spec.should_hijack_dns("1.1.1.1:53".parse().unwrap()));
    assert!(spec.should_hijack_dns("198.18.0.2:1053".parse().unwrap()));
    assert!(!spec.should_hijack_dns("1.1.1.1:5353".parse().unwrap()));
}

#[test]
fn dns_hijack_matches_any_and_protocol_prefixed_targets() {
    let spec = TunRuntimeSpec::new(
        "tun0",
        TunInboundConfig {
            dns_hijack: vec!["any:53".into(), "tcp://any:5353".into()],
            ..TunInboundConfig::default()
        },
    );
    assert!(spec.should_hijack_dns("8.8.8.8:53".parse().unwrap()));
    assert!(spec.should_hijack_dns("1.1.1.1:5353".parse().unwrap()));
    assert!(!spec.should_hijack_dns("1.1.1.1:853".parse().unwrap()));
    assert!(spec.should_hijack_dns_for_network(NetworkKind::Udp, "8.8.8.8:53".parse().unwrap()));
    assert!(!spec.should_hijack_dns_for_network(NetworkKind::Tcp, "8.8.8.8:53".parse().unwrap()));
    assert!(spec.should_hijack_dns_for_network(NetworkKind::Tcp, "8.8.8.8:5353".parse().unwrap()));
    assert!(!spec.should_hijack_dns_for_network(NetworkKind::Udp, "8.8.8.8:5353".parse().unwrap()));
}

#[test]
fn include_exclude_filters_apply_to_interfaces_packages_and_uids() {
    let spec = spec();
    assert!(spec.allows_interface("en0"));
    assert!(!spec.allows_interface("utun2"));
    assert!(spec.allows_package("com.example.app"));
    assert!(!spec.allows_package("com.example.blocked"));
    assert!(spec.allows_uid(1200));
    assert!(!spec.allows_uid(1500));
    assert!(!spec.allows_uid(999));
}

#[test]
fn metadata_preparation_marks_tun_session_kind() {
    let spec = spec();
    let tcp = spec.prepare_tcp_metadata(
        Some("10.0.0.2:50000".parse::<SocketAddr>().unwrap()),
        "93.184.216.34:443".parse().unwrap(),
    );
    assert_eq!(tcp.network, NetworkKind::Tcp);
    assert_eq!(tcp.kind, SessionKind::Tun);
    assert_eq!(tcp.inbound_name, "tun0");

    let udp = spec.prepare_udp_metadata(None, "1.1.1.1:53".parse().unwrap());
    assert_eq!(udp.network, NetworkKind::Udp);
    assert_eq!(udp.kind, SessionKind::Tun);
    assert_eq!(udp.dst_port, Some(53));
}

#[cfg(target_os = "linux")]
#[test]
fn requested_linux_tun_name_prefers_device_and_skips_internal_names() {
    let explicit = TunRuntimeSpec::new(
        "__top_level_tun__",
        TunInboundConfig {
            device: "mihomo0".into(),
            ..Default::default()
        },
    );
    assert_eq!(requested_linux_tun_name(&explicit).unwrap(), "mihomo0");

    let internal = TunRuntimeSpec::new("__top_level_tun__", TunInboundConfig::default());
    assert_eq!(requested_linux_tun_name(&internal).unwrap(), "");

    let listener = TunRuntimeSpec::new("edge-tun", TunInboundConfig::default());
    assert_eq!(requested_linux_tun_name(&listener).unwrap(), "edge-tun");
}

#[cfg(target_os = "linux")]
#[test]
fn requested_linux_tun_name_rejects_overlong_names() {
    let spec = TunRuntimeSpec::new(
        "edge-tun",
        TunInboundConfig {
            device: "this-name-is-way-too-long-for-linux-tun".into(),
            ..Default::default()
        },
    );
    let err = requested_linux_tun_name(&spec).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_tun_setup_commands_configure_mtu_addresses_and_link_up() {
    let spec = TunRuntimeSpec::new(
        "edge-tun",
        TunInboundConfig {
            mtu: 1400,
            inet4_address: vec!["10.0.0.1/30".into()],
            inet6_address: vec!["fd00::1/126".into()],
            ..Default::default()
        },
    );
    let commands = linux_tun_setup_commands(&spec, "mihomo0");
    assert_eq!(
        commands,
        vec![
            vec!["link", "set", "dev", "mihomo0", "mtu", "1400"],
            vec!["addr", "add", "10.0.0.1/30", "dev", "mihomo0"],
            vec!["-6", "addr", "add", "fd00::1/126", "dev", "mihomo0"],
            vec!["link", "set", "dev", "mihomo0", "up"],
        ]
        .into_iter()
        .map(|items| items.into_iter().map(str::to_owned).collect::<Vec<_>>())
        .collect::<Vec<_>>()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_tun_setup_commands_include_auto_route_rules() {
    let spec = TunRuntimeSpec::new(
        "edge-tun",
        TunInboundConfig {
            auto_route: true,
            iproute2_table_index: 2022,
            iproute2_rule_index: 9000,
            inet4_address: vec!["198.19.0.1/30".into()],
            inet6_address: vec!["fd00::1/126".into()],
            ..Default::default()
        },
    );
    let commands = linux_tun_setup_commands(&spec, "mihomo0");
    let rendered = commands
        .iter()
        .map(|parts| parts.join(" "))
        .collect::<Vec<_>>();
    assert!(rendered.contains(&"route replace 0.0.0.0/0 dev mihomo0 table 2022".to_owned()));
    assert!(rendered.contains(&"-6 route replace ::/0 dev mihomo0 table 2022".to_owned()));
    assert!(rendered.contains(&"rule add to 198.19.0.0/30 lookup 2022 priority 9000".to_owned()));
    assert!(rendered.contains(&"rule add not dport 53 lookup main suppress_prefixlength 0 priority 9001".to_owned()));
    assert!(rendered.contains(&"rule add lookup main iif mihomo0 priority 9002".to_owned()));
    assert!(rendered.contains(&"rule add not iif lo lookup 2022 priority 9003".to_owned()));
    assert!(rendered.contains(&"rule add iif lo from 0.0.0.0/32 lookup 2022 priority 9004".to_owned()));
    assert!(rendered.contains(&"rule add iif lo from 198.19.0.0/30 lookup 2022 priority 9005".to_owned()));
    assert!(rendered.contains(&"-6 rule add to fd00::/126 lookup 2022 priority 9000".to_owned()));
    assert!(rendered.contains(&"-6 rule add not dport 53 lookup main suppress_prefixlength 0 priority 9001".to_owned()));
    assert!(rendered.contains(&"-6 rule add lookup main iif mihomo0 priority 9002".to_owned()));
    assert!(rendered.contains(&"-6 rule add iif lo from ::/1 lookup main priority 9003".to_owned()));
    assert!(rendered.contains(&"-6 rule add iif lo from 8000::/1 lookup main priority 9004".to_owned()));
    assert!(rendered.contains(&"-6 rule add iif lo from fd00::/126 lookup 2022 priority 9005".to_owned()));
    assert!(rendered.contains(&"-6 rule add lookup 2022 priority 9006".to_owned()));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_tun_setup_commands_include_linux_rule_filters() {
    let spec = TunRuntimeSpec::new(
        "edge-tun",
        TunInboundConfig {
            auto_route: true,
            iproute2_table_index: 2022,
            iproute2_rule_index: 9000,
            inet4_address: vec!["198.19.0.1/30".into()],
            inet6_address: vec!["fd00::1/126".into()],
            include_interface: vec!["br-lan".into()],
            exclude_interface: vec!["docker0".into()],
            include_uid: vec![1000],
            include_uid_range: vec!["2000:2999".into()],
            exclude_uid: vec![3000],
            exclude_uid_range: vec!["4000:4999".into()],
            exclude_src_port: vec![53],
            exclude_src_port_range: vec!["1000:2000".into()],
            exclude_dst_port: vec![443],
            exclude_dst_port_range: vec!["8000:8100".into()],
            strict_route: true,
            ..Default::default()
        },
    );
    let commands = linux_tun_setup_commands(&spec, "mihomo0");
    let rendered = commands
        .iter()
        .map(|parts| parts.join(" "))
        .collect::<Vec<_>>();
    assert!(rendered.contains(&"rule add sport 53 goto 9010 priority 9000".to_owned()));
    assert!(rendered.contains(&"rule add sport 1000-2000 goto 9010 priority 9000".to_owned()));
    assert!(rendered.contains(&"rule add dport 443 goto 9010 priority 9001".to_owned()));
    assert!(rendered.contains(&"rule add dport 8000-8100 goto 9010 priority 9001".to_owned()));
    assert!(rendered.contains(&"rule add uidrange 3000 goto 9010 priority 9002".to_owned()));
    assert!(rendered.contains(&"rule add uidrange 4000-4999 goto 9010 priority 9002".to_owned()));
    assert!(rendered.contains(&"rule add iif br-lan goto 9005 priority 9003".to_owned()));
    assert!(rendered.contains(&"rule add goto 9010 priority 9004".to_owned()));
    assert!(rendered.contains(&"rule add priority 9005".to_owned()));
    assert!(rendered.contains(&"rule add uidrange 1000 goto 9008 priority 9006".to_owned()));
    assert!(rendered.contains(&"rule add uidrange 2000-2999 goto 9008 priority 9006".to_owned()));
    assert!(rendered.contains(&"rule add goto 9010 priority 9007".to_owned()));
    assert!(rendered.contains(&"rule add priority 9008".to_owned()));
    assert!(rendered.contains(&"rule add priority 9010".to_owned()));
    assert!(rendered.contains(&"-6 rule add sport 53 goto 9010 priority 9000".to_owned()));
    assert!(rendered.contains(&"-6 rule add dport 443 goto 9010 priority 9001".to_owned()));
    assert!(rendered.contains(&"-6 rule add uidrange 1000 goto 9008 priority 9006".to_owned()));
    assert!(rendered.contains(&"-6 rule add priority 9010".to_owned()));
}
