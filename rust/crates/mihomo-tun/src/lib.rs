use std::net::SocketAddr;

use mihomo_core::{Metadata, NetworkKind, RewriteStage, SessionKind, SubsystemManifest};
use mihomo_inbound::{TunInboundConfig, TunStack};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunRuntimeSpec {
    pub name: String,
    pub config: TunInboundConfig,
}

impl TunRuntimeSpec {
    pub fn new(name: impl Into<String>, config: TunInboundConfig) -> Self {
        Self {
            name: name.into(),
            config,
        }
    }

    pub fn stack(&self) -> TunStack {
        self.config.stack.clone()
    }

    pub fn should_hijack_dns(&self, destination: SocketAddr) -> bool {
        self.config
            .dns_hijack
            .iter()
            .any(|entry| dns_hijack_matches(entry, destination))
    }

    pub fn allows_interface(&self, name: &str) -> bool {
        allows_value(&self.config.include_interface, &self.config.exclude_interface, name)
    }

    pub fn allows_package(&self, package: &str) -> bool {
        allows_value(&self.config.include_package, &self.config.exclude_package, package)
    }

    pub fn allows_uid(&self, uid: u32) -> bool {
        let include_matches = self.config.include_uid.contains(&uid)
            || self
                .config
                .include_uid_range
                .iter()
                .any(|range| uid_in_range(uid, range));
        let exclude_matches = self.config.exclude_uid.contains(&uid)
            || self
                .config
                .exclude_uid_range
                .iter()
                .any(|range| uid_in_range(uid, range));

        if !self.config.include_uid.is_empty() || !self.config.include_uid_range.is_empty() {
            include_matches && !exclude_matches
        } else {
            !exclude_matches
        }
    }

    pub fn prepare_tcp_metadata(
        &self,
        source: Option<SocketAddr>,
        destination: SocketAddr,
    ) -> Metadata {
        let mut metadata = Metadata {
            network: NetworkKind::Tcp,
            kind: SessionKind::Tun,
            inbound_name: self.name.clone(),
            dst_ip: Some(destination.ip()),
            dst_port: Some(destination.port()),
            special_proxy: self.config.base.special_proxy.clone(),
            special_rules: self.config.base.special_rules.clone(),
            ..Metadata::default()
        };
        if let Some(source) = source {
            metadata.src_ip = Some(source.ip());
            metadata.src_port = Some(source.port());
        }
        metadata
    }

    pub fn prepare_udp_metadata(
        &self,
        source: Option<SocketAddr>,
        destination: SocketAddr,
    ) -> Metadata {
        let mut metadata = Metadata {
            network: NetworkKind::Udp,
            kind: SessionKind::Tun,
            dst_ip: Some(destination.ip()),
            dst_port: Some(destination.port()),
            inbound_name: self.name.clone(),
            special_proxy: self.config.base.special_proxy.clone(),
            special_rules: self.config.base.special_rules.clone(),
            ..Metadata::default()
        };
        if let Some(source) = source {
            metadata.src_ip = Some(source.ip());
            metadata.src_port = Some(source.port());
        }
        metadata
    }
}

fn allows_value(include: &[String], exclude: &[String], value: &str) -> bool {
    if !include.is_empty() && !include.iter().any(|item| item == value) {
        return false;
    }
    !exclude.iter().any(|item| item == value)
}

fn uid_in_range(uid: u32, raw: &str) -> bool {
    let Some((start, end)) = raw.split_once(':') else {
        return false;
    };
    let Ok(start) = start.trim().parse::<u32>() else {
        return false;
    };
    let Ok(end) = end.trim().parse::<u32>() else {
        return false;
    };
    start <= uid && uid <= end
}

fn dns_hijack_matches(entry: &str, destination: SocketAddr) -> bool {
    let Some((host, port)) = entry.rsplit_once(':') else {
        return false;
    };
    let Ok(port) = port.trim().parse::<u16>() else {
        return false;
    };
    if port != destination.port() {
        return false;
    }
    let host = host.trim();
    host == "*"
        || host == "0.0.0.0"
        || host == "::"
        || host == destination.ip().to_string()
}

pub const MODULE: SubsystemManifest = SubsystemManifest {
    crate_name: "mihomo-tun",
    go_areas: &["listener/sing_tun", "listener/redir", "listener/tproxy"],
    contracts: &["tun", "redir", "tproxy", "transparent interception"],
    stage: RewriteStage::Verified,
};

pub fn manifest() -> &'static SubsystemManifest {
    &MODULE
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use mihomo_core::{NetworkKind, SessionKind};
    use mihomo_inbound::{TunInboundConfig, TunStack};

    use super::TunRuntimeSpec;

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
}
