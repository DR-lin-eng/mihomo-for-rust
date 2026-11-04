use std::collections::BTreeSet;
use std::fmt;

use mihomo_inbound::{GenericInboundConfig, InboundDefinition};
use mihomo_outbound::OutboundDefinition;
use serde_yaml::Value;
use uuid::Uuid;

use crate::RuntimeConfigDocument;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigValidationError {
    InvalidSmartConfig(String),
    InvalidEbpfConfig(String),
    DuplicateProxyName(String),
    DuplicateProxyGroupName(String),
    DuplicateListenerName(String),
    ReservedProviderName(String),
    ProxyGroupMissingName(usize),
    UnsupportedProxyGroupType(String),
    ProxyGroupReferenceNotFound {
        group: String,
        reference: String,
    },
    ProviderVehicleUnsupported {
        provider: String,
        vehicle_type: String,
    },
    InvalidProxyUuid {
        proxy: String,
        protocol: String,
        uuid: String,
        error: String,
    },
    InvalidListenerUuid {
        listener: String,
        protocol: String,
        uuid: String,
        error: String,
    },
}

impl fmt::Display for ConfigValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEbpfConfig(message) => write!(f, "invalid ebpf configuration: {message}"),
            Self::InvalidSmartConfig(message) => write!(f, "invalid smart group: {message}"),
            Self::DuplicateProxyName(name) => write!(f, "proxy {name} is the duplicate name"),
            Self::DuplicateProxyGroupName(name) => {
                write!(f, "proxy group {name}: the duplicate name")
            }
            Self::DuplicateListenerName(name) => write!(f, "listener {name} is the duplicate name"),
            Self::ReservedProviderName(name) => {
                write!(f, "can not defined a provider called `{name}`")
            }
            Self::ProxyGroupMissingName(index) => write!(f, "proxy group {index}: missing name"),
            Self::UnsupportedProxyGroupType(name) => write!(
                f,
                "unsupported proxy group type or removed group behavior: {name}"
            ),
            Self::ProxyGroupReferenceNotFound { group, reference } => {
                write!(f, "proxy group {group}: '{reference}' not found")
            }
            Self::ProviderVehicleUnsupported {
                provider,
                vehicle_type,
            } => write!(
                f,
                "parse proxy provider {provider} error: unsupport vehicle type: {vehicle_type}"
            ),
            Self::InvalidProxyUuid {
                proxy,
                protocol,
                uuid,
                error,
            } => write!(
                f,
                "{protocol} proxy {proxy} has invalid uuid {uuid:?}: {error}"
            ),
            Self::InvalidListenerUuid {
                listener,
                protocol,
                uuid,
                error,
            } => write!(
                f,
                "{protocol} listener {listener} has invalid user uuid {uuid:?}: {error}"
            ),
        }
    }
}

impl std::error::Error for ConfigValidationError {}

impl RuntimeConfigDocument {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        let mut interfaces = BTreeSet::new();
        for name in self
            .ebpf
            .redirect_to_tun
            .iter()
            .chain(&self.ebpf.auto_redir)
            .chain(&self.ebpf.direct_offload)
        {
            if name.is_empty()
                || name.len() >= 16
                || !name
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
            {
                return Err(ConfigValidationError::InvalidEbpfConfig(format!(
                    "invalid interface name: {name:?}"
                )));
            }
            if !interfaces.insert(name) {
                return Err(ConfigValidationError::InvalidEbpfConfig(format!(
                    "interface {name} is configured more than once"
                )));
            }
        }
        if !self.ebpf.redirect_to_tun.is_empty() || !self.ebpf.direct_offload.is_empty() {
            if !self.tun.enable || self.tun.config.device.trim().is_empty() {
                return Err(ConfigValidationError::InvalidEbpfConfig(
                    "redirect-to-tun requires tun.enable and an explicit tun.device".into(),
                ));
            }
            if interfaces.contains(&self.tun.config.device) {
                return Err(ConfigValidationError::InvalidEbpfConfig(
                    "the TUN device cannot be a source interface".into(),
                ));
            }
            if self.tun.config.auto_redirect {
                return Err(ConfigValidationError::InvalidEbpfConfig(
                    "redirect-to-tun cannot be combined with tun.auto-redirect".into(),
                ));
            }
        }
        if !self.ebpf.direct_offload.is_empty() && !self.allow_lan {
            return Err(ConfigValidationError::InvalidEbpfConfig("direct-offload requires allow-lan: true".into()));
        }
        if !self.ebpf.direct_offload.is_empty() && self.tun.config.file_descriptor > 0 {
            return Err(ConfigValidationError::InvalidEbpfConfig("direct-offload requires a named kernel TUN device".into()));
        }
        if self.ebpf.enabled() && self.tun.config.auto_redirect {
            return Err(ConfigValidationError::InvalidEbpfConfig(
                "eBPF capture cannot be combined with tun.auto-redirect".into(),
            ));
        }
        if !self.ebpf.auto_redir.is_empty() && !self.allow_lan {
            return Err(ConfigValidationError::InvalidEbpfConfig(
                "auto-redir requires allow-lan: true".into(),
            ));
        }
        if self.ebpf.enabled()
            && self.routing_mark != 0
            && self.routing_mark as u32 != self.ebpf.effective_bypass_mark()
        {
            return Err(ConfigValidationError::InvalidEbpfConfig(
                "routing-mark must match ebpf.bypass-mark to prevent routing loops".into(),
            ));
        }
        if self.ebpf.enabled() {
            for proxy in &self.proxies {
                let mark = proxy.base().routing_mark;
                if mark != 0 && mark as u32 != self.ebpf.effective_bypass_mark() {
                    return Err(ConfigValidationError::InvalidEbpfConfig(format!(
                        "proxy {} routing-mark must match ebpf.bypass-mark",
                        proxy.name()
                    )));
                }
            }
        }

        let mut seen_proxy_names = BTreeSet::new();
        for proxy in &self.proxies {
            let name = proxy.name().to_owned();
            if !seen_proxy_names.insert(name.clone()) {
                return Err(ConfigValidationError::DuplicateProxyName(name));
            }
            validate_outbound_uuid(proxy)?;
        }

        let mut available_proxy_refs: BTreeSet<String> = [
            "DIRECT",
            "REJECT",
            "REJECT-DROP",
            "COMPATIBLE",
            "PASS",
            "GLOBAL",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        available_proxy_refs.extend(seen_proxy_names.iter().cloned());

        for (name, provider) in &self.proxy_providers {
            if name == "default" {
                return Err(ConfigValidationError::ReservedProviderName(name.clone()));
            }
            if provider.vehicle_type().is_none() {
                return Err(ConfigValidationError::ProviderVehicleUnsupported {
                    provider: name.clone(),
                    vehicle_type: provider.provider_type.clone(),
                });
            }
        }

        let all_group_names = self
            .proxy_groups
            .iter()
            .map(|group| group.name.clone())
            .collect::<Vec<_>>();
        let all_group_name_set = all_group_names.iter().cloned().collect::<BTreeSet<_>>();

        let mut seen_group_names = BTreeSet::new();
        for (index, group) in self.proxy_groups.iter().enumerate() {
            if group.name.is_empty() {
                return Err(ConfigValidationError::ProxyGroupMissingName(index));
            }
            if group.group_type == "smart" {
                for key in ["uselightgbm", "collectdata", "prefer-asn"] {
                    if group
                        .extra
                        .get(key)
                        .is_some_and(|value| !value.is_null() && value.as_bool().is_none())
                    {
                        return Err(ConfigValidationError::InvalidSmartConfig(format!(
                            "{}: {key} must be a boolean",
                            group.name
                        )));
                    }
                }
                if group
                    .extra
                    .get("sample-rate")
                    .is_some_and(|value| !value.is_null() && value.as_f64().is_none())
                {
                    return Err(ConfigValidationError::InvalidSmartConfig(format!(
                        "{}: sample-rate must be a number",
                        group.name
                    )));
                }
                if group
                    .extra
                    .get("policy-priority")
                    .is_some_and(|value| !value.is_null() && value.as_str().is_none())
                {
                    return Err(ConfigValidationError::InvalidSmartConfig(format!(
                        "{}: policy-priority must be a string",
                        group.name
                    )));
                }
                if !(0..=65535).contains(&group.tolerance) {
                    return Err(ConfigValidationError::InvalidSmartConfig(format!(
                        "{}: tolerance out of range",
                        group.name
                    )));
                }
            }
            if group.group_type == "relay" || group.kind().is_none() {
                return Err(ConfigValidationError::UnsupportedProxyGroupType(
                    group.group_type.clone(),
                ));
            }
            if !seen_group_names.insert(group.name.clone())
                || available_proxy_refs.contains(&group.name)
            {
                return Err(ConfigValidationError::DuplicateProxyGroupName(
                    group.name.clone(),
                ));
            }
            for reference in &group.proxies {
                if !available_proxy_refs.contains(reference)
                    && !all_group_name_set.contains(reference)
                {
                    return Err(ConfigValidationError::ProxyGroupReferenceNotFound {
                        group: group.name.clone(),
                        reference: reference.clone(),
                    });
                }
            }
            for provider_name in &group.use_providers {
                if !self.proxy_providers.contains_key(provider_name) {
                    return Err(ConfigValidationError::ProxyGroupReferenceNotFound {
                        group: group.name.clone(),
                        reference: provider_name.clone(),
                    });
                }
            }
        }

        let mut seen_listener_names = BTreeSet::new();
        for listener in &self.listeners {
            let name = listener.base().name.clone();
            if !seen_listener_names.insert(name.clone()) {
                return Err(ConfigValidationError::DuplicateListenerName(name));
            }
            validate_listener_uuid(listener)?;
        }

        Ok(())
    }
}

fn validate_outbound_uuid(proxy: &OutboundDefinition) -> Result<(), ConfigValidationError> {
    match proxy {
        OutboundDefinition::Vless(config) => validate_uuid_field(
            proxy.name(),
            "vless",
            config.extra.get("uuid"),
            invalid_proxy_uuid_error,
        )?,
        OutboundDefinition::Vmess(config) => validate_uuid_field(
            proxy.name(),
            "vmess",
            config.extra.get("uuid"),
            invalid_proxy_uuid_error,
        )?,
        OutboundDefinition::Tuic(config) => validate_uuid_field(
            proxy.name(),
            "tuic",
            config.extra.get("uuid"),
            invalid_proxy_uuid_error,
        )?,
        _ => {}
    }
    Ok(())
}

fn validate_listener_uuid(listener: &InboundDefinition) -> Result<(), ConfigValidationError> {
    match listener {
        InboundDefinition::Vless(config) => validate_listener_first_user_uuid(config, "vless"),
        InboundDefinition::Vmess(config) => validate_listener_first_user_uuid(config, "vmess"),
        _ => Ok(()),
    }
}

fn validate_listener_first_user_uuid(
    config: &GenericInboundConfig,
    protocol: &'static str,
) -> Result<(), ConfigValidationError> {
    let users = config
        .extra
        .get("users")
        .and_then(Value::as_sequence)
        .filter(|users| !users.is_empty());
    let Some(first_user) = users.and_then(|users| users.first()) else {
        return Ok(());
    };
    let Some(user) = first_user.as_mapping() else {
        return Ok(());
    };
    validate_uuid_field(
        &config.base.name,
        protocol,
        user.get(Value::String("uuid".to_owned())),
        invalid_listener_uuid_error,
    )
}

fn validate_uuid_field(
    owner: &str,
    protocol: &'static str,
    value: Option<&Value>,
    error_builder: fn(String, String, String, String) -> ConfigValidationError,
) -> Result<(), ConfigValidationError> {
    let uuid = value
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if uuid.is_empty() {
        return Ok(());
    }
    Uuid::parse_str(uuid).map_err(|err| {
        error_builder(
            owner.to_owned(),
            protocol.to_owned(),
            uuid.to_owned(),
            err.to_string(),
        )
    })?;
    Ok(())
}

fn invalid_proxy_uuid_error(
    proxy: String,
    protocol: String,
    uuid: String,
    error: String,
) -> ConfigValidationError {
    ConfigValidationError::InvalidProxyUuid {
        proxy,
        protocol,
        uuid,
        error,
    }
}

fn invalid_listener_uuid_error(
    listener: String,
    protocol: String,
    uuid: String,
    error: String,
) -> ConfigValidationError {
    ConfigValidationError::InvalidListenerUuid {
        listener,
        protocol,
        uuid,
        error,
    }
}
