use std::net::IpAddr;

use mihomo_core::{NetworkKind, SessionKind};
use regex::{Regex, RegexBuilder};

use crate::engine::DomainProviderPattern;
use crate::types::RuleError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NumericRange {
    pub(crate) start: u64,
    pub(crate) end: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NumericRanges {
    pub(crate) ranges: Vec<NumericRange>,
}

impl NumericRanges {
    pub(crate) fn parse(
        raw: &str,
        max: u64,
        err: fn(String) -> RuleError,
        require_non_empty: bool,
    ) -> Result<Self, RuleError> {
        let normalized = raw.trim();
        if normalized.is_empty() {
            return Err(err(raw.to_owned()));
        }

        let mut ranges = Vec::new();
        for segment in normalized.replace(',', "/").split('/') {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            if segment == "*" {
                if require_non_empty && !ranges.is_empty() {
                    return Err(err(raw.to_owned()));
                }
                return Ok(Self {
                    ranges: vec![NumericRange { start: 0, end: max }],
                });
            }

            let (start_raw, end_raw) = segment
                .split_once('-')
                .map_or((segment, segment), |(start, end)| {
                    (start.trim(), end.trim())
                });
            let start = parse_u64(start_raw).ok_or_else(|| err(raw.to_owned()))?;
            let end = parse_u64(end_raw).ok_or_else(|| err(raw.to_owned()))?;
            if start > end || end > max {
                return Err(err(raw.to_owned()));
            }
            ranges.push(NumericRange { start, end });
        }

        if require_non_empty && ranges.is_empty() {
            return Err(err(raw.to_owned()));
        }

        Ok(Self { ranges })
    }

    pub(crate) fn contains(&self, value: u64) -> bool {
        self.ranges
            .iter()
            .any(|range| range.start <= value && value <= range.end)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Cidr {
    pub(crate) network: IpAddr,
    pub(crate) prefix_len: u8,
}

impl Cidr {
    pub(crate) fn parse(raw: &str) -> Result<Self, RuleError> {
        let Some((ip, prefix)) = raw.split_once('/') else {
            return Err(RuleError::InvalidCidr(raw.to_owned()));
        };
        let network = ip
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| RuleError::InvalidCidr(raw.to_owned()))?;
        let prefix_len = prefix
            .trim()
            .parse::<u8>()
            .map_err(|_| RuleError::InvalidCidr(raw.to_owned()))?;
        match network {
            IpAddr::V4(_) if prefix_len <= 32 => Ok(Self {
                network,
                prefix_len,
            }),
            IpAddr::V6(_) if prefix_len <= 128 => Ok(Self {
                network,
                prefix_len,
            }),
            _ => Err(RuleError::InvalidCidr(raw.to_owned())),
        }
    }

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = prefix_mask_u32(self.prefix_len);
                (u32::from(network) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = prefix_mask_u128(self.prefix_len);
                (u128::from(network) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

pub(crate) fn parse_domain_provider_pattern(raw: &str) -> DomainProviderPattern {
    let normalized = normalize(raw);
    if normalized.starts_with("+.") {
        DomainProviderPattern::Suffix(normalized.trim_start_matches("+.").to_owned())
    } else if normalized.starts_with('.') {
        DomainProviderPattern::Suffix(normalized.trim_start_matches('.').to_owned())
    } else if normalized.contains('*') || normalized.contains('?') {
        DomainProviderPattern::Wildcard(normalized)
    } else {
        DomainProviderPattern::Exact(normalized)
    }
}

pub(crate) fn parse_network(raw: &str) -> Result<NetworkKind, RuleError> {
    match raw.trim().to_ascii_uppercase().as_str() {
        "TCP" => Ok(NetworkKind::Tcp),
        "UDP" => Ok(NetworkKind::Udp),
        "ALL" => Ok(NetworkKind::All),
        _ => Err(RuleError::InvalidNetwork(raw.to_owned())),
    }
}

pub(crate) fn compile_regex(pattern: &str) -> Result<Regex, RuleError> {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .map_err(|_| RuleError::InvalidRegex(pattern.to_owned()))
}

pub(crate) fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

pub(crate) fn eq_ignore_ascii_case(left: &str, right: &str) -> bool {
    !left.is_empty() && normalize(left) == *right
}

pub(crate) fn parse_name_list(
    raw: &str,
    err: fn(String) -> RuleError,
) -> Result<Vec<String>, RuleError> {
    let values = raw
        .split('/')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Err(err(raw.to_owned()));
    }
    Ok(values)
}

pub(crate) fn parse_in_types(raw: &str) -> Result<Vec<SessionKind>, RuleError> {
    let values = raw
        .split('/')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Err(RuleError::InvalidInType(raw.to_owned()));
    }

    let mut kinds = Vec::new();
    for value in values {
        match value.to_ascii_uppercase().as_str() {
            "HTTP" => kinds.push(SessionKind::Http),
            "HTTPS" => kinds.push(SessionKind::Https),
            "SOCKS" => {
                kinds.push(SessionKind::Socks4);
                kinds.push(SessionKind::Socks5);
            }
            "SOCKS4" => kinds.push(SessionKind::Socks4),
            "SOCKS5" => kinds.push(SessionKind::Socks5),
            "SHADOWSOCKS" => kinds.push(SessionKind::ShadowSocks),
            "VMESS" => kinds.push(SessionKind::Vmess),
            "VLESS" => kinds.push(SessionKind::Vless),
            "REDIR" => kinds.push(SessionKind::Redir),
            "TPROXY" => kinds.push(SessionKind::TProxy),
            "TROJAN" => kinds.push(SessionKind::Trojan),
            "TUNNEL" => kinds.push(SessionKind::Tunnel),
            "TUN" => kinds.push(SessionKind::Tun),
            "TUIC" => kinds.push(SessionKind::Tuic),
            "HYSTERIA2" => kinds.push(SessionKind::Hysteria2),
            "ANYTLS" => kinds.push(SessionKind::AnyTls),
            "MIERU" => kinds.push(SessionKind::Mieru),
            "SUDOKU" => kinds.push(SessionKind::Sudoku),
            "TRUSTTUNNEL" => kinds.push(SessionKind::TrustTunnel),
            "INNER" => kinds.push(SessionKind::Inner),
            _ => return Err(RuleError::InvalidInType(raw.to_owned())),
        }
    }
    Ok(kinds)
}

pub(crate) fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut pi, mut vi) = (0_usize, 0_usize);
    let (mut star, mut backtrack) = (None, 0_usize);

    while vi < value.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == value[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            backtrack = vi;
        } else if let Some(star_index) = star {
            pi = star_index + 1;
            backtrack += 1;
            vi = backtrack;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

pub(crate) fn parse_u64(raw: &str) -> Option<u64> {
    raw.parse::<u64>().ok()
}

pub(crate) fn prefix_mask_u32(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

pub(crate) fn prefix_mask_u128(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}
