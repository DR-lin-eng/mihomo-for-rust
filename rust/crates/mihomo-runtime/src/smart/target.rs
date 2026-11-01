use super::features;
use mihomo_core::Metadata;
use std::collections::BTreeMap;
pub fn asn(metadata: &Metadata) -> &str {
    let value = metadata
        .dst_ip_asn
        .trim()
        .trim_start_matches("AS")
        .trim_start_matches("as")
        .split_whitespace()
        .next()
        .unwrap_or("");
    if value.bytes().all(|byte| byte.is_ascii_digit()) {
        value
    } else {
        ""
    }
}
pub fn site(host: &str, ip: &str) -> String {
    let host = host.trim_end_matches('.').to_lowercase();
    if host.is_empty() {
        return ip.into();
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host;
    }
    let Some(domain) = psl::domain_str(&host) else {
        return host;
    };
    if host == domain {
        return if host.matches('.').count() == 1 {
            format!("*.{host}")
        } else {
            host
        };
    }
    let sub = host
        .strip_suffix(domain)
        .unwrap_or("")
        .trim_end_matches('.');
    let last = sub.rsplit('.').next().unwrap_or("");
    let hex = last.len() >= 8
        && last
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    let digits = last.bytes().filter(u8::is_ascii_digit).count();
    let letters = last.bytes().filter(u8::is_ascii_alphabetic).count();
    let random = last.contains('-')
        || hex
        || (letters > 0
            && digits > 0
            && (last.len() > 10 || digits as f64 / last.len() as f64 > 0.6));
    if !sub.contains('.') || random {
        format!("*.{domain}")
    } else {
        format!("*.{last}.{domain}")
    }
}
pub fn rule_kind(target: &str) -> u8 {
    let Some((kind, name)) = target
        .rsplit_once(" [")
        .and_then(|(kind, name)| name.strip_suffix(']').map(|name| (kind, name)))
    else {
        return 0;
    };
    let name = name
        .split('@')
        .next()
        .unwrap_or("")
        .trim_start_matches('!')
        .to_lowercase();
    match kind {
        "GeoIP" | "SrcGeoIP" => {
            if (name.len() == 2 && name.bytes().all(|b| b.is_ascii_alphabetic()))
                || [
                    "cloudflare",
                    "cloudfront",
                    "fastly",
                    "private",
                    "cn",
                    "gfw",
                    "greatfire",
                    "ads-all",
                    "oc-cn-domain",
                    "china-domain",
                    "china-ip",
                    "tor",
                ]
                .contains(&name.as_str())
            {
                3
            } else {
                1
            }
        }
        "RuleSet" | "GeoSite" => {
            if [
                "cn",
                "private",
                "gfw",
                "greatfire",
                "ads-all",
                "oc-cn-domain",
                "china-domain",
                "china-ip",
                "tor",
            ]
            .contains(&name.as_str())
                || ["category-", "geolocation-", "tld-"]
                    .iter()
                    .any(|prefix| name.starts_with(prefix))
                || name.strip_prefix("as").is_some_and(features::shared_asn)
            {
                3
            } else {
                1
            }
        }
        _ => 2,
    }
}
pub fn claims(evidence: &BTreeMap<String, BTreeMap<String, u32>>) -> BTreeMap<String, String> {
    let mut result = BTreeMap::<String, String>::new();
    for (target, networks) in evidence {
        if rule_kind(target) != 1 || networks.len() >= 6 {
            continue;
        }
        for (asn, hits) in networks {
            if features::shared_asn(asn) || (networks.len() < 2 && *hits < 4) {
                continue;
            }
            result
                .entry(asn.clone())
                .and_modify(|current| {
                    if current != target {
                        *current = "-".into();
                    }
                })
                .or_insert_with(|| target.clone());
        }
    }
    result
}
fn claim<'a>(
    evidence: &'a BTreeMap<String, BTreeMap<String, u32>>,
    network: &str,
) -> Option<&'a str> {
    let mut owner = None;
    for (target, networks) in evidence {
        if rule_kind(target) != 1 || networks.len() >= 6 {
            continue;
        }
        if networks
            .get(network)
            .is_some_and(|hits| networks.len() >= 2 || *hits >= 4)
        {
            if owner.is_some_and(|old| old != target) {
                return None;
            }
            owner = Some(target.as_str());
        }
    }
    owner
}
pub fn key(
    prefer_asn: bool,
    metadata: &Metadata,
    evidence: &BTreeMap<String, BTreeMap<String, u32>>,
) -> String {
    let wildcard = site(
        metadata.host.as_deref().unwrap_or(""),
        &metadata.dst_ip.map(|ip| ip.to_string()).unwrap_or_default(),
    );
    let (rule, count) = metadata
        .smart_rule
        .as_ref()
        .map(|(rule, count)| (rule.as_str(), *count))
        .unwrap_or(("", 0));
    let kind = rule_kind(rule);
    let network = asn(metadata);
    if !prefer_asn {
        return if kind == 0 { wildcard } else { rule.into() };
    }
    let diversity = evidence
        .get(rule)
        .map(|entries| {
            entries
                .keys()
                .filter(|asn| !features::shared_asn(asn))
                .count()
        })
        .unwrap_or(0);
    let broad = kind == 0 || kind == 3 || (kind == 1 && (count >= 10000 || diversity >= 6));
    if !broad {
        return if rule.is_empty() {
            wildcard
        } else {
            rule.into()
        };
    }
    if network.is_empty() || features::shared_asn(network) {
        return wildcard;
    }
    if let Some(claim) = claim(evidence, network) {
        return claim.into();
    }
    format!("asn:{network}")
}
