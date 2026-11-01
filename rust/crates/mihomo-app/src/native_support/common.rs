use std::collections::BTreeSet;

use mihomo_runtime::NativeSupportGap;

pub(super) fn surface_support_gap(name: &str, reason: &str) -> NativeSupportGap {
    NativeSupportGap {
        proxy_name: name.to_owned(),
        kind: None,
        provider_name: String::new(),
        reason: reason.to_owned(),
    }
}

pub(super) fn filter_support_gaps_for_default_path(
    gaps: Vec<NativeSupportGap>,
    names: Option<&BTreeSet<String>>,
) -> Vec<NativeSupportGap> {
    match names {
        Some(names) => gaps
            .into_iter()
            .filter(|gap| names.contains(&gap.proxy_name))
            .collect(),
        None => gaps,
    }
}
