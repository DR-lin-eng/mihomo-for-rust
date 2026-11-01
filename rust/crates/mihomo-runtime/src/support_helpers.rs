use serde_yaml::Value;

pub(super) fn unsupported_protocol_reason(name: &str) -> Option<String> {
    Some(format!(
        "{name} is not yet implemented in the native Rust runtime"
    ))
}

pub(super) fn extra_string(
    extra: &std::collections::BTreeMap<String, Value>,
    key: &str,
) -> String {
    extra
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

pub(super) fn extra_bool(
    extra: &std::collections::BTreeMap<String, Value>,
    key: &str,
) -> bool {
    extra.get(key).and_then(Value::as_bool).unwrap_or(false)
}

pub(super) fn extra_u64(
    extra: &std::collections::BTreeMap<String, Value>,
    key: &str,
) -> u64 {
    extra.get(key).and_then(Value::as_u64).unwrap_or(0)
}

pub(super) fn nested_sequence<'a>(
    extra: &'a std::collections::BTreeMap<String, Value>,
    key: &str,
) -> &'a [Value] {
    extra.get(key)
        .and_then(Value::as_sequence)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

pub(super) fn string_list(
    extra: &std::collections::BTreeMap<String, Value>,
    key: &str,
) -> Vec<String> {
    extra
        .get(key)
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub(super) fn nested_string(
    extra: &std::collections::BTreeMap<String, Value>,
    outer_key: &str,
    inner_key: &str,
) -> String {
    nested_map(extra, outer_key)
        .and_then(|mapping| mapping.get(Value::String(inner_key.to_owned())))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

pub(super) fn nested_map<'a>(
    extra: &'a std::collections::BTreeMap<String, Value>,
    outer_key: &str,
) -> Option<&'a serde_yaml::Mapping> {
    extra.get(outer_key).and_then(Value::as_mapping)
}

pub(super) fn nested_mapping_map<'a>(
    mapping: Option<&'a serde_yaml::Mapping>,
    key: &str,
) -> Option<&'a serde_yaml::Mapping> {
    mapping
        .and_then(|mapping| mapping.get(Value::String(key.to_owned())))
        .and_then(Value::as_mapping)
}

pub(super) fn nested_mapping_string(
    mapping: Option<&serde_yaml::Mapping>,
    key: &str,
) -> String {
    mapping
        .and_then(|mapping| mapping.get(Value::String(key.to_owned())))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

pub(super) fn nested_mapping_bool(
    mapping: Option<&serde_yaml::Mapping>,
    key: &str,
) -> bool {
    mapping
        .and_then(|mapping| mapping.get(Value::String(key.to_owned())))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(super) fn nested_mapping_contains(
    mapping: Option<&serde_yaml::Mapping>,
    key: &str,
) -> bool {
    mapping
        .map(|mapping| mapping.contains_key(Value::String(key.to_owned())))
        .unwrap_or(false)
}
