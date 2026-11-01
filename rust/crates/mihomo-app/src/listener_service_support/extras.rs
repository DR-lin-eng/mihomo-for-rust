use std::collections::BTreeMap;

pub(crate) fn extra_string(extra: &BTreeMap<String, serde_yaml::Value>, key: &str) -> String {
    extra
        .get(key)
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

pub(crate) fn nested_string(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    key: &str,
) -> String {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

pub(crate) fn nested_string_map(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    key: &str,
) -> BTreeMap<String, String> {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_mapping)
        .map(|mapping| {
            mapping
                .iter()
                .filter_map(|(name, value)| {
                    Some((name.as_str()?.to_owned(), value.as_str()?.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn nested_string_map_list(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    key: &str,
) -> BTreeMap<String, Vec<String>> {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_mapping)
        .map(|mapping| {
            mapping
                .iter()
                .filter_map(|(name, value)| {
                    let name = name.as_str()?.to_owned();
                    let values = if let Some(text) = value.as_str() {
                        vec![text.to_owned()]
                    } else {
                        value
                            .as_sequence()
                            .map(|sequence| {
                                sequence
                                    .iter()
                                    .filter_map(serde_yaml::Value::as_str)
                                    .map(str::to_owned)
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default()
                    };
                    Some((name, values))
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn nested_optional_bool(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    key: &str,
) -> Option<bool> {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_bool)
}

pub(crate) fn nested_value_exists(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    key: &str,
) -> bool {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .is_some_and(|mapping| mapping.contains_key(&serde_yaml::Value::String(key.to_owned())))
}

pub(crate) fn extra_contains_key(extra: &BTreeMap<String, serde_yaml::Value>, key: &str) -> bool {
    extra.contains_key(key)
}

pub(crate) fn extra_bool(extra: &BTreeMap<String, serde_yaml::Value>, key: &str) -> bool {
    extra
        .get(key)
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false)
}

pub(crate) fn extra_i32(extra: &BTreeMap<String, serde_yaml::Value>, key: &str) -> i32 {
    extra
        .get(key)
        .and_then(serde_yaml::Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .unwrap_or_default()
}

pub(crate) fn extra_string_list(
    extra: &BTreeMap<String, serde_yaml::Value>,
    key: &str,
) -> Vec<String> {
    extra
        .get(key)
        .and_then(serde_yaml::Value::as_sequence)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_yaml::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn doubly_nested_string(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    middle: &str,
    key: &str,
) -> String {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(middle.to_owned())))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

pub(crate) fn doubly_nested_u16(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    middle: &str,
    key: &str,
) -> Option<u16> {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(middle.to_owned())))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_i64)
        .and_then(|value| u16::try_from(value).ok())
}

pub(crate) fn doubly_nested_bool(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    middle: &str,
    key: &str,
) -> Option<bool> {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(middle.to_owned())))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_bool)
}

pub(crate) fn doubly_nested_string_map(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    middle: &str,
    key: &str,
) -> BTreeMap<String, String> {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(middle.to_owned())))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_mapping)
        .map(|mapping| {
            mapping
                .iter()
                .filter_map(|(name, value)| {
                    Some((name.as_str()?.to_owned(), value.as_str()?.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn doubly_nested_string_list(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    middle: &str,
    key: &str,
) -> Vec<String> {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(middle.to_owned())))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(key.to_owned())))
        .and_then(serde_yaml::Value::as_sequence)
        .map(|sequence| {
            sequence
                .iter()
                .filter_map(serde_yaml::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn doubly_nested_value_exists(
    extra: &BTreeMap<String, serde_yaml::Value>,
    parent: &str,
    middle: &str,
    key: &str,
) -> bool {
    extra
        .get(parent)
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|mapping| mapping.get(&serde_yaml::Value::String(middle.to_owned())))
        .and_then(serde_yaml::Value::as_mapping)
        .is_some_and(|mapping| mapping.contains_key(&serde_yaml::Value::String(key.to_owned())))
}

pub(crate) fn non_empty_or(value: String, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_owned()
    } else {
        value
    }
}
