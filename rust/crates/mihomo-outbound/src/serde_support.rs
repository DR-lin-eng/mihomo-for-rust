use serde::{Deserialize, Deserializer};

#[derive(Deserialize)]
#[serde(untagged)]
enum StringLikeScalar {
    String(String),
    Signed(i64),
    Unsigned(u64),
    Float(f64),
    Bool(bool),
}

pub(crate) fn deserialize_string_like<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<StringLikeScalar>::deserialize(deserializer)?;
    Ok(match value {
        None => String::new(),
        Some(StringLikeScalar::String(value)) => value,
        Some(StringLikeScalar::Signed(value)) => value.to_string(),
        Some(StringLikeScalar::Unsigned(value)) => value.to_string(),
        Some(StringLikeScalar::Float(value)) => value.to_string(),
        Some(StringLikeScalar::Bool(value)) => value.to_string(),
    })
}
