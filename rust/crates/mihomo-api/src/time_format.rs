use chrono::{TimeZone, Utc};
pub(crate) const ZERO_TIME: &str = "0001-01-01T00:00:00Z";
pub(crate) fn format_unix_ms(value: u64) -> String {
    if value == 0 || value > 253402300799999 {
        return ZERO_TIME.into();
    }
    i64::try_from(value)
        .ok()
        .and_then(|value| Utc.timestamp_millis_opt(value).single())
        .map(|date| date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_else(|| ZERO_TIME.into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timestamps_keep_go_zero_and_rfc3339_milliseconds() {
        assert_eq!(format_unix_ms(0), ZERO_TIME);
        assert_eq!(format_unix_ms(1), "1970-01-01T00:00:00.001Z");
        assert_eq!(format_unix_ms(1793491200123), "2026-11-01T00:00:00.123Z");
        assert_eq!(format_unix_ms(u64::MAX), ZERO_TIME);
    }
}
