//! Optional local databases enrich Smart metadata without issuing a DNS query.
use mihomo_core::Metadata;
use std::path::Path;
use std::sync::Arc;

pub(crate) struct SmartGeoData {
    asn: Option<maxminddb::Reader<Vec<u8>>>,
    country: Option<maxminddb::Reader<Vec<u8>>>,
}
impl std::fmt::Debug for SmartGeoData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmartGeoData")
            .field("asn", &self.asn.is_some())
            .field("country", &self.country.is_some())
            .finish()
    }
}
impl SmartGeoData {
    pub fn load(home: &Path) -> Arc<Self> {
        let files = std::fs::read_dir(home)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        let open = |names: &[&str]| {
            files
                .iter()
                .find(|path| {
                    path.file_name().is_some_and(|name| {
                        names
                            .iter()
                            .any(|expected| name.to_string_lossy().eq_ignore_ascii_case(expected))
                    })
                })
                .and_then(|path| match maxminddb::Reader::open_readfile(path) {
                    Ok(reader) => Some(reader),
                    Err(error) => {
                        mihomo_core::push_log(
                            mihomo_core::LogLevel::Warn,
                            format!("[Smart] cannot load {}: {error}", path.display()),
                        );
                        None
                    }
                })
        };
        Arc::new(Self {
            asn: open(&["ASN.mmdb", "GeoLite2-ASN.mmdb"]),
            country: open(&[
                "Country.mmdb",
                "GeoLite2-Country.mmdb",
                "GeoIP.mmdb",
                "GeoLite2-City.mmdb",
            ]),
        })
    }
    pub fn enrich(&self, metadata: &mut Metadata) {
        let Some(ip) = metadata
            .dst_ip
            .or_else(|| metadata.host.as_deref().and_then(|host| host.parse().ok()))
        else {
            return;
        };
        if metadata.dst_ip_asn.is_empty() || metadata.dst_ip_asn == "unknown" {
            if let Some(asn) = self
                .asn
                .as_ref()
                .and_then(|reader| reader.lookup::<maxminddb::geoip2::Asn<'_>>(ip).ok())
            {
                if let Some(number) = asn.autonomous_system_number {
                    metadata.dst_ip_asn = format!(
                        "AS{number} {}",
                        asn.autonomous_system_organization.unwrap_or_default()
                    )
                    .trim()
                    .into();
                }
            }
        }
        if metadata.dst_geoip.as_ref().is_none_or(Vec::is_empty) {
            if let Some(country) = self
                .country
                .as_ref()
                .and_then(|reader| reader.lookup::<maxminddb::geoip2::Country<'_>>(ip).ok())
                .and_then(|record| record.country.or(record.registered_country))
                .and_then(|record| record.iso_code)
            {
                metadata.dst_geoip = Some(vec![country.to_owned()]);
            }
        }
    }
}
