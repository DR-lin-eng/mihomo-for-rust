# OpenClash GeoSite/GeoIP compatibility

The native Rust runtime now reads standard `GeoSite.dat`, `geosite.dat`, `geosite.site`, `GeoIP.dat`, and `geoip.dat` files from the configured home directory, its `geo/` directory, or its `resources/` directory.

`GEOSITE,name,target` and `GEOIP,CC,target` rules are materialized as inline classical rule providers before the runtime registry is built. GeoSite domain types (plain, regex, domain suffix, and full domain) and GeoSite attributes are preserved. GeoIP protobuf CIDRs are converted to `IP-CIDR`/`IP-CIDR6` entries.

This fixes the startup error `rule provider not found: cn` when an OpenClash configuration contains `GEOSITE,cn,...` and the standard GeoSite database is present. A configuration test without starting the runtime does not load the data file; runtime startup does.

The implementation does not yet use `country.mmdb` or `asn.mmdb` for rule matching. Keep the corresponding `.dat` database beside the OpenClash configuration when using GEOSITE/GEOIP rules with the native Rust runtime.
