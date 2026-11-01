OpenWrt ARM64 GeoSite/GeoIP compatibility build

This build adds standard GeoSite.dat/geosite.dat/geosite.site and GeoIP.dat loading. It synthesizes inline classical rule providers for GEOSITE and GEOIP rules, so OpenClash configurations using `GEOSITE,cn` no longer fail with `rule provider not found: cn` when the database exists beside the config.

Validated with an OpenClash-style `GeoSite.dat` fixture and `GEOSITE,cn,DIRECT`: the Rust app starts and remains running until the smoke timeout. The two geodata decoder tests pass on the aarch64-unknown-linux-musl target. It was also checked in an Alpine ARM64 container as a static ELF64 executable and passed six REALITY/Vision Xray scenarios. Router hardware and full country.mmdb/ASN behavior remain untested.

The raw executable and gzip package are in `bin/`. Use the uncompressed executable for direct replacement if OpenClash expects a binary, then chmod +x. The `.sha256` file contains both hashes.
