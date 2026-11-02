mod manifest;
mod matchers;
mod packet;
mod mapping;
mod runtime;
mod support;
mod types;
mod upstream;
mod exchange_race;

pub use packet::build_servfail_response;

use std::net::IpAddr;

pub use manifest::{manifest, MODULE};
pub use types::{
    CachedAnswer, DnsError, DnsPacketTransport, DnsRecordType, DnsRuntime, DnsRuntimeConfig,
    DnsUpstream, EnhancedMode, FakeIpFilterMode, NetworkDnsUpstream, ResolveAnswer,
    ResolveSource, SystemDnsPacketTransport,
};
#[doc(hidden)]
pub fn quic_root_store_for_tests_and_runtime(
) -> Result<rustls023::RootCertStore, DnsError> {
    upstream::quic_root_store()
}

#[doc(hidden)]
pub fn register_test_root_certificate_for_tests_and_runtime(
    pem: &str,
) -> Result<(), DnsError> {
    upstream::register_test_root_certificate(pem)
}

#[doc(hidden)]
pub fn build_dns_query_for_tests(
    host: &str,
    query_type: DnsRecordType,
    request_id: u16,
) -> Result<Vec<u8>, DnsError> {
    packet::build_dns_query(host, query_type, request_id)
}

#[doc(hidden)]
pub fn parse_dns_response_for_tests(
    payload: &[u8],
    request_id: u16,
    query_type: DnsRecordType,
) -> Result<Vec<IpAddr>, DnsError> {
    packet::parse_dns_response(payload, request_id, query_type)
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod cold_start_tests;
