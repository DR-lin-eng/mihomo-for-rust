mod boot;
mod document;
mod validation;

#[cfg(test)]
mod tests;

pub use boot::{
    parse_args, BootEnvironment, BootOptions, Command, ConfigSource, ParseError, ResolvedBoot,
};
pub use document::{
    parse_runtime_config_document, EbpfConfig, DnsFallbackFilterConfig, GeoXUrlConfig, HostMappingValue,
    RuleProviderBehavior, RuleProviderDefinition, RuleProviderFormat, RuleProviderVehicleType,
    RuntimeConfigDocument, SnifferProtocolConfig, StringOrList, TopLevelDnsConfig,
    TopLevelProfileConfig, TopLevelSnifferConfig, TopLevelTunConfig, TuicServerConfig,
};
pub use validation::ConfigValidationError;
