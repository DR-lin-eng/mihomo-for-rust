use crate::{
    GroupDefinition, OutboundDefinition, ProviderPayloadDocument, ProxyProviderDefinition,
};

pub fn parse_outbound_yaml(input: &str) -> Result<OutboundDefinition, serde_yaml::Error> {
    serde_yaml::from_str(input)
}

pub fn parse_group_yaml(input: &str) -> Result<GroupDefinition, serde_yaml::Error> {
    serde_yaml::from_str(input)
}

pub fn parse_provider_yaml(input: &str) -> Result<ProxyProviderDefinition, serde_yaml::Error> {
    serde_yaml::from_str(input)
}

pub fn parse_provider_payload_document(
    input: &str,
) -> Result<ProviderPayloadDocument, serde_yaml::Error> {
    serde_yaml::from_str(input)
}
