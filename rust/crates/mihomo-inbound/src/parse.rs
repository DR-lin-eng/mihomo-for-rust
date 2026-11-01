use crate::InboundDefinition;

pub fn parse_inbound_yaml(input: &str) -> Result<InboundDefinition, serde_yaml::Error> {
    serde_yaml::from_str(input)
}
