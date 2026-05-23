use mihomo_config::RuntimeConfigDocument;
use mihomo_inbound::InboundKind;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ListenerOrigin {
    TopLevel,
    Custom,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveListener {
    pub synthetic_name: String,
    pub kind: InboundKind,
    pub addresses: Vec<String>,
    pub origin: ListenerOrigin,
}

pub fn build_effective_listeners(document: &RuntimeConfigDocument) -> Vec<EffectiveListener> {
    let mut listeners = Vec::new();

    maybe_push_top_level_listener(
        &mut listeners,
        "__top_level_http__",
        InboundKind::Http,
        document.port,
        document.bind_address.as_str(),
        document.allow_lan,
    );
    maybe_push_top_level_listener(
        &mut listeners,
        "__top_level_socks__",
        InboundKind::Socks,
        document.socks_port,
        document.bind_address.as_str(),
        document.allow_lan,
    );
    maybe_push_top_level_listener(
        &mut listeners,
        "__top_level_redir__",
        InboundKind::Redir,
        document.redir_port,
        document.bind_address.as_str(),
        document.allow_lan,
    );
    maybe_push_top_level_listener(
        &mut listeners,
        "__top_level_tproxy__",
        InboundKind::TProxy,
        document.tproxy_port,
        document.bind_address.as_str(),
        document.allow_lan,
    );
    maybe_push_top_level_listener(
        &mut listeners,
        "__top_level_mixed__",
        InboundKind::Mixed,
        document.mixed_port,
        document.bind_address.as_str(),
        document.allow_lan,
    );

    listeners.extend(document.listeners.iter().map(|listener| EffectiveListener {
        synthetic_name: listener.base().name.clone(),
        kind: listener.kind(),
        addresses: listener.raw_addresses(),
        origin: ListenerOrigin::Custom,
    }));

    listeners
}

fn maybe_push_top_level_listener(
    listeners: &mut Vec<EffectiveListener>,
    synthetic_name: &str,
    kind: InboundKind,
    port: u16,
    bind_address: &str,
    allow_lan: bool,
) {
    let address = gen_addr(bind_address, port, allow_lan);
    if port_is_zero(&address) {
        return;
    }
    listeners.push(EffectiveListener {
        synthetic_name: synthetic_name.to_owned(),
        kind,
        addresses: vec![address],
        origin: ListenerOrigin::TopLevel,
    });
}

fn port_is_zero(addr: &str) -> bool {
    addr.rsplit_once(':')
        .map(|(_, port)| port.is_empty() || port == "0")
        .unwrap_or(true)
}

fn gen_addr(host: &str, port: u16, allow_lan: bool) -> String {
    if allow_lan {
        if host == "*" {
            format!(":{port}")
        } else {
            format!("{host}:{port}")
        }
    } else {
        format!("127.0.0.1:{port}")
    }
}

#[cfg(test)]
mod tests {
    use mihomo_config::parse_runtime_config_document;
    use mihomo_inbound::InboundKind;

    use super::{build_effective_listeners, EffectiveListener, ListenerOrigin};

    #[test]
    fn top_level_ports_respect_allow_lan_and_bind_address() {
        let document = parse_runtime_config_document(
            r#"
port: 7890
socks-port: 7891
allow-lan: true
bind-address: "*"
"#,
        )
        .unwrap();
        let listeners = build_effective_listeners(&document);
        assert_eq!(
            listeners,
            vec![
                EffectiveListener {
                    synthetic_name: "__top_level_http__".into(),
                    kind: InboundKind::Http,
                    addresses: vec![":7890".into()],
                    origin: ListenerOrigin::TopLevel,
                },
                EffectiveListener {
                    synthetic_name: "__top_level_socks__".into(),
                    kind: InboundKind::Socks,
                    addresses: vec![":7891".into()],
                    origin: ListenerOrigin::TopLevel,
                },
            ]
        );
    }

    #[test]
    fn top_level_ports_bind_to_loopback_when_allow_lan_is_false() {
        let document = parse_runtime_config_document(
            r#"
mixed-port: 10801
allow-lan: false
bind-address: 0.0.0.0
"#,
        )
        .unwrap();
        let listeners = build_effective_listeners(&document);
        assert_eq!(
            listeners,
            vec![EffectiveListener {
                synthetic_name: "__top_level_mixed__".into(),
                kind: InboundKind::Mixed,
                addresses: vec!["127.0.0.1:10801".into()],
                origin: ListenerOrigin::TopLevel,
            }]
        );
    }

    #[test]
    fn explicit_listeners_are_appended_after_top_level_surfaces() {
        let document = parse_runtime_config_document(
            r#"
port: 7890
listeners:
  - type: socks
    name: custom-socks
    listen: 127.0.0.1
    port: "1080-1081"
"#,
        )
        .unwrap();
        let listeners = build_effective_listeners(&document);
        assert_eq!(listeners.len(), 2);
        assert_eq!(listeners[0].synthetic_name, "__top_level_http__");
        assert_eq!(listeners[1].synthetic_name, "custom-socks");
        assert_eq!(listeners[1].addresses, vec!["127.0.0.1:1080", "127.0.0.1:1081"]);
    }
}
