use std::collections::BTreeMap;

use mihomo_api::{default_storage_root, StorageStore};
use mihomo_runtime::BootstrapState;

const STORAGE_KEY_SELECTED_PROXY: &str = "selected-proxy";
pub const SELECTED_PROXY_ENV: &str = "MIHOMO_SELECTED_PROXY_JSON";

pub fn restore_selected_proxy_mapping(state: &mut BootstrapState) {
    if state.document.profile.store_selected {
        let store = StorageStore::new(default_storage_root(&state.resolved_boot.home_dir));
        if let Ok(Some(payload)) = store.get(STORAGE_KEY_SELECTED_PROXY) {
            if let Ok(mapping) = serde_json::from_slice::<BTreeMap<String, String>>(&payload) {
                state.apply_selected_proxy_mapping(&mapping);
            }
        }
    }
    if let Some(mapping) = selected_proxy_mapping_from_env() {
        state.apply_selected_proxy_mapping(&mapping);
    }
}

pub fn selected_proxy_mapping_from_state(state: &BootstrapState) -> BTreeMap<String, String> {
    state
        .document
        .proxy_groups
        .iter()
        .map(|group| {
            let selected = state
                .registry
                .groups
                .get(&group.name)
                .and_then(|view| view.runtime.selected().map(ToOwned::to_owned))
                .unwrap_or_default();
            (group.name.clone(), selected)
        })
        .collect()
}

pub fn selected_proxy_mapping_from_env() -> Option<BTreeMap<String, String>> {
    let payload = std::env::var(SELECTED_PROXY_ENV).ok()?;
    serde_json::from_str(&payload).ok()
}
