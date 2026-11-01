use super::*;
impl ApiController {
    pub(super) fn handle_smart_get(&self, path: &str) -> Option<ApiHttpResponse> {
        if let Some(raw) = path
            .strip_prefix("/group/")
            .and_then(|path| path.strip_suffix("/smart"))
        {
            let name = percent_decode(raw);
            return Some(
                match self
                    .runtime_tunnel
                    .as_ref()
                    .and_then(|tunnel| tunnel.smart_diagnostics(&name))
                {
                    Some(data) => self.json_ok(&data),
                    None => self.not_found(),
                },
            );
        }
        if path != "/group/weights"
            && !path
                .strip_prefix("/group/")
                .is_some_and(|suffix| suffix.ends_with("/weights"))
        {
            return None;
        }
        let Some(tunnel) = &self.runtime_tunnel else {
            return Some(error_response(503, "Smart cache not available"));
        };
        if path == "/group/weights" {
            return Some(
                self.json_ok(
                    &serde_json::json!({"weights":tunnel.smart_rankings(None),"errors":{}}),
                ),
            );
        }
        let raw = path
            .trim_start_matches("/group/")
            .trim_end_matches("/weights");
        let name = percent_decode(raw);
        let registry = tunnel.registry_snapshot();
        let Some(group) = registry.groups.get(&name) else {
            return Some(self.not_found());
        };
        if group.runtime.smart.is_none() {
            return Some(
                json_response(
                    400,
                    &serde_json::json!({"weights":[],"error":"Not a Smart group"}),
                )
                .unwrap(),
            );
        }
        let weights = tunnel
            .smart_rankings(Some(&name))
            .remove(&name)
            .unwrap_or_default();
        Some(self.json_ok(&serde_json::json!({"weights":weights})))
    }
    pub(super) fn handle_smart_post(&self, path: &str) -> Option<ApiHttpResponse> {
        if path != "/cache/smart/flush"
            && !path.starts_with("/cache/smart/flush/")
            && path != "/upgrade/lgbm"
        {
            return None;
        }
        let Some(tunnel) = &self.runtime_tunnel else {
            return Some(error_response(503, "Smart cache not available"));
        };
        let result = if path == "/upgrade/lgbm" {
            let url = self
                .bootstrap_state
                .as_ref()
                .map(|state| {
                    state
                        .lock()
                        .unwrap()
                        .document
                        .extra
                        .get("lgbm-url")
                        .and_then(serde_yaml::Value::as_str)
                        .unwrap_or(mihomo_runtime::smart::DEFAULT_MODEL_URL)
                        .to_owned()
                })
                .unwrap_or_else(|| mihomo_runtime::smart::DEFAULT_MODEL_URL.into());
            tunnel.update_smart_model(&url)
        } else {
            let config = path.strip_prefix("/cache/smart/flush/").map(percent_decode);
            tunnel.flush_smart_cache(config.as_deref())
        };
        Some(match result {
            Ok(()) => ApiHttpResponse {
                status_code: 204,
                headers: Default::default(),
                body: Vec::new(),
            },
            Err(error) => error_response(500, &error),
        })
    }
}
