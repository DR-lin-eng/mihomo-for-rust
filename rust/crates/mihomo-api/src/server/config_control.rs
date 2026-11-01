use super::*;

impl ApiController {
    fn config_from_yaml(
        &self,
        yaml: &str,
        previous: &BootstrapState,
    ) -> Result<BootstrapState, String> {
        let (document, provider_sources, registry) =
            mihomo_runtime::bootstrap_from_yaml(yaml, &previous.resolved_boot.home_dir)
                .map_err(|err| err.to_string())?;
        let state = BootstrapState {
            resolved_boot: previous.resolved_boot.clone(),
            document,
            provider_sources,
            registry,
        };
        state
            .build_runtime_tunnel()
            .map_err(|err| err.to_string())?;
        state.build_dns_runtime().map_err(|err| err.to_string())?;
        Ok(state)
    }

    fn apply_config_request(&self, state: BootstrapState) -> ApiHttpResponse {
        let Some(control) = &self.control_tx else {
            return error_response(503, "configuration control is unavailable");
        };
        let (reply, result) = mpsc::channel();
        if control
            .send(ApiControlCommand::ApplyConfig {
                state: Box::new(state),
                reply,
            })
            .is_err()
        {
            return error_response(503, "configuration control is unavailable");
        }
        match result.recv_timeout(Duration::from_secs(30)) {
            Ok(Ok(())) => ApiHttpResponse {
                status_code: 204,
                headers: BTreeMap::new(),
                body: Vec::new(),
            },
            Ok(Err(err)) => error_response(400, &err),
            Err(_) => error_response(503, "configuration apply did not finish within 30 seconds"),
        }
    }

    pub(super) fn handle_config_replace(&self, request: &ApiHttpRequest) -> ApiHttpResponse {
        #[derive(serde::Deserialize)]
        struct Replace {
            #[serde(default)]
            path: String,
            #[serde(default)]
            payload: String,
        }
        let input = match serde_json::from_slice::<Replace>(&request.body) {
            Ok(input) => input,
            Err(_) => return error_response(400, "Body invalid"),
        };
        let Some(shared) = &self.bootstrap_state else {
            return error_response(503, "bootstrap state is unavailable");
        };
        let previous = shared.lock().unwrap().clone();
        let yaml = if !input.payload.is_empty() {
            input.payload
        } else {
            let candidate = if input.path.is_empty() {
                previous.resolved_boot.config_display_path()
            } else {
                let candidate = PathBuf::from(input.path);
                if !candidate.is_absolute() {
                    return error_response(400, "path is not a absolute path");
                }
                let canonical = match fs::canonicalize(&candidate) {
                    Ok(path) => path,
                    Err(err) => return error_response(400, &err.to_string()),
                };
                let mut allowed = vec![previous.resolved_boot.home_dir.clone()];
                if let mihomo_config::ConfigSource::File(path) =
                    &previous.resolved_boot.config_source
                {
                    allowed.push(path.clone());
                }
                if let Some(paths) = std::env::var_os("SAFE_PATHS") {
                    allowed.extend(std::env::split_paths(&paths));
                }
                if !allowed
                    .iter()
                    .filter_map(|path| fs::canonicalize(path).ok())
                    .any(|root| canonical.starts_with(root))
                {
                    return error_response(
                        400,
                        "path is not within the configuration directory or SAFE_PATHS",
                    );
                }
                candidate
            };
            match fs::read_to_string(candidate) {
                Ok(yaml) => yaml,
                Err(err) => return error_response(400, &err.to_string()),
            }
        };
        match self.config_from_yaml(&yaml, &previous) {
            Ok(state) => self.apply_config_request(state),
            Err(err) => error_response(400, &err),
        }
    }

    pub(super) fn handle_config_patch(&self, request: &ApiHttpRequest) -> ApiHttpResponse {
        let input =
            match serde_json::from_slice::<serde_json::Map<String, JsonValue>>(&request.body) {
                Ok(input) => input,
                Err(_) => return error_response(400, "Body invalid"),
            };
        for (key, allowed) in [
            ("mode", &["rule", "global", "direct"][..]),
            (
                "log-level",
                &["debug", "info", "warning", "error", "silent"][..],
            ),
            ("find-process-mode", &["always", "strict", "off"][..]),
        ] {
            if let Some(value) = input.get(key).filter(|value| !value.is_null()) {
                if !value.as_str().is_some_and(|value| allowed.contains(&value)) {
                    return error_response(400, "Body invalid");
                }
            }
        }
        let Some(tunnel) = &self.runtime_tunnel else {
            return error_response(503, "runtime tunnel is unavailable");
        };
        // Mode and logging can be changed without dropping live connections.
        if input.keys().all(|key| key == "mode" || key == "log-level") {
            if let Some(mode) = input.get("mode").and_then(JsonValue::as_str) {
                if tunnel.set_mode(mode).is_err() {
                    return error_response(400, "Body invalid");
                }
            }
            if let Some(shared) = &self.bootstrap_state {
                let mut state = shared.lock().unwrap();
                if let Some(mode) = input.get("mode").and_then(JsonValue::as_str) {
                    state.document.mode = mode.into();
                }
                if let Some(level) = input.get("log-level").and_then(JsonValue::as_str) {
                    state.document.log_level = level.into();
                    mihomo_core::set_log_level(level);
                }
            }
            return ApiHttpResponse {
                status_code: 204,
                headers: BTreeMap::new(),
                body: Vec::new(),
            };
        }
        let Some(shared) = &self.bootstrap_state else {
            return error_response(503, "bootstrap state is unavailable");
        };
        let mut previous = shared.lock().unwrap().clone();
        previous.document.mode = tunnel.current_mode();
        let mut merged = match serde_json::to_value(&previous.document) {
            Ok(value) => value,
            Err(err) => return error_response(500, &err.to_string()),
        };
        let recognized = [
            "port",
            "socks-port",
            "redir-port",
            "tproxy-port",
            "mixed-port",
            "tun",
            "tuic-server",
            "ss-config",
            "vmess-config",
            "allow-lan",
            "skip-auth-prefixes",
            "lan-allowed-ips",
            "lan-disallowed-ips",
            "bind-address",
            "mode",
            "log-level",
            "ipv6",
            "tcp-concurrent",
            "find-process-mode",
            "interface-name",
        ];
        for (key, value) in input {
            if value.is_null() {
                continue;
            }
            if key == "sniffing" {
                if !value.is_boolean() {
                    return error_response(400, "Body invalid");
                }
                merged["sniffer"]["enable"] = value;
            } else if recognized.contains(&key.as_str()) {
                if let (Some(current), Some(update)) = (
                    merged.get_mut(&key).and_then(JsonValue::as_object_mut),
                    value.as_object(),
                ) {
                    current.extend(update.clone());
                } else {
                    merged[&key] = value;
                }
            }
        }
        let yaml = match serde_yaml::to_string(&merged) {
            Ok(yaml) => yaml,
            Err(err) => return error_response(400, &err.to_string()),
        };
        match self.config_from_yaml(&yaml, &previous) {
            Ok(state) => self.apply_config_request(state),
            Err(err) => error_response(400, &err),
        }
    }
}
