use super::*;
use crate::{ExecutionPlan, RuntimeTunnel};

#[derive(Clone, Debug)]
pub(crate) struct SmartContext {
    pub model_path: PathBuf,
    pub state_path: PathBuf,
    pub config_name: String,
    pub collector: Arc<Collector>,
    pub geo: Arc<super::geodata::SmartGeoData>,
    model_update: Arc<Mutex<()>>,
    state_write: Arc<Mutex<()>>,
}
#[derive(Serialize, Deserialize)]
struct Persisted {
    version: u32,
    config_name: String,
    groups: BTreeMap<String, SmartState>,
}

impl RuntimeTunnel {
    pub fn configure_smart(&self, home: &Path, config_name: &str, collector_size_mb: f64) {
        if !self
            .registry
            .lock()
            .unwrap()
            .groups
            .values()
            .any(|view| view.runtime.smart.is_some())
        {
            return;
        }
        let model_path = fs::read_dir(home)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .eq_ignore_ascii_case("Model.bin")
            })
            .map(|entry| entry.path())
            .unwrap_or_else(|| home.join("Model.bin"));
        let hash = config_name.bytes().fold(14695981039346656037u64, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(1099511628211)
        });
        let context = SmartContext {
            model_path,
            state_path: home.join("storage").join(format!("smart-{hash:016x}.json")),
            config_name: config_name.into(),
            collector: Arc::new(Collector::new(home, collector_size_mb)),
            geo: super::geodata::SmartGeoData::load(home),
            model_update: Arc::new(Mutex::new(())),
            state_write: Arc::new(Mutex::new(())),
        };
        let persisted = fs::metadata(&context.state_path)
            .ok()
            .filter(|meta| meta.len() <= 16 * 1024 * 1024)
            .and_then(|_| fs::read(&context.state_path).ok())
            .and_then(|data| serde_json::from_slice::<Persisted>(&data).ok())
            .filter(|data| data.version == 1 && data.config_name == config_name);
        let needs_model = self.registry.lock().unwrap().groups.values().any(|view| {
            view.runtime
                .smart
                .as_ref()
                .is_some_and(|smart| smart.options.use_lightgbm)
        });
        let model = if needs_model && context.model_path.is_file() {
            match LightGbmModel::load(&context.model_path) {
                Ok(model) => {
                    let message = format!(
                        "[Smart] Model file loaded successfully: {} trees, {} features",
                        model.tree_count(),
                        model.feature_names.len()
                    );
                    eprintln!("{message}");
                    mihomo_core::push_log(mihomo_core::LogLevel::Info, message);
                    Some(Arc::new(model))
                }
                Err(error) => {
                    let message =
                        format!("[Smart] model unavailable, using adaptive scoring: {error}");
                    eprintln!("{message}");
                    mihomo_core::push_log(mihomo_core::LogLevel::Warn, message);
                    None
                }
            }
        } else {
            None
        };
        let mut registry = self.registry.lock().unwrap();
        for (name, view) in &mut registry.groups {
            if let Some(smart) = &mut view.runtime.smart {
                smart.collector = Some(Arc::clone(&context.collector));
                if let Some(state) = persisted.as_ref().and_then(|data| data.groups.get(name)) {
                    smart.state = state.clone();
                    while smart.state.records.len() > MAX_RECORDS {
                        smart.state.records.pop_first();
                    }
                    smart
                        .state
                        .nodes
                        .retain(|node, _| view.candidate_names.contains(node));
                    smart.state.advanced.trim();
                }
                smart.set_model(model.clone());
            }
        }
        *self.smart_context.lock().unwrap() = Some(context);
    }
    pub(crate) fn enrich_smart_metadata(&self, metadata: &mut Metadata) {
        let context = self.smart_context.lock().unwrap().clone();
        let Some(context) = context else {
            return;
        };
        // Only consult already available addresses. DNS routing remains with the configured resolver.
        if metadata.dst_ip.is_none() {
            if let (Some(host), Some(runtime)) = (metadata.host.as_deref(), self.dns_runtime()) {
                if let Some(answer) = runtime.lock().unwrap().cached_answer(host) {
                    metadata.dst_ip = answer.ips.first().copied();
                }
            }
        }
        context.geo.enrich(metadata);
    }
    pub fn persist_smart_state(&self) -> Result<(), String> {
        let Some(context) = self.smart_context.lock().unwrap().clone() else {
            return Ok(());
        };
        let _write_guard = context.state_write.lock().unwrap();
        #[derive(Serialize)]
        struct PersistedView<'a> {
            version: u32,
            config_name: &'a str,
            groups: BTreeMap<&'a str, &'a SmartState>,
        }
        let data = {
            let registry = self.registry.lock().unwrap();
            let groups = registry
                .groups
                .iter()
                .filter_map(|(name, view)| {
                    view.runtime
                        .smart
                        .as_ref()
                        .map(|smart| (name.as_str(), &smart.state))
                })
                .collect();
            serde_json::to_vec(&PersistedView {
                version: 1,
                config_name: &context.config_name,
                groups,
            })
            .map_err(|error| error.to_string())?
        };
        if let Some(parent) = context.state_path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let temp = context
            .state_path
            .with_extension(format!("json.{}.tmp", std::process::id()));
        fs::write(&temp, &data)
            .and_then(|_| fs::rename(&temp, &context.state_path))
            .map_err(|error| error.to_string())
    }
    pub fn flush_smart_cache(&self, config: Option<&str>) -> Result<(), String> {
        let context = self
            .smart_context
            .lock()
            .unwrap()
            .clone()
            .ok_or("smart cache not available")?;
        if config.is_none_or(|name| name == context.config_name) {
            self.smart_advanced.invalidate();
            for view in self.registry.lock().unwrap().groups.values_mut() {
                if let Some(smart) = &mut view.runtime.smart {
                    smart.flush();
                }
            }
            self.persist_smart_state()?;
        }
        let _guard = context.state_write.lock().unwrap();
        let storage = context
            .state_path
            .parent()
            .ok_or("invalid Smart storage directory")?;
        if let Some(name) = config.filter(|name| *name != context.config_name) {
            let hash = name.bytes().fold(14695981039346656037u64, |h, b| {
                (h ^ u64::from(b)).wrapping_mul(1099511628211)
            });
            let file = storage.join(format!("smart-{hash:016x}.json"));
            if let Err(error) = fs::remove_file(file) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    return Err(error.to_string());
                }
            }
        } else if config.is_none() {
            for entry in fs::read_dir(storage).map_err(|error| error.to_string())? {
                let entry = entry.map_err(|error| error.to_string())?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with("smart-") && name.ends_with(".json") {
                    fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
                }
            }
        }
        Ok(())
    }
    pub fn smart_model_loaded(&self) -> bool {
        self.registry.lock().unwrap().groups.values().any(|view| {
            view.runtime
                .smart
                .as_ref()
                .is_some_and(|smart| smart.model.is_some())
        })
    }
    pub fn smart_model_required(&self) -> bool {
        self.registry.lock().unwrap().groups.values().any(|view| {
            view.runtime
                .smart
                .as_ref()
                .is_some_and(|smart| smart.options.use_lightgbm)
        })
    }
    pub fn reload_smart_model(&self) -> Result<(), String> {
        let context = self
            .smart_context
            .lock()
            .unwrap()
            .clone()
            .ok_or("smart cache not available")?;
        let model = Arc::new(LightGbmModel::load(&context.model_path)?);
        for view in self.registry.lock().unwrap().groups.values_mut() {
            if let Some(smart) = &mut view.runtime.smart {
                smart.set_model(Some(Arc::clone(&model)));
            }
        }
        Ok(())
    }
    pub fn update_smart_model(&self, url: &str) -> Result<(), String> {
        let context = self
            .smart_context
            .lock()
            .unwrap()
            .clone()
            .ok_or("smart cache not available")?;
        let _update_guard = context.model_update.lock().unwrap();
        let bytes = super::download::fetch_model(self, url).map_err(|error| error.to_string())?;
        let text = std::str::from_utf8(&bytes).map_err(|_| "model is not UTF-8 LightGBM text")?;
        let model = Arc::new(LightGbmModel::parse(text)?);
        let temp = context
            .model_path
            .with_extension(format!("bin.{}.tmp", std::process::id()));
        fs::write(&temp, bytes)
            .and_then(|_| fs::rename(&temp, &context.model_path))
            .map_err(|error| error.to_string())?;
        for view in self.registry.lock().unwrap().groups.values_mut() {
            if let Some(smart) = &mut view.runtime.smart {
                smart.set_model(Some(Arc::clone(&model)));
            }
        }
        Ok(())
    }
    pub fn smart_tracker(
        &self,
        metadata: &Metadata,
        plan: &ExecutionPlan,
        connect_ms: u64,
    ) -> Option<SmartTracker> {
        let mut metadata = metadata.clone();
        self.enrich_smart_metadata(&mut metadata);
        if metadata.smart_rule.is_none() {
            metadata.smart_rule = self.smart_rule_for(&metadata);
        }
        SmartTracker::new(
            Arc::clone(&self.registry),
            &metadata,
            plan,
            connect_ms,
            self.smart_advanced.clone(),
        )
    }
    pub(crate) fn record_smart_dial_failure(
        &self,
        metadata: &Metadata,
        plan: &ExecutionPlan,
        connect_ms: u64,
    ) {
        let mut registry = self.registry.lock().unwrap();
        for pair in plan.selected_path.windows(2) {
            if let Some(smart) = registry
                .groups
                .get_mut(&pair[0])
                .and_then(|view| view.runtime.smart.as_mut())
            {
                smart.observe(
                    &pair[0],
                    &pair[1],
                    metadata,
                    &Observation {
                        success: false,
                        connect_ms,
                        ..Default::default()
                    },
                );
            }
        }
    }
    pub fn smart_group_last_used(&self, group: &str) -> u64 {
        self.registry
            .lock()
            .unwrap()
            .groups
            .get(group)
            .and_then(|view| view.runtime.smart.as_ref())
            .map(SmartGroup::last_used)
            .unwrap_or(0)
    }
    pub fn smart_rankings(&self, group: Option<&str>) -> BTreeMap<String, Vec<SmartNodeRank>> {
        let states = self.candidate_states.lock().unwrap().clone();
        let registry = self.registry.lock().unwrap();
        registry
            .groups
            .iter()
            .filter(|(name, _)| group.is_none_or(|group| group == name.as_str()))
            .filter_map(|(name, view)| {
                let smart = view.runtime.smart.as_ref()?;
                let candidates = view
                    .candidate_names
                    .iter()
                    .map(|name| {
                        let state = states.get(name);
                        crate::ProxyCandidate {
                            name: name.clone(),
                            alive: state.map(|state| state.alive).unwrap_or(true),
                            last_delay_ms: state.map(|state| state.last_delay_ms).unwrap_or(0),
                            supports_udp: state.map(|state| state.supports_udp).unwrap_or_else(
                                || {
                                    registry
                                        .proxy_definitions
                                        .get(name)
                                        .map(crate::outbound_supports_udp)
                                        .unwrap_or(true)
                                },
                            ),
                        }
                    })
                    .collect::<Vec<_>>();
                Some((name.clone(), smart.ranking(&candidates)))
            })
            .collect()
    }
}
