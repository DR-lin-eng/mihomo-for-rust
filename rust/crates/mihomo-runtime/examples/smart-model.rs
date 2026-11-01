//! Diagnostic helper for comparison with the independent LightGBM implementation.
use mihomo_runtime::smart::{features::ModelInput, model::LightGbmModel};
fn main() {
    let mut arguments = std::env::args().skip(1);
    let path = arguments.next().expect("model path");
    let fixtures = arguments.next().expect("JSON fixtures path");
    let model = LightGbmModel::load(std::path::Path::new(&path)).expect("model loads");
    let fixtures: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixtures).unwrap()).unwrap();
    let now = fixtures["now"].as_u64().unwrap();
    let results = fixtures["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| {
            let input: ModelInput = serde_json::from_value(value.clone()).unwrap();
            let features = input.features(now);
            let mut raw = features.to_vec();
            raw.resize(model.feature_names.len().max(raw.len()), 0.0);
            let score = model.predict(&raw).unwrap();
            serde_json::json!({"features":features.as_slice(),"prediction":score,"adaptive":mihomo_runtime::smart::adaptive_weight(&input,1.0,now)})
        })
        .collect::<Vec<_>>();
    println!(
        "{}",
        serde_json::json!({"trees":model.tree_count(),"features":model.feature_names,"results":results})
    );
}
