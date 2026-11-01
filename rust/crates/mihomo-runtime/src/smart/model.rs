//! LightGBM text inference, including categorical splits and Smart's scaler trailer.
use std::collections::BTreeMap;
use std::path::Path;

const MAX_MODEL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FEATURES: usize = 4096;

#[derive(Clone, Debug, PartialEq)]
pub struct LightGbmModel {
    pub feature_names: Vec<String>,
    trees: Vec<Tree>,
    transforms: Vec<Transform>,
    average_output: bool,
}
impl Eq for LightGbmModel {}

#[derive(Clone, Debug, PartialEq)]
struct Tree {
    features: Vec<u16>,
    thresholds: Vec<f64>,
    decisions: Vec<u8>,
    left: Vec<i32>,
    right: Vec<i32>,
    leaves: Vec<f64>,
    cat_boundaries: Vec<u32>,
    cat_threshold: Vec<u32>,
}
#[derive(Clone, Debug, PartialEq)]
struct Transform {
    indices: Vec<usize>,
    center: Vec<f64>,
    scale: Vec<f64>,
}

type Fields<'a> = BTreeMap<&'a str, &'a str>;

impl LightGbmModel {
    pub fn load(path: &Path) -> Result<Self, String> {
        use std::io::Read;
        let file = std::fs::File::open(path).map_err(|err| err.to_string())?;
        let mut text = String::new();
        file.take(MAX_MODEL_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|err| err.to_string())?;
        if text.len() as u64 > MAX_MODEL_BYTES {
            return Err("Smart model exceeds 64 MiB".into());
        }
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        if !text.starts_with("tree\n") && !text.starts_with("tree\r\n") {
            return Err("expected LightGBM text model".into());
        }
        let header = fields(text.split("Tree=").next().unwrap_or_default());
        let count = number::<usize>(&header, "max_feature_idx")?
            .checked_add(1)
            .ok_or("feature count overflow")?;
        if count == 0 || count > MAX_FEATURES {
            return Err("invalid model feature count".into());
        }
        if number::<usize>(&header, "num_class")? != 1 {
            return Err("Smart requires a single output model".into());
        }
        let objective = header.get("objective").copied().unwrap_or("regression");
        // Huber changes the training loss, not the prediction link: native
        // LightGBM returns the same tree sum as ordinary regression.
        if !objective.starts_with("regression")
            && objective.split_whitespace().next() != Some("huber")
        {
            return Err(format!("unsupported Smart objective: {objective}"));
        }
        let names = header
            .get("feature_names")
            .ok_or("missing feature_names")?
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if names.len() != count {
            return Err("model feature count does not match feature_names".into());
        }
        let mut trees = Vec::new();
        for chunk in text.split("Tree=").skip(1) {
            let data = fields(chunk);
            if trees.len() >= 10000 {
                return Err("too many model trees".into());
            }
            let leaves = number::<usize>(&data, "num_leaves")?;
            if leaves == 0 || leaves > 65536 {
                return Err("invalid tree leaf count".into());
            }
            if data.get("is_linear").is_some_and(|value| *value != "0") {
                return Err("linear LightGBM trees are unsupported".into());
            }
            let tree = Tree {
                features: array(&data, "split_feature")?,
                thresholds: array(&data, "threshold")?,
                decisions: array(&data, "decision_type")?,
                left: array(&data, "left_child")?,
                right: array(&data, "right_child")?,
                leaves: array(&data, "leaf_value")?,
                cat_boundaries: optional_array(&data, "cat_boundaries")?,
                cat_threshold: optional_array(&data, "cat_threshold")?,
            };
            tree.validate(leaves, count)?;
            trees.push(tree);
        }
        if trees.is_empty() {
            return Err("Smart model has no trees".into());
        }
        let transforms = parse_transforms(text, count, &names)?;
        Ok(Self {
            feature_names: names,
            trees,
            transforms,
            average_output: header.contains_key("average_output")
                || text.lines().any(|line| line.trim() == "average_output"),
        })
    }

    pub fn tree_count(&self) -> usize {
        self.trees.len()
    }

    /// Receives unscaled features in model order, matching Smart's prepareFeatures.
    pub fn predict(&self, raw: &[f64]) -> Result<f64, String> {
        if raw.len() < self.feature_names.len() {
            return Err("not enough model features".into());
        }
        let mut features = raw[..self.feature_names.len()].to_vec();
        for transform in &self.transforms {
            for (i, slot) in transform.indices.iter().enumerate() {
                features[*slot] = (features[*slot] - transform.center[i]) / transform.scale[i];
            }
        }
        let sum = self
            .trees
            .iter()
            .map(|tree| tree.predict(&features))
            .sum::<f64>();
        let result = if self.average_output {
            sum / self.trees.len() as f64
        } else {
            sum
        };
        if !result.is_finite() {
            return Err("non-finite model prediction".into());
        }
        Ok(result)
    }
}

impl Tree {
    fn validate(&self, leaves: usize, count: usize) -> Result<(), String> {
        let nodes = leaves - 1;
        if self.leaves.len() != leaves
            || [
                self.features.len(),
                self.thresholds.len(),
                self.decisions.len(),
                self.left.len(),
                self.right.len(),
            ]
            .iter()
            .any(|len| *len != nodes)
        {
            return Err("tree array lengths do not match num_leaves".into());
        }
        if self
            .leaves
            .iter()
            .chain(&self.thresholds)
            .any(|value| !value.is_finite())
            || self.features.iter().any(|slot| usize::from(*slot) >= count)
        {
            return Err("invalid tree value or feature index".into());
        }
        for node in 0..nodes {
            for child in [self.left[node], self.right[node]] {
                if (child >= 0 && child as usize >= nodes)
                    || (child < 0 && (!child) as usize >= leaves)
                {
                    return Err("tree child out of bounds".into());
                }
            }
            if self.decisions[node] & 1 != 0 {
                let slot = self.thresholds[node] as usize;
                if self.thresholds[node] < 0.0
                    || self.thresholds[node].fract() != 0.0
                    || slot + 1 >= self.cat_boundaries.len()
                {
                    return Err("invalid categorical split".into());
                }
                if self.cat_boundaries[slot] > self.cat_boundaries[slot + 1]
                    || self.cat_boundaries[slot + 1] as usize > self.cat_threshold.len()
                {
                    return Err("categorical bitset out of bounds".into());
                }
            }
        }
        // Validate the reachable graph once; prediction can then traverse safely.
        if nodes > 0 {
            let mut state = vec![0u8; nodes];
            let mut stack = vec![(0usize, false)];
            while let Some((node, exit)) = stack.pop() {
                if exit {
                    state[node] = 2;
                    continue;
                }
                if state[node] == 1 {
                    return Err("cycle in model tree".into());
                }
                if state[node] == 2 {
                    continue;
                }
                state[node] = 1;
                stack.push((node, true));
                for child in [self.right[node], self.left[node]] {
                    if child >= 0 {
                        stack.push((child as usize, false));
                    }
                }
            }
        }
        Ok(())
    }
    fn predict(&self, features: &[f64]) -> f64 {
        if self.features.is_empty() {
            return self.leaves[0];
        }
        let mut node = 0usize;
        loop {
            let value = features[usize::from(self.features[node])];
            let flags = self.decisions[node];
            let left = if flags & 1 != 0 {
                if !value.is_finite() || value < 0.0 || value > i32::MAX as f64 {
                    false
                } else {
                    let category = value as usize;
                    let index = self.thresholds[node] as usize;
                    let start = self.cat_boundaries[index] as usize;
                    let end = self.cat_boundaries[index + 1] as usize;
                    start + category / 32 < end
                        && self.cat_threshold[start + category / 32] & (1u32 << (category % 32))
                            != 0
                }
            } else {
                let missing_type = (flags >> 2) & 3;
                if (missing_type == 2 && value.is_nan())
                    || (missing_type == 1 && (value == 0.0 || value.is_nan()))
                {
                    flags & 2 != 0
                } else {
                    let value = if value.is_nan() { 0.0 } else { value };
                    value <= self.thresholds[node]
                }
            };
            let child = if left {
                self.left[node]
            } else {
                self.right[node]
            };
            if child < 0 {
                return self.leaves[(!child) as usize];
            }
            node = child as usize;
        }
    }
}
fn fields(text: &str) -> Fields<'_> {
    text.lines()
        .filter_map(|line| line.trim().split_once('='))
        .map(|(key, value)| (key.trim(), value.trim()))
        .collect()
}
fn number<T: std::str::FromStr>(data: &Fields<'_>, key: &str) -> Result<T, String> {
    data.get(key)
        .ok_or_else(|| format!("missing {key}"))?
        .parse()
        .map_err(|_| format!("invalid {key}"))
}
fn array<T: std::str::FromStr>(data: &Fields<'_>, key: &str) -> Result<Vec<T>, String> {
    data.get(key)
        .ok_or_else(|| format!("missing {key}"))?
        .split_whitespace()
        .map(|v| v.parse().map_err(|_| format!("invalid {key}")))
        .collect()
}
fn optional_array<T: std::str::FromStr>(data: &Fields<'_>, key: &str) -> Result<Vec<T>, String> {
    if data.contains_key(key) {
        array(data, key)
    } else {
        Ok(vec![])
    }
}

fn parse_transforms(text: &str, count: usize, names: &[String]) -> Result<Vec<Transform>, String> {
    let Some((_, tail)) = text.split_once("[transforms]") else {
        return Ok(vec![]);
    };
    let content = tail
        .split_once("[/transforms]")
        .ok_or("unterminated transforms trailer")?
        .0;
    let mut section = "";
    let mut definitions = BTreeMap::<&str, Fields<'_>>::new();
    let mut order = BTreeMap::<usize, &str>::new();
    let mut enabled = false;
    for line in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        if line.starts_with('[') && line.ends_with(']') {
            section = line.trim_matches(['[', ']']);
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match section {
            "order" => {
                order.insert(key.parse().map_err(|_| "invalid transform order")?, value);
            }
            "definitions" => {
                if let Some((id, param)) = key.split_once('_') {
                    definitions.entry(id).or_default().insert(param, value);
                }
            }
            _ => {
                if key == "transform" {
                    enabled = value == "true";
                }
            }
        }
    }
    if !enabled {
        return Ok(vec![]);
    }
    for (slot, name) in order {
        if slot < count && names[slot] != name {
            return Err("transform feature order does not match model".into());
        }
    }
    let mut transforms = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for params in definitions.values() {
        let kind = params.get("type").copied().ok_or("transform has no type")?;
        let parse = |key: &str| -> Result<Vec<f64>, String> {
            params
                .get(key)
                .ok_or_else(|| format!("missing transform {key}"))?
                .split(',')
                .map(|v| {
                    v.trim()
                        .parse::<f64>()
                        .map_err(|_| format!("invalid transform {key}"))
                })
                .collect()
        };
        let indices = params
            .get("features")
            .ok_or("missing transform features")?
            .split(',')
            .map(|v| {
                v.trim()
                    .parse::<usize>()
                    .map_err(|_| "invalid transform feature".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let center = parse(match kind {
            "StandardScaler" => "mean",
            "RobustScaler" => "center",
            _ => return Err("unsupported feature transform".into()),
        })?;
        let scale = parse("scale")?;
        if indices.len() != center.len() || indices.len() != scale.len() {
            return Err("transform parameter count mismatch".into());
        }
        for (i, slot) in indices.iter().enumerate() {
            // Current upstream computes 32 slots, older models use only 30.
            if *slot >= super::features::FEATURE_NAMES.len() {
                return Err("transform feature out of bounds".into());
            }
            if !center[i].is_finite() || !scale[i].is_finite() || scale[i] == 0.0 {
                return Err("invalid transform scale".into());
            }
            if *slot < count && !seen.insert(*slot) {
                return Err("overlapping feature transforms".into());
            }
        }
        let kept = indices
            .iter()
            .enumerate()
            .filter(|(_, slot)| **slot < count)
            .map(|(i, slot)| (*slot, center[i], scale[i]))
            .collect::<Vec<_>>();
        transforms.push(Transform {
            indices: kept.iter().map(|v| v.0).collect(),
            center: kept.iter().map(|v| v.1).collect(),
            scale: kept.iter().map(|v| v.2).collect(),
        });
    }
    Ok(transforms)
}
