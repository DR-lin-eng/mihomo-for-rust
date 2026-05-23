use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use base64::Engine as _;

const STORAGE_SIZE_LIMIT: usize = 1024 * 1024;
const STORAGE_KEY_SIZE_LIMIT: usize = 64;
const MAX_STORAGE_ENTRIES: usize = STORAGE_SIZE_LIMIT / STORAGE_KEY_SIZE_LIMIT;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageError {
    InvalidKey,
    PayloadTooLarge,
    PayloadInvalidJson,
    Io(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "invalid storage key"),
            Self::PayloadTooLarge => write!(f, "payload exceeds 1MB limit"),
            Self::PayloadInvalidJson => write!(f, "Body invalid"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for StorageError {}

#[derive(Clone, Debug)]
pub struct StorageStore {
    root: PathBuf,
}

impl StorageStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        validate_storage_key(key)?;
        let path = self.entry_path(key);
        match fs::read(path) {
            Ok(data) => Ok(Some(data)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(StorageError::Io(err.to_string())),
        }
    }

    pub fn set(&self, key: &str, data: &[u8]) -> Result<(), StorageError> {
        validate_storage_key(key)?;
        if data.len() > STORAGE_SIZE_LIMIT {
            return Err(StorageError::PayloadTooLarge);
        }
        if !serde_json::from_slice::<serde_json::Value>(data).is_ok() {
            return Err(StorageError::PayloadInvalidJson);
        }
        fs::create_dir_all(&self.root).map_err(|err| StorageError::Io(err.to_string()))?;

        let key_path = self.entry_path(key);
        let existing = match fs::read(&key_path) {
            Ok(current) => Some(current),
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => return Err(StorageError::Io(err.to_string())),
        };
        let current_total = self.total_size()?;
        let current_entries = self.entry_metadata()?;
        let existing_len = existing.as_ref().map_or(0, Vec::len);

        if current_total
            .saturating_sub(existing_len)
            .saturating_add(data.len())
            > STORAGE_SIZE_LIMIT
            || (existing.is_none() && current_entries.len() >= MAX_STORAGE_ENTRIES)
        {
            self.evict_until_fit(key, data.len(), existing.is_some())?;
        }

        fs::write(key_path, data).map_err(|err| StorageError::Io(err.to_string()))
    }

    pub fn delete(&self, key: &str) -> Result<(), StorageError> {
        validate_storage_key(key)?;
        let path = self.entry_path(key);
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(StorageError::Io(err.to_string())),
        }
    }

    fn entry_path(&self, key: &str) -> PathBuf {
        self.root.join(storage_filename(key))
    }

    fn total_size(&self) -> Result<usize, StorageError> {
        Ok(self
            .entry_metadata()?
            .values()
            .map(|entry| entry.len)
            .sum())
    }

    fn entry_metadata(&self) -> Result<BTreeMap<String, StorageEntryMeta>, StorageError> {
        let mut entries = BTreeMap::new();
        let read_dir = match fs::read_dir(&self.root) {
            Ok(dir) => dir,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(entries),
            Err(err) => return Err(StorageError::Io(err.to_string())),
        };

        for item in read_dir {
            let item = item.map_err(|err| StorageError::Io(err.to_string()))?;
            let path = item.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            let Some(key) = decode_storage_filename(name) else {
                continue;
            };
            let metadata = item
                .metadata()
                .map_err(|err| StorageError::Io(err.to_string()))?;
            let modified = metadata
                .modified()
                .unwrap_or(UNIX_EPOCH)
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            entries.insert(
                key,
                StorageEntryMeta {
                    len: usize::try_from(metadata.len()).unwrap_or(usize::MAX),
                    modified_at_ms: modified,
                },
            );
        }

        Ok(entries)
    }

    fn evict_until_fit(
        &self,
        key: &str,
        new_len: usize,
        replacing_existing: bool,
    ) -> Result<(), StorageError> {
        let mut entries = self.entry_metadata()?.into_iter().collect::<Vec<_>>();
        entries.sort_by(|(left_key, left_meta), (right_key, right_meta)| {
            left_meta
                .modified_at_ms
                .cmp(&right_meta.modified_at_ms)
                .then_with(|| left_key.cmp(right_key))
        });

        let mut total: usize = entries.iter().map(|(_, meta)| meta.len).sum();
        let mut count = entries.len();
        for (entry_key, meta) in entries {
            if entry_key == key {
                total = total.saturating_sub(meta.len);
                count = count.saturating_sub(1);
                continue;
            }
            if total.saturating_add(new_len) <= STORAGE_SIZE_LIMIT
                && (replacing_existing || count < MAX_STORAGE_ENTRIES)
            {
                break;
            }
            let _ = fs::remove_file(self.entry_path(&entry_key));
            total = total.saturating_sub(meta.len);
            count = count.saturating_sub(1);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StorageEntryMeta {
    len: usize,
    modified_at_ms: u128,
}

fn validate_storage_key(key: &str) -> Result<(), StorageError> {
    if key.is_empty() || key.len() > STORAGE_KEY_SIZE_LIMIT || key.contains('/') || key.contains('\\') {
        return Err(StorageError::InvalidKey);
    }
    Ok(())
}

fn storage_filename(key: &str) -> String {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.as_bytes());
    format!("{encoded}.json")
}

fn decode_storage_filename(name: &str) -> Option<String> {
    let encoded = name.strip_suffix(".json")?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()?;
    String::from_utf8(decoded).ok()
}

pub fn default_storage_root(home_dir: &Path) -> PathBuf {
    home_dir.join("storage")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{default_storage_root, StorageError, StorageStore};

    #[test]
    fn storage_store_roundtrips_json_payload() {
        let root = unique_temp_dir("mihomo-api-storage-roundtrip");
        let store = StorageStore::new(default_storage_root(&root));
        store.set("key-a", br#"{"value":1}"#).unwrap();
        assert_eq!(store.get("key-a").unwrap(), Some(br#"{"value":1}"#.to_vec()));
        store.delete("key-a").unwrap();
        assert_eq!(store.get("key-a").unwrap(), None);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn storage_store_rejects_invalid_payload_and_key() {
        let root = unique_temp_dir("mihomo-api-storage-invalid");
        let store = StorageStore::new(default_storage_root(&root));
        assert_eq!(store.set("bad/key", br#"{"value":1}"#).unwrap_err(), StorageError::InvalidKey);
        assert_eq!(store.set("good", b"not-json").unwrap_err(), StorageError::PayloadInvalidJson);
        let _ = fs::remove_dir_all(root);
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nanos}"))
    }
}
