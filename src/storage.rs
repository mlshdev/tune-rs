use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{Map, Value};
use tracing::{info, warn};

use crate::models::{Server, Servers};
use crate::provider::ProviderName;

const MANIFEST_FILENAME: &str = "manifest.json";
const MANIFEST_VERSION: u8 = 1;
const LEGACY_FILEPATH: &str = "/gluetun/servers.json";

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("writing {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("decoding {what}: {source}")]
    Decode {
        what: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("encoding servers: {0}")]
    Encode(#[from] serde_json::Error),
}

pub fn hardcoded() -> BTreeMap<ProviderName, Servers> {
    let raw = |provider: ProviderName| -> &'static str {
        match provider {
            ProviderName::Mullvad => include_str!("../servers/mullvad.json"),
        }
    };
    ProviderName::ALL
        .into_iter()
        .map(|provider| {
            let servers: Servers = serde_json::from_str(raw(provider))
                .unwrap_or_else(|err| panic!("embedded {provider} servers are invalid: {err}"));
            (provider, servers)
        })
        .collect()
}

pub fn sort_servers(servers: &mut [Server]) {
    servers.sort_by(|a, b| {
        (&a.country, &a.city, &a.hostname, &a.isp, &a.vpn).cmp(&(
            &b.country,
            &b.city,
            &b.hostname,
            &b.isp,
            &b.vpn,
        ))
    });
}

#[derive(Clone, Debug)]
pub struct Storage {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    hardcoded: BTreeMap<ProviderName, Servers>,
    merged: RwLock<BTreeMap<ProviderName, Servers>>,
    directory: Option<PathBuf>,
}

impl Storage {
    pub fn new(directory: Option<PathBuf>) -> Result<Self, StorageError> {
        let hardcoded = hardcoded();
        let storage = Self {
            inner: Arc::new(Inner {
                merged: RwLock::new(hardcoded.clone()),
                hardcoded,
                directory,
            }),
        };
        if let Some(directory) = &storage.inner.directory {
            storage.sync(directory)?;
        }
        Ok(storage)
    }

    pub fn servers(&self, provider: ProviderName) -> Vec<Server> {
        self.read_merged()
            .get(&provider)
            .map(|servers| servers.servers.clone())
            .unwrap_or_default()
    }

    pub fn servers_object(&self, provider: ProviderName) -> Servers {
        self.read_merged()
            .get(&provider)
            .cloned()
            .unwrap_or_default()
    }

    pub fn hardcoded_version(&self, provider: ProviderName) -> u16 {
        self.inner
            .hardcoded
            .get(&provider)
            .map_or(0, |servers| servers.version)
    }

    pub fn set_servers(
        &self,
        provider: ProviderName,
        mut servers: Vec<Server>,
    ) -> Result<(), StorageError> {
        sort_servers(&mut servers);
        let mut merged = self
            .inner
            .merged
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut next = merged.clone();
        let entry = next.entry(provider).or_default();
        entry.version = self.hardcoded_version(provider);
        entry.timestamp = unix_now();
        entry.servers = servers;
        if let Some(directory) = &self.inner.directory {
            Self::flush_snapshot(&directory.join(MANIFEST_FILENAME), &next)?;
        }
        *merged = next;
        Ok(())
    }

    fn read_merged(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<ProviderName, Servers>> {
        self.inner
            .merged
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn sync(&self, directory: &Path) -> Result<(), StorageError> {
        let versions: HashMap<ProviderName, u16> = self
            .inner
            .hardcoded
            .iter()
            .map(|(provider, servers)| (*provider, servers.version))
            .collect();
        let manifest_path = directory.join(MANIFEST_FILENAME);
        let legacy = Path::new(LEGACY_FILEPATH);
        let mut source = manifest_path.clone();
        let mut on_file = read_file(&manifest_path, &versions)?;
        let has_legacy = legacy != manifest_path && legacy.is_file();
        if on_file.is_none() && has_legacy {
            info!(path = %legacy.display(), directory = %directory.display(), "migrating legacy servers file");
            source = legacy.to_path_buf();
            on_file = read_file(legacy, &versions)?;
        }
        let on_file = on_file.unwrap_or_default();
        let count_on_file: usize = on_file.values().map(|s| s.servers.len()).sum();
        let merged = if count_on_file == 0 {
            info!(directory = %directory.display(), "writing hardcoded servers data files");
            self.inner.hardcoded.clone()
        } else {
            info!(count_on_file, path = %source.display(), "merging hardcoded servers with servers on file");
            ProviderName::ALL
                .into_iter()
                .map(|provider| {
                    let hardcoded = self
                        .inner
                        .hardcoded
                        .get(&provider)
                        .cloned()
                        .unwrap_or_default();
                    let persisted = on_file.get(&provider).cloned().unwrap_or_default();
                    (
                        provider,
                        merge_provider(provider, hardcoded, persisted, unix_now()),
                    )
                })
                .collect()
        };
        let unchanged = merged == on_file;
        *self
            .inner
            .merged
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = merged;
        if unchanged {
            return Ok(());
        }
        if let Err(err) = self.flush(&manifest_path) {
            warn!(error = %err, "failed writing servers to manifest");
            return Ok(());
        }
        if source == legacy
            && let Err(err) = std::fs::remove_file(legacy)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            warn!(error = %err, path = %legacy.display(), "failed removing legacy servers file");
        }
        Ok(())
    }

    fn flush(&self, manifest_path: &Path) -> Result<(), StorageError> {
        Self::flush_snapshot(manifest_path, &self.read_merged())
    }

    fn flush_snapshot(
        manifest_path: &Path,
        merged: &BTreeMap<ProviderName, Servers>,
    ) -> Result<(), StorageError> {
        let directory = manifest_path.parent().unwrap_or_else(|| Path::new("/"));
        create_dir(directory)?;
        let mut manifest = Map::new();
        manifest.insert("version".into(), Value::from(MANIFEST_VERSION));
        for (provider, servers) in merged {
            let path = if servers.filepath.is_empty() {
                directory.join(format!("{provider}.json"))
            } else {
                PathBuf::from(&servers.filepath)
            };
            if let Some(parent) = path.parent() {
                create_dir(parent)?;
            }
            let mut encoded = servers.clone();
            encoded.filepath.clear();
            sort_servers(&mut encoded.servers);
            write_json(&path, &serde_json::to_vec_pretty(&encoded)?)?;
            let mut entry = Map::new();
            entry.insert("filepath".into(), Value::from(path.display().to_string()));
            manifest.insert(provider.to_string(), Value::Object(entry));
        }
        write_json(
            manifest_path,
            &serde_json::to_vec_pretty(&Value::Object(manifest))?,
        )
    }
}

fn create_dir(path: &Path) -> Result<(), StorageError> {
    std::fs::create_dir_all(path).map_err(|source| StorageError::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn write_json(path: &Path, content: &[u8]) -> Result<(), StorageError> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, content)
        .and_then(|()| std::fs::rename(&tmp, path))
        .map_err(|source| StorageError::Write {
            path: path.to_path_buf(),
            source,
        })
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn read_file(
    path: &Path,
    versions: &HashMap<ProviderName, u16>,
) -> Result<Option<BTreeMap<ProviderName, Servers>>, StorageError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) if bytes.is_empty() => return Ok(None),
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(StorageError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let raw: Map<String, Value> =
        serde_json::from_slice(&bytes).map_err(|source| StorageError::Decode {
            what: path.display().to_string(),
            source,
        })?;
    let mut result = BTreeMap::new();
    for provider in ProviderName::ALL {
        let Some(value) = raw.get(provider.as_str()) else {
            continue;
        };
        let hardcoded_version = versions.get(&provider).copied().unwrap_or(0);
        if let Some(servers) = read_provider(provider, value, hardcoded_version)? {
            result.insert(provider, servers);
        }
    }
    Ok(Some(result))
}

fn read_provider(
    provider: ProviderName,
    value: &Value,
    hardcoded_version: u16,
) -> Result<Option<Servers>, StorageError> {
    let referenced = value
        .get("filepath")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty());
    let (servers, source) = match referenced {
        Some(filepath) => {
            let bytes = match std::fs::read(filepath) {
                Ok(bytes) => bytes,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    warn!(%provider, filepath, "servers file referenced by the manifest does not exist, using hardcoded servers");
                    return Ok(None);
                }
                Err(source) => {
                    return Err(StorageError::Read {
                        path: filepath.into(),
                        source,
                    });
                }
            };
            let mut servers: Servers =
                serde_json::from_slice(&bytes).map_err(|source| StorageError::Decode {
                    what: filepath.to_owned(),
                    source,
                })?;
            servers.filepath = filepath.to_owned();
            (servers, Some(filepath))
        }
        None => {
            let servers = Servers::deserialize(value).map_err(|source| StorageError::Decode {
                what: format!("{provider} servers"),
                source,
            })?;
            (servers, None)
        }
    };
    if servers.version != hardcoded_version {
        let preferred = if servers.preferred { " preferred" } else { "" };
        let from = source
            .map(|path| format!(" from file {path}"))
            .unwrap_or_default();
        let message = format!(
            "{provider}{preferred} servers{from} discarded because they have version {} and hardcoded servers have version {hardcoded_version}",
            servers.version
        );
        if servers.preferred {
            warn!("{message}");
        } else {
            info!("{message}");
        }
        return Ok(None);
    }
    Ok(Some(servers))
}

pub(crate) fn merge_provider(
    provider: ProviderName,
    hardcoded: Servers,
    persisted: Servers,
    now: i64,
) -> Servers {
    if persisted.preferred
        && persisted.version == hardcoded.version
        && !persisted.servers.is_empty()
    {
        info!(%provider, "using servers from file (marked as preferred)");
        return persisted;
    }
    if persisted.timestamp > now {
        warn!(%provider, timestamp = persisted.timestamp, "persisted servers have a timestamp in the future, ignoring them");
    } else if persisted.timestamp > hardcoded.timestamp {
        info!(%provider, newer_by_seconds = persisted.timestamp - hardcoded.timestamp, "using servers from file which are more recent");
        return persisted;
    }
    let mut keep: HashMap<String, Server> = persisted
        .servers
        .into_iter()
        .filter(|server| server.keep)
        .map(|server| (server.key(), server))
        .collect();
    let mut merged = hardcoded;
    let hardcoded_servers = std::mem::take(&mut merged.servers);
    merged.servers = hardcoded_servers
        .into_iter()
        .map(|server| keep.remove(&server.key()).unwrap_or(server))
        .collect();
    merged.servers.extend(keep.into_values());
    sort_servers(&mut merged.servers);
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::VPN_WIREGUARD;

    fn server(hostname: &str, keep: bool) -> Server {
        Server {
            vpn: VPN_WIREGUARD.into(),
            hostname: hostname.into(),
            keep,
            ..Server::default()
        }
    }

    #[test]
    fn embedded_servers_load() {
        let all = hardcoded();
        assert_eq!(all.len(), 1);
        assert!(all.values().all(|s| !s.servers.is_empty()));
        assert!(
            all.values()
                .flat_map(|s| &s.servers)
                .all(|s| s.vpn == VPN_WIREGUARD)
        );
    }

    #[test]
    fn merge_prefers_newer_persisted() {
        let hardcoded = Servers {
            version: 1,
            timestamp: 10,
            servers: vec![server("a", false)],
            ..Default::default()
        };
        let persisted = Servers {
            version: 1,
            timestamp: 20,
            servers: vec![server("b", false)],
            ..Default::default()
        };
        let merged = merge_provider(ProviderName::Mullvad, hardcoded, persisted, 100);
        assert_eq!(merged.servers[0].hostname, "b");
    }

    #[test]
    fn merge_keeps_marked_servers() {
        let hardcoded = Servers {
            version: 1,
            timestamp: 30,
            servers: vec![server("a", false)],
            ..Default::default()
        };
        let persisted = Servers {
            version: 1,
            timestamp: 20,
            servers: vec![server("a", true), server("z", true), server("x", false)],
            ..Default::default()
        };
        let merged = merge_provider(ProviderName::Mullvad, hardcoded, persisted, 100);
        let names: Vec<&str> = merged.servers.iter().map(|s| s.hostname.as_str()).collect();
        assert_eq!(names, vec!["a", "z"]);
        assert!(merged.servers[0].keep);
    }

    #[test]
    fn merge_ignores_future_timestamp() {
        let hardcoded = Servers {
            version: 1,
            timestamp: 10,
            servers: vec![server("a", false)],
            ..Default::default()
        };
        let persisted = Servers {
            version: 1,
            timestamp: 1000,
            servers: vec![server("b", false)],
            ..Default::default()
        };
        let merged = merge_provider(ProviderName::Mullvad, hardcoded, persisted, 100);
        assert_eq!(merged.servers[0].hostname, "a");
    }

    #[test]
    fn roundtrip_directory() {
        let dir = std::env::temp_dir().join(format!("tune-storage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = Storage::new(Some(dir.clone())).expect("storage");
        assert!(dir.join(MANIFEST_FILENAME).is_file());
        assert!(dir.join("mullvad.json").is_file());
        storage
            .set_servers(ProviderName::Mullvad, vec![server("only", false)])
            .expect("set");
        let reloaded = Storage::new(Some(dir.clone())).expect("reload");
        assert_eq!(reloaded.servers(ProviderName::Mullvad).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_persistence_keeps_previous_memory_snapshot() {
        let dir = std::env::temp_dir().join(format!("tune-storage-failure-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = Storage::new(Some(dir.clone())).expect("storage");
        let before = storage.servers_object(ProviderName::Mullvad);
        std::fs::remove_dir_all(&dir).expect("remove directory");
        std::fs::write(&dir, b"not a directory").expect("block writes");
        assert!(
            storage
                .set_servers(ProviderName::Mullvad, vec![server("replacement", false)])
                .is_err()
        );
        assert_eq!(storage.servers_object(ProviderName::Mullvad), before);
        std::fs::remove_file(dir).expect("cleanup");
    }

    #[test]
    fn preferred_mullvad_list_and_manifest_ignore_other_providers() {
        let dir =
            std::env::temp_dir().join(format!("tune-storage-preferred-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("directory");
        let data = Servers {
            version: hardcoded()[&ProviderName::Mullvad].version,
            timestamp: 0,
            preferred: true,
            servers: vec![server("preferred", false)],
            ..Servers::default()
        };
        let manifest =
            serde_json::json!({"version": 1, "mullvad": data, "protonvpn": "invalid ignored data"});
        std::fs::write(
            dir.join(MANIFEST_FILENAME),
            serde_json::to_vec(&manifest).expect("encode"),
        )
        .expect("write");
        let storage = Storage::new(Some(dir.clone())).expect("storage");
        assert!(storage.servers_object(ProviderName::Mullvad).preferred);
        assert_eq!(
            storage.servers(ProviderName::Mullvad)[0].hostname,
            "preferred"
        );
        assert!(!dir.join("protonvpn.json").exists());
        std::fs::remove_dir_all(dir).expect("cleanup");
    }
}
