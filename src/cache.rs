//! On-disk cache of matching results, one file per image digest, so a re-run
//! doesn't call the API again. Images are immutable per digest; advisories are
//! not, hence the TTL. Best effort: any cache error is a miss, never a failure.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::vuln::Finding;

#[derive(Debug, Clone)]
pub struct Cache {
    dir: Option<PathBuf>,
    ttl: Duration,
    /// `false` (`--no-cache`): never read, still refresh what was fetched.
    read: bool,
}

#[derive(Serialize, Deserialize)]
struct Entry<T> {
    source: String,
    fetched_at: i64,
    data: T,
}

impl Cache {
    pub const DEFAULT_TTL: Duration = Duration::from_secs(6 * 3600);

    pub fn new(dir: Option<PathBuf>, ttl: Duration, read: bool) -> Self {
        Self { dir, ttl, read }
    }

    /// `$XDG_CACHE_HOME/virtsec`, else `~/.cache/virtsec`.
    pub fn default_dir() -> Option<PathBuf> {
        std::env::var_os("XDG_CACHE_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
            .map(|d| d.join("virtsec"))
    }

    /// `vulns/<digest>.json`, or any other `<name>.json` (the KEV catalogue).
    fn path(&self, name: &str) -> Option<PathBuf> {
        let name: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '/' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        Some(self.dir.as_ref()?.join(format!("{name}.json")))
    }

    /// Findings by package purl, if a fresh entry from `source` exists.
    pub fn get(&self, source: &str, digest: &str) -> Option<HashMap<String, Vec<Finding>>> {
        self.get_json(&format!("vulns/{digest}"), source)
    }

    pub fn put(&self, source: &str, digest: &str, findings: &HashMap<String, Vec<Finding>>) {
        self.put_json(&format!("vulns/{digest}"), source, findings)
    }

    pub fn get_json<T: DeserializeOwned>(&self, name: &str, source: &str) -> Option<T> {
        if !self.read {
            return None;
        }
        let entry: Entry<T> =
            serde_json::from_slice(&std::fs::read(self.path(name)?).ok()?).ok()?;
        let age = chrono::Utc::now().timestamp() - entry.fetched_at;
        (entry.source == source && (0..self.ttl.as_secs() as i64).contains(&age))
            .then_some(entry.data)
    }

    pub fn put_json<T: Serialize>(&self, name: &str, source: &str, data: &T) {
        let Some(path) = self.path(name) else {
            return;
        };
        let entry = Entry {
            source: source.to_string(),
            fetched_at: chrono::Utc::now().timestamp(),
            data,
        };
        let write = || -> std::io::Result<()> {
            std::fs::create_dir_all(path.parent().expect("cache path has a parent"))?;
            // Write-then-rename: a concurrent reader never sees half a file.
            let tmp = path.with_extension(format!("tmp{}", std::process::id()));
            std::fs::write(&tmp, serde_json::to_vec(&entry)?)?;
            std::fs::rename(tmp, &path)
        };
        if let Err(e) = write() {
            tracing::debug!(error = %e, path = %path.display(), "cannot write vuln cache");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ttl_source_and_no_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(Some(dir.path().into()), Duration::from_secs(60), true);
        let mut m = HashMap::new();
        m.insert("pkg:x/a@1".to_string(), Vec::new());
        cache.put("https://vuln.mlab.sh", "sha256:abc", &m);

        assert!(cache.get("https://vuln.mlab.sh", "sha256:abc").is_some());
        assert!(
            cache.get("https://onprem", "sha256:abc").is_none(),
            "other source"
        );
        assert!(cache.get("https://vuln.mlab.sh", "sha256:zzz").is_none());

        let expired = Cache::new(Some(dir.path().into()), Duration::ZERO, true);
        assert!(expired.get("https://vuln.mlab.sh", "sha256:abc").is_none());
        let no_read = Cache::new(Some(dir.path().into()), Duration::from_secs(60), false);
        assert!(no_read.get("https://vuln.mlab.sh", "sha256:abc").is_none());
    }
}
