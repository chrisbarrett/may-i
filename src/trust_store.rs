// Persistent trust store — JSON file mapping program names to SHA-256 hashes.
//
// Location: `~/.local/share/may-i/trust.json` (or XDG_DATA_HOME equivalent).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// On-disk trust store format.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustStore {
    #[serde(flatten)]
    pub entries: BTreeMap<String, String>,
}

/// Result of comparing a computed hash against the trust store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustStatus {
    /// Hash matches stored value.
    Trusted,
    /// Hash differs from stored value.
    Changed,
    /// No stored value (first load).
    New,
}

impl TrustStore {
    /// Load the trust store from disk. Returns empty store if file doesn't exist.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let store: TrustStore = serde_json::from_str(&content).unwrap_or_default();
                Ok(store)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TrustStore::default()),
            Err(e) => Err(e),
        }
    }

    /// Save the trust store to disk.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(&self)?;
        std::fs::write(path, content)
    }

    /// Check the trust status of a program.
    pub fn check(&self, program: &str, computed_hash: &str) -> TrustStatus {
        match self.entries.get(program) {
            Some(stored) if stored == computed_hash => TrustStatus::Trusted,
            Some(_) => TrustStatus::Changed,
            None => TrustStatus::New,
        }
    }

    /// Approve a program by storing its hash.
    pub fn approve(&mut self, program: String, hash: String) {
        self.entries.insert(program, hash);
    }
}

/// Default trust store path.
pub fn default_trust_store_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        return Some(PathBuf::from(xdg).join("may-i/trust.json"));
    }
    dirs::data_dir().map(|d| d.join("may-i/trust.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_store_returns_new_for_any_program() {
        let store = TrustStore::default();
        assert_eq!(store.check("git", "sha256:abc"), TrustStatus::New);
    }

    #[test]
    fn matching_hash_returns_trusted() {
        let mut store = TrustStore::default();
        store.approve("git".into(), "sha256:abc123".into());
        assert_eq!(store.check("git", "sha256:abc123"), TrustStatus::Trusted);
    }

    #[test]
    fn mismatched_hash_returns_changed() {
        let mut store = TrustStore::default();
        store.approve("git".into(), "sha256:old".into());
        assert_eq!(store.check("git", "sha256:new"), TrustStatus::Changed);
    }

    #[test]
    fn persist_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");

        let mut store = TrustStore::default();
        store.approve("git".into(), "sha256:abc".into());
        store.approve("docker".into(), "sha256:def".into());
        store.save(&path).unwrap();

        let loaded = TrustStore::load(&path).unwrap();
        assert_eq!(loaded.check("git", "sha256:abc"), TrustStatus::Trusted);
        assert_eq!(loaded.check("docker", "sha256:def"), TrustStatus::Trusted);
    }

    #[test]
    fn load_nonexistent_returns_empty() {
        let store = TrustStore::load(Path::new("/nonexistent/trust.json")).unwrap();
        assert!(store.entries.is_empty());
    }

    #[test]
    fn bypass_for_untouched_programs() {
        // Programs not in computed hashes are not checked
        let store = TrustStore::default();
        // This just validates the API — if a program has no computed hash,
        // it simply isn't checked against the store.
        assert_eq!(store.check("ls", "sha256:whatever"), TrustStatus::New);
    }
}
