// Persistent trust store — JSON file mapping program names to hashes + canonical forms.
//
// Location: `~/.local/share/may-i/trust.json` (or XDG_DATA_HOME equivalent).
//
// Format (v2):
// {
//   "version": 2,
//   "programs": {
//     "git": { "hash": "sha256:...", "rules": ["(rule \"git\" (effect :allow))"] }
//   }
// }

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// On-disk trust store format (v2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustStore {
    version: u32,
    programs: BTreeMap<String, ProgramEntry>,
}

/// Per-program entry in the trust store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramEntry {
    pub hash: String,
    pub rules: Vec<String>,
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

/// An entry whose stored canonical forms don't match its stored hash.
#[derive(Debug, Clone)]
pub struct SuspectEntry {
    pub program: String,
    pub stored_hash: String,
    pub stored_rules: Vec<String>,
}

/// Result of loading the trust store.
pub struct LoadResult {
    pub store: TrustStore,
    pub suspects: Vec<SuspectEntry>,
    /// True if the file existed but could not be parsed.
    pub was_corrupt: bool,
}

impl Default for TrustStore {
    fn default() -> Self {
        TrustStore {
            version: 2,
            programs: BTreeMap::new(),
        }
    }
}

impl TrustStore {
    /// Load the trust store from disk. Returns empty store if file doesn't exist
    /// or is in an unrecognized format. Also verifies integrity of stored entries.
    pub fn load(path: &Path) -> std::io::Result<LoadResult> {
        let (store, was_corrupt) = match std::fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str::<TrustStore>(&content) {
                Ok(s) => (s, false),
                Err(_) => (TrustStore::default(), true),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (TrustStore::default(), false),
            Err(e) => return Err(e),
        };

        let suspects = store.verify_integrity();

        Ok(LoadResult {
            store,
            suspects,
            was_corrupt,
        })
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
        match self.programs.get(program) {
            Some(entry) if entry.hash == computed_hash => TrustStatus::Trusted,
            Some(_) => TrustStatus::Changed,
            None => TrustStatus::New,
        }
    }

    /// Approve a program by storing its hash and canonical forms.
    pub fn approve(&mut self, program: String, hash: String, rules: Vec<String>) {
        self.programs.insert(program, ProgramEntry { hash, rules });
    }

    /// Get the previously stored canonical forms for a program (for diff computation).
    pub fn previous_rules(&self, program: &str) -> Option<&[String]> {
        self.programs.get(program).map(|e| e.rules.as_slice())
    }

    /// Re-approve a suspect entry by recomputing its hash from its stored forms.
    pub fn reapprove(&mut self, program: &str) {
        if let Some(entry) = self.programs.get_mut(program) {
            entry.hash = hash_rules(&entry.rules);
        }
    }

    /// Remove an entry from the store.
    pub fn drop_entry(&mut self, program: &str) {
        self.programs.remove(program);
    }

    /// Verify integrity of all stored entries.
    /// Returns entries whose stored canonical forms don't re-hash to the stored hash.
    fn verify_integrity(&self) -> Vec<SuspectEntry> {
        let mut suspects = Vec::new();
        for (program, entry) in &self.programs {
            if entry.rules.is_empty() {
                // No stored forms to verify (shouldn't happen in v2, but be safe).
                continue;
            }
            let expected = hash_rules(&entry.rules);
            if expected != entry.hash {
                suspects.push(SuspectEntry {
                    program: program.clone(),
                    stored_hash: entry.hash.clone(),
                    stored_rules: entry.rules.clone(),
                });
            }
        }
        suspects
    }
}

/// Compute the trust hash from canonical rule strings, matching
/// `compute_trust_hashes` algorithm: join with newline, SHA-256.
fn hash_rules(rules: &[String]) -> String {
    let combined = rules.join("\n");
    let mut hasher = Sha256::new();
    hasher.update(combined.as_bytes());
    let result = hasher.finalize();
    format!("sha256:{}", hex::encode(result))
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
        store.approve("git".into(), "sha256:abc123".into(), vec!["rule1".into()]);
        assert_eq!(store.check("git", "sha256:abc123"), TrustStatus::Trusted);
    }

    #[test]
    fn mismatched_hash_returns_changed() {
        let mut store = TrustStore::default();
        store.approve("git".into(), "sha256:old".into(), vec!["rule1".into()]);
        assert_eq!(store.check("git", "sha256:new"), TrustStatus::Changed);
    }

    #[test]
    fn round_trip_persist_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");

        let rules = vec![r#"(rule "git" (effect :allow))"#.to_string()];
        let hash = hash_rules(&rules);

        let mut store = TrustStore::default();
        store.approve("git".into(), hash.clone(), rules.clone());
        store.save(&path).unwrap();

        let loaded = TrustStore::load(&path).unwrap();
        assert_eq!(loaded.store.check("git", &hash), TrustStatus::Trusted);
        assert!(loaded.suspects.is_empty());
    }

    #[test]
    fn load_nonexistent_returns_empty() {
        let result = TrustStore::load(Path::new("/nonexistent/trust.json")).unwrap();
        assert!(result.store.programs.is_empty());
        assert!(result.suspects.is_empty());
    }

    #[test]
    fn load_unrecognized_format_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");
        // Write old v1 format (flat map)
        std::fs::write(&path, r#"{"git": "sha256:abc"}"#).unwrap();

        let result = TrustStore::load(&path).unwrap();
        assert!(
            result.store.programs.is_empty(),
            "v1 format should be discarded"
        );
    }

    #[test]
    fn previous_rules_returns_stored_forms() {
        let mut store = TrustStore::default();
        let rules = vec!["(rule \"git\" (effect :allow))".to_string()];
        store.approve("git".into(), "sha256:abc".into(), rules.clone());
        assert_eq!(store.previous_rules("git"), Some(rules.as_slice()));
    }

    #[test]
    fn previous_rules_returns_none_for_unknown() {
        let store = TrustStore::default();
        assert_eq!(store.previous_rules("git"), None);
    }

    #[test]
    fn integrity_verification_passes_for_valid_entries() {
        let mut store = TrustStore::default();
        let rules = vec![r#"(rule "git" (effect :allow))"#.to_string()];
        let hash = hash_rules(&rules);
        store.approve("git".into(), hash, rules);
        assert!(store.verify_integrity().is_empty());
    }

    #[test]
    fn integrity_verification_detects_tampered_hash() {
        let mut store = TrustStore::default();
        let rules = vec![r#"(rule "git" (effect :allow))"#.to_string()];
        store.approve("git".into(), "sha256:tampered".into(), rules);
        let suspects = store.verify_integrity();
        assert_eq!(suspects.len(), 1);
        assert_eq!(suspects[0].program, "git");
    }

    #[test]
    fn integrity_verification_detects_tampered_rules() {
        let mut store = TrustStore::default();
        let rules = vec![r#"(rule "git" (effect :allow))"#.to_string()];
        let hash = hash_rules(&rules);
        // Store with correct hash but then tamper the rules
        store.approve(
            "git".into(),
            hash,
            vec!["(rule \"git\" (effect :deny))".into()],
        );
        let suspects = store.verify_integrity();
        assert_eq!(suspects.len(), 1);
    }

    #[test]
    fn reapprove_fixes_suspect_entry() {
        let mut store = TrustStore::default();
        let rules = vec![r#"(rule "git" (effect :allow))"#.to_string()];
        store.approve("git".into(), "sha256:tampered".into(), rules);
        assert_eq!(store.verify_integrity().len(), 1);

        store.reapprove("git");
        assert!(store.verify_integrity().is_empty());
    }

    #[test]
    fn drop_entry_removes_program() {
        let mut store = TrustStore::default();
        store.approve("git".into(), "sha256:abc".into(), vec!["rule".into()]);
        store.drop_entry("git");
        assert_eq!(store.check("git", "sha256:abc"), TrustStatus::New);
    }

    #[test]
    fn v2_format_has_version_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");

        let mut store = TrustStore::default();
        store.approve("git".into(), "sha256:abc".into(), vec!["rule".into()]);
        store.save(&path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(json["version"], 2);
        assert!(json["programs"]["git"]["hash"].is_string());
        assert!(json["programs"]["git"]["rules"].is_array());
    }
}
