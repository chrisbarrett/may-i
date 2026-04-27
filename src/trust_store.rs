// Persistent trust store — JSON file mapping rule hashes to per-rule entries.
//
// Location: `~/.local/share/may-i/trust.json` (or XDG_DATA_HOME equivalent).
//
// Format (v3):
// {
//   "version": 3,
//   "rules": {
//     "sha256:abc...": {
//       "program": "git",
//       "form": "(rule \"git\" (effect :allow))",
//       "status": "approved"
//     }
//   }
// }

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Status of a single rule in the trust store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleStatus {
    Approved,
    Blocked,
}

/// Per-rule entry in the trust store (v3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleEntry {
    pub program: String,
    pub form: String,
    pub status: RuleStatus,
}

/// Result of checking a rule's trust status against the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustCheck {
    /// Rule is approved in the store.
    Approved,
    /// Rule is explicitly blocked in the store.
    Blocked,
    /// Rule is not in the store (never reviewed).
    Pending,
}

/// Result of comparing a computed hash against the trust store (program-level).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustStatus {
    /// Hash matches stored value.
    Trusted,
    /// Hash differs from stored value.
    Changed,
    /// No stored value (first load).
    New,
}

/// An entry whose stored canonical form doesn't match its hash key.
#[derive(Debug, Clone)]
pub struct SuspectEntry {
    pub hash: String,
    pub program: String,
    pub stored_form: String,
}

/// Result of loading the trust store.
pub struct LoadResult {
    pub store: TrustStore,
    pub suspects: Vec<SuspectEntry>,
    /// True if the file existed but could not be parsed.
    pub was_corrupt: bool,
}

// --- On-disk formats ---

/// v3 on-disk format.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoreV3 {
    version: u32,
    rules: BTreeMap<String, RuleEntry>,
}

/// v2 on-disk format (for migration).
#[derive(Debug, Clone, Deserialize)]
struct StoreV2 {
    version: u32,
    programs: BTreeMap<String, ProgramEntryV2>,
}

#[derive(Debug, Clone, Deserialize)]
struct ProgramEntryV2 {
    #[allow(dead_code)]
    hash: String,
    rules: Vec<String>,
}

/// On-disk trust store.
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    rules: BTreeMap<String, RuleEntry>,
}

impl TrustStore {
    /// Load the trust store from disk. Handles v2→v3 migration.
    pub fn load(path: &Path) -> std::io::Result<LoadResult> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LoadResult {
                    store: TrustStore::default(),
                    suspects: Vec::new(),
                    was_corrupt: false,
                });
            }
            Err(e) => return Err(e),
        };

        // Try v3 first.
        if let Ok(v3) = serde_json::from_str::<StoreV3>(&content)
            && v3.version == 3
        {
            let store = TrustStore { rules: v3.rules };
            let suspects = store.verify_integrity();
            return Ok(LoadResult {
                store,
                suspects,
                was_corrupt: false,
            });
        }

        // Try v2 migration.
        if let Ok(v2) = serde_json::from_str::<StoreV2>(&content)
            && v2.version == 2
        {
            let store = migrate_v2(v2);
            let suspects = store.verify_integrity();
            return Ok(LoadResult {
                store,
                suspects,
                was_corrupt: false,
            });
        }

        // Check if it's valid JSON but unrecognized format vs actual corruption.
        let was_corrupt = serde_json::from_str::<serde_json::Value>(&content).is_err();
        Ok(LoadResult {
            store: TrustStore::default(),
            suspects: Vec::new(),
            was_corrupt,
        })
    }

    /// Save the trust store to disk in v3 format.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let on_disk = StoreV3 {
            version: 3,
            rules: self.rules.clone(),
        };
        let content = serde_json::to_string_pretty(&on_disk).map_err(std::io::Error::other)?;
        std::fs::write(path, content)
    }

    /// Check trust status of a single rule by its hash.
    pub fn check_rule(&self, hash: &str) -> TrustCheck {
        match self.rules.get(hash) {
            Some(entry) if entry.status == RuleStatus::Approved => TrustCheck::Approved,
            Some(_) => TrustCheck::Blocked,
            None => TrustCheck::Pending,
        }
    }

    /// Program-level trust check (backward compat).
    /// A program is trusted if its computed hash matches the old per-program scheme.
    /// With v3, we check program-level by verifying all rules for the program are approved.
    pub fn check(&self, program: &str, computed_hash: &str) -> TrustStatus {
        // Collect all stored entries for this program.
        let program_entries: Vec<&RuleEntry> = self
            .rules
            .values()
            .filter(|e| e.program == program)
            .collect();

        if program_entries.is_empty() {
            return TrustStatus::New;
        }

        // Re-hash stored forms to compare with computed hash.
        let mut stored_forms: Vec<&str> = program_entries.iter().map(|e| e.form.as_str()).collect();
        stored_forms.sort(); // Canonical ordering for comparison
        let rehashed = hash_rules_from_strs(&stored_forms);

        if rehashed == computed_hash {
            TrustStatus::Trusted
        } else {
            TrustStatus::Changed
        }
    }

    /// Approve a single rule.
    pub fn approve_rule(&mut self, hash: String, program: String, form: String) {
        self.rules.insert(
            hash,
            RuleEntry {
                program,
                form,
                status: RuleStatus::Approved,
            },
        );
    }

    /// Block a single rule.
    pub fn block_rule(&mut self, hash: String, program: String, form: String) {
        self.rules.insert(
            hash,
            RuleEntry {
                program,
                form,
                status: RuleStatus::Blocked,
            },
        );
    }

    /// Backward-compat: approve a program by storing all its rules as approved.
    pub fn approve(&mut self, program: String, _hash: String, rules: Vec<String>) {
        for form in rules {
            let rule_hash = hash_single_rule(&form);
            self.rules.insert(
                rule_hash,
                RuleEntry {
                    program: program.clone(),
                    form,
                    status: RuleStatus::Approved,
                },
            );
        }
    }

    /// Get previously stored canonical forms for a program (for diff computation).
    pub fn previous_rules(&self, program: &str) -> Option<Vec<String>> {
        let forms: Vec<String> = self
            .rules
            .values()
            .filter(|e| e.program == program)
            .map(|e| e.form.clone())
            .collect();
        if forms.is_empty() { None } else { Some(forms) }
    }

    /// Get the stored form for a specific hash (for diff of changed rules).
    pub fn previous_form(&self, hash: &str) -> Option<&str> {
        self.rules.get(hash).map(|e| e.form.as_str())
    }

    /// Remove entries whose hashes are not in the current config.
    pub fn cleanup_orphans(&mut self, current_hashes: &std::collections::BTreeSet<String>) {
        self.rules.retain(|hash, _| current_hashes.contains(hash));
    }

    /// Re-approve a suspect entry by recomputing its hash.
    pub fn reapprove(&mut self, program: &str) {
        // Find entries for this program and re-hash them.
        let entries_to_fix: Vec<(String, RuleEntry)> = self
            .rules
            .iter()
            .filter(|(_, e)| e.program == program)
            .map(|(h, e)| (h.clone(), e.clone()))
            .collect();

        for (old_hash, entry) in entries_to_fix {
            let correct_hash = hash_single_rule(&entry.form);
            if correct_hash != old_hash {
                self.rules.remove(&old_hash);
                self.rules.insert(correct_hash, entry);
            }
        }
    }

    /// Remove all entries for a program.
    pub fn drop_entry(&mut self, program: &str) {
        self.rules.retain(|_, e| e.program != program);
    }

    /// Verify integrity: each entry's hash key should match hash of its stored form.
    fn verify_integrity(&self) -> Vec<SuspectEntry> {
        let mut suspects = Vec::new();
        for (hash, entry) in &self.rules {
            let expected = hash_single_rule(&entry.form);
            if expected != *hash {
                suspects.push(SuspectEntry {
                    hash: hash.clone(),
                    program: entry.program.clone(),
                    stored_form: entry.form.clone(),
                });
            }
        }
        suspects
    }

    /// Iterate all rule entries.
    pub fn iter_rules(&self) -> impl Iterator<Item = (&str, &RuleEntry)> {
        self.rules.iter().map(|(h, e)| (h.as_str(), e))
    }
}

/// Migrate v2 store to v3: expand per-program rules into individual entries.
fn migrate_v2(v2: StoreV2) -> TrustStore {
    let mut rules = BTreeMap::new();
    for (program, entry) in v2.programs {
        for form in entry.rules {
            let hash = hash_single_rule(&form);
            rules.insert(
                hash,
                RuleEntry {
                    program: program.clone(),
                    form,
                    status: RuleStatus::Approved,
                },
            );
        }
    }
    TrustStore { rules }
}

/// Hash a single canonical rule form.
fn hash_single_rule(form: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(form.as_bytes());
    let result = hasher.finalize();
    format!("sha256:{}", hex::encode(result))
}

/// Hash multiple rule forms joined by newline (for backward-compat program-level check).
fn hash_rules_from_strs(rules: &[&str]) -> String {
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

    // --- RuleEntry + RuleStatus basics ---

    #[test]
    fn rule_status_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&RuleStatus::Approved).unwrap(),
            r#""approved""#
        );
        assert_eq!(
            serde_json::to_string(&RuleStatus::Blocked).unwrap(),
            r#""blocked""#
        );
    }

    #[test]
    fn rule_entry_round_trips_json() {
        let entry = RuleEntry {
            program: "git".into(),
            form: r#"(rule "git" (effect :allow))"#.into(),
            status: RuleStatus::Approved,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: RuleEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    // --- TrustCheck per-rule ---

    #[test]
    fn check_rule_pending_for_empty_store() {
        let store = TrustStore::default();
        assert_eq!(store.check_rule("sha256:abc"), TrustCheck::Pending);
    }

    #[test]
    fn check_rule_approved() {
        let mut store = TrustStore::default();
        store.approve_rule(
            "sha256:abc".into(),
            "git".into(),
            r#"(rule "git" (effect :allow))"#.into(),
        );
        assert_eq!(store.check_rule("sha256:abc"), TrustCheck::Approved);
    }

    #[test]
    fn check_rule_blocked() {
        let mut store = TrustStore::default();
        store.block_rule(
            "sha256:abc".into(),
            "git".into(),
            r#"(rule "git" (effect :allow))"#.into(),
        );
        assert_eq!(store.check_rule("sha256:abc"), TrustCheck::Blocked);
    }

    // --- approve_rule / block_rule ---

    #[test]
    fn approve_then_block_changes_status() {
        let mut store = TrustStore::default();
        store.approve_rule("sha256:abc".into(), "git".into(), "form".into());
        assert_eq!(store.check_rule("sha256:abc"), TrustCheck::Approved);

        store.block_rule("sha256:abc".into(), "git".into(), "form".into());
        assert_eq!(store.check_rule("sha256:abc"), TrustCheck::Blocked);
    }

    // --- previous_form ---

    #[test]
    fn previous_form_returns_stored_form() {
        let mut store = TrustStore::default();
        store.approve_rule("sha256:abc".into(), "git".into(), "my form".into());
        assert_eq!(store.previous_form("sha256:abc"), Some("my form"));
    }

    #[test]
    fn previous_form_returns_none_for_unknown() {
        let store = TrustStore::default();
        assert_eq!(store.previous_form("sha256:abc"), None);
    }

    // --- previous_rules (program-level backward compat) ---

    #[test]
    fn previous_rules_collects_program_forms() {
        let mut store = TrustStore::default();
        store.approve_rule("sha256:a".into(), "git".into(), "form1".into());
        store.approve_rule("sha256:b".into(), "git".into(), "form2".into());
        let prev = store.previous_rules("git").unwrap();
        assert_eq!(prev.len(), 2);
        assert!(prev.contains(&"form1".to_string()));
        assert!(prev.contains(&"form2".to_string()));
    }

    #[test]
    fn previous_rules_returns_none_for_unknown_program() {
        let store = TrustStore::default();
        assert_eq!(store.previous_rules("git"), None);
    }

    // --- cleanup_orphans ---

    #[test]
    fn cleanup_orphans_removes_stale_entries() {
        let mut store = TrustStore::default();
        store.approve_rule("sha256:keep".into(), "git".into(), "form1".into());
        store.approve_rule("sha256:stale".into(), "git".into(), "form2".into());

        let mut current = std::collections::BTreeSet::new();
        current.insert("sha256:keep".to_string());
        store.cleanup_orphans(&current);

        assert_eq!(store.check_rule("sha256:keep"), TrustCheck::Approved);
        assert_eq!(store.check_rule("sha256:stale"), TrustCheck::Pending);
    }

    // --- drop_entry ---

    #[test]
    fn drop_entry_removes_all_program_rules() {
        let mut store = TrustStore::default();
        store.approve_rule("sha256:a".into(), "git".into(), "form1".into());
        store.approve_rule("sha256:b".into(), "git".into(), "form2".into());
        store.approve_rule("sha256:c".into(), "cargo".into(), "form3".into());

        store.drop_entry("git");

        assert_eq!(store.check_rule("sha256:a"), TrustCheck::Pending);
        assert_eq!(store.check_rule("sha256:b"), TrustCheck::Pending);
        assert_eq!(store.check_rule("sha256:c"), TrustCheck::Approved);
    }

    // --- Round-trip persistence ---

    #[test]
    fn round_trip_v3_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");

        let mut store = TrustStore::default();
        let form1 = r#"(rule "git" (effect :allow))"#;
        let hash1 = hash_single_rule(form1);
        store.approve_rule(hash1.clone(), "git".into(), form1.into());

        let form2 = r#"(rule "git" (effect :deny))"#;
        let hash2 = hash_single_rule(form2);
        store.block_rule(hash2.clone(), "git".into(), form2.into());
        store.save(&path).unwrap();

        let loaded = TrustStore::load(&path).unwrap();
        assert!(loaded.suspects.is_empty());
        assert!(!loaded.was_corrupt);
        assert_eq!(loaded.store.check_rule(&hash1), TrustCheck::Approved);
        assert_eq!(loaded.store.check_rule(&hash2), TrustCheck::Blocked);
    }

    #[test]
    fn saved_file_has_version_3() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");

        let store = TrustStore::default();
        store.save(&path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(json["version"], 3);
        assert!(json["rules"].is_object());
    }

    // --- v2 → v3 migration ---

    #[test]
    fn v2_migrates_to_v3_with_approved_status() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");

        let v2_json = serde_json::json!({
            "version": 2,
            "programs": {
                "git": {
                    "hash": "sha256:doesntmatter",
                    "rules": [
                        r#"(rule "git" (effect :allow))"#,
                        r#"(rule "git" (effect :deny))"#
                    ]
                }
            }
        });
        std::fs::write(&path, serde_json::to_string(&v2_json).unwrap()).unwrap();

        let loaded = TrustStore::load(&path).unwrap();
        assert!(!loaded.was_corrupt);

        // Both rules should be individually accessible and approved.
        let hash1 = hash_single_rule(r#"(rule "git" (effect :allow))"#);
        let hash2 = hash_single_rule(r#"(rule "git" (effect :deny))"#);
        assert_eq!(loaded.store.check_rule(&hash1), TrustCheck::Approved);
        assert_eq!(loaded.store.check_rule(&hash2), TrustCheck::Approved);

        // Program name preserved.
        assert_eq!(
            loaded.store.previous_form(&hash1),
            Some(r#"(rule "git" (effect :allow))"#)
        );
    }

    #[test]
    fn v2_migration_preserves_multiple_programs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");

        let v2_json = serde_json::json!({
            "version": 2,
            "programs": {
                "git": {
                    "hash": "sha256:x",
                    "rules": [r#"(rule "git" (effect :allow))"#]
                },
                "cargo": {
                    "hash": "sha256:y",
                    "rules": [r#"(rule "cargo" (effect :allow))"#]
                }
            }
        });
        std::fs::write(&path, serde_json::to_string(&v2_json).unwrap()).unwrap();

        let loaded = TrustStore::load(&path).unwrap();
        let git_hash = hash_single_rule(r#"(rule "git" (effect :allow))"#);
        let cargo_hash = hash_single_rule(r#"(rule "cargo" (effect :allow))"#);
        assert_eq!(loaded.store.check_rule(&git_hash), TrustCheck::Approved);
        assert_eq!(loaded.store.check_rule(&cargo_hash), TrustCheck::Approved);

        // Check program names are correct.
        let git_entry = loaded.store.rules.get(&git_hash).unwrap();
        assert_eq!(git_entry.program, "git");
        let cargo_entry = loaded.store.rules.get(&cargo_hash).unwrap();
        assert_eq!(cargo_entry.program, "cargo");
    }

    // --- Integrity verification ---

    #[test]
    fn integrity_passes_for_valid_entries() {
        let mut store = TrustStore::default();
        let form = r#"(rule "git" (effect :allow))"#;
        let hash = hash_single_rule(form);
        store.approve_rule(hash, "git".into(), form.into());
        assert!(store.verify_integrity().is_empty());
    }

    #[test]
    fn integrity_detects_tampered_form() {
        let mut store = TrustStore::default();
        // Store with wrong hash key.
        store.rules.insert(
            "sha256:tampered".into(),
            RuleEntry {
                program: "git".into(),
                form: r#"(rule "git" (effect :allow))"#.into(),
                status: RuleStatus::Approved,
            },
        );
        let suspects = store.verify_integrity();
        assert_eq!(suspects.len(), 1);
        assert_eq!(suspects[0].program, "git");
    }

    // --- reapprove ---

    #[test]
    fn reapprove_fixes_suspect_entries() {
        let mut store = TrustStore::default();
        let form = r#"(rule "git" (effect :allow))"#;
        store.rules.insert(
            "sha256:wrong".into(),
            RuleEntry {
                program: "git".into(),
                form: form.into(),
                status: RuleStatus::Approved,
            },
        );
        assert_eq!(store.verify_integrity().len(), 1);

        store.reapprove("git");
        assert!(store.verify_integrity().is_empty());

        let correct_hash = hash_single_rule(form);
        assert_eq!(store.check_rule(&correct_hash), TrustCheck::Approved);
    }

    // --- Load edge cases ---

    #[test]
    fn load_nonexistent_returns_empty() {
        let result = TrustStore::load(Path::new("/nonexistent/trust.json")).unwrap();
        assert!(result.store.rules.is_empty());
        assert!(result.suspects.is_empty());
        assert!(!result.was_corrupt);
    }

    #[test]
    fn load_corrupt_file_returns_empty_with_corrupt_flag() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");
        std::fs::write(&path, "not valid json at all{{{").unwrap();

        let result = TrustStore::load(&path).unwrap();
        assert!(result.store.rules.is_empty());
        assert!(result.was_corrupt);
    }

    #[test]
    fn load_unrecognized_json_returns_empty_without_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");
        std::fs::write(&path, r#"{"something": "else"}"#).unwrap();

        let result = TrustStore::load(&path).unwrap();
        assert!(result.store.rules.is_empty());
        assert!(!result.was_corrupt);
    }

    // --- backward-compat approve() ---

    #[test]
    fn approve_stores_individual_rules() {
        let mut store = TrustStore::default();
        let rules = vec![
            r#"(rule "git" (effect :allow))"#.to_string(),
            r#"(rule "git" (effect :deny))"#.to_string(),
        ];
        store.approve("git".into(), "sha256:ignored".into(), rules);

        let hash1 = hash_single_rule(r#"(rule "git" (effect :allow))"#);
        let hash2 = hash_single_rule(r#"(rule "git" (effect :deny))"#);
        assert_eq!(store.check_rule(&hash1), TrustCheck::Approved);
        assert_eq!(store.check_rule(&hash2), TrustCheck::Approved);
    }
}
