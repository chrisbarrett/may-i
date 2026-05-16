// Re-canonicalise approved trust-store entries after a config migration.
//
// `cmd_migrate` calls `rehash_after_migration` after rewriting on-disk configs
// so existing approvals carry forward to whatever canonical form the current
// engine emits. The trust-gate spec requires this work to live in the trust
// module: `cmd_trust` is the only cmd-layer caller allowed to touch
// `TrustStore::load` directly.

use std::path::Path;

use super::store::{RuleEntry, TrustStore, default_trust_store_path};

/// Reload the trust store, recompute the canonical form of every entry, and
/// write the store back when any hashes changed. Returns the number of
/// entries rewritten.
pub fn rehash_after_migration() -> miette::Result<usize> {
    let Some(store_path) = default_trust_store_path() else {
        return Ok(0);
    };
    if !store_path.exists() {
        return Ok(0);
    }
    rehash_at(&store_path)
}

/// Path-injecting variant used by `rehash_after_migration` and unit tests.
pub(crate) fn rehash_at(store_path: &Path) -> miette::Result<usize> {
    let load = TrustStore::load(store_path)
        .map_err(|e| miette::miette!("Failed to load trust store: {e}"))?;
    let mut store = load.store;
    let mut rehashed = 0usize;
    let entries: Vec<(String, RuleEntry)> = store
        .iter_rules()
        .map(|(h, e)| (h.to_string(), e.clone()))
        .collect();
    for (old_hash, entry) in entries {
        let Some(new_form) = recanonicalise_rule_form(&entry.form) else {
            continue;
        };
        if new_form == entry.form {
            continue;
        }
        let new_hash = may_i_engine::trust::hash_rule(&new_form);
        if new_hash == old_hash {
            continue;
        }
        store.replace_rule(&old_hash, new_hash, new_form);
        rehashed += 1;
    }
    if rehashed > 0 {
        store
            .save(store_path)
            .map_err(|e| miette::miette!("Failed to save trust store: {e}"))?;
    }
    Ok(rehashed)
}

/// Re-parse a stored canonical rule form and re-emit it with the current
/// canonicaliser. Returns `None` if the form fails to parse — caller leaves
/// such entries untouched.
fn recanonicalise_rule_form(form: &str) -> Option<String> {
    let (forms, errs) = may_i_sexpr::parse(form);
    if !errs.is_empty() {
        return None;
    }
    let sexpr = forms.into_iter().next()?;
    let rule = may_i_config::parse_rule(&sexpr).ok()?;
    Some(may_i_engine::trust::canonical_rule(&rule.value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::store::{RuleStatus, TrustCheck};

    fn write_store(path: &Path, store: &TrustStore) {
        store.save(path).expect("save store");
    }

    #[test]
    fn rehash_preserves_approval_status_when_canonical_form_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("trust.json");

        // Use an already-canonical form: parsing + re-emitting yields the
        // same string, so rehash should leave the entry untouched.
        let form = may_i_engine::trust::canonical_rule(&{
            let (forms, _) = may_i_sexpr::parse(r#"(rule "git" (allow))"#);
            let sexpr = forms.into_iter().next().unwrap();
            may_i_config::parse_rule(&sexpr).unwrap().value
        });
        let hash = may_i_engine::trust::hash_rule(&form);

        let mut store = TrustStore::default();
        store.approve_rule(hash.clone(), "git".into(), form.clone());
        write_store(&store_path, &store);

        let rehashed = rehash_at(&store_path).expect("rehash");
        assert_eq!(rehashed, 0, "canonical form unchanged — no rehash expected");

        let reloaded = TrustStore::load(&store_path).expect("reload").store;
        assert_eq!(reloaded.check_rule(&hash), TrustCheck::Approved);
    }

    #[test]
    fn rehash_updates_entries_whose_canonical_form_changed() {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("trust.json");

        // Stored form has extra whitespace; canonicaliser will emit a
        // tighter form, so the hash key must change.
        let stored_form = r#"(rule  "git"  (allow))"#.to_string();
        let stale_hash = "sha256:stale-from-an-old-canonicaliser".to_string();

        let mut store = TrustStore::default();
        // Bypass `approve_rule` integrity by inserting via the public API;
        // load tolerates a mismatched key (it records the entry as a
        // suspect). For this scenario we want the entry preserved across
        // load, so use approve_rule with the stale hash directly.
        store.approve_rule(stale_hash.clone(), "git".into(), stored_form.clone());
        write_store(&store_path, &store);

        let recanonical = {
            let (forms, _) = may_i_sexpr::parse(&stored_form);
            let sexpr = forms.into_iter().next().unwrap();
            may_i_engine::trust::canonical_rule(&may_i_config::parse_rule(&sexpr).unwrap().value)
        };
        assert_ne!(
            recanonical, stored_form,
            "test premise: canonicaliser should rewrite this form"
        );
        let expected_new_hash = may_i_engine::trust::hash_rule(&recanonical);

        let rehashed = rehash_at(&store_path).expect("rehash");
        assert_eq!(rehashed, 1);

        let reloaded = TrustStore::load(&store_path).expect("reload").store;
        assert_eq!(
            reloaded.check_rule(&expected_new_hash),
            TrustCheck::Approved
        );
        assert_eq!(reloaded.check_rule(&stale_hash), TrustCheck::Pending);

        // Approval carried over with the same status.
        let entry = reloaded
            .iter_rules()
            .find(|(h, _)| *h == expected_new_hash)
            .map(|(_, e)| e)
            .expect("rewritten entry present");
        assert_eq!(entry.status, RuleStatus::Approved);
        assert_eq!(entry.form, recanonical);
    }

    #[test]
    fn rehash_skips_when_store_path_does_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.json");
        let rehashed = rehash_at(&missing).expect("rehash");
        assert_eq!(rehashed, 0);
    }

    #[test]
    fn rehash_after_migration_uses_xdg_data_home() {
        let dir = tempfile::tempdir().unwrap();
        let xdg = dir.path();
        let store_path = xdg.join("may-i").join("trust.json");

        // Pre-populate a store that needs rehashing so we can confirm the
        // wrapper resolved the path and ran the rehash.
        let stored_form = r#"(rule  "git"  (allow))"#.to_string();
        let stale_hash = "sha256:stale".to_string();
        let mut store = TrustStore::default();
        store.approve_rule(stale_hash, "git".into(), stored_form);
        std::fs::create_dir_all(store_path.parent().unwrap()).unwrap();
        store.save(&store_path).unwrap();

        let count = temp_env::with_var("XDG_DATA_HOME", Some(xdg.as_os_str()), || {
            rehash_after_migration().expect("rehash")
        });
        assert_eq!(count, 1);
    }

    #[test]
    fn rehash_after_migration_noop_when_store_missing() {
        let dir = tempfile::tempdir().unwrap();
        let count = temp_env::with_var("XDG_DATA_HOME", Some(dir.path().as_os_str()), || {
            rehash_after_migration().expect("rehash")
        });
        assert_eq!(count, 0);
    }

    #[test]
    fn rehash_leaves_unparseable_entries_alone() {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("trust.json");

        let garbage_form = "(((not a rule)))".to_string();
        let hash = may_i_engine::trust::hash_rule(&garbage_form);
        let mut store = TrustStore::default();
        store.approve_rule(hash.clone(), "?".into(), garbage_form);
        write_store(&store_path, &store);

        let rehashed = rehash_at(&store_path).expect("rehash");
        assert_eq!(rehashed, 0);
        let reloaded = TrustStore::load(&store_path).expect("reload").store;
        assert_eq!(reloaded.check_rule(&hash), TrustCheck::Approved);
    }
}
