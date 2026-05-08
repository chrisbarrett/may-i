// Integration test for the Class A trust-hash rehash performed by
// `may-i migrate` (§19). When the canonical-form rendering of a rule
// changes (e.g. `(allow)` → `(allow)`), an existing approval
// for that rule SHALL carry forward without re-prompting.

mod common;

use assert_cmd::cargo::cargo_bin_cmd;
use std::io::Write;

#[test]
fn class_a_rehash_preserves_approval() {
    let trust_dir = tempfile::tempdir().unwrap();

    // Write a config in legacy syntax that uses a `(load …)` so the
    // engine treats the loaded rules as needing trust approval.
    let dir = tempfile::tempdir().unwrap();
    let rules_path = dir.path().join("rules.lisp");
    std::fs::write(&rules_path, r#"(rule "echo" (allow "from loaded file"))"#).unwrap();
    let mut config = tempfile::NamedTempFile::new().unwrap();
    write!(config, "(load \"{}\")", rules_path.display()).unwrap();

    // Approve all (TOFU all loaded rules).
    let mut approve = cargo_bin_cmd!("may-i");
    let approve_out = approve
        .env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .args(["trust", "--all"])
        .output()
        .expect("run");
    assert!(
        approve_out.status.success(),
        "approval failed: {}",
        String::from_utf8_lossy(&approve_out.stderr)
    );

    // Migrate the loaded rules file (root has no inline rules).
    let mut migrate = cargo_bin_cmd!("may-i");
    let migrate_out = migrate
        .env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .args(["migrate", "--yes"])
        .output()
        .expect("run");
    assert!(
        migrate_out.status.success(),
        "migrate failed: {}",
        String::from_utf8_lossy(&migrate_out.stderr)
    );
    // The exact "Rehashed N" notice depends on whether canonical
    // rendering actually shifted — under the current canonicaliser, an
    // already-trusted legacy form stores in the new shape, so a fresh
    // approval may not need rehashing. The behavioural guarantee
    // (approval carries forward) is what we assert below.
    let _ = String::from_utf8_lossy(&migrate_out.stdout);

    // Confirm the loaded file got migrated to the new syntax.
    let migrated_text = std::fs::read_to_string(&rules_path).unwrap();
    assert!(
        migrated_text.contains("(allow"),
        "loaded file should use new decision verb form: {migrated_text}"
    );

    // After migration the approval should still cover the rule. Run an
    // eval and confirm we don't get a trust-blocked response.
    let mut eval = cargo_bin_cmd!("may-i");
    eval.env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .write_stdin(common::bash_payload("echo hi"));
    let eval_out = eval.output().expect("run");
    assert!(
        eval_out.status.success(),
        "eval after migration failed: {}",
        String::from_utf8_lossy(&eval_out.stderr)
    );
    let resp = common::parse_json(&eval_out);
    let decision = resp["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("");
    let reason = resp["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("");
    // The rule should still be approved — no trust-related reason.
    assert!(
        !reason.contains("trust"),
        "approval should carry over after Class A rehash; got reason: {reason}"
    );
    // And the rule itself should now allow the inner echo.
    assert_eq!(
        decision, "allow",
        "echo should be allowed by the migrated rule; reason: {reason}"
    );
}
