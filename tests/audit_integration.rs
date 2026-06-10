// Integration tests for the Audit log: which invocation modes write, the
// threshold gate, the parse-failure floor, and the record's shape end-to-end.

mod common;

use common::{bash_payload, may_i, may_i_cmd, write_config};
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

fn write_file(dir: &std::path::Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, content).unwrap();
    path
}

/// A temp directory plus the audit file path inside it.
fn audit_target() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    (dir, path)
}

fn read_records(path: &PathBuf) -> Vec<serde_json::Value> {
    match std::fs::read_to_string(path) {
        Ok(s) => s
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("record is valid JSON"))
            .collect(),
        Err(_) => vec![],
    }
}

#[test]
fn eval_deny_writes_one_rule_record() {
    let cfg = write_config(r#"(rule "rm" (deny "danger"))"#);
    let (_dir, path) = audit_target();

    may_i(&cfg)
        .args([
            "--audit-threshold",
            "deny",
            "--audit-file",
            path.to_str().unwrap(),
            "eval",
            "rm -rf /",
        ])
        .assert()
        .success();

    let recs = read_records(&path);
    assert_eq!(recs.len(), 1, "exactly one record");
    let r = &recs[0];
    assert_eq!(r["mode"], "eval");
    assert_eq!(r["decision"], "deny");
    assert_eq!(r["source"], "rule");
    assert!(r["harness"].is_null(), "eval has no harness");
    assert!(
        r["rules"].as_array().is_some_and(|a| !a.is_empty()),
        "deciding rule hash present: {r}"
    );
}

#[test]
fn hook_deny_writes_record_with_harness_and_cwd() {
    let cfg = write_config(r#"(rule "rm" (deny "danger"))"#);
    let (_dir, path) = audit_target();

    // Hook deny is signalled in the JSON envelope; the process still exits 0.
    may_i(&cfg)
        .env("MAYI_AUDIT_THRESHOLD", "deny")
        .env("MAYI_AUDIT_FILE", path.to_str().unwrap())
        .write_stdin(bash_payload("rm -rf /"))
        .assert()
        .success();

    let recs = read_records(&path);
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    assert_eq!(r["mode"], "hook");
    assert_eq!(r["decision"], "deny");
    assert_eq!(r["harness"], "claude-code");
    assert_eq!(r["cwd"], "/tmp", "cwd from payload");
}

#[test]
fn check_writes_nothing_at_any_threshold() {
    let cfg = write_config(
        r#"
        (rule "rm" (deny "danger"))
        (check (deny "rm -rf /"))
        "#,
    );
    let (_dir, path) = audit_target();

    may_i(&cfg)
        .args([
            "--audit-threshold",
            "all",
            "--audit-file",
            path.to_str().unwrap(),
            "check",
        ])
        .assert()
        .success();

    assert!(read_records(&path).is_empty(), "check must not write");
}

#[test]
fn allow_is_not_recorded_at_deny_threshold() {
    let cfg = write_config(r#"(rule "ls" (allow))"#);
    let (_dir, path) = audit_target();

    may_i(&cfg)
        .args([
            "--audit-threshold",
            "deny",
            "--audit-file",
            path.to_str().unwrap(),
            "eval",
            "ls",
        ])
        .assert()
        .success();

    assert!(read_records(&path).is_empty(), "allow below deny threshold");
}

#[test]
fn parse_failure_is_always_recorded_even_below_threshold() {
    let cfg = write_config(r#"(rule "echo" (allow))"#);
    let (_dir, path) = audit_target();

    // Unterminated quote → error-severity parse diagnostic → decision floors
    // to ask. At threshold `deny`, ask is below the bar, but a parse failure
    // is always recorded.
    may_i(&cfg)
        .args([
            "--audit-threshold",
            "deny",
            "--audit-file",
            path.to_str().unwrap(),
            "eval",
            "echo \"unterminated",
        ])
        .assert()
        .success();

    let recs = read_records(&path);
    assert_eq!(recs.len(), 1, "parse failure recorded: {recs:?}");
    let r = &recs[0];
    assert_eq!(r["source"], "parse-floor");
    assert_eq!(r["parse_ok"], false);
    assert!(!r["diagnostic"].is_null(), "diagnostic present");
}

#[test]
fn audit_form_in_loaded_file_is_rejected_end_to_end() {
    // Primary config pulls in a file via `(load …)` that tries to configure
    // the Audit log — a hard load error; no command is evaluated.
    let dir = TempDir::new().unwrap();
    write_file(
        dir.path(),
        "extra.lisp",
        r#"(audit (threshold :off))
(rule "echo" (allow))"#,
    );
    let root = write_file(dir.path(), "config.lisp", r#"(load "extra.lisp")"#);

    let mut cmd = may_i_cmd();
    cmd.env("MAYI_CONFIG", &root);
    cmd.args(["eval", "echo hi"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("only in the primary config"));
}

#[test]
fn configured_dev_null_overrides_default_location() {
    let cfg = write_config(r#"(rule "rm" (deny "danger"))"#);
    // Point the default location at an empty temp dir so we can prove it is
    // never created when an explicit file is configured.
    let xdg = TempDir::new().unwrap();

    may_i(&cfg)
        .env("XDG_STATE_HOME", xdg.path())
        .args([
            "--audit-threshold",
            "deny",
            "--audit-file",
            "/dev/null",
            "eval",
            "rm -rf /",
        ])
        .assert()
        .success();

    // The default `$XDG_STATE_HOME/may-i/audit.jsonl` must not exist.
    assert!(
        !xdg.path().join("may-i").exists(),
        "default location must not be created when a file is configured"
    );
}

#[test]
fn record_rules_match_the_aggregate_decision_across_units() {
    // `rm $(echo safe)` is two units: the outer `rm` denies, the embedded
    // `echo` allows. The record's decision is `deny`, and its `rules` must be
    // the rm rule only — the allowing echo rule must not leak in.
    let cfg = write_config(
        r#"
        (rule "rm" (deny "danger"))
        (rule "echo" (allow))
        "#,
    );
    let (_dir, path) = audit_target();

    may_i(&cfg)
        .args([
            "--audit-threshold",
            "deny",
            "--audit-file",
            path.to_str().unwrap(),
            "eval",
            "rm $(echo safe)",
        ])
        .assert()
        .success();

    let recs = read_records(&path);
    assert_eq!(recs.len(), 1, "{recs:?}");
    let r = &recs[0];
    assert_eq!(r["decision"], "deny");
    let rules = r["rules"].as_array().expect("rules array");
    assert_eq!(rules.len(), 1, "exactly the deciding rule: {r}");
}

#[test]
fn off_threshold_writes_nothing() {
    let cfg = write_config(r#"(rule "rm" (deny "danger"))"#);
    let (_dir, path) = audit_target();

    // No audit flags/env at all → threshold off.
    may_i(&cfg)
        .args(["--audit-file", path.to_str().unwrap(), "eval", "rm -rf /"])
        .assert()
        .success();

    assert!(read_records(&path).is_empty(), "off records nothing");
}
