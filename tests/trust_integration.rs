// Integration tests for the trust boundary.

mod common;

use assert_cmd::cargo::cargo_bin_cmd;
use common::{bash_payload, parse_json};
use std::io::Write;

/// Create a config with a load directive pointing to a rules file.
fn setup_loaded_config(
    root_rules: &str,
    loaded_rules: &str,
) -> (tempfile::TempDir, tempfile::NamedTempFile) {
    let dir = tempfile::tempdir().unwrap();

    // Write the loaded rules file
    let rules_path = dir.path().join("rules.lisp");
    std::fs::write(&rules_path, loaded_rules).unwrap();

    // Write the root config with a load directive
    let mut config = tempfile::NamedTempFile::new().unwrap();
    write!(config, "{root_rules}\n(load \"{}\")", rules_path.display()).unwrap();

    (dir, config)
}

#[test]
fn eval_blocked_on_first_load() {
    let (_dir, config) = setup_loaded_config(
        r#"(rule "ls" (allow))"#,
        r#"(rule "echo" (allow "loaded rule"))"#,
    );

    // Use a custom trust store path that doesn't exist (fresh)
    let trust_dir = tempfile::tempdir().unwrap();
    let trust_path = trust_dir.path().join("trust.json");

    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .write_stdin(bash_payload("echo hello"));

    let output = cmd.output().expect("run");
    assert!(
        output.status.success(),
        "hook should succeed (returns ask), stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let resp = parse_json(&output);
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"], "ask",
        "should block with ask for untrusted loaded content"
    );
    let reason = resp["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("");
    assert!(
        reason.contains("trust"),
        "reason should mention trust: {reason}"
    );
    // Trust store file should NOT exist yet (no TOFU)
    assert!(
        !trust_path.exists(),
        "trust store should not be created by checking"
    );
}

#[test]
fn eval_succeeds_after_approval() {
    let (_dir, config) = setup_loaded_config("", r#"(rule "echo" (allow "loaded rule"))"#);

    let trust_dir = tempfile::tempdir().unwrap();

    // First, approve trust via the trust subcommand
    let mut approve = cargo_bin_cmd!("may-i");
    approve
        .env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .args(["trust", "--all"]);

    let approve_output = approve.output().expect("run trust --all");
    assert!(
        approve_output.status.success(),
        "trust --all should succeed, stderr: {}",
        String::from_utf8_lossy(&approve_output.stderr)
    );

    // Now evaluate — should proceed normally
    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .write_stdin(bash_payload("echo hello"));

    let output = cmd.output().expect("run");
    assert!(
        output.status.success(),
        "hook should succeed after approval, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let resp = parse_json(&output);
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"], "allow",
        "should allow after trust approval"
    );
}

#[test]
fn eval_blocked_on_change() {
    let dir = tempfile::tempdir().unwrap();
    let rules_path = dir.path().join("rules.lisp");
    std::fs::write(&rules_path, r#"(rule "echo" (allow "v1"))"#).unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    write!(config, "(load \"{}\")", rules_path.display()).unwrap();

    let trust_dir = tempfile::tempdir().unwrap();

    // Approve initial version
    let mut approve = cargo_bin_cmd!("may-i");
    approve
        .env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .args(["trust", "--all"]);
    approve.output().expect("approve");

    // Modify the loaded file
    std::fs::write(&rules_path, r#"(rule "echo" (deny "v2 changed"))"#).unwrap();

    // Evaluate — should block because hash changed
    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .write_stdin(bash_payload("echo hello"));

    let output = cmd.output().expect("run");
    assert!(output.status.success());

    let resp = parse_json(&output);
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"], "ask",
        "should block with ask after loaded rules changed"
    );
}

#[test]
fn trust_list_shows_new_status() {
    let (_dir, config) = setup_loaded_config("", r#"(rule "echo" (allow "loaded rule"))"#);
    let trust_dir = tempfile::tempdir().unwrap();

    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .args(["trust", "--json"]);

    let output = cmd.output().expect("run trust --json");
    assert!(output.status.success());

    let resp: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse JSON");
    let arr = resp.as_array().expect("should be array");
    assert!(!arr.is_empty(), "should list at least one program");

    let echo_entry = arr.iter().find(|e| e["program"] == "echo");
    assert!(echo_entry.is_some(), "should list echo program");
    assert_eq!(echo_entry.unwrap()["status"], "pending");
}

#[test]
fn trust_approve_specific_program() {
    let (_dir, config) = setup_loaded_config("", r#"(rule "echo" (allow "loaded rule"))"#);
    let trust_dir = tempfile::tempdir().unwrap();

    // Approve just "echo"
    let mut approve = cargo_bin_cmd!("may-i");
    approve
        .env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .args(["trust", "echo"]);
    let output = approve.output().expect("run trust echo");
    assert!(
        output.status.success(),
        "trust echo should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify it's now trusted
    let mut list = cargo_bin_cmd!("may-i");
    list.env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .args(["trust", "--json"]);
    let output = list.output().expect("run trust --json");
    let resp: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse JSON");
    let echo_entry = resp
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["program"] == "echo")
        .unwrap();
    assert_eq!(echo_entry["status"], "approved");
}

#[test]
fn trust_all_approves_all_programs() {
    let (_dir, config) = setup_loaded_config(
        "",
        r#"(rule "echo" (allow "loaded"))
(rule "cat" (allow "loaded"))"#,
    );
    let trust_dir = tempfile::tempdir().unwrap();

    let mut approve = cargo_bin_cmd!("may-i");
    approve
        .env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .args(["trust", "--all", "--json"]);
    let output = approve.output().expect("run trust --all");
    assert!(output.status.success());

    let resp: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse JSON");
    let approved = resp["approved"].as_array().expect("approved array");
    assert!(approved.len() >= 2, "should approve at least echo and cat");

    // Verify all trusted
    let mut list = cargo_bin_cmd!("may-i");
    list.env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .args(["trust", "--json"]);
    let output = list.output().expect("run trust --json");
    let resp: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse JSON");
    for entry in resp.as_array().unwrap() {
        assert_eq!(entry["status"], "approved", "all rules should be approved");
    }
}

#[test]
fn trust_nonexistent_program_fails() {
    let (_dir, config) = setup_loaded_config("", r#"(rule "echo" (allow "loaded"))"#);
    let trust_dir = tempfile::tempdir().unwrap();

    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .args(["trust", "nonexistent"]);
    let output = cmd.output().expect("run trust nonexistent");
    assert!(!output.status.success(), "should fail for unknown program");
}

#[test]
fn primary_only_config_bypasses_trust() {
    let config = common::write_config(r#"(rule "echo" (allow "safe"))"#);
    let trust_dir = tempfile::tempdir().unwrap();

    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .write_stdin(bash_payload("echo hello"));

    let output = cmd.output().expect("run");
    assert!(output.status.success());

    let resp = parse_json(&output);
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"], "allow",
        "primary-only config should bypass trust entirely"
    );
}

#[test]
fn eval_untrusted_shows_warning_and_trace() {
    let (_dir, config) = setup_loaded_config(
        r#"(rule "ls" (allow))"#,
        r#"(rule "echo" (allow "loaded rule"))"#,
    );

    let trust_dir = tempfile::tempdir().unwrap();

    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .args(["eval", "echo hello"]);

    let output = cmd.output().expect("run");
    assert!(output.status.success(), "eval should succeed");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Untrusted rules"),
        "stderr should contain advisory box: {stderr}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Trace") || stdout.contains("Result"),
        "stdout should contain trace/result output: {stdout}"
    );
}

#[test]
fn check_untrusted_shows_warning_then_results() {
    let (_dir, config) = setup_loaded_config(
        r#"(check :allow "echo hello")
(rule "echo" (allow))"#,
        r#"(rule "echo" (allow "loaded rule"))"#,
    );

    let trust_dir = tempfile::tempdir().unwrap();

    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .args(["check"]);

    let output = cmd.output().expect("run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Untrusted rules"),
        "stderr should contain trust advisory: {stderr}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Summary"),
        "stdout should contain check results: {stdout}"
    );
}

#[test]
fn check_json_unaffected_by_trust() {
    let (_dir, config) = setup_loaded_config(
        r#"(check :allow "echo hello")
(rule "echo" (allow))"#,
        r#"(rule "echo" (allow "loaded rule"))"#,
    );

    let trust_dir = tempfile::tempdir().unwrap();

    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .args(["check", "--json"]);

    let output = cmd.output().expect("run");
    assert!(output.status.success());

    let resp: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse JSON");
    assert!(
        resp["results"].is_array(),
        "JSON output should have results"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Untrusted"),
        "JSON mode should not show advisory: {stderr}"
    );
}

#[test]
fn eval_json_untrusted_still_blocks() {
    let (_dir, config) = setup_loaded_config(
        r#"(rule "ls" (allow))"#,
        r#"(rule "echo" (allow "loaded rule"))"#,
    );

    let trust_dir = tempfile::tempdir().unwrap();

    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.env("MAYI_CONFIG", config.path())
        .env("XDG_DATA_HOME", trust_dir.path())
        .args(["eval", "--json", "echo hello"]);

    let output = cmd.output().expect("run");
    assert!(output.status.success());

    let resp: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse JSON");
    assert_eq!(resp["decision"], "ask", "JSON mode should still block");
    assert!(
        resp["reason"].as_str().unwrap_or("").contains("trust"),
        "reason should mention trust"
    );
}
