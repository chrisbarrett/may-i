// Integration tests for the Claude Code hook entry point.

mod common;

use assert_cmd::cargo::cargo_bin_cmd;
use common::{bash_payload, may_i, parse_json, write_config};
use predicates::prelude::*;

#[test]
fn config_flag_nonexistent_path_produces_descriptive_error() {
    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.args(["--config", "/tmp/nonexistent-mayi-config-12345.lisp"]);
    cmd.write_stdin(bash_payload("echo hello"));

    let output = cmd.output().expect("run");

    // Should fail with exit code 2 (blocking error)
    assert_eq!(output.status.code(), Some(2), "expected exit code 2");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("No such file"),
        "stderr should mention the missing file: {stderr}"
    );
}

#[test]
fn hook_resolves_defined_predicates() {
    let cfg = write_config(
        r#"
(define is-cc (fact? :client/claude-code))
(rule "rm"
      (when is-cc (deny "CC denied")))
"#,
    );
    let output = may_i(&cfg)
        .write_stdin(bash_payload("rm foo"))
        .output()
        .expect("run");

    assert!(
        output.status.success(),
        "exit 0 expected, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let resp = parse_json(&output);

    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"], "deny",
        "defined predicate is-cc should resolve and match :client/claude-code"
    );
}

#[test]
fn hook_preserves_quoted_arguments() {
    let cfg = write_config(
        r#"
(rule "echo"
      (args (positional "hello world"))
      (allow "matched quoted arg"))
"#,
    );
    let output = may_i(&cfg)
        .write_stdin(bash_payload(r#"echo "hello world""#))
        .output()
        .expect("run");

    assert!(
        output.status.success(),
        "exit 0 expected, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let resp = parse_json(&output);

    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"], "allow",
        "quoted argument should be preserved as a single token"
    );
}

#[test]
fn hook_json_flag_produces_valid_json() {
    let cfg = write_config(
        r#"
(rule "echo" (allow "echo is safe"))
"#,
    );
    let output = may_i(&cfg)
        .arg("--json")
        .write_stdin(bash_payload("echo hello"))
        .output()
        .expect("run");

    assert!(
        output.status.success(),
        "exit 0 expected, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let resp = parse_json(&output);

    assert_eq!(resp["hookSpecificOutput"]["permissionDecision"], "allow");
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecisionReason"],
        "echo is safe"
    );
}

#[test]
fn hook_nonexistent_config_via_flag_exits_two() {
    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.args(["--config", "/nonexistent/path/config.lisp"])
        .write_stdin(bash_payload("echo hello"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn hook_nonexistent_mayi_config_env_exits_two() {
    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.env("MAYI_CONFIG", "/tmp/bogus.lisp")
        .write_stdin(bash_payload("echo hello"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("MAYI_CONFIG"))
        .stderr(predicate::str::contains("nonexistent"));
}
