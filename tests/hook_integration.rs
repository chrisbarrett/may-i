// Integration tests for the Claude Code hook entry point.

mod common;

use assert_cmd::cargo::cargo_bin_cmd;
use common::{bash_payload, may_i, write_config};
use predicates::prelude::*;

#[test]
fn hook_resolves_defined_predicates() {
    let cfg = write_config(
        r#"
(define is-cc (fact? :client/claude-code))
(rule "rm"
      (when is-cc (effect :deny "CC denied")))
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

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

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
      (effect :allow "matched quoted arg"))
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

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"], "allow",
        "quoted argument should be preserved as a single token"
    );
}

#[test]
fn hook_json_flag_produces_valid_json() {
    let cfg = write_config(
        r#"
(rule "echo" (effect :allow "echo is safe"))
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

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

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
