// Integration tests for the hook entry point. Covers both the default
// Claude Code profile and the Codex profile (selected by the presence
// of `turn_id` in the stdin payload).

mod common;

use common::{bash_payload, codex_bash_payload, may_i, may_i_cmd, parse_json, write_config};
use predicates::prelude::*;

#[test]
fn config_flag_nonexistent_path_produces_descriptive_error() {
    let mut cmd = may_i_cmd();
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
    let mut cmd = may_i_cmd();
    cmd.args(["--config", "/nonexistent/path/config.lisp"])
        .write_stdin(bash_payload("echo hello"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn codex_ask_omits_permission_decision_and_uses_additional_context() {
    let cfg = write_config(
        r#"
(rule "curl" (ask "needs review"))
"#,
    );
    let output = may_i(&cfg)
        .write_stdin(codex_bash_payload("curl example.com"))
        .output()
        .expect("run");

    assert!(
        output.status.success(),
        "exit 0 expected, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let resp = parse_json(&output);
    let hook = &resp["hookSpecificOutput"];
    assert_eq!(hook["hookEventName"], "PreToolUse");
    assert_eq!(hook["additionalContext"], "needs review");
    assert!(hook.get("permissionDecision").is_none());
    assert!(hook.get("permissionDecisionReason").is_none());
}

#[test]
fn claude_code_ask_unchanged_without_turn_id() {
    let cfg = write_config(
        r#"
(rule "curl" (ask "needs review"))
"#,
    );
    let output = may_i(&cfg)
        .write_stdin(bash_payload("curl example.com"))
        .output()
        .expect("run");

    assert!(output.status.success());

    let resp = parse_json(&output);
    let hook = &resp["hookSpecificOutput"];
    assert_eq!(hook["permissionDecision"], "ask");
    assert_eq!(hook["permissionDecisionReason"], "needs review");
    assert!(hook.get("additionalContext").is_none());
}

#[test]
fn codex_allow_and_deny_match_claude_code_shape() {
    let cfg = write_config(
        r#"
(rule "echo" (allow "safe"))
(rule "rm" (deny "dangerous"))
"#,
    );

    for (cmd, expected) in [("echo hi", "allow"), ("rm foo", "deny")] {
        let codex = may_i(&cfg)
            .write_stdin(codex_bash_payload(cmd))
            .output()
            .expect("codex run");
        let claude = may_i(&cfg)
            .write_stdin(bash_payload(cmd))
            .output()
            .expect("claude run");

        assert!(
            codex.status.success(),
            "codex {cmd}: {}",
            String::from_utf8_lossy(&codex.stderr)
        );
        assert!(
            claude.status.success(),
            "claude {cmd}: {}",
            String::from_utf8_lossy(&claude.stderr)
        );

        let codex_resp = parse_json(&codex);
        let claude_resp = parse_json(&claude);

        assert_eq!(
            codex_resp, claude_resp,
            "{cmd} response shapes must match bit-for-bit"
        );
        assert_eq!(
            codex_resp["hookSpecificOutput"]["permissionDecision"],
            expected
        );
    }
}

#[test]
fn codex_client_fact_is_visible_to_rules() {
    let cfg = write_config(
        r#"
(rule "rm"
      (when (fact? :client/codex) (deny "Codex denied")))
"#,
    );
    let output = may_i(&cfg)
        .write_stdin(codex_bash_payload("rm foo"))
        .output()
        .expect("run");

    assert!(output.status.success());
    let resp = parse_json(&output);
    assert_eq!(resp["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecisionReason"],
        "Codex denied"
    );
}

#[test]
fn hook_nonexistent_mayi_config_env_exits_two() {
    let mut cmd = may_i_cmd();
    cmd.env("MAYI_CONFIG", "/tmp/bogus.lisp")
        .write_stdin(bash_payload("echo hello"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("MAYI_CONFIG"))
        .stderr(predicate::str::contains("nonexistent"));
}

// ── harden-env-write-scope: hook captures the entry environment ─────

#[test]
fn hook_captures_exported_name_so_bare_reassignment_reaches() {
    // `GIT_DIR` is exported into the hook process. The entry environment is
    // captured before git-env scrubbing, so a bare reassignment of `GIT_DIR`
    // is a reaching write and floors.
    let cfg = write_config(r#"(rule "ls" (allow))"#);
    let output = may_i(&cfg)
        .env("GIT_DIR", "/tmp/somegit")
        .write_stdin(bash_payload("GIT_DIR=/evil; ls"))
        .output()
        .expect("run");
    let resp = parse_json(&output);
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"], "ask",
        "exported GIT_DIR must be in the entry environment: {resp}"
    );
}

#[test]
fn hook_unexported_name_stays_shell_local() {
    // A name not in the process environment is shell-local when bare-assigned.
    let cfg = write_config(r#"(rule "ls" (allow))"#);
    let output = may_i(&cfg)
        .env_remove("DEFINITELY_UNSET_NAME_XYZ")
        .write_stdin(bash_payload("DEFINITELY_UNSET_NAME_XYZ=/evil; ls"))
        .output()
        .expect("run");
    let resp = parse_json(&output);
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"], "allow",
        "unexported name must be shell-local: {resp}"
    );
}
