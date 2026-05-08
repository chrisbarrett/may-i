// Integration tests for the unified evaluation pipeline.

mod common;

use assert_cmd::cargo::cargo_bin_cmd;
use common::{bash_payload, may_i, parse_json, write_config};

// 5.1: echo hello && rm -rf / with echo allowed → :ask (verifies hook path fix)
#[test]
fn hook_compound_command_evaluates_all_parts() {
    let cfg = write_config(
        r#"
(rule "echo" (allow))
"#,
    );
    let output = may_i(&cfg)
        .write_stdin(bash_payload("echo hello && rm -rf /"))
        .output()
        .expect("run");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let resp = parse_json(&output);
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"], "ask",
        "compound command with unmatched `rm` should produce :ask"
    );
}

// 5.2: echo $(rm -rf /) with echo allowed + rm denied → :deny
#[test]
fn hook_embedded_substitution_denied() {
    let cfg = write_config(
        r#"
(rule "echo" (allow))
(rule "rm" (deny "rm denied"))
"#,
    );
    let output = may_i(&cfg)
        .write_stdin(bash_payload("echo $(rm -rf /)"))
        .output()
        .expect("run");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let resp = parse_json(&output);
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"], "deny",
        "embedded $(rm -rf /) should produce :deny"
    );
}

// 5.3: $EDITOR file.txt → :ask with dynamic reason
#[test]
fn hook_dynamic_command_name_asks() {
    let cfg = write_config(
        r#"
(rule "echo" (allow))
"#,
    );
    let output = may_i(&cfg)
        .write_stdin(bash_payload("$EDITOR file.txt"))
        .output()
        .expect("run");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let resp = parse_json(&output);
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"], "ask",
        "$EDITOR should produce :ask (dynamic command name)"
    );
    let reason = resp["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("");
    assert!(
        reason.contains("dynamic"),
        "reason should mention dynamic: {reason}"
    );
}

// 5.4: if true; then rm -rf /; fi with rm denied → :deny
#[test]
fn hook_if_then_rm_denied() {
    let cfg = write_config(
        r#"
(rule "true" (allow))
(rule "rm" (deny "rm denied"))
"#,
    );
    let output = may_i(&cfg)
        .write_stdin(bash_payload("if true; then rm -rf /; fi"))
        .output()
        .expect("run");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let resp = parse_json(&output);
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"], "deny",
        "if-then with denied rm should produce :deny"
    );
}

// 5.5: empty string → :ask
#[test]
fn hook_empty_command_asks() {
    let cfg = write_config(
        r#"
(rule "echo" (allow))
"#,
    );
    let output = may_i(&cfg)
        .write_stdin(bash_payload(""))
        .output()
        .expect("run");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let resp = parse_json(&output);
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"], "ask",
        "empty command should produce :ask"
    );
}

// 5.6: JSON and non-JSON paths return same decision for compound commands
#[test]
fn json_and_pretty_agree_on_compound_commands() {
    let cfg = write_config(
        r#"
(rule "echo" (allow))
(rule "rm" (deny "rm denied"))
"#,
    );

    // JSON mode
    let json_output = {
        let mut cmd = cargo_bin_cmd!("may-i");
        cmd.env("MAYI_CONFIG", cfg.path());
        cmd.args(["eval", "--json", "echo hello && rm -rf /"]);
        cmd.output().expect("run json")
    };
    assert!(
        json_output.status.success(),
        "json stderr: {}",
        String::from_utf8_lossy(&json_output.stderr)
    );
    let json_resp: serde_json::Value =
        serde_json::from_slice(&json_output.stdout).expect("parse json");
    let json_decision = json_resp["decision"].as_str().unwrap();

    // Hook mode (same compound command)
    let hook_output = may_i(&cfg)
        .write_stdin(bash_payload("echo hello && rm -rf /"))
        .output()
        .expect("run hook");
    assert!(
        hook_output.status.success(),
        "hook stderr: {}",
        String::from_utf8_lossy(&hook_output.stderr)
    );
    let hook_resp = parse_json(&hook_output);
    let hook_decision = hook_resp["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap();

    assert_eq!(
        json_decision, hook_decision,
        "JSON eval ({json_decision}) and hook ({hook_decision}) should agree"
    );
    assert_eq!(json_decision, "deny");
}

// 5.7: deeply nested substitution respects recursion depth limit
#[test]
fn deeply_nested_substitution_depth_limit() {
    let cfg = write_config(
        r#"
(rule "echo" (allow))
(rule "rm" (allow))
"#,
    );

    // Build deeply nested: $(echo $(echo $(echo ...$(rm /)...)))
    let mut command = "rm /".to_string();
    for _ in 0..15 {
        command = format!("echo $({command})");
    }

    let output = may_i(&cfg)
        .write_stdin(bash_payload(&command))
        .output()
        .expect("run");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let resp = parse_json(&output);
    let decision = resp["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap();
    // Should hit depth limit and return :ask
    assert_eq!(
        decision, "ask",
        "deeply nested substitution should hit depth limit and return :ask"
    );
}
