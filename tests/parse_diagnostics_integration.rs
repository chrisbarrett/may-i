// Integration tests for parse diagnostics.

mod common;

use common::{bash_payload, may_i, parse_json, write_config};

// 6.5: echo "unterminated shows miette-formatted diagnostic on stderr
#[test]
fn unterminated_quote_shows_miette_on_stderr() {
    let cfg = write_config(r#"(rule "echo" (effect :allow))"#);
    let output = may_i(&cfg)
        .args(["eval", r#"echo "unterminated"#])
        .output()
        .expect("run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unterminated double quote"),
        "stderr should contain miette diagnostic, got: {stderr}"
    );
}

// 7.1: echo "hello; rm -rf / with echo allowed → :ask (Error diagnostic floors decision)
#[test]
fn error_diagnostic_floors_at_ask() {
    let cfg = write_config(r#"(rule "echo" (effect :allow))"#);
    let output = may_i(&cfg)
        .write_stdin(bash_payload(r#"echo "hello; rm -rf /"#))
        .output()
        .expect("run");

    assert!(output.status.success());
    let resp = parse_json(&output);
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"], "ask",
        "unterminated quote should floor at :ask"
    );
}

// 7.2: if true; then echo hello with echo allowed → :allow (Warning doesn't floor)
#[test]
fn warning_diagnostic_does_not_floor() {
    let cfg = write_config(
        r#"
(rule "echo" (effect :allow))
(rule "true" (effect :allow))
"#,
    );
    let output = may_i(&cfg)
        .write_stdin(bash_payload("if true; then echo hello"))
        .output()
        .expect("run");

    assert!(output.status.success());
    let resp = parse_json(&output);
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"], "allow",
        "missing fi (warning) should not affect decision"
    );
}

// 7.3: rm "unterminated with rm denied → :deny (floor is ask but deny > ask)
#[test]
fn deny_wins_over_error_floor() {
    let cfg = write_config(r#"(rule "rm" (effect :deny "rm denied"))"#);
    let output = may_i(&cfg)
        .write_stdin(bash_payload(r#"rm "unterminated"#))
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
        "deny should win over ask floor"
    );
}

// 7.4: echo hello → no diagnostics in JSON output
#[test]
fn well_formed_no_diagnostics_in_json() {
    let cfg = write_config(r#"(rule "echo" (effect :allow))"#);
    let output = may_i(&cfg)
        .args(["eval", "--json", "echo hello"])
        .output()
        .expect("run");

    assert!(output.status.success());
    let resp: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse JSON");
    assert!(
        resp.get("parse_diagnostics").is_none(),
        "well-formed input should not have parse_diagnostics"
    );
}

// 7.5: JSON output for malformed input includes parse_diagnostics array
#[test]
fn malformed_input_has_diagnostics_in_json() {
    let cfg = write_config(r#"(rule "echo" (effect :allow))"#);
    let output = may_i(&cfg)
        .args(["eval", "--json", r#"echo "unterminated"#])
        .output()
        .expect("run");

    assert!(output.status.success());
    let resp: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse JSON");
    let diags = resp
        .get("parse_diagnostics")
        .expect("should have parse_diagnostics");
    assert!(diags.is_array());
    let arr = diags.as_array().unwrap();
    assert!(!arr.is_empty());
    assert_eq!(arr[0]["kind"], "unterminated_double_quote");
    assert_eq!(arr[0]["severity"], "error");
    assert!(arr[0]["message"].as_str().unwrap().contains("unterminated"));
    assert!(arr[0]["span"]["start"].is_number());
}
