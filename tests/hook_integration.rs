// Integration tests for the Claude Code hook entry point.

mod common;

use common::{bash_payload, may_i, write_config};

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
