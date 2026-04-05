// Integration tests for the Claude Code hook entry point.

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use std::io::Write;
use tempfile::NamedTempFile;

fn write_config(contents: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp config");
    f.write_all(contents.as_bytes()).expect("write temp config");
    f
}

fn bash_payload(command: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "test-session-001",
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": "/tmp",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_input": {
            "command": command
        },
        "tool_use_id": "toolu_test_001"
    })
    .to_string()
}

fn may_i(config: &NamedTempFile) -> Command {
    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.env("MAYI_CONFIG", config.path());
    cmd
}

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
(rule (command "echo")
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
