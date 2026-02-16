// End-to-end tests for the Claude Code PreToolUse hook protocol.
//
// These tests invoke the `may-i` binary as a subprocess with JSON on stdin,
// exactly as Claude Code does in production, and verify stdout JSON, stderr,
// and exit codes.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;
use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Minimal config that allows `ls` and denies `rm -rf /`.
const TEST_CONFIG: &str = r#"
(rule (command (or "ls" "tree"))
      (allow "Read-only filesystem inspection"))

(rule (command "rm")
      (args (and (anywhere "-r" "--recursive")
                 (anywhere "/")))
      (deny "Dangerous deletion"))

(rule (command "echo")
      (allow "Shell builtin"))
"#;

fn write_config() -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp config");
    f.write_all(TEST_CONFIG.as_bytes())
        .expect("write temp config");
    f
}

/// Build a PreToolUse hook payload for a Bash command.
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

/// Build a PreToolUse hook payload for a non-Bash tool.
fn non_bash_payload(tool_name: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "test-session-001",
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": "/tmp",
        "permission_mode": "default",
        "tool_name": tool_name,
        "tool_input": {
            "file_path": "/tmp/test.txt"
        },
        "tool_use_id": "toolu_test_002"
    })
    .to_string()
}

fn may_i(config: &NamedTempFile) -> Command {
    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.env("MAYI_CONFIG", config.path());
    cmd
}

// ---------------------------------------------------------------------------
// Hook protocol: allowed commands
// ---------------------------------------------------------------------------

#[test]
fn hook_allows_matching_command() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .write_stdin(bash_payload("ls -la"))
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 expected");

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    assert_eq!(
        resp["hookSpecificOutput"]["hookEventName"],
        "PreToolUse"
    );
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"],
        "allow"
    );
}

#[test]
fn hook_denies_matching_command() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .write_stdin(bash_payload("rm -r /"))
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 even for deny decisions");

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
    // Reason should be populated
    let reason = resp["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("");
    assert!(!reason.is_empty(), "deny should include a reason");
}

#[test]
fn hook_asks_for_unmatched_command() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .write_stdin(bash_payload("curl https://example.com"))
        .output()
        .expect("run");

    assert!(output.status.success());

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"],
        "ask"
    );
}

// ---------------------------------------------------------------------------
// Hook protocol: non-Bash tools are silently passed through
// ---------------------------------------------------------------------------

#[test]
fn hook_silent_for_non_bash_tool() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .write_stdin(non_bash_payload("Read"))
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 for non-Bash tools");
    assert!(
        output.stdout.is_empty(),
        "no stdout for non-Bash tools (got {:?})",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn hook_silent_for_write_tool() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .write_stdin(non_bash_payload("Write"))
        .output()
        .expect("run");

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn hook_silent_for_edit_tool() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .write_stdin(non_bash_payload("Edit"))
        .output()
        .expect("run");

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
}

// ---------------------------------------------------------------------------
// Hook protocol: missing tool_name field treated as non-Bash
// ---------------------------------------------------------------------------

#[test]
fn hook_silent_when_tool_name_absent() {
    let cfg = write_config();
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "test-session-001",
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": "/tmp",
        "tool_input": { "command": "ls" }
    })
    .to_string();

    let output = may_i(&cfg)
        .write_stdin(payload)
        .output()
        .expect("run");

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
}

// ---------------------------------------------------------------------------
// Hook protocol: error handling (exit code 2)
// ---------------------------------------------------------------------------

#[test]
fn hook_exits_2_on_invalid_json() {
    let cfg = write_config();
    may_i(&cfg)
        .write_stdin("this is not json")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Invalid JSON"));
}

#[test]
fn hook_exits_2_on_missing_command_field() {
    let cfg = write_config();
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {}
    })
    .to_string();

    may_i(&cfg)
        .write_stdin(payload)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Missing tool_input.command"));
}

#[test]
fn hook_exits_2_on_bad_config() {
    let mut bad_cfg = NamedTempFile::new().expect("create temp");
    bad_cfg
        .write_all(b"this is not valid (((")
        .expect("write");

    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.env("MAYI_CONFIG", bad_cfg.path());
    cmd.write_stdin(bash_payload("ls"))
        .assert()
        .code(2)
        .stderr(predicate::str::is_empty().not());
}

// ---------------------------------------------------------------------------
// Hook protocol: JSON output structure
// ---------------------------------------------------------------------------

#[test]
fn hook_response_has_correct_structure() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .write_stdin(bash_payload("echo hello"))
        .output()
        .expect("run");

    assert!(output.status.success());

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON");

    // Top-level must have hookSpecificOutput and nothing else unexpected
    assert!(resp.get("hookSpecificOutput").is_some());

    let hook = &resp["hookSpecificOutput"];
    assert_eq!(hook["hookEventName"], "PreToolUse");

    // permissionDecision must be one of the three valid values
    let decision = hook["permissionDecision"].as_str().unwrap();
    assert!(
        ["allow", "deny", "ask"].contains(&decision),
        "unexpected decision: {decision}"
    );

    // permissionDecisionReason must be a string (possibly empty)
    assert!(hook["permissionDecisionReason"].is_string());
}

// ---------------------------------------------------------------------------
// Hook protocol: real-world payload shapes from Claude Code
// ---------------------------------------------------------------------------

#[test]
fn hook_handles_real_bash_payload() {
    let cfg = write_config();
    // Realistic payload with extra fields Claude Code includes
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "2bbf6c7c-9e83-438d-acc6-ff8d7813beaf",
        "transcript_path": "/Users/chris/.claude/projects/foo/2bbf6c7c.jsonl",
        "cwd": "/Users/chris/src/project",
        "permission_mode": "acceptEdits",
        "tool_name": "Bash",
        "tool_input": {
            "command": "ls -la",
            "description": "List files with details"
        },
        "tool_use_id": "toolu_01ABC123XYZ"
    })
    .to_string();

    let output = may_i(&cfg)
        .write_stdin(payload)
        .output()
        .expect("run");

    assert!(output.status.success());

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"],
        "allow"
    );
}

#[test]
fn hook_handles_payload_with_extra_fields() {
    let cfg = write_config();
    // Claude Code may add new fields over time; hook must not choke
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "test",
        "transcript_path": "/tmp/t.jsonl",
        "cwd": "/tmp",
        "permission_mode": "bypassPermissions",
        "tool_name": "Bash",
        "tool_input": { "command": "echo hi" },
        "tool_use_id": "toolu_xyz",
        "some_future_field": true,
        "another_field": { "nested": 42 }
    })
    .to_string();

    let output = may_i(&cfg)
        .write_stdin(payload)
        .output()
        .expect("run");

    assert!(output.status.success());
    assert!(!output.stdout.is_empty(), "should produce JSON output");
}

// ---------------------------------------------------------------------------
// Hook protocol: security filter integration
// ---------------------------------------------------------------------------

#[test]
fn hook_denies_credential_access() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .write_stdin(bash_payload("cat /home/user/.ssh/id_rsa"))
        .output()
        .expect("run");

    assert!(output.status.success());

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
}

#[test]
fn hook_denies_env_file_access() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .write_stdin(bash_payload("cat .env.production"))
        .output()
        .expect("run");

    assert!(output.status.success());

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(
        resp["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
}

// ---------------------------------------------------------------------------
// Hook protocol: stderr is clean on success
// ---------------------------------------------------------------------------

#[test]
fn hook_no_stderr_on_success() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .write_stdin(bash_payload("ls"))
        .output()
        .expect("run");

    assert!(output.status.success());
    assert!(
        output.stderr.is_empty(),
        "stderr must be empty on success (got {:?})",
        String::from_utf8_lossy(&output.stderr)
    );
}
