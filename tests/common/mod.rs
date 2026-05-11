#![allow(dead_code, unreachable_pub)]

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use std::io::Write;
use tempfile::NamedTempFile;

/// Write a config string to a temporary file.
pub fn write_config(contents: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp config");
    f.write_all(contents.as_bytes()).expect("write temp config");
    f
}

/// Build the JSON payload for a Bash hook event.
pub fn bash_payload(command: &str) -> String {
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

/// Parse JSON from command output.
pub fn parse_json(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("parse JSON output")
}

/// Build an `assert_cmd::Command` for `may-i` with `MAYI_CONFIG` pre-set.
///
/// Sets the child's `current_dir` to `std::env::temp_dir()` so repo-local
/// discovery does not walk into the workspace's `.git/`. Tests that need a
/// specific cwd MUST override with `.current_dir(...)` and document why.
pub fn may_i(config: &NamedTempFile) -> Command {
    let mut cmd = may_i_cmd();
    cmd.env("MAYI_CONFIG", config.path());
    cmd
}

/// Build an `assert_cmd::Command` for `may-i` with an isolated `current_dir`
/// but no `MAYI_CONFIG`. Use for tests that pass `--config` explicitly or
/// invoke subcommands that don't need a config.
pub fn may_i_cmd() -> Command {
    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.current_dir(std::env::temp_dir());
    cmd
}
