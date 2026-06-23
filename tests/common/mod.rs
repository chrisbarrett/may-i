#![allow(dead_code, unreachable_pub)]

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;
use tempfile::{NamedTempFile, TempDir};

/// Write a config string to a temporary file.
pub fn write_config(contents: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp config");
    f.write_all(contents.as_bytes()).expect("write temp config");
    f
}

/// Build the JSON payload for a Bash hook event (Claude Code shape).
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

/// Build the JSON payload for a Codex Bash hook event. Same shape as
/// [`bash_payload`] with `turn_id` added — that key is what the hook
/// dispatcher uses to select the Codex profile.
pub fn codex_bash_payload(command: &str) -> String {
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
        "tool_use_id": "toolu_test_001",
        "turn_id": "t-test-001"
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

/// A process-wide empty directory used as a hermetic `HOME` / `XDG_CONFIG_HOME`
/// for [`may_i_cmd`]. Created once and kept for the test process's lifetime so
/// the returned [`Command`] doesn't outlive a per-call `TempDir`.
fn isolated_home() -> &'static Path {
    static HOME: OnceLock<TempDir> = OnceLock::new();
    HOME.get_or_init(|| TempDir::new().expect("create isolated HOME"))
        .path()
}

/// Build an `assert_cmd::Command` for `may-i` with an isolated `current_dir`
/// but no `MAYI_CONFIG`. Use for tests that pass `--config` explicitly or
/// invoke subcommands that don't need a config.
///
/// Config discovery is neutralised so a missing config can never resolve the
/// developer's real `~/.config/may-i/config.lisp`: inherited `MAYI_CONFIG` is
/// removed, and `HOME` / `XDG_CONFIG_HOME` point at a guaranteed-empty dir.
/// Resolution order is `--config` → `$MAYI_CONFIG` → `$XDG_CONFIG_HOME/may-i/…`
/// → `~/.config/may-i/…`, so a config-bearing test still wins via `--config` or
/// `MAYI_CONFIG`, while a config-less invocation falls through to an absent path
/// instead of leaking the real config. (Trust-store tests that rely on
/// `XDG_DATA_HOME` are unaffected — that var is left alone.)
pub fn may_i_cmd() -> Command {
    let mut cmd = cargo_bin_cmd!("may-i");
    let home = isolated_home();
    cmd.current_dir(std::env::temp_dir())
        .env_remove("MAYI_CONFIG")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home);
    cmd
}
