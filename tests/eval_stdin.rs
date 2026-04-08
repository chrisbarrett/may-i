// Integration tests for eval reading commands from stdin.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;
use tempfile::NamedTempFile;

const TEST_CONFIG: &str = r#"
(rule "echo"
      (effect :allow "echo is safe"))
"#;

fn write_config() -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp config");
    f.write_all(TEST_CONFIG.as_bytes())
        .expect("write temp config");
    f
}

fn may_i(config: &NamedTempFile) -> Command {
    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.env("MAYI_CONFIG", config.path());
    cmd
}

#[test]
fn eval_reads_command_from_stdin() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .args(["--json", "eval"])
        .write_stdin("echo hello\n")
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 expected");

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    assert_eq!(resp["decision"], "allow");
    assert_eq!(resp["reason"], "echo is safe");
}

#[test]
fn eval_rejects_both_argv_and_stdin() {
    let cfg = write_config();
    may_i(&cfg)
        .args(["eval", "echo hello"])
        .write_stdin("echo world\n")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("ambiguous"));
}

#[test]
fn eval_stdin_trims_whitespace() {
    let cfg = write_config();
    let output = may_i(&cfg)
        .args(["--json", "eval"])
        .write_stdin("  echo hello  \n")
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 expected");

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    assert_eq!(resp["decision"], "allow");
}

#[test]
fn eval_rejects_empty_stdin() {
    let cfg = write_config();
    may_i(&cfg)
        .args(["eval"])
        .write_stdin("   \n")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("empty"));
}
