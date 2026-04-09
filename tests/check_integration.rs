// Integration tests for the `check` subcommand.

mod common;

use assert_cmd::cargo::cargo_bin_cmd;
use common::{may_i, write_config};
use predicates::prelude::*;

#[test]
fn check_valid_config_exits_zero() {
    let cfg = write_config(
        r#"(rule "echo" (effect :allow "echo is safe")
  (check :allow "echo hello"))"#,
    );
    may_i(&cfg)
        .arg("check")
        .assert()
        .success()
        .stdout(predicate::str::contains("1 passed, 0 failed"));
}

#[test]
fn check_failing_assertion_exits_nonzero() {
    let cfg = write_config(
        r#"(rule "echo" (effect :allow "echo is safe")
  (check :deny "echo hello"))"#,
    );
    may_i(&cfg)
        .arg("check")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("0 passed, 1 failed"));
}

#[test]
fn check_undefined_predicate_exits_two() {
    let cfg = write_config(r#"(rule "echo" (when undefined-pred (effect :allow "test")))"#);
    may_i(&cfg)
        .arg("check")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("undefined predicate"));
}

#[test]
fn check_verbose_shows_passing_checks() {
    let cfg = write_config(
        r#"(rule "echo" (effect :allow "echo is safe")
  (check :allow "echo hello"))"#,
    );
    may_i(&cfg)
        .args(["check", "--verbose"])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASS"));
}

#[test]
fn check_json_produces_valid_json() {
    let cfg = write_config(
        r#"(rule "echo" (effect :allow "echo is safe")
  (check :allow "echo hello"))"#,
    );
    let output = may_i(&cfg).args(["check", "--json"]).output().expect("run");

    assert!(output.status.success());

    let resp: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON stdout");

    assert_eq!(resp["passed"], 1);
    assert_eq!(resp["failed"], 0);
}

#[test]
fn check_config_not_found_exits_two() {
    let mut cmd = cargo_bin_cmd!("may-i");
    cmd.args(["--config", "/nonexistent/path/config.lisp", "check"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not found"));
}
