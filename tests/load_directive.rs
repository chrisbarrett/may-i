// Integration tests for the `(load ...)` config directive.

mod common;

use common::{may_i, may_i_cmd, write_config};
use predicates::prelude::*;
use tempfile::TempDir;

fn write_file(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, content).unwrap();
    path
}

/// Multi-file config via load produces identical eval results to single-file.
#[test]
fn multi_file_eval_matches_single_file() {
    // Single-file config
    let single = write_config(
        r#"(rule "echo" (allow "echo is safe"))
(rule "git" (and (positional "status") (allow "git status ok")))
(check :allow "echo hello" :allow "git status")"#,
    );

    // Multi-file config
    let dir = TempDir::new().unwrap();
    write_file(
        dir.path(),
        "rules/echo.lisp",
        r#"(rule "echo" (allow "echo is safe"))"#,
    );
    write_file(
        dir.path(),
        "rules/git.lisp",
        r#"(rule "git" (and (positional "status") (allow "git status ok")))"#,
    );
    let root = write_file(
        dir.path(),
        "config.lisp",
        r#"(load "rules/echo.lisp")
(load "rules/git.lisp")
(check :allow "echo hello" :allow "git status")"#,
    );

    // Both should produce identical eval for "echo hello"
    let single_output = may_i(&single)
        .args(["eval", "echo", "hello"])
        .output()
        .unwrap();

    let mut multi_cmd = may_i_cmd();
    multi_cmd.env("MAYI_CONFIG", &root);
    let multi_output = multi_cmd.args(["eval", "echo", "hello"]).output().unwrap();

    assert_eq!(single_output.status, multi_output.status);
    assert_eq!(single_output.stdout, multi_output.stdout);

    // Both should pass checks
    may_i(&single)
        .arg("check")
        .assert()
        .success()
        .stdout(predicate::str::contains("2 passed, 0 failed"));

    let mut multi_check = may_i_cmd();
    multi_check.env("MAYI_CONFIG", &root);
    multi_check
        .arg("check")
        .assert()
        .success()
        .stdout(predicate::str::contains("2 passed, 0 failed"));
}

/// Load with glob pattern works in integration.
#[test]
fn load_glob_integration() {
    let dir = TempDir::new().unwrap();
    write_file(
        dir.path(),
        "rules/01-echo.lisp",
        r#"(rule "echo" (allow "echo"))"#,
    );
    write_file(
        dir.path(),
        "rules/02-git.lisp",
        r#"(rule "git" (allow "git"))"#,
    );
    let root = write_file(
        dir.path(),
        "config.lisp",
        r#"(load "rules/*.lisp")
(check :allow "echo hello" :allow "git status")"#,
    );

    let mut cmd = may_i_cmd();
    cmd.env("MAYI_CONFIG", &root);
    cmd.arg("check")
        .assert()
        .success()
        .stdout(predicate::str::contains("2 passed, 0 failed"));
}

/// Load with missing literal file produces error.
#[test]
fn load_missing_file_integration() {
    let dir = TempDir::new().unwrap();
    let root = write_file(dir.path(), "config.lisp", r#"(load "nonexistent.lisp")"#);

    let mut cmd = may_i_cmd();
    cmd.env("MAYI_CONFIG", &root);
    cmd.args(["eval", "echo"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}
