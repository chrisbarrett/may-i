// Integration tests for `may-i migrate` walking the `(load …)` graph
// (§17). Verifies that running migrate on a primary config also rewrites
// every reachable loaded file in place, and that --dry-run previews
// without writing.

mod common;

use common::may_i_cmd;
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

#[test]
fn migrate_walks_load_graph_and_rewrites_each_file() {
    // Three files: root (which loads two children) plus two child files,
    // all in legacy syntax.
    let dir = TempDir::new().unwrap();
    let root = write_file(
        dir.path(),
        "config.lisp",
        r#"(load "rules/echo.lisp")
(load "rules/git.lisp")
(rule "ls" (effect :allow))"#,
    );
    let echo = write_file(
        dir.path(),
        "rules/echo.lisp",
        r#"(rule "echo" (effect :allow "echo is safe"))"#,
    );
    let git = write_file(
        dir.path(),
        "rules/git.lisp",
        r#"(rule "git" (effect :allow))"#,
    );

    let mut cmd = may_i_cmd();
    cmd.env("MAYI_CONFIG", &root);
    cmd.args(["migrate", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Migrated 3 file(s) in-place"));

    let root_text = std::fs::read_to_string(&root).unwrap();
    let echo_text = std::fs::read_to_string(&echo).unwrap();
    let git_text = std::fs::read_to_string(&git).unwrap();

    for (name, text) in [
        ("root", &root_text),
        ("echo", &echo_text),
        ("git", &git_text),
    ] {
        assert!(
            !text.contains("(effect :allow"),
            "{name} should have legacy effect form replaced: {text}"
        );
        assert!(
            text.contains("(allow"),
            "{name} should have decision verb form: {text}"
        );
    }
}

#[test]
fn migrate_dry_run_does_not_modify_files() {
    let dir = TempDir::new().unwrap();
    let root = write_file(dir.path(), "config.lisp", r#"(load "rules/echo.lisp")"#);
    let echo = write_file(
        dir.path(),
        "rules/echo.lisp",
        r#"(rule "echo" (effect :allow))"#,
    );

    let original_root = std::fs::read_to_string(&root).unwrap();
    let original_echo = std::fs::read_to_string(&echo).unwrap();

    let mut cmd = may_i_cmd();
    cmd.env("MAYI_CONFIG", &root);
    cmd.args(["migrate", "--dry-run", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Dry run"));

    assert_eq!(std::fs::read_to_string(&root).unwrap(), original_root);
    assert_eq!(std::fs::read_to_string(&echo).unwrap(), original_echo);
}
