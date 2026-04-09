// Integration tests for the `migrate` subcommand.

mod common;

use common::{may_i, write_config};
use predicates::prelude::*;

#[test]
fn migrate_v1_config_produces_v2_output() {
    let cfg = write_config(r#"(rule (command "echo") (effect :allow "echo is safe"))"#);
    may_i(&cfg)
        .args(["migrate", "-o", "/dev/stdout", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("(rule \"echo\""))
        .stdout(predicate::str::contains(":allow"));
}

#[test]
fn migrate_v2_config_outputs_unchanged() {
    let input = r#"(rule "echo" (effect :allow "echo is safe"))"#;
    let cfg = write_config(input);
    let output = may_i(&cfg)
        .args(["migrate", "-o", "/dev/stdout", "--yes"])
        .output()
        .expect("run");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The v2 config should not be structurally changed by migration.
    // Check that no diff/change markers appear and the key elements survive.
    assert!(
        stdout.contains(r#"(rule "echo""#),
        "rule command should be unchanged: {stdout}"
    );
    assert!(
        stdout.contains(r#"(effect :allow "echo is safe")"#),
        "effect should be unchanged: {stdout}"
    );
    assert!(
        !stdout.contains("(command"),
        "should not introduce (command ...) wrapper: {stdout}"
    );
}

#[test]
fn migrate_in_place_rewrites_file() {
    let cfg = write_config(r#"(rule (command "echo") (effect :allow "echo is safe"))"#);
    let path = cfg.path().to_path_buf();

    may_i(&cfg)
        .args(["migrate", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("in-place"));

    let migrated = std::fs::read_to_string(&path).expect("read migrated file");
    assert!(
        !migrated.contains("(command \"echo\")"),
        "v1 command wrapper should be removed"
    );
    assert!(
        migrated.contains("\"echo\""),
        "command name should be inlined"
    );
}
