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
    let cfg = write_config(r#"(rule "echo" (effect :allow "echo is safe"))"#);
    let output = may_i(&cfg)
        .args(["migrate", "-o", "/dev/stdout", "--yes"])
        .output()
        .expect("run");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rule"), "output should contain the rule");
    assert!(
        stdout.contains(":allow"),
        "output should preserve the effect"
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
