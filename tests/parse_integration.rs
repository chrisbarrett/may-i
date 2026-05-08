// Integration tests for the `parse` subcommand.

mod common;

use common::{may_i, write_config};
use predicates::prelude::*;

const MINIMAL_CONFIG: &str = r#"(rule "echo" (allow "ok"))"#;

#[test]
fn parse_simple_command_exits_zero() {
    let cfg = write_config(MINIMAL_CONFIG);
    may_i(&cfg)
        .args(["parse", "echo hello"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Literal"));
}

#[test]
fn parse_shows_command_structure() {
    let cfg = write_config(MINIMAL_CONFIG);
    may_i(&cfg)
        .args(["parse", "echo hello"])
        .assert()
        .success()
        .stdout(predicate::str::contains("SimpleCommand"))
        .stdout(predicate::str::contains("echo"))
        .stdout(predicate::str::contains("hello"));
}

#[test]
fn parse_reads_from_stdin_via_file_flag() {
    let cfg = write_config(MINIMAL_CONFIG);
    may_i(&cfg)
        .args(["parse", "-f", "-"])
        .write_stdin("echo hello\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("SimpleCommand"))
        .stdout(predicate::str::contains("echo"));
}

#[test]
fn parse_pipeline() {
    let cfg = write_config(MINIMAL_CONFIG);
    may_i(&cfg)
        .args(["parse", "echo hello | grep h"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Pipeline").or(predicate::str::contains("Pipe")));
}
