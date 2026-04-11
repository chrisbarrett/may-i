// Integration tests for eval reading commands from stdin.

mod common;

use common::{may_i, parse_json, write_config};
use predicates::prelude::*;

const TEST_CONFIG: &str = r#"
(rule "echo"
      (effect :allow "echo is safe"))
"#;

#[test]
fn eval_reads_command_from_stdin() {
    let cfg = write_config(TEST_CONFIG);
    let output = may_i(&cfg)
        .args(["--json", "eval"])
        .write_stdin("echo hello\n")
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 expected");

    let resp = parse_json(&output);

    assert_eq!(resp["decision"], "allow");
    assert_eq!(resp["reason"], "echo is safe");
}

#[test]
fn eval_rejects_both_argv_and_stdin() {
    let cfg = write_config(TEST_CONFIG);
    may_i(&cfg)
        .args(["eval", "echo hello"])
        .write_stdin("echo world\n")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("ambiguous"));
}

#[test]
fn eval_stdin_trims_whitespace() {
    let cfg = write_config(TEST_CONFIG);
    let output = may_i(&cfg)
        .args(["--json", "eval"])
        .write_stdin("  echo hello  \n")
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 expected");

    let resp = parse_json(&output);

    assert_eq!(resp["decision"], "allow");
}

#[test]
fn eval_rejects_empty_stdin() {
    let cfg = write_config(TEST_CONFIG);
    may_i(&cfg)
        .args(["eval"])
        .write_stdin("   \n")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("no command provided"));
}

#[test]
fn eval_fact_flag_is_used_in_evaluation() {
    let cfg = write_config(
        r#"
(define is-ssh (fact? :via/ssh))
(rule "echo" (when is-ssh (effect :deny "no echo over ssh")))
"#,
    );
    let output = may_i(&cfg)
        .args(["--json", "eval", "--fact", ":via/ssh"])
        .write_stdin("echo hello\n")
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 expected");

    let resp = parse_json(&output);

    assert_eq!(resp["decision"], "deny");
    assert_eq!(resp["reason"], "no echo over ssh");
}

#[test]
fn eval_without_matching_fact_falls_through() {
    let cfg = write_config(
        r#"
(define is-ssh (fact? :via/ssh))
(rule "echo" (when is-ssh (effect :deny "no echo over ssh")))
"#,
    );
    let output = may_i(&cfg)
        .args(["--json", "eval"])
        .write_stdin("echo hello\n")
        .output()
        .expect("run");

    assert!(output.status.success(), "exit 0 expected");

    let resp = parse_json(&output);

    assert_eq!(
        resp["decision"], "ask",
        "without the fact, rule should not match and default to ask"
    );
}
