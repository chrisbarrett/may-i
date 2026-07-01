// Integration tests for the `check` subcommand.

mod common;

use common::{may_i, may_i_cmd, parse_json, write_config};
use predicates::prelude::*;

#[test]
fn check_valid_config_exits_zero() {
    let cfg = write_config(
        r#"(rule "echo" (allow "echo is safe")
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
        r#"(rule "echo" (allow "echo is safe")
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
    let cfg = write_config(r#"(rule "echo" (when undefined-pred (allow "test")))"#);
    may_i(&cfg)
        .arg("check")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("undefined predicate"));
}

#[test]
fn check_verbose_shows_passing_checks() {
    let cfg = write_config(
        r#"(rule "echo" (allow "echo is safe")
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
        r#"(rule "echo" (allow "echo is safe")
  (check :allow "echo hello"))"#,
    );
    let output = may_i(&cfg).args(["check", "--json"]).output().expect("run");

    assert!(output.status.success());

    let resp = parse_json(&output);

    assert_eq!(resp["passed"], 1);
    assert_eq!(resp["failed"], 0);
}

#[test]
fn check_config_not_found_exits_two() {
    let mut cmd = may_i_cmd();
    cmd.args(["--config", "/nonexistent/path/config.lisp", "check"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn check_untested_scope_rule_warns_but_passes() {
    // A scope-dependent env rule with no (with-env …) coverage: the run must
    // still succeed (the advisory does not fail it) and surface the warning.
    let cfg = write_config(r#"(env "PATH" (when (scope reaches-child) (ask)))"#);
    may_i(&cfg)
        .arg("check")
        .assert()
        .success()
        .stdout(predicate::str::contains("Untested scope-dependent"))
        .stdout(predicate::str::contains("PATH"));
}

#[test]
fn check_scope_rule_with_with_env_coverage_no_warning() {
    let cfg = write_config(
        r#"
        (rule "ls" (allow))
        (env "PATH" (when (scope reaches-child) (ask)))
        (check (with-env ["PATH"] (ask "PATH=/evil:$PATH")))
        "#,
    );
    may_i(&cfg)
        .arg("check")
        .assert()
        .success()
        .stdout(predicate::str::contains("1 passed, 0 failed"))
        .stdout(predicate::str::contains("Untested scope-dependent").not());
}

#[test]
fn check_with_env_floors_bare_reassignment() {
    // End-to-end: (with-env ["PATH"]) makes the bare reassignment reach a
    // child, so the (ask …) expectation passes.
    let cfg = write_config(
        r#"
        (rule "ls" (allow))
        (check (with-env ["PATH"] (ask "PATH=/evil:$PATH; ls")))
        "#,
    );
    may_i(&cfg)
        .arg("check")
        .assert()
        .success()
        .stdout(predicate::str::contains("1 passed, 0 failed"));
}

#[test]
fn check_is_hermetic_ignores_host_environment() {
    // PATH is exported on the host, but `check` is hermetic: with no
    // (with-env …), the bare reassignment is treated as shell-local, so the
    // (allow …) expectation passes regardless of the host environment.
    let cfg = write_config(
        r#"
        (rule "ls" (allow))
        (check (allow "PATH=/evil:$PATH; ls"))
        "#,
    );
    may_i(&cfg)
        .env("PATH", "/usr/bin:/bin")
        .arg("check")
        .assert()
        .success()
        .stdout(predicate::str::contains("1 passed, 0 failed"));
}
