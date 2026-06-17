//! Scenarios for the provably-constant-variable-command-name requirement: a
//! variable command name whose value is provably constant within the command
//! is resolved to that literal and evaluated as that command; every other
//! variable command name stays dynamic and asks as before.

use may_i_config::parse_config;
use may_i_core::{ContextFacts, Decision};

use crate::eval::evaluate_command;

fn facts() -> ContextFacts {
    ContextFacts::default()
}

fn decide(config_src: &str, input: &str) -> crate::EvalResult {
    let config = parse_config(config_src).expect("config parses");
    evaluate_command(input, &config, &facts()).expect("evaluation succeeds")
}

const RM_ASKS: &str = r#"(rule "rm" (ask "no rm"))"#;

#[test]
fn constant_assignment_resolves_the_command_name() {
    let result = decide("", "BIN=./target/debug/may-i; $BIN eval foo");
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("./target/debug/may-i"),
        "reason should name the resolved command: {reason:?}"
    );
    assert!(
        !reason.contains("dynamic command name") && !reason.contains("$BIN"),
        "resolved command must not read as dynamic: {reason:?}"
    );
}

#[test]
fn resolved_command_name_is_gated_by_its_rule() {
    let result = decide(RM_ASKS, "R=rm; $R -rf /danger");
    assert!(
        result.decision >= Decision::Ask,
        "expected at least ask, got {:?} ({:?})",
        result.decision,
        result.reason
    );
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(
        !reason.contains("dynamic command name"),
        "resolved rm must be gated by its rule, not reported dynamic: {reason:?}"
    );
}

#[test]
fn assignment_from_a_substitution_stays_dynamic() {
    let result = decide("", "BIN=$(which terragrunt); $BIN apply");
    assert!(
        result.decision >= Decision::Ask,
        "expected at least ask, got {:?} ({:?})",
        result.decision,
        result.reason
    );
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("dynamic command name") || reason.contains("$BIN"),
        "substitution-assigned command name must stay dynamic: {reason:?}"
    );
}

#[test]
fn loop_variable_command_name_stays_dynamic() {
    let result = decide("", "for c in rm cp; do $c x; done");
    assert!(
        result.decision >= Decision::Ask,
        "expected at least ask, got {:?} ({:?})",
        result.decision,
        result.reason
    );
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("dynamic command name") || reason.contains("$c"),
        "loop variable command name must stay dynamic: {reason:?}"
    );
}

#[test]
fn reassignment_makes_the_value_not_provable() {
    let result = decide("", "B=echo; B=rm; $B x");
    assert!(
        result.decision >= Decision::Ask,
        "expected at least ask, got {:?} ({:?})",
        result.decision,
        result.reason
    );
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("dynamic command name") || reason.contains("$B"),
        "reassigned command name must stay dynamic: {reason:?}"
    );
}

// -- Task 3.2: guard — a literal command name is untouched --

#[test]
fn literal_command_name_is_unchanged() {
    let plain = decide("", "echo hello");
    // The presence of a constant env must not alter a literal command name's
    // decision or reason.
    let with_const_env = decide("", "BIN=./x; echo hello");
    let plain_reason = plain.reason.as_deref().unwrap_or("");
    assert!(
        plain_reason.contains("echo"),
        "literal command name should be evaluated as `echo`: {plain_reason:?}"
    );
    assert_eq!(plain.decision, with_const_env.decision);
    assert_eq!(plain.reason, with_const_env.reason);
}
