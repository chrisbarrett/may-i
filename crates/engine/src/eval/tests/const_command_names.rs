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
    // `which` is allowed so the embedded substitution in the assignment value
    // (now correctly gated — it runs a command) does not itself floor; the
    // remaining floor must come from the dynamic `$BIN` command name.
    let result = decide(
        r#"(rule "which" (allow))"#,
        "BIN=$(which terragrunt); $BIN apply",
    );
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
fn enumerable_loop_variable_command_name_resolves_per_value() {
    // `for c in rm cp; do $c x; done` is statically enumerable, so `$c` resolves
    // to `rm` and `cp` in the unrolled bodies — the command name is no longer a
    // dynamic expansion. With a rule allowing both, every value is allowed.
    let allowed = decide(
        r#"(rule "rm" (allow "ok")) (rule "cp" (allow "ok"))"#,
        "for c in rm cp; do $c x; done",
    );
    assert_eq!(
        allowed.decision,
        Decision::Allow,
        "both resolved command names should be allowed: {:?}",
        allowed.reason
    );

    // With no rules the resolved commands ask per the No-rule path — not as a
    // dynamic command name, since enumeration resolved the loop variable.
    let result = decide("", "for c in rm cp; do $c x; done");
    assert!(
        result.decision >= Decision::Ask,
        "expected at least ask, got {:?} ({:?})",
        result.decision,
        result.reason
    );
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(
        !reason.contains("dynamic command name"),
        "enumerated loop command name must resolve, not stay dynamic: {reason:?}"
    );
}

#[test]
fn non_enumerable_loop_variable_command_name_stays_dynamic() {
    // A non-enumerable list (a non-constant variable) leaves `$c` unresolved, so
    // the command name is still a dynamic expansion exactly as before.
    let result = decide("", "for c in $X; do $c arg; done");
    assert!(
        result.decision >= Decision::Ask,
        "expected at least ask, got {:?} ({:?})",
        result.decision,
        result.reason
    );
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("dynamic command name") || reason.contains("$c"),
        "non-enumerable loop variable command name must stay dynamic: {reason:?}"
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

#[test]
fn use_before_the_assignment_stays_dynamic() {
    // At the `$B` use site the assignment `B=rm` has not yet executed, so the
    // value is the inherited environment, not `rm`. The command name must stay
    // dynamic (D2 — use-order-awareness on the command-name path).
    let result = decide("", "$B x; B=rm");
    assert!(
        result.decision >= Decision::Ask,
        "expected at least ask, got {:?} ({:?})",
        result.decision,
        result.reason
    );
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("dynamic command name") || reason.contains("$B"),
        "use-before-assignment command name must stay dynamic: {reason:?}"
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
