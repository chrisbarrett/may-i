//! Scenarios for statically-enumerable `for` loops: when the loop list is a
//! provable finite literal set and the loop variable is unmutated in the body,
//! the body is unrolled once per value with the loop variable seeded as a
//! provably-constant scalar, and the per-value decisions combine strictest-wins
//! across evaluation units. A non-enumerable list, an in-body reassignment, or
//! an over-budget unroll falls back to today's flagged behaviour.

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

#[test]
fn all_list_values_match_allow_resolves_to_allow() {
    // Every iteration's `s3://bkt/$k` resolves to a literal the allow covers, so
    // the loop variable no longer floors the decision — the body is unrolled per
    // value and each value is allowed.
    let config = r#"(rule "aws" (when (anywhere (regex "^s3://bkt/(a|b|c)$")) (allow "known")))"#;
    let result = decide(
        config,
        r#"for k in a b c; do aws s3 cp "s3://bkt/$k" /tmp/x; done"#,
    );
    assert_eq!(
        result.decision,
        Decision::Allow,
        "all values covered by the allow should resolve to allow: {:?}",
        result.reason
    );
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(
        !reason.contains("unresolved shell expansion"),
        "enumerated loop variable must not floor as unresolved: {reason:?}"
    );
}

#[test]
fn over_budget_loop_falls_back_to_flagged() {
    // A list far larger than the unit budget is not unrolled: the loop variable
    // stays unresolved and floors the `:allow` exactly as before — never
    // under-asking. (Budget is 64 units; 100 values × 1 body unit > 64.)
    let values: String = (0..100)
        .map(|i| format!("v{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    let config = r#"(rule "tool" (when (anywhere (regex ".")) (allow "any")))"#;
    let input = format!("for k in {values}; do tool \"$k\"; done");
    let result = decide(config, &input);
    assert!(
        result.decision >= Decision::Ask,
        "over-budget loop must fall back to a flagged floor, not allow: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn within_budget_loop_unrolls_and_allows() {
    // A list comfortably within budget unrolls; with every value covered by the
    // allow the decision is `:allow`. Isolates the budget boundary from the
    // over-budget case above (same rule, same shape, fewer values).
    let values: String = (0..10)
        .map(|i| format!("v{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    let config = r#"(rule "tool" (when (anywhere (regex "^v[0-9]+$")) (allow "any")))"#;
    let input = format!("for k in {values}; do tool \"$k\"; done");
    let result = decide(config, &input);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "within-budget loop should unroll and allow: {:?}",
        result.reason
    );
}
