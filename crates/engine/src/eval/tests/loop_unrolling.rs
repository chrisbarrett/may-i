//! Scenarios for statically-enumerable `for` loops: when the loop list is a
//! provable finite literal set and the loop variable is unmutated in the body,
//! the body is unrolled once per value with the loop variable seeded as a
//! provably-constant scalar, and the per-value decisions combine strictest-wins
//! across evaluation units. A non-enumerable list, an in-body reassignment, or
//! an over-budget unroll falls back to today's flagged behaviour.

use may_i_config::parse_config;
use may_i_core::{ContextFacts, Decision};
use proptest::prelude::*;

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

#[test]
fn one_value_failing_the_allow_floors_to_ask() {
    // Only `ok` matches the allow; the `danger` iteration is uncovered, so the
    // meet over iterations takes the stricter `:ask` (spec scenario 2).
    let config = r#"(rule "aws" (when (anywhere "s3://bkt/ok") (allow "ok only")))"#;
    let result = decide(
        config,
        r#"for k in ok danger; do aws s3 cp "s3://bkt/$k" /tmp/x; done"#,
    );
    assert!(
        result.decision >= Decision::Ask,
        "an uncovered iteration must floor the meet to at least ask: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn a_value_matching_a_deny_rule_yields_deny() {
    // One iteration resolves to a value a deny rule gates; deny is strictest, so
    // the whole loop denies (every iteration runs).
    let config = r#"(rule "rm"
                      (or (when (anywhere "/tmp/keep") (allow "ok"))
                          (when (anywhere "/etc/shadow") (deny "secret"))))"#;
    let result = decide(
        config,
        r#"for p in /tmp/keep /etc/shadow; do rm "$p"; done"#,
    );
    assert_eq!(
        result.decision,
        Decision::Deny,
        "a deny-matching iteration must make the meet deny: {:?}",
        result.reason
    );
}

#[test]
fn nested_enumerable_loops_unroll_to_the_product() {
    // 2×2 = 4 iterations, all covered by the allow keyed on `a/b`-shaped paths.
    let config = r#"(rule "cp" (when (anywhere (regex "^src/(x|y)/(1|2)$")) (allow "grid")))"#;
    let result = decide(
        config,
        r#"for d in x y; do for f in 1 2; do cp "src/$d/$f" /tmp/x; done; done"#,
    );
    assert_eq!(
        result.decision,
        Decision::Allow,
        "nested enumerable loops should unroll to the covered product: {:?}",
        result.reason
    );
}

#[test]
fn nested_enumerable_loops_one_cell_uncovered_floors() {
    // The same 2×2 grid but the allow misses `y/2`; that one cell floors the
    // whole meet to ask — the product is combined strictest-wins.
    let config = r#"(rule "cp" (when (anywhere (regex "^src/(x/(1|2)|y/1)$")) (allow "grid")))"#;
    let result = decide(
        config,
        r#"for d in x y; do for f in 1 2; do cp "src/$d/$f" /tmp/x; done; done"#,
    );
    assert!(
        result.decision >= Decision::Ask,
        "an uncovered grid cell must floor the product to ask: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn nested_loops_over_budget_fall_back_without_under_asking() {
    // 12×12 = 144 unrolled units > 64 budget: the inner (or outer) loop is not
    // unrolled, its variable stays unresolved, and the allow floors. Never
    // under-asks even though every concrete value would have matched.
    let outer: String = (0..12)
        .map(|i| format!("d{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    let inner: String = (0..12)
        .map(|i| format!("f{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    // The allow is keyed on the *whole* resolved path, satisfiable only when
    // both loop variables resolve. Over budget the inner loop stays flagged, so
    // the `$f`-bearing word cannot satisfy the anchored regex and the decision
    // floors — never under-asks.
    let config = r#"(rule "cp" (when (anywhere (regex "^d[0-9]+/f[0-9]+$")) (allow "grid")))"#;
    let input =
        format!("for d in {outer}; do for f in {inner}; do cp \"$d/$f\" /tmp/x; done; done");
    let result = decide(config, &input);
    assert!(
        result.decision >= Decision::Ask,
        "over-budget nested unroll must fall back to a flagged floor: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn non_literal_list_stays_flagged() {
    // `for k in $(ls); do rm "$k"; done` — the list is not statically
    // enumerable, so `$k` stays unresolved and floors the allow (spec scenario 3).
    let config = r#"(rule "rm" (when (anywhere (regex ".")) (allow "any")))"#;
    let result = decide(config, r#"for k in $(ls); do rm "$k"; done"#);
    assert!(
        result.decision >= Decision::Ask,
        "non-enumerable list must keep the loop variable flagged: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn in_body_reassignment_stays_flagged() {
    // `for k in a b; do k=$(date); rm "$k"; done` — the loop variable is
    // reassigned before the use, so it stays unresolved (spec scenario 4).
    let config = r#"(rule "rm" (when (anywhere (regex ".")) (allow "any")))"#;
    let result = decide(config, r#"for k in a b; do k=$(date); rm "$k"; done"#);
    assert!(
        result.decision >= Decision::Ask,
        "in-body reassignment must keep the loop variable flagged: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

proptest! {
    /// Metamorphic (task 3.5): the decision for an enumerable single-value loop
    /// body equals the decision for the bare command with that literal
    /// substituted for `$k`. Run over each value so every unrolled per-value
    /// classification is pinned to its literal counterpart.
    #[test]
    fn prop_unrolled_value_equals_literal_substitution(
        values in proptest::collection::vec("[a-z][a-z0-9]{0,6}", 1..4),
        decision in prop_oneof![Just("allow"), Just("ask"), Just("deny")],
        // Pick which single value the rule keys on, so the per-value match
        // genuinely varies across the list.
        idx in 0usize..4,
    ) {
        let keyed = &values[idx % values.len()];
        let config = format!(
            r#"(rule "tool" (when (anywhere "p/{keyed}") ({decision} "r")))"#
        );

        // Single-value loop: each value's unrolled body must match the bare
        // `tool p/<value>` command, decision *and* reason (resolution reproduces
        // the literal classification exactly).
        for v in &values {
            let looped = decide(&config, &format!("for k in {v}; do tool \"p/$k\"; done"));
            let literal = decide(&config, &format!("tool p/{v}"));
            prop_assert_eq!(
                looped.decision,
                literal.decision,
                "value {} diverged: looped {:?} vs literal {:?}",
                v, looped.reason, literal.reason
            );
            prop_assert_eq!(looped.reason, literal.reason);
        }

        // Multi-value loop: the meet equals the strictest decision over the
        // per-literal substitutions (every iteration runs).
        let list = values.join(" ");
        let looped_all = decide(&config, &format!("for k in {list}; do tool \"p/$k\"; done"));
        let expected = values
            .iter()
            .map(|v| decide(&config, &format!("tool p/{v}")).decision)
            .max()
            .unwrap();
        prop_assert_eq!(
            looped_all.decision,
            expected,
            "multi-value meet must equal strictest per-literal decision: {:?}",
            looped_all.reason
        );
    }
}
