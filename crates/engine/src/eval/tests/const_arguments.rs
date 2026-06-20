//! Scenarios for the provably-constant-variable-argument requirement: an
//! argument word whose every expansion resolves to a provably-constant literal
//! is resolved before matchers see it, so it matches on its real value and no
//! longer floors an `:allow` as an unresolved expansion. A word with any
//! unresolved part stays expansion-bearing and floors exactly as before
//! (all-or-nothing per word).

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
fn constant_variables_resolve_a_mixed_argument_word() {
    // `BUCKET=b; KEY=k; aws s3 cp "s3://$BUCKET/$KEY" /tmp/x` — the target word
    // resolves to `s3://b/k`, so an allow keyed on that literal applies without
    // an unresolved-expansion floor.
    let config = r#"(rule "aws" (when (anywhere "s3://b/k") (allow "known object")))"#;
    let result = decide(
        config,
        r#"BUCKET=b; KEY=k; aws s3 cp "s3://$BUCKET/$KEY" /tmp/x"#,
    );
    assert_eq!(
        result.decision,
        Decision::Allow,
        "resolved argument should satisfy the allow: {:?}",
        result.reason
    );
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(
        !reason.contains("unresolved shell expansion"),
        "resolved argument must not floor as unresolved: {reason:?}"
    );
}

#[test]
fn partially_resolved_argument_word_still_floors() {
    // Only `BUCKET` is constant; `KEY` has no qualifying assignment, so the
    // whole word stays expansion-bearing (all-or-nothing) and floors the allow.
    // The regex matches the literal `s3://` prefix that survives flattening, so
    // the matcher attempts the word and then floors on its unresolved part.
    let config = r#"(rule "aws" (when (anywhere (regex "^s3://")) (allow "s3 url")))"#;
    let result = decide(config, r#"BUCKET=b; aws s3 cp "s3://$BUCKET/$KEY" /tmp/x"#);
    assert!(
        result.decision >= Decision::Ask,
        "partially-resolved word must floor: {:?} ({:?})",
        result.decision,
        result.reason
    );
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("unresolved shell expansion"),
        "expected an unresolved-expansion floor: {reason:?}"
    );
}

#[test]
fn resolved_argument_is_gated_by_a_deny_rule() {
    // `P=/etc/shadow; cat "$P"` resolves the argument to `/etc/shadow`, so a
    // deny keyed on that real value fires — resolution tightens soundly (D3).
    let config = r#"(rule "cat" (when (anywhere "/etc/shadow") (deny "no shadow")))"#;
    let result = decide(config, r#"P=/etc/shadow; cat "$P""#);
    assert_eq!(
        result.decision,
        Decision::Deny,
        "resolved argument must be gated by the deny: {:?}",
        result.reason
    );
}

#[test]
fn argument_from_a_substitution_stays_unresolved() {
    // `T=$(mktemp)` is not provably constant, so `$T` stays expansion-bearing.
    let config = r#"(rule "rm" (when (anywhere (regex ".")) (allow "any")))"#;
    let result = decide(config, r#"T=$(mktemp); rm "$T""#);
    assert!(
        result.decision >= Decision::Ask,
        "substitution-derived argument must floor: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn argument_used_before_its_assignment_stays_unresolved() {
    // `rm "$T"; T=/tmp/x` — at the use site `T` is the inherited environment,
    // not `/tmp/x` (D2 on the argument path), so the word stays unresolved and
    // the allow keyed on the literal `/tmp/x` must not fire. (Contrast the
    // straight-line `T=/tmp/x; rm "$T"`, which would resolve and allow.)
    let config = r#"(rule "rm" (when (anywhere "/tmp/x") (allow "tmp x")))"#;
    let used_before = decide(config, r#"rm "$T"; T=/tmp/x"#);
    assert!(
        used_before.decision >= Decision::Ask,
        "use-before-assignment argument must not resolve to allow: {:?} ({:?})",
        used_before.decision,
        used_before.reason
    );

    // Sanity: the assign-then-use form does resolve and allow, isolating the
    // ordering as the cause.
    let assign_first = decide(config, r#"T=/tmp/x; rm "$T""#);
    assert_eq!(
        assign_first.decision,
        Decision::Allow,
        "assign-then-use must resolve and allow: {:?}",
        assign_first.reason
    );
}

proptest! {
    /// Metamorphic: for a provably-constant argument, the decision and reason
    /// equal those of the same command with the resolved literal written
    /// directly in place of the `$VAR` (D3 — resolution reproduces the literal).
    #[test]
    fn prop_resolved_argument_equals_literal_argument(
        value in "[a-z][a-z0-9/_.-]{0,12}",
        config_decision in prop_oneof![Just("allow"), Just("ask"), Just("deny")],
    ) {
        // A rule that keys on the exact resolved value, so resolution is what
        // makes (or fails to make) the match.
        let config = format!(
            r#"(rule "tool" (when (anywhere "{value}") ({config_decision} "r")))"#
        );

        let resolved = decide(&config, &format!("A={value}; tool {value}_static $A"));
        let literal = decide(&config, &format!("tool {value}_static {value}"));

        prop_assert_eq!(resolved.decision, literal.decision);
        prop_assert_eq!(resolved.reason, literal.reason);
    }
}

// A `${VAR…}` operator word resolves only when every operand is inert; an
// operand bash would itself expand (nested `$`/backtick, or a glob/tilde in an
// operand that becomes part of the output) keeps the word expansion-bearing so
// our resolved literal can never diverge from bash and satisfy an `:allow`.

#[test]
fn operator_operand_nested_expansion_in_strip_pattern_floors() {
    // bash: Y=axb; X=a; cat "${Y#$X}" strips leading `a` -> runs `cat xb`.
    // may-i must NOT resolve to `axb` (literal `$X` strip) and allow.
    let config = r#"(rule "cat" (when (anywhere "axb") (allow "lit")))"#;
    let result = decide(config, r#"Y=axb; X=a; cat "${Y#$X}""#);
    assert!(
        result.decision >= Decision::Ask,
        "nested expansion in strip pattern must floor: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn operator_operand_nested_expansion_in_replacement_floors() {
    // bash: Y=cat; R=dog; echo "${Y/cat/$R}" -> `dog`. may-i must not resolve
    // to the literal `$R` and allow on the wrong value.
    let config = r#"(rule "echo" (when (anywhere "$R") (allow "lit")))"#;
    let result = decide(config, r#"Y=cat; R=dog; echo "${Y/cat/$R}""#);
    assert!(
        result.decision >= Decision::Ask,
        "nested expansion in replacement must floor: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn operator_operand_glob_in_default_value_floors() {
    // ${A:+/tmp/*} emits operand text /tmp/* which bash globs at runtime.
    let config = r#"(rule "tool" (when (anywhere "/tmp/*") (allow "lit")))"#;
    let result = decide(config, r#"A=x; tool ${A:+/tmp/*}"#);
    assert!(
        result.decision >= Decision::Ask,
        "glob in output operand must floor: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn inert_operator_operand_still_resolves() {
    // Guard against over-conservatism: an operator whose operands are all inert
    // (plain literals) still resolves so the allow narrows as intended.
    // Y=name.txt; strip the `.txt` suffix -> `name`.
    let config = r#"(rule "cat" (when (anywhere "name") (allow "ok")))"#;
    let result = decide(config, r#"Y=name.txt; cat "${Y%.txt}""#);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "inert operator operand should still resolve and allow: {:?}",
        result.reason
    );
}
