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

#[test]
fn operator_operand_brace_in_output_floors() {
    // bash brace-expands ${A:+/var/log/app{.log,/../../etc/shadow}} to two
    // words; the second normalises to /etc/shadow. may-i must not resolve the
    // word to a single literal that satisfies a ^/var/log/ allow.
    let config = r#"(rule "cat" (when (anywhere (regex "^/var/log/")) (allow "logs")))"#;
    let result = decide(
        config,
        r#"A=x; cat ${A:+/var/log/app{.log,/../../etc/shadow}}"#,
    );
    assert!(
        result.decision >= Decision::Ask,
        "brace in output operand must floor: {:?} ({:?})",
        result.decision,
        result.reason
    );

    // Baseline: the same braces at top level already floor (top-level
    // BraceExpansion is expansion-bearing). The operator-operand path must not
    // be a hiding place that bypasses that protection.
    let baseline = decide(config, r#"cat /var/log/app{.log,/../../etc/shadow}"#);
    assert!(
        baseline.decision >= Decision::Ask,
        "top-level brace baseline must floor: {:?} ({:?})",
        baseline.decision,
        baseline.reason
    );
}

#[test]
fn unquoted_value_with_glob_floors() {
    // bash glob-expands unquoted $A -> /etc/passwd at runtime, defeating the
    // deny. may-i must not resolve $A to the inert literal /etc/passw? and allow.
    let config = r#"(rule "cat" (or (when (anywhere "/etc/passwd") (deny "secret"))
                                     (when (anywhere (regex "^/etc/")) (allow "etc"))))"#;
    let result = decide(config, r#"A=/etc/passw?; cat $A"#);
    assert!(
        result.decision >= Decision::Ask,
        "unquoted glob-bearing value must not resolve-and-allow: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn quoted_value_with_glob_still_resolves() {
    // "$A" is NOT glob-expanded by bash, so resolution stays faithful.
    let config = r#"(rule "cat" (when (anywhere "/etc/passw?") (allow "ok")))"#;
    let result = decide(config, r#"A=/etc/passw?; cat "$A""#);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "quoted value must still resolve: {:?}",
        result.reason
    );
}

#[test]
fn leading_tilde_on_resolved_word_floors() {
    // `~$A` resolves to a word with a leading literal `~`, which bash tilde-
    // expands at runtime. The resolved word stays expansion-bearing (the
    // `!is_expansion_bearing()` half of the gate, which the value-verbatim half
    // does not catch), so it must floor an :allow keyed on the literal text.
    let config = r#"(rule "cat" (when (anywhere "~x") (allow "lit")))"#;
    let result = decide(config, r#"A=x; cat ~$A"#);
    assert!(
        result.decision >= Decision::Ask,
        "leading-tilde resolved word must floor: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

// The `glob_*` helpers treat `\` as an ordinary char, so a bash pattern with a
// backslash-escaped metachar (`\*`, `\[`) — which bash matches *literally* —
// strips/replaces differently from bash. Resolving such an operator word would
// diverge from the real argument and could dodge a deny. These must floor.

#[test]
fn operator_escaped_metachar_strip_pattern_floors() {
    // bash: Y='[p]/etc/shadow'; "${Y#\[p\]}" strips literal "[p]" -> "/etc/shadow",
    // which the deny gates. may-i's glob helpers ignore the escape and would keep
    // "[p]/etc/shadow", dodging the deny — so the word must stay unresolved.
    let config = r#"(rule "cat"
                      (or (when (anywhere "/etc/shadow") (deny "secret"))
                          (when (anywhere (regex ".")) (allow "fallthrough"))))"#;
    let result = decide(config, r#"Y='[p]/etc/shadow'; cat "${Y#\[p\]}""#);
    assert!(
        result.decision >= Decision::Ask,
        "escaped-metachar strip pattern must floor, not allow: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn operator_escaped_star_suffix_pattern_floors() {
    // bash: Y='/etc/shadow*'; "${Y%\*}" strips a literal trailing '*' -> "/etc/shadow".
    let config = r#"(rule "cat"
                      (or (when (anywhere "/etc/shadow") (deny "secret"))
                          (when (anywhere (regex ".")) (allow "fallthrough"))))"#;
    let result = decide(config, r#"Y='/etc/shadow*'; cat "${Y%\*}""#);
    assert!(
        result.decision >= Decision::Ask,
        "escaped-star suffix pattern must floor, not allow: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn operator_substring_arithmetic_offset_floors() {
    // bash treats the offset as an arithmetic expression: ${Y:2+2} -> offset 4.
    // may-i parses only plain decimals, so a non-trivial expression must floor
    // rather than silently resolve at offset 0.
    let config = r#"(rule "cat"
                      (or (when (anywhere "/etc/shadow") (deny "secret"))
                          (when (anywhere (regex ".")) (allow "fallthrough"))))"#;
    let result = decide(config, r#"Y=SAFE/etc/shadow; cat "${Y:2+2}""#);
    assert!(
        result.decision >= Decision::Ask,
        "arithmetic substring offset must floor, not allow: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn operator_substring_octal_offset_floors() {
    // ${Y:010} is octal 8 to bash, decimal 10 to a bare parse — floor the divergence.
    let config = r#"(rule "tool" (when (anywhere "23456789abc") (allow "ok")))"#;
    let result = decide(config, r#"Y=0123456789abc; tool "${Y:010}""#);
    assert!(
        result.decision >= Decision::Ask,
        "octal substring offset must floor, not allow on a decimal reading: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn operator_plain_substring_still_resolves() {
    // Guard against over-conservatism: a plain decimal offset/length still resolves.
    let config = r#"(rule "tool" (when (anywhere "cde") (allow "ok")))"#;
    let result = decide(config, r#"Y=abcde; tool "${Y:2}""#);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "plain substring offset must still resolve: {:?}",
        result.reason
    );
}

#[test]
fn operator_length_counts_characters_not_bytes() {
    // bash ${#Y} counts characters; a byte count would diverge for multibyte values.
    let config = r#"(rule "tool" (when (anywhere "4") (allow "ok")))"#;
    let result = decide(config, "Y=café; tool \"${#Y}\"");
    assert_eq!(
        result.decision,
        Decision::Allow,
        "length must count characters (4 for café), not bytes: {:?}",
        result.reason
    );
}

#[test]
fn operator_anchored_replace_floors() {
    // bash `${Y/#b/}` deletes a leading 'b' (start-anchored): "b/etc/shadow" ->
    // "/etc/shadow", gated by the deny. The AST drops the `#` anchor, so resolution
    // would search for a literal "#b" and keep the value — the word must floor.
    let config = r#"(rule "cat"
                      (or (when (anywhere "/etc/shadow") (deny "secret"))
                          (when (anywhere (regex ".")) (allow "fallthrough"))))"#;
    let result = decide(config, r#"Y=b/etc/shadow; cat "${Y/#b/}""#);
    assert!(
        result.decision >= Decision::Ask,
        "anchored replace must floor, not allow: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn operator_unanchored_replace_still_resolves() {
    // Guard: an ordinary (unanchored) replace still resolves.
    let config = r#"(rule "tool" (when (anywhere "XbXcX") (allow "ok")))"#;
    let result = decide(config, r#"Y=abaca; tool "${Y//a/X}""#);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "unanchored replace must still resolve: {:?}",
        result.reason
    );
}

#[test]
fn operator_case_conversion_with_pattern_floors() {
    // bash `${Y^^a}` uppercases only matching chars: "abcabc" -> "AbcAbc". The
    // `Uppercase` op carries no pattern, so resolving would full-uppercase and
    // diverge — the patterned form must floor.
    let config = r#"(rule "tool"
                      (or (when (anywhere "ABCABC") (allow "wrong"))
                          (when (anywhere "AbcAbc") (allow "right"))))"#;
    let result = decide(config, r#"Y=abcabc; tool "${Y^^a}""#);
    // It must not resolve to the divergent full-uppercase value.
    assert!(
        result.reason.as_deref() != Some("wrong"),
        "patterned case conversion must not resolve to full-uppercase: {:?}",
        result.reason
    );
}

#[test]
fn operator_plain_case_conversion_still_resolves() {
    // Guard: pattern-less ${Y^^} still resolves.
    let config = r#"(rule "tool" (when (anywhere "ABC") (allow "ok")))"#;
    let result = decide(config, r#"Y=abc; tool "${Y^^}""#);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "plain uppercase must still resolve: {:?}",
        result.reason
    );
}

#[test]
fn operator_replace_all_empty_matchable_pattern_terminates() {
    // ${V//*/y}: pattern `*` matches the empty string; glob_replace's all-branch
    // makes no progress on a zero-width match (would loop forever). The form is
    // floored, so evaluation TERMINATES (the property under test). The bare
    // allow rule applies regardless.
    let config = r#"(rule "echo" (allow "ok"))"#;
    let result = decide(config, r#"V=x; echo "${V//*/y}""#);
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reason);
}

#[test]
fn operator_replace_first_only_star_still_resolves() {
    // A first-only replace (`/`, not `//`) with `*` terminates, so it must not
    // be over-floored: ${V/*/y} on V=x resolves to `y` and the allow applies.
    let config = r#"(rule "echo" (when (anywhere "y") (allow "ok")))"#;
    let result = decide(config, r#"V=x; echo "${V/*/y}""#);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "first-only star replace should resolve: {:?}",
        result.reason
    );
}
