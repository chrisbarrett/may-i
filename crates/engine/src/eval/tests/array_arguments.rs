//! Scenarios for the provably-constant-array argument requirement: a
//! subscripted parameter expansion over a provably-constant **indexed** array
//! resolves before matchers see it — `${arr[i]}` to one element, quoted
//! `"${arr[@]}"` to one argv word per element (a word-count-changing splice),
//! and `${#arr[@]}` to the element count. `${arr[*]}`, unquoted `${arr[@]}`,
//! any mutated or non-literal array, and every associative array stay
//! expansion-bearing and floor an `:allow` exactly as before (all-or-nothing).

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

fn floored(result: &crate::EvalResult) -> bool {
    result.decision >= Decision::Ask
}

// -- Quoted `[@]` argv splice (D2) --

#[test]
fn quoted_all_expands_to_one_argument_per_element() {
    // Spec scenario: matchers see s3://bkt/a, s3://bkt/b, /tmp/x, and the allow
    // keyed on both sources fires without an unresolved-expansion floor.
    let config = r#"(rule "aws"
                      (when (and (anywhere "s3://bkt/a") (anywhere "s3://bkt/b"))
                            (allow "known bucket")))"#;
    let result = decide(
        config,
        r#"parts=(s3://bkt/a s3://bkt/b); aws s3 cp "${parts[@]}" /tmp/x"#,
    );
    assert_eq!(
        result.decision,
        Decision::Allow,
        "spliced array sources should satisfy the allow: {:?}",
        result.reason
    );
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(
        !reason.contains("unresolved shell expansion"),
        "spliced argv must not floor as unresolved: {reason:?}"
    );
}

#[test]
fn positional_after_splice_keeps_alignment() {
    // The destination positional sits *after* the `[@]` splice; splicing two
    // elements must not misalign it. The rule asserts the exact post-splice
    // argv shape: s3 cp <a> <b> /tmp/dest.
    let config = r#"(rule "aws"
                      (when (positional "s3" "cp" "src-a" "src-b" "/tmp/dest")
                            (allow "exact shape")))"#;
    let result = decide(
        config,
        r#"parts=(src-a src-b); aws s3 cp "${parts[@]}" /tmp/dest"#,
    );
    assert_eq!(
        result.decision,
        Decision::Allow,
        "positional after splice should align: {:?}",
        result.reason
    );
}

#[test]
fn empty_array_splice_yields_no_arguments() {
    // `"${empty[@]}"` expands to zero argv words, so the destination is the
    // sole positional argument.
    let config = r#"(rule "tool" (when (positional "only") (allow "ok")))"#;
    let result = decide(config, r#"empty=(); tool "${empty[@]}" only"#);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "empty-array splice should contribute no args: {:?}",
        result.reason
    );
}

// -- Single-element index (D3) --

#[test]
fn literal_index_resolves_single_element() {
    // Spec scenario: `"${zones[1]}"` resolves to `z-b`.
    let config = r#"(rule "echo" (when (anywhere "z-b") (allow "zone b")))"#;
    let result = decide(config, r#"zones=(z-a z-b z-c); echo "${zones[1]}""#);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "literal index should resolve to z-b: {:?}",
        result.reason
    );
}

#[test]
fn constant_scalar_index_resolves_the_element() {
    // The index word can itself be a provably-constant scalar: `i=1` makes
    // `${zones[$i]}` resolve to element 1.
    let config = r#"(rule "echo" (when (anywhere "z-b") (allow "zone b")))"#;
    let result = decide(config, r#"i=1; zones=(z-a z-b z-c); echo "${zones[$i]}""#);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "constant scalar index should resolve to z-b: {:?}",
        result.reason
    );
}

#[test]
fn negative_index_resolves_from_end() {
    // bash `${arr[-1]}` is the last element.
    let config = r#"(rule "echo" (when (anywhere "z-c") (allow "last")))"#;
    let result = decide(config, r#"zones=(z-a z-b z-c); echo "${zones[-1]}""#);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "negative index should resolve from the end: {:?}",
        result.reason
    );
}

#[test]
fn out_of_range_index_stays_unresolved() {
    let config = r#"(rule "echo" (when (anywhere (regex ".")) (allow "any")))"#;
    let result = decide(config, r#"zones=(z-a z-b); echo "${zones[9]}""#);
    assert!(
        floored(&result),
        "out-of-range index must floor: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn dynamic_index_stays_unresolved() {
    // `${zones[$RANDOM]}` has a non-constant index — unprovable.
    let config = r#"(rule "echo" (when (anywhere (regex ".")) (allow "any")))"#;
    let result = decide(config, r#"zones=(z-a z-b); echo "${zones[$RANDOM]}""#);
    assert!(
        floored(&result),
        "dynamic index must floor: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn index_resolved_value_is_gated_by_a_deny() {
    // Resolution only tightens: a deny keyed on the real element fires.
    let config = r#"(rule "cat" (when (anywhere "/etc/shadow") (deny "secret")))"#;
    let result = decide(config, r#"f=(/etc/shadow); cat "${f[0]}""#);
    assert_eq!(
        result.decision,
        Decision::Deny,
        "resolved element must be gated by the deny: {:?}",
        result.reason
    );
}

// -- Length form (D3) --

#[test]
fn length_resolves_to_count() {
    // Spec scenario: `${#arr[@]}` resolves to 3.
    let config = r#"(rule "echo" (when (anywhere "3") (allow "three")))"#;
    let result = decide(config, r#"arr=(a b c); echo "${#arr[@]}""#);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "length form should resolve to the count 3: {:?}",
        result.reason
    );
}

#[test]
fn length_of_single_element_resolves_to_char_length() {
    // `${#arr[1]}` is the character length of element 1 (`café` → 4).
    let config = r#"(rule "tool" (when (anywhere "4") (allow "ok")))"#;
    let result = decide(config, "arr=(x café y); tool \"${#arr[1]}\"");
    assert_eq!(
        result.decision,
        Decision::Allow,
        "length of element should be its char count: {:?}",
        result.reason
    );
}

#[test]
fn star_length_resolves_to_count() {
    // `${#arr[*]}` is the element count, like `${#arr[@]}`.
    let config = r#"(rule "echo" (when (anywhere "2") (allow "two")))"#;
    let result = decide(config, r#"arr=(a b); echo "${#arr[*]}""#);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "star length should resolve to the count: {:?}",
        result.reason
    );
}

// -- Forms that must stay unresolved --

#[test]
fn length_of_element_with_dynamic_index_stays_unresolved() {
    // `${#arr[$x]}` — the char-length of a dynamically-indexed element cannot be
    // resolved (the index does not reduce to a known integer), so it floors.
    let config = r#"(rule "echo" (when (anywhere (regex ".")) (allow "any")))"#;
    let result = decide(config, r#"arr=(café x); echo "${#arr[$x]}""#);
    assert!(
        floored(&result),
        "length of a dynamically-indexed element must floor: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn length_of_out_of_range_element_stays_unresolved() {
    // `${#arr[9]}` — no element 9, so the char-length form has nothing to
    // resolve and floors.
    let config = r#"(rule "echo" (when (anywhere (regex ".")) (allow "any")))"#;
    let result = decide(config, r#"arr=(a b); echo "${#arr[9]}""#);
    assert!(
        floored(&result),
        "length of an out-of-range element must floor: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn non_numeric_literal_index_stays_unresolved() {
    // `${arr[notanumber]}` — a non-numeric subscript is an arithmetic
    // expression bash evaluates (an unset name → 0); we do not model it, so it
    // must floor rather than guess.
    let config = r#"(rule "echo" (when (anywhere (regex ".")) (allow "any")))"#;
    let result = decide(config, r#"arr=(a b); echo "${arr[notanumber]}""#);
    assert!(
        floored(&result),
        "non-numeric literal index must floor: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn octal_leading_zero_index_stays_unresolved() {
    // `${arr[010]}` — bash evaluates the subscript arithmetically, where a
    // leading `0` means OCTAL: `010` == 8, not 10. Resolving it as decimal 10
    // would key matchers on the wrong element (a wrong-`:allow` on a value the
    // program never receives). It must floor rather than resolve.
    let config = r#"(rule "echo"
                      (or (when (anywhere "danger") (deny "bad"))
                          (when (anywhere "safe") (allow "ok"))))"#;
    // bash index 8 == "danger"; decimal-10 misread == "safe".
    let result = decide(
        config,
        r#"arr=(e0 e1 e2 e3 e4 e5 e6 e7 danger e9 safe); echo "${arr[010]}""#,
    );
    assert!(
        floored(&result),
        "octal leading-zero index must floor, not resolve to decimal: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn operator_element_poisons_the_array() {
    // A non-word token inside the array literal (`|`) is not a modelled element;
    // the array must not be treated as a constant sequence.
    let config = r#"(rule "cmd" (when (anywhere (regex ".")) (allow "any")))"#;
    let result = decide(config, r#"arr=(a | b); cmd "${arr[@]}""#);
    assert!(
        floored(&result),
        "array with an unmodelled element must floor: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn star_form_stays_unresolved() {
    // Spec scenario: `"${arr[*]}"` join depends on IFS — must floor.
    let config = r#"(rule "cmd" (when (anywhere (regex ".")) (allow "any")))"#;
    let result = decide(config, r#"arr=(a b); cmd "${arr[*]}""#);
    assert!(
        floored(&result),
        "star form must floor: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn unquoted_all_stays_unresolved() {
    // Unquoted `${arr[@]}` is word-split/globbed by bash — must floor.
    let config = r#"(rule "cmd" (when (anywhere (regex ".")) (allow "any")))"#;
    let result = decide(config, r#"arr=(a b); cmd ${arr[@]}"#);
    assert!(
        floored(&result),
        "unquoted [@] must floor: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn mutated_array_stays_unresolved() {
    // Spec scenario: `arr+=(c)` makes the array non-constant.
    let config = r#"(rule "cmd" (when (anywhere (regex ".")) (allow "any")))"#;
    let result = decide(config, r#"arr=(a b); arr+=(c); cmd "${arr[@]}""#);
    assert!(
        floored(&result),
        "appended array must floor: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn element_assignment_mutation_stays_unresolved() {
    let config = r#"(rule "cmd" (when (anywhere (regex ".")) (allow "any")))"#;
    let result = decide(config, r#"arr=(a b); arr[0]=evil; cmd "${arr[@]}""#);
    assert!(
        floored(&result),
        "element-assignment-mutated array must floor: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn nonliteral_element_stays_unresolved() {
    // Spec scenario: an element from a substitution keeps the whole array
    // unresolved.
    let config = r#"(rule "cmd" (when (anywhere (regex ".")) (allow "any")))"#;
    let result = decide(config, r#"arr=(a $(hostname) c); cmd "${arr[@]}""#);
    assert!(
        floored(&result),
        "non-literal element must floor the whole expansion: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn associative_all_stays_unresolved() {
    // Spec scenario: associative element order is unspecified — never resolve.
    let config = r#"(rule "cmd" (when (anywhere (regex ".")) (allow "any")))"#;
    let result = decide(config, r#"declare -A m=([a]=1 [b]=2); cmd "${m[@]}""#);
    assert!(
        floored(&result),
        "associative [@] must floor: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn unquoted_index_with_glob_value_stays_unresolved() {
    // An unquoted `${arr[0]}` whose element holds a glob metachar is
    // glob-expanded by bash at runtime, so resolving it could satisfy an allow
    // on a value the program never receives.
    let config = r#"(rule "cat"
                      (or (when (anywhere "/etc/passwd") (deny "secret"))
                          (when (anywhere (regex "^/etc/")) (allow "etc"))))"#;
    let result = decide(config, r#"arr=("/etc/passw?"); cat ${arr[0]}"#);
    assert!(
        floored(&result),
        "unquoted glob-bearing element must not resolve-and-allow: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn keyword_spelled_elements_resolve_faithfully() {
    // `arr=(fi)` — `fi` is a keyword token but a literal array element. The
    // splice must produce the argument `fi`, identical to writing it inline,
    // not silently drop it (which would resolve to zero args).
    let config = r#"(rule "tool" (when (positional "fi") (allow "ok")))"#;
    let result = decide(config, r#"arr=(fi); tool "${arr[@]}""#);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "keyword-spelled element must splice as `fi`: {:?}",
        result.reason
    );
}

// -- Metamorphic (D3) --

proptest! {
    /// A resolved quoted `"${arr[@]}"` classifies identically to its element
    /// literals written inline in the command — the splice reproduces exactly
    /// what bash passes.
    #[test]
    fn prop_splice_equals_inline_elements(
        elems in proptest::collection::vec("[a-z][a-z0-9/_.-]{0,8}", 1..4),
        config_decision in prop_oneof![Just("allow"), Just("ask"), Just("deny")],
    ) {
        // A rule that keys on every element, so resolution drives the match.
        let anywheres = elems
            .iter()
            .map(|e| format!("(anywhere \"{e}\")"))
            .collect::<Vec<_>>()
            .join(" ");
        let config = format!(
            r#"(rule "tool" (when (and {anywheres}) ({config_decision} "r")))"#
        );

        let list = elems.join(" ");
        let inline = elems.join(" ");
        let spliced = decide(&config, &format!("arr=({list}); tool \"${{arr[@]}}\""));
        let written = decide(&config, &format!("tool {inline}"));

        prop_assert_eq!(spliced.decision, written.decision);
        prop_assert_eq!(spliced.reason, written.reason);
    }
}
