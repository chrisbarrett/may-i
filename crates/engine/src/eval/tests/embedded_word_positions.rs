//! Scenarios for embedded-command-substitutions-are-evaluated-in-every-word-
//! position: a `$( … )` / backtick / process substitution executes a command
//! wherever it appears, so it must be gated even in a bare assignment value, a
//! `for` loop's iteration words, or a `case` subject/pattern. Before the
//! structural-word walk these positions resolved to `:allow` with the embedded
//! command unreviewed.

use may_i_config::parse_config;
use may_i_core::{ContextFacts, Decision};

use crate::eval::evaluate_command;

fn decide(config_src: &str, input: &str) -> crate::EvalResult {
    let config = parse_config(config_src).expect("config parses");
    evaluate_command(input, &config, &ContextFacts::default()).expect("evaluation succeeds")
}

const DENY_RM_ALLOW_ECHO: &str = r#"
(rule "rm" (deny "no rm"))
(rule "echo" (allow))
"#;

#[test]
fn substitution_in_bare_assignment_value_is_denied() {
    let result = decide(DENY_RM_ALLOW_ECHO, "z=$(rm -rf /); echo done");
    assert_eq!(
        result.decision,
        Decision::Deny,
        "embedded rm in bare assignment value must be denied: {:?}",
        result.reason
    );
}

#[test]
fn substitution_in_for_loop_words_is_denied() {
    let result = decide(
        r#"(rule "rm" (deny "no rm"))"#,
        "for x in $(rm -rf /); do echo \"$x\"; done",
    );
    assert_eq!(
        result.decision,
        Decision::Deny,
        "embedded rm in for-loop words must be denied: {:?}",
        result.reason
    );
}

#[test]
fn substitution_in_case_subject_is_denied() {
    let result = decide(
        r#"(rule "rm" (deny "no rm"))"#,
        "case $(rm -rf /) in *) echo hi;; esac",
    );
    assert_eq!(
        result.decision,
        Decision::Deny,
        "embedded rm in case subject must be denied: {:?}",
        result.reason
    );
}

#[test]
fn substitution_in_param_expansion_default_is_denied() {
    let result = decide(DENY_RM_ALLOW_ECHO, "echo ${x:-$(rm -rf /)}");
    assert_eq!(
        result.decision,
        Decision::Deny,
        "embedded rm in parameter-expansion default value must be denied: {:?}",
        result.reason
    );
}

#[test]
fn substitution_in_param_expansion_pattern_is_denied() {
    let result = decide(DENY_RM_ALLOW_ECHO, "echo ${x#$(rm -rf /)}");
    assert_eq!(
        result.decision,
        Decision::Deny,
        "embedded rm in parameter-expansion strip-prefix pattern must be denied: {:?}",
        result.reason
    );
}
