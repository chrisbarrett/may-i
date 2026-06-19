//! Scenarios for the provably-constant-variable-argument requirement: an
//! argument word whose every expansion resolves to a provably-constant literal
//! is resolved before matchers see it, so it matches on its real value and no
//! longer floors an `:allow` as an unresolved expansion. A word with any
//! unresolved part stays expansion-bearing and floors exactly as before
//! (all-or-nothing per word).

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
