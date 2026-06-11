//! Scenarios for evaluate-unquoted-heredoc-substitutions: an embedded
//! command in an **unquoted** heredoc body is executed by real bash at
//! expansion time, so it must become its own evaluation unit; a quoted
//! body stays inviolable.

use may_i_config::parse_config;
use may_i_core::{ContextFacts, Decision};

use crate::eval::evaluate_command;

const RULES: &str = r#"
(rule "cat" (allow))
(rule "rm" (when (anywhere "--force") (deny "no force")))
"#;

fn decide(input: &str) -> crate::EvalResult {
    let config = parse_config(RULES).expect("config parses");
    evaluate_command(input, &config, &ContextFacts::default()).expect("evaluation succeeds")
}

#[test]
fn unquoted_heredoc_command_substitution_is_evaluated() {
    let result = decide("cat <<EOF\n$(rm --force)\nEOF\n");
    assert_eq!(
        result.decision,
        Decision::Deny,
        "embedded rm must be evaluated: {:?}",
        result.reason
    );
}

#[test]
fn unquoted_heredoc_backtick_is_evaluated() {
    let result = decide("cat <<EOF\n`rm --force`\nEOF\n");
    assert_eq!(result.decision, Decision::Deny, "{:?}", result.reason);
}

#[test]
fn quoted_heredoc_body_stays_inert() {
    for input in [
        "cat <<'EOF'\n$(rm --force)\nEOF\n",
        "cat <<\"EOF\"\n$(rm --force)\nEOF\n",
        "cat <<\\EOF\n$(rm --force)\nEOF\n",
    ] {
        let result = decide(input);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "quoted body must stay inert for {input:?}: {:?}",
            result.reason
        );
    }
}

#[test]
fn process_substitution_text_in_body_stays_inert() {
    let result = decide("cat <<EOF\n<(rm --force)\nEOF\n");
    assert_eq!(
        result.decision,
        Decision::Allow,
        "bash performs no process substitution in heredoc bodies: {:?}",
        result.reason
    );
}

#[test]
fn unterminated_substitution_in_body_floors_to_ask() {
    let result = decide("cat <<EOF\n$(rm --force\nEOF\n");
    assert_eq!(
        result.decision,
        Decision::Ask,
        "unterminated substitution is not recursed into; the error floor owns it: {:?}",
        result.reason
    );
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(
        reason.starts_with("parse error:"),
        "expected parse-error reason, got: {reason}"
    );
    assert!(
        !reason.contains("No rule for command"),
        "must not fabricate a command from the swallowed tail: {reason}"
    );
}

#[test]
fn nested_substitution_in_body_is_evaluated() {
    // The outer extraction yields `echo $(rm --force)`; recursion finds
    // the inner rm.
    let config = parse_config(
        r#"
(rule "cat" (allow))
(rule "echo" (allow))
(rule "rm" (when (anywhere "--force") (deny "no force")))
"#,
    )
    .unwrap();
    let result = evaluate_command(
        "cat <<EOF\n$(echo $(rm --force))\nEOF\n",
        &config,
        &ContextFacts::default(),
    )
    .unwrap();
    assert_eq!(result.decision, Decision::Deny, "{:?}", result.reason);
}
