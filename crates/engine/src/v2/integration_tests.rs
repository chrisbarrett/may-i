// Integration tests for v2 unified rule DSL end-to-end evaluation.
// Task 7.6: Write integration tests for end-to-end evaluation

use crate::v2::evaluate_v2;
use may_i_config::v2::{parse_config, resolve::validate_and_resolve};
use may_i_core::types::{ContextFacts, Decision};

fn test_context() -> ContextFacts {
    ContextFacts::default()
}

#[test]
fn integration_simple_allow_rule() {
    let config = parse_config(
        r#"
        (rule "git" (effect :allow))
    "#,
    )
    .unwrap();

    let facts = test_context();
    let result = evaluate_v2("git", &[], &config, &facts);

    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn integration_simple_deny_rule() {
    let config = parse_config(
        r#"
        (rule "rm" (effect :deny "rm is dangerous"))
    "#,
    )
    .unwrap();

    let facts = test_context();
    let result = evaluate_v2("rm", &[], &config, &facts);

    assert_eq!(result.decision, Decision::Deny);
    assert!(result.reason.unwrap().contains("dangerous"));
}

#[test]
fn integration_rule_with_fact_predicate() {
    let config = parse_config(
        r#"
        (rule "git" (has :via/ssh) (effect :ask "SSH operations require confirmation"))
    "#,
    )
    .unwrap();

    let mut facts = test_context();
    facts.insert_present(":via/ssh");

    let result = evaluate_v2("git", &[], &config, &facts);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_rule_with_arg_pattern() {
    let config = parse_config(
        r#"
        (rule "git" (positional "push") (effect :allow))
    "#,
    )
    .unwrap();

    let facts = test_context();
    let result = evaluate_v2("git", &["push".to_string()], &config, &facts);

    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn integration_rule_with_and_combinator() {
    let config = parse_config(
        r#"
        (rule "git" (and (positional "push") (has :via/ssh)) (effect :ask))
    "#,
    )
    .unwrap();

    let mut facts = test_context();
    facts.insert_present(":via/ssh");

    let result = evaluate_v2("git", &["push".to_string()], &config, &facts);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_rule_with_or_combinator() {
    let config = parse_config(
        r#"
        (rule "git" (or (positional "push") (positional "pull")) (effect :allow))
    "#,
    )
    .unwrap();

    let facts = test_context();

    let result = evaluate_v2("git", &["push".to_string()], &config, &facts);
    assert_eq!(result.decision, Decision::Allow);

    let result = evaluate_v2("git", &["pull".to_string()], &config, &facts);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn integration_rule_with_not_combinator() {
    let config = parse_config(
        r#"
        (rule "git" (not (anywhere "--force")) (effect :allow))
    "#,
    )
    .unwrap();

    let facts = test_context();

    // Without --force, should allow
    let result = evaluate_v2("git", &["push".to_string()], &config, &facts);
    assert_eq!(result.decision, Decision::Allow);

    // With --force, should not match and return ask
    let result = evaluate_v2(
        "git",
        &["push".to_string(), "--force".to_string()],
        &config,
        &facts,
    );
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_rule_with_when_effect() {
    let config = parse_config(
        r#"
        (rule "git" (when (has :via/ssh) (effect :ask)))
    "#,
    )
    .unwrap();

    let mut facts = test_context();
    facts.insert_present(":via/ssh");

    let result = evaluate_v2("git", &[], &config, &facts);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_rule_with_unless_effect() {
    let config = parse_config(
        r#"
        (rule "git" (unless (has :local) (effect :ask)))
    "#,
    )
    .unwrap();

    let facts = test_context();
    // No :local fact, so should ask
    let result = evaluate_v2("git", &[], &config, &facts);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_rule_with_if_effect() {
    let config = parse_config(
        r#"
        (rule "git" (if (has :via/ssh) (effect :ask) (effect :allow)))
    "#,
    )
    .unwrap();

    let mut facts = test_context();
    facts.insert_present(":via/ssh");

    let result = evaluate_v2("git", &[], &config, &facts);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_rule_with_case_effect() {
    let config = parse_config(
        r#"
        (rule "git"
            (case
                ((positional "push") (effect :ask))
                ((positional "pull") (effect :allow))
                (else (effect :deny))))
    "#,
    )
    .unwrap();

    let facts = test_context();

    let result = evaluate_v2("git", &["push".to_string()], &config, &facts);
    assert_eq!(result.decision, Decision::Ask);

    let result = evaluate_v2("git", &["pull".to_string()], &config, &facts);
    assert_eq!(result.decision, Decision::Allow);

    let result = evaluate_v2("git", &["status".to_string()], &config, &facts);
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn integration_named_predicate_with_define() {
    let config = parse_config(
        r#"
        (define ssh-session (has :via/ssh))
        (rule "git" ssh-session (effect :ask))
    "#,
    )
    .unwrap();

    // Resolve named predicates before evaluation
    let (resolved_rules, _) = validate_and_resolve(&config.rules, &config.defines).unwrap();

    let mut resolved_config = config;
    resolved_config.rules = resolved_rules;

    let mut facts = test_context();
    facts.insert_present(":via/ssh");

    let result = evaluate_v2("git", &[], &resolved_config, &facts);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_multiple_rules_most_restrictive_wins() {
    let config = parse_config(
        r#"
        (rule "git" (effect :allow))
        (rule "git" (positional "rm") (effect :deny))
    "#,
    )
    .unwrap();

    let facts = test_context();

    // Simple git should allow
    let result = evaluate_v2("git", &[], &config, &facts);
    assert_eq!(result.decision, Decision::Allow);

    // git rm should deny (most restrictive)
    let result = evaluate_v2("git", &["rm".to_string()], &config, &facts);
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn integration_or_command_pattern() {
    let config = parse_config(
        r#"
        (rule (or "git" "gh") (effect :allow))
    "#,
    )
    .unwrap();

    let facts = test_context();

    let result = evaluate_v2("git", &[], &config, &facts);
    assert_eq!(result.decision, Decision::Allow);

    let result = evaluate_v2("gh", &[], &config, &facts);
    assert_eq!(result.decision, Decision::Allow);

    let result = evaluate_v2("hg", &[], &config, &facts);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_forbidden_pattern() {
    let config = parse_config(
        r#"
        (rule "git" (forbidden "--force") (effect :allow))
    "#,
    )
    .unwrap();

    let facts = test_context();

    // Without --force, should allow
    let result = evaluate_v2("git", &["push".to_string()], &config, &facts);
    assert_eq!(result.decision, Decision::Allow);

    // With --force, should not match
    let result = evaluate_v2(
        "git",
        &["push".to_string(), "--force".to_string()],
        &config,
        &facts,
    );
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_anywhere_pattern() {
    let config = parse_config(
        r#"
        (rule "rm" (anywhere "-r") (effect :ask "Recursive delete requires confirmation"))
    "#,
    )
    .unwrap();

    let facts = test_context();

    let result = evaluate_v2(
        "rm",
        &["-r".to_string(), "foo".to_string()],
        &config,
        &facts,
    );
    assert_eq!(result.decision, Decision::Ask);

    let result = evaluate_v2("rm", &["foo".to_string()], &config, &facts);
    assert_eq!(result.decision, Decision::Ask); // No rule matched
}

#[test]
fn integration_no_matching_rule_returns_ask() {
    let config = parse_config(
        r#"
        (rule "git" (effect :allow))
    "#,
    )
    .unwrap();

    let facts = test_context();

    let result = evaluate_v2("hg", &[], &config, &facts);
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_exact_pattern_requires_all_args() {
    let config = parse_config(
        r#"
        (rule "git" (exact "status") (effect :allow))
    "#,
    )
    .unwrap();

    let facts = test_context();

    // Exact match
    let result = evaluate_v2("git", &["status".to_string()], &config, &facts);
    assert_eq!(result.decision, Decision::Allow);

    // Extra args - no match
    let result = evaluate_v2(
        "git",
        &["status".to_string(), "--short".to_string()],
        &config,
        &facts,
    );
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_complex_nested_combinators() {
    let config = parse_config(
        r#"
        (rule "kubectl"
            (and
                (or (positional "apply") (positional "delete"))
                (has [:env "prod"]))
            (effect :deny "No mutations in prod"))
    "#,
    )
    .unwrap();

    let mut facts = test_context();
    facts.insert_scalar(":env", "prod".to_string());

    let result = evaluate_v2("kubectl", &["apply".to_string()], &config, &facts);
    assert_eq!(result.decision, Decision::Deny);

    let result = evaluate_v2("kubectl", &["delete".to_string()], &config, &facts);
    assert_eq!(result.decision, Decision::Deny);

    // Non-mutation command should not match
    let result = evaluate_v2("kubectl", &["get".to_string()], &config, &facts);
    assert_eq!(result.decision, Decision::Ask);
}
