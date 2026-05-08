// Integration tests for unified rule DSL end-to-end evaluation.

use crate::evaluate;
use may_i_config::{parse_config, resolve::validate_and_resolve};
use may_i_core::types::{ContextFacts, Decision};
use may_i_core::Keyword;

fn kw(s: &str) -> Keyword {
    Keyword::new(s).unwrap()
}

fn test_context() -> ContextFacts {
    ContextFacts::default()
}

#[test]
fn integration_simple_allow_rule() {
    let config = parse_config(
        r#"
        (rule "git" :effect :allow)
    "#,
    )
    .unwrap();

    let facts = test_context();
    let result = evaluate("git", &[], &config, &facts).unwrap();

    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn integration_simple_deny_rule() {
    let config = parse_config(
        r#"
        (rule "rm" :effect [:deny "rm is dangerous"])
    "#,
    )
    .unwrap();

    let facts = test_context();
    let result = evaluate("rm", &[], &config, &facts).unwrap();

    assert_eq!(result.decision, Decision::Deny);
    assert!(result.reason.unwrap().contains("dangerous"));
}

#[test]
fn integration_rule_with_fact_predicate() {
    let config = parse_config(
        r#"
        (rule "git"
            (when (fact? :via/ssh) (ask "SSH operations require confirmation"))
            :effect (deny))
    "#,
    )
    .unwrap();

    let mut facts = test_context();
    facts.insert_present(kw(":via/ssh"));

    let result = evaluate("git", &[], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_rule_with_arg_pattern() {
    let config = parse_config(
        r#"
        (rule "git" (positional "push") :effect :allow)
    "#,
    )
    .unwrap();

    let facts = test_context();
    let result = evaluate("git", &["push".to_string()], &config, &facts).unwrap();

    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn integration_rule_with_and_combinator() {
    let config = parse_config(
        r#"
        (rule "git"
            (when (and (fact? :via/ssh) (positional "push")) (ask))
            :effect (deny))
    "#,
    )
    .unwrap();

    let mut facts = test_context();
    facts.insert_present(kw(":via/ssh"));

    let result = evaluate("git", &["push".to_string()], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_rule_with_or_combinator() {
    let config = parse_config(
        r#"
        (rule "git"
            (when (or (positional "push") (positional "pull")) (allow))
            :effect (deny))
    "#,
    )
    .unwrap();

    let facts = test_context();

    let result = evaluate("git", &["push".to_string()], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Allow);

    let result = evaluate("git", &["pull".to_string()], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn integration_rule_with_not_combinator() {
    let config = parse_config(
        r#"
        (rule "git"
            (when (not (anywhere "--force")) (allow))
            :effect (deny))
    "#,
    )
    .unwrap();

    let facts = test_context();

    // Without --force, should allow
    let result = evaluate("git", &["push".to_string()], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Allow);

    // With --force, should deny (default effect)
    let result = evaluate(
        "git",
        &["push".to_string(), "--force".to_string()],
        &config,
        &facts,
    ).unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn integration_rule_with_when_effect() {
    let config = parse_config(
        r#"
        (rule "git"
            (when (fact? :via/ssh) (ask))
            :effect (deny))
    "#,
    )
    .unwrap();

    let mut facts = test_context();
    facts.insert_present(kw(":via/ssh"));

    let result = evaluate("git", &[], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_rule_with_unless_effect() {
    let config = parse_config(
        r#"
        (rule "git"
            (unless (fact? :local) (ask))
            :effect (allow))
    "#,
    )
    .unwrap();

    let facts = test_context();
    // No :local fact, so should ask
    let result = evaluate("git", &[], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_rule_with_if_effect() {
    let config = parse_config(
        r#"
        (rule "git"
            (if (fact? :via/ssh) (ask) (allow))
            :effect (deny))
    "#,
    )
    .unwrap();

    let mut facts = test_context();
    facts.insert_present(kw(":via/ssh"));

    let result = evaluate("git", &[], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_rule_with_case_effect() {
    // Note: 'case' was renamed to 'cond' in the unified effect model
    let config = parse_config(
        r#"
        (rule "git"
            (cond
                ((positional "push") (ask))
                ((positional "pull") (allow))
                (else (deny)))
            :effect (deny))
    "#,
    )
    .unwrap();

    let facts = test_context();

    let result = evaluate("git", &["push".to_string()], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Ask);

    let result = evaluate("git", &["pull".to_string()], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Allow);

    let result = evaluate("git", &["status".to_string()], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn integration_named_predicate_with_define() {
    let config = parse_config(
        r#"
        (define ssh-session (fact? :via/ssh))
        (rule "git"
            (when ssh-session (ask))
            :effect (deny))
    "#,
    )
    .unwrap();

    // Resolve named predicates before evaluation
    let resolved_rules = validate_and_resolve(&config.rules, &config.defines).unwrap();

    let mut resolved_config = config;
    resolved_config.rules = resolved_rules;

    let mut facts = test_context();
    facts.insert_present(kw(":via/ssh"));

    let result = evaluate("git", &[], &resolved_config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_multiple_rules_most_restrictive_wins() {
    // In the unified effect model, rules are evaluated in order.
    // More specific rules should come first.
    // Use 'when' to combine pattern matching with the desired effect.
    let config = parse_config(
        r#"
        (rule "git"
            (when (positional "rm") (deny "git rm is restricted"))
            :effect (allow))
    "#,
    )
    .unwrap();

    let facts = test_context();

    // git rm should deny (specific pattern matches)
    let result = evaluate("git", &["rm".to_string()], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Deny);

    // Simple git should allow (falls through to default effect)
    let result = evaluate("git", &[], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn integration_or_command_pattern() {
    let config = parse_config(
        r#"
        (rule (or "git" "gh") :effect :allow)
    "#,
    )
    .unwrap();

    let facts = test_context();

    let result = evaluate("git", &[], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Allow);

    let result = evaluate("gh", &[], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Allow);

    let result = evaluate("hg", &[], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_forbidden_pattern() {
    let config = parse_config(
        r#"
        (rule "git"
            (when (forbidden "--force") (allow))
            :effect (deny))
    "#,
    )
    .unwrap();

    let facts = test_context();

    // Without --force, should allow
    let result = evaluate("git", &["push".to_string()], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Allow);

    // With --force, should not match
    let result = evaluate(
        "git",
        &["push".to_string(), "--force".to_string()],
        &config,
        &facts,
    ).unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn integration_anywhere_pattern() {
    let config = parse_config(
        r#"
        (rule "rm"
            (when (anywhere "-r") (ask "Recursive delete requires confirmation"))
            :effect (allow))
    "#,
    )
    .unwrap();

    let facts = test_context();

    let result = evaluate(
        "rm",
        &["-r".to_string(), "foo".to_string()],
        &config,
        &facts,
    ).unwrap();
    assert_eq!(result.decision, Decision::Ask);

    let result = evaluate("rm", &["foo".to_string()], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn integration_no_matching_rule_returns_ask() {
    let config = parse_config(
        r#"
        (rule "git" :effect :allow)
    "#,
    )
    .unwrap();

    let facts = test_context();

    let result = evaluate("hg", &[], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_exact_pattern_requires_all_args() {
    let config = parse_config(
        r#"
        (rule "git"
            (when (exact "status") (allow))
            :effect (ask))
    "#,
    )
    .unwrap();

    let facts = test_context();

    // Exact match
    let result = evaluate("git", &["status".to_string()], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Allow);

    // Extra positional args - no match (flags are ignored by exact)
    let result = evaluate(
        "git",
        &["status".to_string(), "extra".to_string()],
        &config,
        &facts,
    ).unwrap();
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn integration_complex_nested_combinators() {
    let config = parse_config(
        r#"
        (rule "kubectl"
            (when (and
                (or (positional "apply") (positional "delete"))
                (fact? [:env "prod"]))
                (deny "No mutations in prod"))
            :effect (allow))
    "#,
    )
    .unwrap();

    let mut facts = test_context();
    facts.insert_scalar(kw(":env"), "prod".to_string());

    let result = evaluate("kubectl", &["apply".to_string()], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Deny);

    let result = evaluate("kubectl", &["delete".to_string()], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Deny);

    // Non-mutation command should not match the when clause, use default
    let result = evaluate("kubectl", &["get".to_string()], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn integration_dot_notation_simple() {
    // (positional "git" . (allow)) matches "git" followed by anything
    let config = parse_config(
        r#"
        (rule "cmd"
            (positional "git" . (allow))
            :effect (deny))
    "#,
    )
    .unwrap();

    let facts = test_context();

    // Should match "git" and return Allow via continuation
    let result = evaluate(
        "cmd",
        &["git".to_string(), "push".to_string()],
        &config,
        &facts,
    ).unwrap();
    assert_eq!(result.decision, Decision::Allow);

    // Should match "git" and return Allow via continuation
    let result = evaluate(
        "cmd",
        &["git".to_string(), "status".to_string()],
        &config,
        &facts,
    ).unwrap();
    assert_eq!(result.decision, Decision::Allow);

    // Should not match "hg", fall through to default
    let result = evaluate(
        "cmd",
        &["hg".to_string(), "status".to_string()],
        &config,
        &facts,
    ).unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn integration_dot_notation_with_may_i() {
    // SSH-style wrapper: capture first arg as "host", recursively evaluate rest
    let config = parse_config(
        r#"
        (rule "ssh"
            (positional * . (may-i (positional *)))
            :effect (deny "No SSH allowed by default"))
        
        (rule "ls" :effect :allow)
        (rule "rm" :effect [:deny "rm is dangerous"])
    "#,
    )
    .unwrap();

    let facts = test_context();

    // ssh host1 ls -> should allow (ls is allowed)
    let result = evaluate(
        "ssh",
        &["host1".to_string(), "ls".to_string(), "-la".to_string()],
        &config,
        &facts,
    ).unwrap();
    assert_eq!(result.decision, Decision::Allow);

    // ssh host1 rm -> should deny (rm is denied)
    let result = evaluate(
        "ssh",
        &["host1".to_string(), "rm".to_string(), "-rf".to_string()],
        &config,
        &facts,
    ).unwrap();
    assert_eq!(result.decision, Decision::Deny);

    // ssh (no args after host) -> should fall through to default
    let result = evaluate("ssh", &["host1".to_string()], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn integration_dot_notation_exact() {
    // Exact with dot: match exactly, then evaluate continuation
    // Note: exact patterns skip flags, so "--short" is not counted
    let config = parse_config(
        r#"
        (rule "cmd"
            (exact "git" "status" . (allow))
            :effect (deny))
    "#,
    )
    .unwrap();

    let facts = test_context();

    // Exact match for "git status"
    let result = evaluate(
        "cmd",
        &["git".to_string(), "status".to_string()],
        &config,
        &facts,
    ).unwrap();
    assert_eq!(result.decision, Decision::Allow);

    // With flag - exact pattern still matches because flags are skipped
    // The continuation (allow) is evaluated
    let result = evaluate(
        "cmd",
        &[
            "git".to_string(),
            "status".to_string(),
            "--short".to_string(),
        ],
        &config,
        &facts,
    ).unwrap();
    assert_eq!(result.decision, Decision::Allow);

    // Extra positional arg - exact match fails, falls through to default
    let result = evaluate(
        "cmd",
        &["git".to_string(), "status".to_string(), "extra".to_string()],
        &config,
        &facts,
    ).unwrap();
    assert_eq!(result.decision, Decision::Deny);
}
