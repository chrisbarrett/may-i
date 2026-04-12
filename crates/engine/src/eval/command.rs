use may_i_core::ast::Config;
use may_i_core::{ContextFacts, Decision};
use may_i_shell_parser as parser;

use crate::fold::{EvalFold, PureFold};
use crate::{EvalError, EvalResult};

use super::context::DEFAULT_RECURSION_LIMIT;
use super::decompose::{EvalUnit, decompose};
use super::entry::evaluate_with_fold;

/// Evaluate a command string against config and context.
///
/// Parses the input, walks the AST to extract all simple commands and embedded
/// substitutions, evaluates each, and returns the aggregate (most restrictive)
/// decision.
pub fn evaluate_command(
    input: &str,
    config: &Config,
    facts: &ContextFacts,
) -> Result<EvalResult, EvalError> {
    let mut fold = PureFold;
    evaluate_command_with_fold(input, config, facts, &mut fold)
}

/// Evaluate a command string with a custom fold for tracing.
pub fn evaluate_command_with_fold<F: EvalFold>(
    input: &str,
    config: &Config,
    facts: &ContextFacts,
    fold: &mut F,
) -> Result<EvalResult, EvalError> {
    evaluate_command_inner(input, config, facts, fold, 0, DEFAULT_RECURSION_LIMIT)
}

fn evaluate_command_inner<F: EvalFold>(
    input: &str,
    config: &Config,
    facts: &ContextFacts,
    fold: &mut F,
    depth: usize,
    limit: usize,
) -> Result<EvalResult, EvalError> {
    if depth >= limit {
        return Ok(EvalResult::new(
            Decision::Ask,
            Some(format!("recursion depth limit ({limit}) exceeded")),
        ));
    }

    let trimmed = input.trim();
    if trimmed.is_empty() {
        let reason = "empty command".to_string();
        let _out = fold.default_ask(&reason);
        return Ok(EvalResult::new(Decision::Ask, Some(reason)));
    }

    let parse_result = parser::parse(input);
    let diagnostics = parse_result.diagnostics.clone();
    let has_parse_errors = parse_result.has_errors();
    let units = decompose(&parse_result.command);

    if units.is_empty() {
        let reason = "empty command".to_string();
        let _out = fold.default_ask(&reason);
        return Ok(EvalResult::new(Decision::Ask, Some(reason)));
    }

    let mut aggregate_decision = Decision::Allow;
    let mut aggregate_reason: Option<String> = None;

    for unit in &units {
        let result = match unit {
            EvalUnit::SimpleCommand { command, args } => {
                evaluate_with_fold(command, args, config, facts, fold)?
            }
            EvalUnit::EmbeddedCommand { source } => {
                let embedded_result =
                    evaluate_command_inner(source, config, facts, fold, depth + 1, limit)?;
                fold.embedded_command(source, embedded_result.decision);
                embedded_result
            }
            EvalUnit::DynamicCommand { reason } => {
                let _out = fold.default_ask(reason);
                EvalResult::new(Decision::Ask, Some(reason.clone()))
            }
        };

        if result.decision >= aggregate_decision {
            aggregate_decision = result.decision;
            aggregate_reason = result.reason;
        }
    }

    // Error-severity parse diagnostics floor the decision at Ask
    if has_parse_errors && aggregate_decision < Decision::Ask {
        aggregate_decision = Decision::Ask;
        aggregate_reason = Some("parse error: ambiguous command boundary".to_string());
    }

    let mut eval_result = EvalResult::new(aggregate_decision, aggregate_reason);
    eval_result.parse_diagnostics = diagnostics;
    Ok(eval_result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::Span;
    use may_i_core::ast::{Config, Effect, SecurityConfig, Spanned};
    use may_i_core::pattern::CommandPattern;

    fn spanned<T>(value: T) -> Spanned<T> {
        Spanned::new(value, Span::new(0, 0))
    }

    fn config_with_rules(rules: Vec<may_i_core::ast::Rule>) -> Config {
        Config {
            rules,
            defines: vec![],
            security: SecurityConfig::default(),
            checks: vec![],
        }
    }

    fn allow_rule(cmd: &str) -> may_i_core::ast::Rule {
        may_i_core::ast::Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                cmd.to_string(),
            ))),
            effect: spanned(Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            }),
            checks: vec![],
            span: Span::new(0, 0),
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        }
    }

    fn deny_rule(cmd: &str) -> may_i_core::ast::Rule {
        may_i_core::ast::Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                cmd.to_string(),
            ))),
            effect: spanned(Effect::Terminal {
                decision: Decision::Deny,
                reason: Some(format!("{cmd} denied")),
            }),
            checks: vec![],
            span: Span::new(0, 0),
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        }
    }

    fn empty_facts() -> ContextFacts {
        ContextFacts::default()
    }

    // -- Simple command --

    #[test]
    fn simple_allowed_command() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command("echo hello", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn simple_no_rule_asks() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("rm -rf /", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
    }

    // -- Compound commands --

    #[test]
    fn compound_and_most_restrictive() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command("echo hello && rm -rf /", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn compound_deny_wins() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let result = evaluate_command("echo hello; rm -rf /", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn compound_all_allowed() {
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("cat")]);
        let result = evaluate_command("echo a && echo b | cat", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    // -- Embedded commands --

    #[test]
    fn embedded_command_denied() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let result = evaluate_command("echo $(rm -rf /)", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn embedded_command_allowed() {
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("date")]);
        let result = evaluate_command("echo $(date)", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn nested_embedded_command() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let result = evaluate_command("echo $(echo $(rm -rf /))", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    // -- Dynamic command names --

    #[test]
    fn dynamic_command_name_asks() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("$EDITOR file.txt", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_deref().unwrap().contains("dynamic"));
    }

    // -- Empty input --

    #[test]
    fn empty_string_asks() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_deref().unwrap().contains("empty"));
    }

    #[test]
    fn whitespace_only_asks() {
        let config = config_with_rules(vec![]);
        let result = evaluate_command("   ", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
    }

    // -- If/for/case --

    #[test]
    fn if_then_deny() {
        let config = config_with_rules(vec![deny_rule("rm")]);
        let result =
            evaluate_command("if true; then rm -rf /; fi", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn or_evaluates_both_sides() {
        let config = config_with_rules(vec![deny_rule("rm")]);
        let result = evaluate_command("false || rm -rf /", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn case_arm_deny() {
        let config = config_with_rules(vec![allow_rule("echo"), deny_rule("rm")]);
        let result = evaluate_command(
            "case $x in a) rm -rf /;; b) echo hi;; esac",
            &config,
            &empty_facts(),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    // -- Process substitution --

    #[test]
    fn process_substitution_both_allowed() {
        let config = config_with_rules(vec![allow_rule("diff"), allow_rule("ls")]);
        let result = evaluate_command("diff <(ls /a) <(ls /b)", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    // -- Recursion depth limit --

    // -- Parse diagnostics --

    #[test]
    fn parse_error_floors_allowed_at_ask() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        // Unterminated double quote — Error severity
        let result = evaluate_command(r#"echo "hello; rm -rf /"#, &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Ask);
        assert!(!result.parse_diagnostics.is_empty());
    }

    #[test]
    fn parse_error_does_not_downgrade_deny() {
        let config = config_with_rules(vec![deny_rule("rm")]);
        // Unterminated quote + denied command — deny > ask
        let result = evaluate_command(r#"rm "unterminated"#, &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn parse_warning_does_not_floor() {
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("true")]);
        // Missing fi — Warning severity
        let result = evaluate_command("if true; then echo hello", &config, &empty_facts()).unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert!(!result.parse_diagnostics.is_empty());
    }

    #[test]
    fn well_formed_has_no_diagnostics() {
        let config = config_with_rules(vec![allow_rule("echo")]);
        let result = evaluate_command("echo hello", &config, &empty_facts()).unwrap();
        assert!(result.parse_diagnostics.is_empty());
    }

    #[test]
    fn recursion_depth_limit() {
        let config = config_with_rules(vec![allow_rule("echo"), allow_rule("rm")]);
        // Create deeply nested: $(echo $(echo $(echo ...$(rm /)...)))
        let mut input = "rm /".to_string();
        for _ in 0..15 {
            input = format!("echo $({input})");
        }
        let result = evaluate_command(&input, &config, &empty_facts()).unwrap();
        // Should hit depth limit and return Ask
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_deref().unwrap().contains("depth"));
    }
}
