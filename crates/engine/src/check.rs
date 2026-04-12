// Config validation — run embedded checks against the engine.

use crate::EvalResult;
use may_i_core::ast::{Check, Config};
use may_i_core::{ContextFacts, Decision};
use may_i_shell_parser::{self as parser, Command};

/// Result of evaluating a single embedded check.
#[derive(Debug)]
pub struct CheckResult<T = ()> {
    pub command: String,
    pub expected: Decision,
    pub actual: Decision,
    pub passed: bool,
    pub context: ContextFacts,
    pub reason: Option<String>,
    pub extra: T,
}

/// Result of parsing a check command string.
pub(crate) enum ParsedCheck {
    /// A simple command with name and arguments.
    Simple(String, Vec<String>),
    /// An empty or assignment-only command.
    Empty,
    /// A compound command (not yet supported).
    Compound,
}

/// Parse a check command string into its components.
pub(crate) fn parse_check_command(input: &str) -> ParsedCheck {
    if let Some((cmd_name, args)) = parser::parse_simple_command(input) {
        ParsedCheck::Simple(cmd_name, args)
    } else {
        match parser::parse(input).command {
            Command::Simple(_) | Command::Assignment(_) => ParsedCheck::Empty,
            _ => ParsedCheck::Compound,
        }
    }
}

/// Evaluate a simple shell command string using the default evaluator.
fn evaluate_simple(input: &str, config: &Config, context: &ContextFacts) -> EvalResult {
    match parse_check_command(input) {
        ParsedCheck::Simple(cmd_name, args) => {
            match crate::eval::evaluate(&cmd_name, &args, config, context) {
                Ok(result) => result,
                Err(e) => EvalResult::new(Decision::Deny, Some(e.to_string())),
            }
        }
        ParsedCheck::Empty => EvalResult::new(Decision::Allow, None),
        ParsedCheck::Compound => EvalResult::new(
            Decision::Ask,
            Some("Compound commands not yet supported in checks".into()),
        ),
    }
}

/// Run all embedded checks from config, using a caller-provided evaluation
/// function. The function receives the full `Check` and returns
/// `(EvalResult, T)` where `T` is any extra data the caller wants to attach
/// (e.g. trace output, location info). Returns `Err` if the evaluation function fails.
pub fn run_checks_with<T, E>(
    config: &Config,
    mut eval_fn: impl FnMut(&Check) -> Result<(EvalResult, T), E>,
) -> Result<Vec<CheckResult<T>>, E> {
    let mut results = Vec::new();

    let checks = config
        .rules
        .iter()
        .flat_map(|rule| rule.checks.iter())
        .chain(config.checks.iter());

    for check in checks {
        let (eval, extra) = eval_fn(check)?;
        results.push(CheckResult {
            command: check.command.clone(),
            expected: check.expected,
            actual: eval.decision,
            passed: eval.decision == check.expected,
            context: check.context.clone(),
            reason: eval.reason,
            extra,
        });
    }

    Ok(results)
}

/// Run all embedded checks using the default evaluator (no extra data).
pub fn run_checks(config: &Config) -> Vec<CheckResult> {
    run_checks_with(config, |check| {
        Ok::<_, std::convert::Infallible>((
            evaluate_simple(&check.command, config, &check.context),
            (),
        ))
    })
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::ast::{Check, Config, Effect, Rule};
    use may_i_core::pattern::CommandPattern;
    use may_i_core::{Decision, Span};

    fn create_test_rule(name: &str, effect: Effect) -> Rule {
        use may_i_core::ast::Spanned;
        Rule {
            command_effect: Spanned::new(
                Effect::CommandPattern(CommandPattern::Literal(name.into())),
                Span::new(0, 0),
            ),
            effect: Spanned::new(effect, Span::new(0, 0)),
            checks: vec![],
            span: Span::new(0, 0),
        }
    }

    #[test]
    fn run_checks_passing() {
        let config = Config {
            rules: vec![create_test_rule(
                "ls",
                Effect::Terminal {
                    decision: Decision::Allow,
                    reason: Some("listed".into()),
                },
            )],
            ..Config::default()
        };

        let check = Check {
            command: "ls -la".into(),
            expected: Decision::Allow,
            context: ContextFacts::default(),
            span: Span::new(0, 0),
        };

        let eval = evaluate_simple(&check.command, &config, &check.context);
        assert_eq!(eval.decision, Decision::Allow);
    }

    #[test]
    fn run_checks_failing() {
        let config = Config {
            rules: vec![create_test_rule(
                "ls",
                Effect::Terminal {
                    decision: Decision::Deny,
                    reason: Some("denied".into()),
                },
            )],
            ..Config::default()
        };

        let check = Check {
            command: "ls".into(),
            expected: Decision::Allow,
            context: ContextFacts::default(),
            span: Span::new(0, 0),
        };

        let eval = evaluate_simple(&check.command, &config, &check.context);
        assert_eq!(eval.decision, Decision::Deny);
    }

    #[test]
    fn compound_command_returns_ask() {
        let config = Config::default();
        let facts = ContextFacts::default();
        let eval = evaluate_simple("ls && rm -rf /", &config, &facts);
        assert_eq!(eval.decision, Decision::Ask);
        assert!(eval.reason.unwrap().contains("Compound"));
    }

    #[test]
    fn empty_command_returns_allow() {
        let config = Config::default();
        let facts = ContextFacts::default();
        let eval = evaluate_simple("", &config, &facts);
        assert_eq!(eval.decision, Decision::Allow);
    }

    #[test]
    fn run_checks_collects_rule_and_config_checks() {
        let s = Span::new(0, 0);
        let rule = Rule {
            command_effect: may_i_core::ast::Spanned::new(
                Effect::CommandPattern(CommandPattern::Literal("echo".into())),
                s,
            ),
            effect: may_i_core::ast::Spanned::new(
                Effect::Terminal {
                    decision: Decision::Allow,
                    reason: Some("ok".into()),
                },
                s,
            ),
            checks: vec![Check {
                command: "echo hi".into(),
                expected: Decision::Allow,
                context: ContextFacts::default(),
                span: s,
            }],
            span: s,
        };

        let config = Config {
            rules: vec![rule],
            checks: vec![Check {
                command: "echo bye".into(),
                expected: Decision::Allow,
                context: ContextFacts::default(),
                span: s,
            }],
            ..Config::default()
        };

        let results = run_checks(&config);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.passed));
    }

    #[test]
    fn unresolved_predicate_returns_error_not_panic() {
        use may_i_core::ast::{Predicate, Spanned};

        let s = Span::new(0, 0);
        let rule = Rule {
            command_effect: Spanned::new(
                Effect::CommandPattern(CommandPattern::Literal("echo".into())),
                s,
            ),
            effect: Spanned::new(
                Effect::When {
                    predicate: Spanned::new(Predicate::Named("undefined".into()), s),
                    effect: Box::new(Spanned::new(
                        Effect::Terminal {
                            decision: Decision::Allow,
                            reason: Some("ok".into()),
                        },
                        s,
                    )),
                },
                s,
            ),
            checks: vec![Check {
                command: "echo hi".into(),
                expected: Decision::Allow,
                context: ContextFacts::default(),
                span: s,
            }],
            span: s,
        };

        let config = Config {
            rules: vec![rule],
            ..Config::default()
        };

        // Should not panic — should return a result with an error diagnostic
        let results = run_checks(&config);
        assert_eq!(results.len(), 1);
        // The check should fail since the predicate can't be resolved
        assert!(!results[0].passed);
    }

    #[test]
    fn word_to_str_with_double_quoted() {
        use may_i_shell_parser::{Word, WordPart};
        let word = Word {
            parts: vec![WordPart::DoubleQuoted(vec![WordPart::Literal(
                "hello world".into(),
            )])],
        };
        assert_eq!(word.to_str(), "hello world");
    }
}
