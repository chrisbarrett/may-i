// Config validation — run embedded checks against the engine.

use crate::engine;
use may_i_core::{Config, Decision};

/// Result of evaluating a single embedded check.
#[derive(Debug)]
pub struct CheckResult {
    pub command: String,
    pub expected: Decision,
    pub actual: Decision,
    pub passed: bool,
    pub reason: Option<String>,
    pub trace: Vec<String>,
    pub location: Option<String>,
}

/// Run all embedded checks from config rules and compare against expected decisions.
pub fn run_checks(config: &Config) -> Vec<CheckResult> {
    let mut results = Vec::new();

    for rule in &config.rules {
        for check in &rule.checks {
            let eval = engine::evaluate(&check.command, config);
            let location = config
                .source_info
                .as_ref()
                .map(|si| si.location_of(check.source_span));
            results.push(CheckResult {
                command: check.command.clone(),
                expected: check.expected,
                actual: eval.decision,
                passed: eval.decision == check.expected,
                reason: eval.reason,
                trace: eval.trace,
                location,
            });
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_sexpr::Span;
    use may_i_core::{Check, CommandMatcher, Effect, Rule};

    #[test]
    fn run_checks_passing() {
        let config = Config {
            rules: vec![Rule {
                command: CommandMatcher::Exact("ls".into()),
                matcher: None,
                effect: Some(Effect { decision: Decision::Allow, reason: Some("allowed".into()) }),
                checks: vec![Check {
                    command: "ls".into(),
                    expected: Decision::Allow,
                    source_span: Span::new(0, 0),
                }],
                source_span: Span::new(0, 0),
            }],
            ..Config::default()
        };
        let results = run_checks(&config);
        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
        assert_eq!(results[0].expected, Decision::Allow);
        assert_eq!(results[0].actual, Decision::Allow);
    }

    #[test]
    fn run_checks_failing() {
        let config = Config {
            rules: vec![Rule {
                command: CommandMatcher::Exact("ls".into()),
                matcher: None,
                effect: Some(Effect { decision: Decision::Allow, reason: Some("allowed".into()) }),
                checks: vec![Check {
                    command: "ls".into(),
                    expected: Decision::Deny, // wrong expectation
                    source_span: Span::new(0, 0),
                }],
                source_span: Span::new(0, 0),
            }],
            ..Config::default()
        };
        let results = run_checks(&config);
        assert_eq!(results.len(), 1);
        assert!(!results[0].passed);
    }

    #[test]
    fn run_checks_empty() {
        let config = Config::default();
        let results = run_checks(&config);
        assert!(results.is_empty());
    }

    #[test]
    fn run_checks_multiple_rules() {
        let config = Config {
            rules: vec![
                Rule {
                    command: CommandMatcher::Exact("ls".into()),
                    matcher: None,
                    effect: Some(Effect { decision: Decision::Allow, reason: None }),
                    checks: vec![
                        Check { command: "ls".into(), expected: Decision::Allow, source_span: Span::new(0, 0) },
                    ],
                    source_span: Span::new(0, 0),
                },
                Rule {
                    command: CommandMatcher::Exact("rm".into()),
                    matcher: None,
                    effect: Some(Effect { decision: Decision::Deny, reason: None }),
                    checks: vec![
                        Check { command: "rm foo".into(), expected: Decision::Deny, source_span: Span::new(0, 0) },
                    ],
                    source_span: Span::new(0, 0),
                },
            ],
            ..Config::default()
        };
        let results = run_checks(&config);
        assert_eq!(results.len(), 2);
        assert!(results[0].passed);
        assert!(results[1].passed);
    }
}
