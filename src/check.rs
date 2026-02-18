// Config validation — run embedded examples against the engine.

use crate::engine;
use crate::types::{Config, Decision};

/// Result of evaluating a single embedded example.
#[derive(Debug)]
pub struct ExampleResult {
    pub command: String,
    pub expected: Decision,
    pub actual: Decision,
    pub passed: bool,
}

/// Run all embedded examples from config rules and compare against expected decisions.
pub fn check_examples(config: &Config) -> Vec<ExampleResult> {
    let mut results = Vec::new();

    for rule in &config.rules {
        for example in &rule.examples {
            let eval = engine::evaluate(&example.command, config);
            results.push(ExampleResult {
                command: example.command.clone(),
                expected: example.expected,
                actual: eval.decision,
                passed: eval.decision == example.expected,
            });
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CommandMatcher, Example, Rule};

    #[test]
    fn check_examples_passing() {
        let config = Config {
            rules: vec![Rule {
                command: CommandMatcher::Exact("ls".into()),
                matcher: None,
                decision: Some(Decision::Allow),
                reason: Some("allowed".into()),
                examples: vec![Example {
                    command: "ls".into(),
                    expected: Decision::Allow,
                }],
            }],
            ..Config::default()
        };
        let results = check_examples(&config);
        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
        assert_eq!(results[0].expected, Decision::Allow);
        assert_eq!(results[0].actual, Decision::Allow);
    }

    #[test]
    fn check_examples_failing() {
        let config = Config {
            rules: vec![Rule {
                command: CommandMatcher::Exact("ls".into()),
                matcher: None,
                decision: Some(Decision::Allow),
                reason: Some("allowed".into()),
                examples: vec![Example {
                    command: "ls".into(),
                    expected: Decision::Deny, // wrong expectation
                }],
            }],
            ..Config::default()
        };
        let results = check_examples(&config);
        assert_eq!(results.len(), 1);
        assert!(!results[0].passed);
    }

    #[test]
    fn check_examples_empty() {
        let config = Config::default();
        let results = check_examples(&config);
        assert!(results.is_empty());
    }

    #[test]
    fn check_examples_multiple_rules() {
        let config = Config {
            rules: vec![
                Rule {
                    command: CommandMatcher::Exact("ls".into()),
                    matcher: None,
                    decision: Some(Decision::Allow),
                    reason: None,
                    examples: vec![
                        Example { command: "ls".into(), expected: Decision::Allow },
                    ],
                },
                Rule {
                    command: CommandMatcher::Exact("rm".into()),
                    matcher: None,
                    decision: Some(Decision::Deny),
                    reason: None,
                    examples: vec![
                        Example { command: "rm foo".into(), expected: Decision::Deny },
                    ],
                },
            ],
            ..Config::default()
        };
        let results = check_examples(&config);
        assert_eq!(results.len(), 2);
        assert!(results[0].passed);
        assert!(results[1].passed);
    }
}
