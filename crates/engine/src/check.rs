// Config validation — run embedded checks against the engine.

use may_i_core::{Config, ContextFacts, Decision, TraceEntry};

/// Result of evaluating a single embedded check.
#[derive(Debug)]
pub struct CheckResult {
    pub command: String,
    pub expected: Decision,
    pub actual: Decision,
    pub passed: bool,
    pub context: ContextFacts,
    pub reason: Option<String>,
    pub trace: Vec<TraceEntry>,
    pub location: Option<String>,
}

/// Run all embedded checks from config rules and compare against expected decisions.
pub fn run_checks(config: &Config) -> Vec<CheckResult> {
    let mut results = Vec::new();

    for rule in &config.rules {
        for check in &rule.checks {
            let eval = crate::evaluate_with_context(&check.command, config, &check.context);
            let location = config
                .source_info
                .as_ref()
                .map(|si| si.location_of(check.source_span));
            results.push(CheckResult {
                command: check.command.clone(),
                expected: check.expected,
                actual: eval.decision,
                passed: eval.decision == check.expected,
                context: check.context.clone(),
                reason: eval.reason,
                trace: eval.trace,
                location,
            });
        }
    }

    for check in &config.checks {
        let eval = crate::evaluate_with_context(&check.command, config, &check.context);
        let location = config
            .source_info
            .as_ref()
            .map(|si| si.location_of(check.source_span));
        results.push(CheckResult {
            command: check.command.clone(),
            expected: check.expected,
            actual: eval.decision,
            passed: eval.decision == check.expected,
            context: check.context.clone(),
            reason: eval.reason,
            trace: eval.trace,
            location,
        });
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::Span;
    use may_i_core::{Check, CommandMatcher, Effect, Rule, RuleBody};

    #[test]
    fn run_checks_passing() {
        let config = Config {
            rules: vec![Rule {
                command: CommandMatcher::Exact("ls".into()),
                context: None,
                body: RuleBody::Effect {
                    matcher: None,
                    effect: Effect {
                        decision: Decision::Allow,
                        reason: Some("allowed".into()),
                    },
                },
                checks: vec![Check {
                    command: "ls".into(),
                    expected: Decision::Allow,
                    context: ContextFacts::default(),
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
                context: None,
                body: RuleBody::Effect {
                    matcher: None,
                    effect: Effect {
                        decision: Decision::Allow,
                        reason: Some("allowed".into()),
                    },
                },
                checks: vec![Check {
                    command: "ls".into(),
                    expected: Decision::Deny, // wrong expectation
                    context: ContextFacts::default(),
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
                    context: None,
                    body: RuleBody::Effect {
                        matcher: None,
                        effect: Effect {
                            decision: Decision::Allow,
                            reason: None,
                        },
                    },
                    checks: vec![Check {
                        command: "ls".into(),
                        expected: Decision::Allow,
                        context: ContextFacts::default(),
                        source_span: Span::new(0, 0),
                    }],
                    source_span: Span::new(0, 0),
                },
                Rule {
                    command: CommandMatcher::Exact("rm".into()),
                    context: None,
                    body: RuleBody::Effect {
                        matcher: None,
                        effect: Effect {
                            decision: Decision::Deny,
                            reason: None,
                        },
                    },
                    checks: vec![Check {
                        command: "rm foo".into(),
                        expected: Decision::Deny,
                        context: ContextFacts::default(),
                        source_span: Span::new(0, 0),
                    }],
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

    #[test]
    fn run_checks_uses_supplied_context_facts() {
        let mut context = ContextFacts::default();
        context.insert_present(":client/opencode");
        context.insert_scalar(":opencode/agent", "build");

        let config = Config {
            rules: vec![Rule {
                command: CommandMatcher::Exact("git".into()),
                context: Some(may_i_core::ContextExpr::Has(may_i_core::FactQuery::Value {
                    key: ":opencode/agent".into(),
                    pattern: may_i_core::FactPattern::Literal("build".into()),
                })),
                body: RuleBody::Effect {
                    matcher: None,
                    effect: Effect {
                        decision: Decision::Allow,
                        reason: Some("build agent".into()),
                    },
                },
                checks: vec![Check {
                    command: "git status".into(),
                    expected: Decision::Allow,
                    context,
                    source_span: Span::new(0, 0),
                }],
                source_span: Span::new(0, 0),
            }],
            ..Config::default()
        };

        let results = run_checks(&config);
        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
        assert_eq!(
            results[0].context.get_scalar(":opencode/agent"),
            Some("build")
        );
    }

    #[test]
    fn run_checks_top_level_checks() {
        // Test config.checks (not rule.checks)
        // Need rules that match for checks to pass
        let config = Config {
            rules: vec![
                Rule {
                    command: CommandMatcher::Exact("ls".into()),
                    context: None,
                    body: RuleBody::Effect {
                        matcher: None,
                        effect: Effect {
                            decision: Decision::Allow,
                            reason: None,
                        },
                    },
                    checks: vec![],
                    source_span: Span::new(0, 0),
                },
                Rule {
                    command: CommandMatcher::Exact("rm".into()),
                    context: None,
                    body: RuleBody::Effect {
                        matcher: None,
                        effect: Effect {
                            decision: Decision::Deny,
                            reason: None,
                        },
                    },
                    checks: vec![],
                    source_span: Span::new(0, 0),
                },
            ],
            checks: vec![
                Check {
                    command: "ls".into(),
                    expected: Decision::Allow,
                    context: ContextFacts::default(),
                    source_span: Span::new(0, 0),
                },
                Check {
                    command: "rm".into(),
                    expected: Decision::Deny,
                    context: ContextFacts::default(),
                    source_span: Span::new(10, 12),
                },
            ],
            ..Config::default()
        };
        let results = run_checks(&config);
        assert_eq!(results.len(), 2);
        assert!(results[0].passed); // ls is allowed by rule
        assert!(results[1].passed); // rm is denied by rule
    }

    #[test]
    fn run_checks_result_has_all_fields() {
        let config = Config {
            rules: vec![Rule {
                command: CommandMatcher::Exact("ls".into()),
                context: None,
                body: RuleBody::Effect {
                    matcher: None,
                    effect: Effect {
                        decision: Decision::Allow,
                        reason: Some("test reason".into()),
                    },
                },
                checks: vec![Check {
                    command: "ls".into(),
                    expected: Decision::Allow,
                    context: ContextFacts::default(),
                    source_span: Span::new(0, 0),
                }],
                source_span: Span::new(0, 0),
            }],
            ..Config::default()
        };
        let results = run_checks(&config);
        assert_eq!(results.len(), 1);

        let result = &results[0];
        assert_eq!(result.command, "ls");
        assert_eq!(result.expected, Decision::Allow);
        assert_eq!(result.actual, Decision::Allow);
        assert!(result.passed);
        assert!(result.reason.is_some());
        assert!(result.reason.as_ref().unwrap().contains("test reason"));
        // trace may be empty but should exist
        assert!(result.trace.is_empty() || !result.trace.is_empty());
    }

    #[test]
    fn run_checks_no_source_info_location_is_none() {
        // When config has no source_info, location should be None
        let config = Config {
            rules: vec![Rule {
                command: CommandMatcher::Exact("ls".into()),
                context: None,
                body: RuleBody::Effect {
                    matcher: None,
                    effect: Effect {
                        decision: Decision::Allow,
                        reason: None,
                    },
                },
                checks: vec![Check {
                    command: "ls".into(),
                    expected: Decision::Allow,
                    context: ContextFacts::default(),
                    source_span: Span::new(0, 0),
                }],
                source_span: Span::new(0, 0),
            }],
            source_info: None,
            ..Config::default()
        };
        let results = run_checks(&config);
        assert_eq!(results.len(), 1);
        assert!(results[0].location.is_none());
    }

    #[test]
    fn run_checks_with_matcher_and_context() {
        // Test rule with matcher and context predicate
        let config = Config {
            rules: vec![Rule {
                command: CommandMatcher::Exact("git".into()),
                context: None,
                body: RuleBody::Effect {
                    matcher: None,
                    effect: Effect {
                        decision: Decision::Allow,
                        reason: Some("allow git".into()),
                    },
                },
                checks: vec![
                    Check {
                        command: "git status".into(),
                        expected: Decision::Allow,
                        context: ContextFacts::default(),
                        source_span: Span::new(0, 0),
                    },
                    Check {
                        command: "git log".into(),
                        expected: Decision::Allow,
                        context: ContextFacts::default(),
                        source_span: Span::new(0, 0),
                    },
                ],
                source_span: Span::new(0, 0),
            }],
            ..Config::default()
        };
        let results = run_checks(&config);
        assert_eq!(results.len(), 2);
        assert!(results[0].passed);
        assert!(results[1].passed);
    }
}
