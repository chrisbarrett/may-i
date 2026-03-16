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
    fn run_checks_supports_nested_with_facts_scopes() {
        let config = may_i_config::parse::parse(
            r#"(rule (command "git")
                   (context (has [:opencode/agent "build"]))
                   (effect :allow "build agent")
                   (check
                     (with-facts [[:client/opencode]]
                       (with-facts [[:opencode/agent "build"]]
                         :allow "git status")
                       (with-facts [[:opencode/agent "plan"]]
                         :ask "git status"))))"#,
            "<test>",
        )
        .expect("config parses");

        let results = run_checks(&config);
        assert_eq!(results.len(), 2);
        assert!(results[0].passed);
        assert_eq!(results[0].actual, Decision::Allow);
        assert_eq!(results[1].actual, Decision::Ask);
        assert_eq!(
            results[0].context.get_scalar(":opencode/agent"),
            Some("build")
        );
        assert_eq!(
            results[1].context.get_scalar(":opencode/agent"),
            Some("plan")
        );
    }
}
