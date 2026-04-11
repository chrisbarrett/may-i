use super::*;

// ── Property tests ────────────────────────────────────────────────

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig { cases: 256, max_shrink_iters: 50, .. Default::default() })]

    #[test]
    fn expr_cond_matches_iff_any_branch_test_matches(
        branches_tests in proptest::collection::vec(
            crate::test_generators::any_match_string(),
            1..5,
        ),
        value in crate::test_generators::any_match_string(),
    ) {
        use may_i_core::pattern::{Expr, ExprBranch};

        let branches: Vec<ExprBranch<Effect>> = branches_tests
            .iter()
            .map(|s| ExprBranch {
                test: Expr::Literal(s.clone()),
                effect: Effect::Terminal { decision: Decision::Allow, reason: None },
            })
            .collect();

        let expr = Expr::Cond(branches);
        let (matched, _facts) = match_expr_with_binding(&expr, &value);
        let expected = branches_tests.iter().any(|s| s == &value);
        proptest::prop_assert_eq!(matched, expected);
    }

    #[test]
    fn build_expr_match_detail_consistency(
        expr in crate::test_generators::any_expr(2),
        value in crate::test_generators::any_match_string(),
    ) {
        use may_i_core::pattern::Expr;

        let detail = build_expr_match_detail(&expr, &value);
        let (matched, _) = match_expr_with_binding(&expr, &value);

        match &expr {
            Expr::Literal(_) => {
                let d = detail.expect("Literal should produce detail");
                if let crate::fold::ExprMatchDetail::Literal { matched: dm, .. } = d {
                    proptest::prop_assert_eq!(dm, matched);
                } else {
                    return Err(proptest::test_runner::TestCaseError::Fail("expected Literal detail".into()));
                }
            }
            Expr::Wildcard => {
                let d = detail.expect("Wildcard should produce detail");
                let is_wildcard = matches!(d, crate::fold::ExprMatchDetail::Wildcard { .. });
                proptest::prop_assert!(is_wildcard);
            }
            // Compound expressions return None
            _ => {
                proptest::prop_assert!(detail.is_none());
            }
        }
    }
}

// --- Targeted branch-coverage unit tests ---

#[test]
fn build_expr_match_detail_regex() {
    use may_i_core::pattern::Expr;

    let expr: Expr<Effect> = Expr::Regex(regex::Regex::new("^prod").unwrap());
    let detail = build_expr_match_detail(&expr, "prod-01");
    match detail {
        Some(crate::fold::ExprMatchDetail::Regex {
            pattern,
            actual,
            matched,
        }) => {
            assert_eq!(pattern, "^prod");
            assert_eq!(actual, "prod-01");
            assert!(matched);
        }
        other => panic!("expected Regex detail, got {other:?}"),
    }

    let detail_miss = build_expr_match_detail(&expr, "dev-01");
    match detail_miss {
        Some(crate::fold::ExprMatchDetail::Regex { matched, .. }) => {
            assert!(!matched);
        }
        other => panic!("expected Regex detail, got {other:?}"),
    }
}

#[test]
fn match_command_pattern_or_with_regex() {
    let re = regex::Regex::new("^git").unwrap();
    let pat = CommandPattern::Or(vec![
        CommandPattern::Literal("ls".into()),
        CommandPattern::Regex(re),
    ]);
    assert!(match_command_pattern(&pat, "ls"));
    assert!(match_command_pattern(&pat, "git-push"));
    assert!(!match_command_pattern(&pat, "rm"));
}

#[test]
fn extract_inner_command_fallback_for_non_simple() {
    // A compound command (with &&) should hit the fallback branch
    let args = vec!["echo".to_string(), "&&".to_string(), "ls".to_string()];
    let result = extract_inner_command(
        &may_i_core::pattern::ArgPattern::Ordered {
            mode: MatchMode::Positional,
            patterns: vec![],
            continuation: None,
        },
        &args,
    );
    // Should return Some — either parsed or fallback
    assert!(result.is_some());
}

#[test]
fn evaluate_fallback_reason_command_matched_but_args_failed() {
    use may_i_core::ast::{Config, Rule, Spanned};
    use may_i_core::pattern::{ArgPattern, CommandPattern, Expr, PositionalArg, Quantifier};
    use may_i_core::span::Span;

    let s = Span::new(0, 1);
    // Rule: "ls" with (positional "specific-arg") — will not match "ls other"
    let rule = Rule::new(
        Spanned::new(
            Effect::CommandPattern(CommandPattern::Literal("ls".into())),
            s,
        ),
        Spanned::new(
            Effect::ArgPattern(ArgPattern::Ordered {
                mode: MatchMode::Positional,
                patterns: vec![PositionalArg {
                    quantifier: Quantifier::One,
                    pattern: Expr::Literal("specific-arg".into()),
                    recursive: false,
                }],
                continuation: None,
            }),
            s,
        ),
        vec![],
        s,
    );

    let config = Config {
        rules: vec![rule],
        ..Config::default()
    };
    let facts = ContextFacts::default();
    let args = vec!["other".to_string()];
    let result = evaluate("ls", &args, &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Ask);
    assert!(
        result.reason.as_ref().unwrap().contains("ls"),
        "reason should mention the command: {:?}",
        result.reason
    );
}

#[test]
fn evaluate_rule_nil_short_circuits() {
    use may_i_core::ast::{Rule, Spanned};
    use may_i_core::pattern::{ArgPattern, CommandPattern, Expr};
    use may_i_core::span::Span;

    let s = Span::new(0, 1);
    // Rule with (forbidden "bad") — if arg is present, Nil is returned
    let rule = Rule::new(
        Spanned::new(
            Effect::CommandPattern(CommandPattern::Literal("test".into())),
            s,
        ),
        Spanned::new(
            Effect::ArgPattern(ArgPattern::Forbidden(vec![Expr::Literal("bad".into())])),
            s,
        ),
        vec![],
        s,
    );

    let rules = vec![rule];
    let facts = ContextFacts::default();
    let args = vec!["bad".to_string()];
    let ctx = EvalContext::new("test", &args, &facts, Default::default());
    let evaluator = Evaluator::new(&rules);
    let result = evaluator.evaluate(&mut PureFold, &ctx).unwrap();
    // Forbidden found → Nil → rule_not_matched → falls through to ask
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn evaluate_rule_predicate_allow_continues() {
    use may_i_core::ast::{Rule, Spanned};
    use may_i_core::pattern::{ArgPattern, CommandPattern, Expr, PositionalArg, Quantifier};
    use may_i_core::span::Span;

    let s = Span::new(0, 1);
    // Rule: "cmd" (and (positional "ok") :allow "done")
    // The positional predicate matches, continues, then terminal fires.
    let rule = Rule::new(
        Spanned::new(
            Effect::CommandPattern(CommandPattern::Literal("cmd".into())),
            s,
        ),
        Spanned::new(
            Effect::And {
                effects: vec![
                    Spanned::new(
                        Effect::ArgPattern(ArgPattern::Ordered {
                            mode: MatchMode::Positional,
                            patterns: vec![PositionalArg {
                                quantifier: Quantifier::One,
                                pattern: Expr::Literal("ok".into()),
                                recursive: false,
                            }],
                            continuation: None,
                        }),
                        s,
                    ),
                    Spanned::new(
                        Effect::Terminal {
                            decision: Decision::Allow,
                            reason: Some("done".into()),
                        },
                        s,
                    ),
                ],
            },
            s,
        ),
        vec![],
        s,
    );

    let rules = vec![rule];
    let facts = ContextFacts::default();
    let args = vec!["ok".to_string()];
    let ctx = EvalContext::new("cmd", &args, &facts, Default::default());
    let evaluator = Evaluator::new(&rules);
    let result = evaluator.evaluate(&mut PureFold, &ctx).unwrap();
    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(result.reason.as_deref(), Some("done"));
}

#[test]
fn build_positional_element_details_with_bind() {
    use may_i_core::Keyword;
    use may_i_core::pattern::{Expr, PositionalArg, Quantifier};

    let patterns = vec![PositionalArg {
        quantifier: Quantifier::One,
        pattern: Expr::Bind {
            key: Keyword::new(":host").unwrap(),
            expr: Box::new(Expr::Wildcard),
        },
        recursive: false,
    }];

    let arg = "prod-01".to_string();
    let args: Vec<&String> = vec![&arg];
    let details = build_positional_element_details(&args, &patterns, true, 1);
    assert_eq!(details.len(), 1);
    let detail = &details[0];
    assert!(detail.binding.is_some());
    let bind = detail.binding.as_ref().unwrap();
    assert_eq!(bind.key.to_string(), ":host");
    assert_eq!(bind.value, Some("prod-01".to_string()));
}

#[test]
fn build_positional_element_details_with_cond_branch_index() {
    use may_i_core::pattern::{Expr, ExprBranch, PositionalArg, Quantifier};

    let patterns = vec![PositionalArg {
        quantifier: Quantifier::One,
        pattern: Expr::Cond(vec![
            ExprBranch {
                test: Expr::Literal("a".into()),
                effect: Effect::Terminal {
                    decision: Decision::Allow,
                    reason: None,
                },
            },
            ExprBranch {
                test: Expr::Literal("b".into()),
                effect: Effect::Terminal {
                    decision: Decision::Deny,
                    reason: None,
                },
            },
        ]),
        recursive: false,
    }];

    let arg = "b".to_string();
    let args: Vec<&String> = vec![&arg];
    let details = build_positional_element_details(&args, &patterns, true, 1);
    assert_eq!(details.len(), 1);
    assert!(matches!(
        details[0].match_kind,
        crate::fold::PositionalMatchKind::CondBranch(1)
    ));
}

// --- FactPattern combinator tests ---

#[test]
fn match_fact_pattern_and() {
    let pat = FactPattern::And(vec![
        FactPattern::Regex(regex::Regex::new("^prod").unwrap()),
        FactPattern::Regex(regex::Regex::new("server$").unwrap()),
    ]);
    assert!(match_fact_pattern(&pat, "prod-server"));
    assert!(!match_fact_pattern(&pat, "prod-host"));
    assert!(!match_fact_pattern(&pat, "dev-server"));
}

#[test]
fn match_fact_pattern_or() {
    let pat = FactPattern::Or(vec![
        FactPattern::Literal("a".to_string()),
        FactPattern::Literal("b".to_string()),
    ]);
    assert!(match_fact_pattern(&pat, "a"));
    assert!(match_fact_pattern(&pat, "b"));
    assert!(!match_fact_pattern(&pat, "c"));
}

#[test]
fn match_fact_pattern_not() {
    let pat = FactPattern::Not(Box::new(FactPattern::Literal("bad".to_string())));
    assert!(!match_fact_pattern(&pat, "bad"));
    assert!(match_fact_pattern(&pat, "good"));
}

#[test]
fn match_fact_pattern_nested_combinators() {
    // (and (not "exclude") (or "a" "b"))
    let pat = FactPattern::And(vec![
        FactPattern::Not(Box::new(FactPattern::Literal("exclude".to_string()))),
        FactPattern::Or(vec![
            FactPattern::Literal("a".to_string()),
            FactPattern::Literal("b".to_string()),
        ]),
    ]);
    assert!(match_fact_pattern(&pat, "a"));
    assert!(match_fact_pattern(&pat, "b"));
    assert!(!match_fact_pattern(&pat, "c"));
    assert!(!match_fact_pattern(&pat, "exclude"));
}

// --- Backtracking tests ---

#[test]
fn zero_or_more_wildcard_backtracks_for_required() {
    use may_i_core::pattern::PositionalArg;
    use may_i_core::{Expr, Quantifier};

    // (* *) "end" — wildcard * greedily consumes all, must backtrack for "end"
    let patterns = vec![
        PositionalArg {
            quantifier: Quantifier::ZeroOrMore,
            pattern: Expr::Wildcard,
            recursive: false,
        },
        PositionalArg {
            quantifier: Quantifier::One,
            pattern: Expr::Literal("end".to_string()),
            recursive: false,
        },
    ];

    let args_owned: Vec<String> = vec!["a", "b", "c", "end"]
        .into_iter()
        .map(String::from)
        .collect();
    let args: Vec<&String> = args_owned.iter().collect();
    let (matched, consumed, _) = match_positional_patterns(&args, &patterns);
    assert!(matched);
    assert_eq!(consumed, 4);
}

#[test]
fn one_or_more_wildcard_backtracks_for_required() {
    use may_i_core::pattern::PositionalArg;
    use may_i_core::{Expr, Quantifier};

    // (+ *) "end" — must consume at least 1, then backtrack for "end"
    let patterns = vec![
        PositionalArg {
            quantifier: Quantifier::OneOrMore,
            pattern: Expr::Wildcard,
            recursive: false,
        },
        PositionalArg {
            quantifier: Quantifier::One,
            pattern: Expr::Literal("end".to_string()),
            recursive: false,
        },
    ];

    let args_owned: Vec<String> = vec!["x", "y", "end"]
        .into_iter()
        .map(String::from)
        .collect();
    let args: Vec<&String> = args_owned.iter().collect();
    let (matched, consumed, _) = match_positional_patterns(&args, &patterns);
    assert!(matched);
    assert_eq!(consumed, 3);
}

#[test]
fn one_or_more_wildcard_fails_when_only_required() {
    use may_i_core::pattern::PositionalArg;
    use may_i_core::{Expr, Quantifier};

    // (+ *) "end" with args ["end"] — can't consume 1+ AND have "end" left
    let patterns = vec![
        PositionalArg {
            quantifier: Quantifier::OneOrMore,
            pattern: Expr::Wildcard,
            recursive: false,
        },
        PositionalArg {
            quantifier: Quantifier::One,
            pattern: Expr::Literal("end".to_string()),
            recursive: false,
        },
    ];

    let args_owned = ["end".to_string()];
    let args: Vec<&String> = args_owned.iter().collect();
    let (matched, _, _) = match_positional_patterns(&args, &patterns);
    assert!(!matched);
}

// --- check.rs coverage: compound commands and run_checks ---

#[test]
fn evaluate_empty_command() {
    let config = may_i_core::ast::Config::default();
    let facts = ContextFacts::default();
    let result = crate::check::run_checks(&config);
    assert!(result.is_empty());

    // Also: assignment-only commands should be allowed
    let result = crate::eval::evaluate("", &[], &config, &facts).unwrap();
    assert_eq!(result.decision, Decision::Ask);
}

#[test]
fn run_checks_with_rule_level_checks() {
    use may_i_core::ast::{Check, Config, Rule, Spanned};
    use may_i_core::pattern::CommandPattern;
    use may_i_core::span::Span;

    let s = Span::new(0, 1);
    let rule = Rule {
        command_effect: Spanned::new(
            Effect::CommandPattern(CommandPattern::Literal("ls".into())),
            s,
        ),
        effect: Spanned::new(
            Effect::Terminal {
                decision: Decision::Allow,
                reason: Some("ok".into()),
            },
            s,
        ),
        checks: vec![Check {
            command: "ls -la".into(),
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

    let results = crate::check::run_checks(&config);
    assert_eq!(results.len(), 1);
    assert!(results[0].passed);
}

#[test]
fn run_checks_with_config_level_checks() {
    use may_i_core::ast::{Check, Config, Rule, Spanned};
    use may_i_core::pattern::CommandPattern;
    use may_i_core::span::Span;

    let s = Span::new(0, 1);
    let rule = Rule {
        command_effect: Spanned::new(
            Effect::CommandPattern(CommandPattern::Literal("git".into())),
            s,
        ),
        effect: Spanned::new(
            Effect::Terminal {
                decision: Decision::Deny,
                reason: Some("no git".into()),
            },
            s,
        ),
        checks: vec![],
        span: s,
    };

    let config = Config {
        rules: vec![rule],
        checks: vec![Check {
            command: "git push".into(),
            expected: Decision::Deny,
            context: ContextFacts::default(),
            span: s,
        }],
        ..Config::default()
    };

    let results = crate::check::run_checks(&config);
    assert_eq!(results.len(), 1);
    assert!(results[0].passed);
    assert_eq!(results[0].actual, Decision::Deny);
}

#[test]
fn or_short_circuits_bindings_on_first_match() {
    use may_i_core::Keyword;
    use may_i_core::pattern::Expr;

    let expr: Expr = Expr::Or(vec![
        Expr::Bind {
            key: Keyword::new(":x").unwrap(),
            expr: Box::new(Expr::Wildcard),
        },
        Expr::Bind {
            key: Keyword::new(":y").unwrap(),
            expr: Box::new(Expr::Wildcard),
        },
    ]);

    let (matched, facts) = match_expr_with_binding(&expr, "val");
    assert!(matched);
    assert!(facts.has(&kw(":x")));
    assert_eq!(facts.get_scalar(&kw(":x")), Some("val"));
    assert!(
        !facts.has(&kw(":y")),
        "second Or alternative should not bind :y"
    );
}

#[test]
fn cond_short_circuits_predicates_after_first_match() {
    use crate::fold::ChildResult;
    use std::sync::{Arc, Mutex};

    // Record what effect_cond receives
    #[derive(Clone)]
    struct RecordingFold {
        cond_branches: Arc<Mutex<Vec<(bool, bool)>>>, // (pred_evaluated, body_evaluated)
    }

    impl EvalFold for RecordingFold {
        type EffectOut = EffectResult;
        type PredicateOut = PredicateResult;

        fn effect_result(out: &EffectResult) -> &EffectResult {
            out
        }
        fn predicate_result(out: &PredicateResult) -> PredicateResult {
            *out
        }

        fn effect_terminal(&mut self, _: &Effect, result: EffectResult) -> EffectResult {
            result
        }
        fn effect_nil(&mut self, _: &Effect) -> EffectResult {
            EffectResult::Nil
        }
        fn effect_command_match(
            &mut self,
            _: &CommandPattern,
            _: &str,
            matched: bool,
        ) -> EffectResult {
            if matched {
                EffectResult::Decision(Decision::Allow, None)
            } else {
                EffectResult::Nil
            }
        }
        fn effect_arg_match(
            &mut self,
            _: &ArgPattern,
            _: &[String],
            matched: bool,
            _: crate::fold::ArgMatchDetail,
        ) -> EffectResult {
            if matched {
                EffectResult::Decision(Decision::Allow, None)
            } else {
                EffectResult::Nil
            }
        }
        fn effect_and(
            &mut self,
            _: Vec<ChildResult<EffectResult>>,
            result: EffectResult,
        ) -> EffectResult {
            result
        }
        fn effect_or(
            &mut self,
            _: Vec<ChildResult<EffectResult>>,
            result: EffectResult,
        ) -> EffectResult {
            result
        }
        fn effect_not(&mut self, _: EffectResult, result: EffectResult) -> EffectResult {
            result
        }
        fn effect_when(
            &mut self,
            _: PredicateResult,
            _: ChildResult<EffectResult>,
            _: &Effect,
            result: EffectResult,
        ) -> EffectResult {
            result
        }
        fn effect_unless(
            &mut self,
            _: PredicateResult,
            _: ChildResult<EffectResult>,
            _: &Effect,
            result: EffectResult,
        ) -> EffectResult {
            result
        }
        fn effect_if(
            &mut self,
            _: PredicateResult,
            _: ChildResult<EffectResult>,
            _: ChildResult<EffectResult>,
            result: EffectResult,
        ) -> EffectResult {
            result
        }
        fn effect_cond(
            &mut self,
            branches: Vec<(ChildResult<PredicateResult>, ChildResult<EffectResult>)>,
            _: Option<ChildResult<EffectResult>>,
            result: EffectResult,
        ) -> EffectResult {
            let mut recorded = self.cond_branches.lock().unwrap();
            for (pred, body) in &branches {
                recorded.push((
                    matches!(pred, ChildResult::Evaluated(_)),
                    matches!(body, ChildResult::Evaluated(_)),
                ));
            }
            result
        }
        fn effect_arg_continuation(
            &mut self,
            _: &ArgPattern,
            _: &[String],
            _: crate::fold::ArgMatchDetail,
            cont: EffectResult,
        ) -> EffectResult {
            cont
        }
        fn effect_may_i(
            &mut self,
            _: &ArgPattern,
            _: &str,
            _: &[String],
            _: EffectResult,
            out: EffectResult,
        ) -> EffectResult {
            out
        }
        fn effect_may_i_no_match(&mut self, _: &ArgPattern) -> EffectResult {
            EffectResult::Nil
        }

        fn predicate_fact(
            &mut self,
            _: &FactQuery,
            result: PredicateResult,
            _: crate::fold::FactDetail,
        ) -> PredicateResult {
            result
        }
        fn predicate_arg(
            &mut self,
            _: &ArgPattern,
            _: &[String],
            result: PredicateResult,
        ) -> PredicateResult {
            result
        }
        fn predicate_and(
            &mut self,
            _: Vec<ChildResult<PredicateResult>>,
            result: PredicateResult,
        ) -> PredicateResult {
            result
        }
        fn predicate_or(
            &mut self,
            _: Vec<ChildResult<PredicateResult>>,
            result: PredicateResult,
        ) -> PredicateResult {
            result
        }
        fn predicate_not(
            &mut self,
            _: PredicateResult,
            result: PredicateResult,
        ) -> PredicateResult {
            result
        }
        fn predicate_named(
            &mut self,
            _: &str,
            _: PredicateResult,
            result: PredicateResult,
        ) -> PredicateResult {
            result
        }

        fn rule_matched(
            &mut self,
            _: &Rule,
            _: Option<usize>,
            _: &ContextFacts,
            _: EffectResult,
            effect_out: EffectResult,
        ) -> EffectResult {
            effect_out
        }
        fn rule_not_matched(
            &mut self,
            _: &Rule,
            _: &ContextFacts,
            _: EffectResult,
            _: EffectResult,
        ) -> EffectResult {
            EffectResult::Nil
        }
        fn rule_skipped(&mut self, _: &Rule) -> EffectResult {
            EffectResult::Nil
        }
        fn default_ask(&mut self, _: &str) -> EffectResult {
            EffectResult::Decision(Decision::Ask, None)
        }
    }

    // Build a cond with 3 branches: first matches, second and third should be skipped
    let mut facts = ContextFacts::default();
    facts.insert_present(kw(":a"));
    let ctx = dummy_context("test", &[], &facts);
    let rules: &[Rule] = &[];

    use may_i_core::Span;
    use may_i_core::ast::Spanned;
    let s = Span::new(0, 0);

    let effect = Effect::Cond {
        branches: vec![
            (
                Spanned::new(Predicate::Fact(FactQuery::Presence { key: kw(":a") }), s),
                Spanned::new(
                    Effect::Terminal {
                        decision: Decision::Allow,
                        reason: Some("first".into()),
                    },
                    s,
                ),
            ),
            (
                Spanned::new(Predicate::Fact(FactQuery::Presence { key: kw(":b") }), s),
                Spanned::new(
                    Effect::Terminal {
                        decision: Decision::Deny,
                        reason: Some("second".into()),
                    },
                    s,
                ),
            ),
            (
                Spanned::new(Predicate::Fact(FactQuery::Presence { key: kw(":c") }), s),
                Spanned::new(
                    Effect::Terminal {
                        decision: Decision::Deny,
                        reason: Some("third".into()),
                    },
                    s,
                ),
            ),
        ],
        fallback: None,
    };

    let recorded = Arc::new(Mutex::new(Vec::new()));
    let mut fold = RecordingFold {
        cond_branches: recorded.clone(),
    };
    let result = evaluate_effect_fold(&mut fold, &effect, &ctx, rules).unwrap();

    assert_eq!(
        result,
        EffectResult::Decision(Decision::Allow, Some("first".into()))
    );

    let branches = recorded.lock().unwrap();
    assert_eq!(branches.len(), 3);
    // First branch: predicate evaluated, body evaluated
    assert_eq!(branches[0], (true, true));
    // Second branch: predicate skipped, body skipped
    assert_eq!(branches[1], (false, false));
    // Third branch: predicate skipped, body skipped
    assert_eq!(branches[2], (false, false));
}
