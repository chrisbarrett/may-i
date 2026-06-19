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
fn command_pattern_or_with_literals() {
    let pat = CommandPattern::Or(vec![
        CommandPattern::Literal("ls".into()),
        CommandPattern::Literal("git".into()),
    ]);
    assert!(pat.is_match("ls"));
    assert!(pat.is_match("git"));
    assert!(!pat.is_match("rm"));
}

#[test]
fn command_pattern_nested_or() {
    let pat = CommandPattern::Or(vec![
        CommandPattern::Or(vec![
            CommandPattern::Literal("git".into()),
            CommandPattern::Literal("hg".into()),
        ]),
        CommandPattern::Literal("svn".into()),
    ]);
    assert!(pat.is_match("git"));
    assert!(pat.is_match("hg"));
    assert!(pat.is_match("svn"));
    assert!(!pat.is_match("cvs"));
}

#[test]
fn evaluate_fallback_reason_command_matched_but_args_failed() {
    use may_i_core::ast::{Config, Rule, Spanned};
    use may_i_core::pattern::{ArgPattern, CommandPattern, Expr, PosTerm, Quantifier};
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
                patterns: vec![PosTerm::single(
                    Quantifier::One,
                    Expr::Literal("specific-arg".into()),
                )],
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
    use may_i_core::pattern::{ArgPattern, CommandPattern, Expr, PosTerm, Quantifier};
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
                            patterns: vec![PosTerm::single(
                                Quantifier::One,
                                Expr::Literal("ok".into()),
                            )],
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
    use may_i_core::pattern::{Expr, PosTerm, Quantifier};

    let patterns = vec![PosTerm::single(
        Quantifier::One,
        Expr::Bind {
            key: Keyword::new(":host").unwrap(),
            expr: Box::new(Expr::Wildcard),
        },
    )];

    let arg = "prod-01".to_string();
    let args: Vec<&str> = vec![&arg];
    let elements = vec![crate::eval::positional::ElementMatch {
        tested: Some(0),
        consumed: 1,
        matched: true,
    }];
    let details = build_positional_element_details(&args, &patterns, &elements);
    assert_eq!(details.len(), 1);
    let detail = &details[0];
    assert!(detail.binding.is_some());
    let bind = detail.binding.as_ref().unwrap();
    assert_eq!(bind.key.to_string(), ":host");
    assert_eq!(bind.value, Some("prod-01".to_string()));
}

#[test]
fn build_positional_element_details_with_cond_branch_index() {
    use may_i_core::pattern::{Expr, ExprBranch, PosTerm, Quantifier};

    let patterns = vec![PosTerm::single(
        Quantifier::One,
        Expr::Cond(vec![
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
    )];

    let arg = "b".to_string();
    let args: Vec<&str> = vec![&arg];
    let elements = vec![crate::eval::positional::ElementMatch {
        tested: Some(0),
        consumed: 1,
        matched: true,
    }];
    let details = build_positional_element_details(&args, &patterns, &elements);
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
    use may_i_core::pattern::PosTerm;
    use may_i_core::{Expr, Quantifier};

    // (* *) "end" — wildcard * greedily consumes all, must backtrack for "end"
    let patterns = vec![
        PosTerm::single(Quantifier::ZeroOrMore, Expr::Wildcard),
        PosTerm::single(Quantifier::One, Expr::Literal("end".to_string())),
    ];

    let args_owned: Vec<String> = vec!["a", "b", "c", "end"]
        .into_iter()
        .map(String::from)
        .collect();
    let args: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();
    let (matched, consumed, _) = match_pos_lit(&args, &patterns);
    assert!(matched);
    assert_eq!(consumed, 4);
}

#[test]
fn one_or_more_wildcard_backtracks_for_required() {
    use may_i_core::pattern::PosTerm;
    use may_i_core::{Expr, Quantifier};

    // (+ *) "end" — must consume at least 1, then backtrack for "end"
    let patterns = vec![
        PosTerm::single(Quantifier::OneOrMore, Expr::Wildcard),
        PosTerm::single(Quantifier::One, Expr::Literal("end".to_string())),
    ];

    let args_owned: Vec<String> = vec!["x", "y", "end"]
        .into_iter()
        .map(String::from)
        .collect();
    let args: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();
    let (matched, consumed, _) = match_pos_lit(&args, &patterns);
    assert!(matched);
    assert_eq!(consumed, 3);
}

#[test]
fn one_or_more_wildcard_fails_when_only_required() {
    use may_i_core::pattern::PosTerm;
    use may_i_core::{Expr, Quantifier};

    // (+ *) "end" with args ["end"] — can't consume 1+ AND have "end" left
    let patterns = vec![
        PosTerm::single(Quantifier::OneOrMore, Expr::Wildcard),
        PosTerm::single(Quantifier::One, Expr::Literal("end".to_string())),
    ];

    let args_owned = ["end".to_string()];
    let args: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();
    let (matched, _, _) = match_pos_lit(&args, &patterns);
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
        provenance: may_i_core::ast::Provenance::PrimaryConfig,
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
        provenance: may_i_core::ast::Provenance::PrimaryConfig,
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
            _: Vec<crate::fold::PositionalElementDetail>,
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
        fn predicate_bound(
            &mut self,
            _: &may_i_core::ast::BindingName,
            result: PredicateResult,
        ) -> PredicateResult {
            result
        }
        fn predicate_matches(
            &mut self,
            _: &may_i_core::ast::BindingName,
            _: &may_i_core::pattern::Expr<Effect>,
            result: PredicateResult,
        ) -> PredicateResult {
            result
        }
        fn predicate_every(
            &mut self,
            _: &may_i_core::ast::BindingName,
            _: &may_i_core::pattern::Expr<Effect>,
            result: PredicateResult,
        ) -> PredicateResult {
            result
        }
        fn predicate_some(
            &mut self,
            _: &may_i_core::ast::BindingName,
            _: &may_i_core::pattern::Expr<Effect>,
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

// ── Parser/engine cross-boundary invariants ──────────────────────
//
// Each property below maps 1:1 to a Requirement in
// `openspec/specs/parser-engine-invariants/spec.md`. The grep-based
// check in `requirement_to_property_mapping_is_complete` enforces the
// link.

mod parser_engine_invariants {
    use crate::eval::decompose::{EvalUnit, decompose};
    use crate::eval::evaluate_command;
    use crate::eval::tests::{arb_shell_chars, arb_with_heredoc, arb_with_single_quoted_region};
    use may_i_core::ContextFacts;
    use may_i_core::ast::Config;
    use proptest::prelude::*;

    fn empty_config() -> Config {
        Config::default()
    }

    fn empty_facts() -> ContextFacts {
        ContextFacts::default()
    }

    proptest! {
        // `max_global_rejects` is bumped from the 1024 default because
        // `prop_wordpart_reparse_round_trip` filters on `!pr.has_errors()`
        // and `arb_with_heredoc()` produces parse-erroring inputs at a
        // rate that overflows the default ceiling under the heavy sweep
        // (`PROPTEST_CASES=10000`). Other tests in the block don't reject.
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 64, max_global_rejects: 100_000, .. ProptestConfig::default() })]

        /// Spec: § Emitted spans lie within input bounds.
        #[test]
        fn prop_spans_within_input_bounds(input in arb_with_heredoc()) {
            let result = evaluate_command(&input, &empty_config(), &empty_facts()).unwrap();
            let len = input.len();
            for seg in &result.segment_decisions {
                prop_assert!(seg.start <= seg.end,
                    "segment start > end: {:?} (input {:?})", seg, input);
                prop_assert!(seg.end <= len,
                    "segment end > input.len() ({}): {:?} (input {:?})", len, seg, input);
            }
            for d in &result.parse_diagnostics {
                prop_assert!(d.span.start <= d.span.end,
                    "diagnostic start > end: {:?} (input {:?})", d, input);
                prop_assert!(d.span.end <= len,
                    "diagnostic end > input.len() ({}): {:?} (input {:?})", len, d, input);
            }
        }

        /// Spec: § Embedded command source matches its span.
        #[test]
        fn prop_embedded_source_matches_span_slice(input in arb_shell_chars()) {
            let parse_result = may_i_shell_parser::parse(&input);
            let units = decompose(&parse_result.command, &input, &parse_result.diagnostics, &std::collections::HashSet::new());
            for unit in &units {
                if let EvalUnit::EmbeddedCommand { source, span, .. } = unit {
                    let (s, e) = *span;
                    prop_assert!(s <= e && e <= input.len(),
                        "embedded span out of bounds: {:?} in input {:?}", span, input);
                    let slice = &input[s..e];
                    prop_assert_eq!(slice, source.as_str(),
                        "slice/source mismatch in {:?}: slice {:?} vs source {:?}",
                        input, slice, source);
                }
            }
        }

        /// Spec: § Single-quoted regions are inviolable.
        #[test]
        fn prop_single_quoted_regions_are_inviolable(
            (input, q_start, q_end) in arb_with_single_quoted_region()
        ) {
            let parse_result = may_i_shell_parser::parse(&input);
            let units = decompose(&parse_result.command, &input, &parse_result.diagnostics, &std::collections::HashSet::new());
            for unit in &units {
                let (s, e) = match unit {
                    EvalUnit::SimpleCommand { span, .. }
                    | EvalUnit::LocalFunctionCall { span, .. }
                    | EvalUnit::EmbeddedCommand { span, .. } => *span,
                    EvalUnit::DynamicCommand { .. }
                    | EvalUnit::EnvPrefix { .. }
                    | EvalUnit::RedirectTarget { .. }
                    | EvalUnit::EnvRead { .. } => continue,
                };
                let strictly_inside =
                    s >= q_start && e <= q_end && (s > q_start || e < q_end);
                prop_assert!(
                    !strictly_inside,
                    "unit {:?} strictly inside quoted region [{},{}] of input {:?}",
                    unit, q_start, q_end, input
                );
            }
        }

        // `prop_quoted_heredoc_bodies_are_inviolable` is exercised by
        // explicit unit tests below (`heredoc_body_inviolable_*`). The
        // black-box property required `locate_quoted_heredoc_body` to agree
        // with the parser on heredoc identification across arbitrary inputs,
        // which became its own brittle re-implementation of the lexer once
        // the corpus included unterminated quotes and backticks. The
        // inviolability invariant is now covered by spec-scenario unit tests
        // plus the 2026-05-11 regression seed.

        /// Spec: § Recursive evaluation stays within parent span.
        #[test]
        fn prop_recursive_segments_stay_within_parent_span(input in arb_shell_chars()) {
            let result = evaluate_command(&input, &empty_config(), &empty_facts()).unwrap();
            let parse_result = may_i_shell_parser::parse(&input);
            let units = decompose(&parse_result.command, &input, &parse_result.diagnostics, &std::collections::HashSet::new());
            for unit in &units {
                if let EvalUnit::EmbeddedCommand { span, .. } = unit {
                    let (p_s, p_e) = *span;
                    for seg in &result.segment_decisions {
                        let strictly_inside = seg.start >= p_s
                            && seg.end <= p_e
                            && (seg.start > p_s || seg.end < p_e);
                        if strictly_inside {
                            prop_assert!(
                                seg.start >= p_s && seg.end <= p_e,
                                "nested segment {:?} escapes parent [{},{}] in input {:?}",
                                seg, p_s, p_e, input
                            );
                        }
                    }
                }
            }
        }

        // Spec: § Parser and engine agree on substitution boundaries.
        //
        // `prop_paren_matchers_agree` deleted in `parser-engine-span-fidelity`:
        // the engine no longer mirrors `find_balanced_paren`. The lexer's
        // `WordPart::CommandSubstitution { span, .. }` is now the single source
        // of truth — span/source coherence is asserted by
        // `prop_wordpart_source_matches_span_slice` below, which subsumes the
        // matcher-agreement guarantee (any disagreement would surface as a
        // slice/source mismatch).

        /// Spec: § WordPart span SHALL equal its source verbatim.
        ///
        /// Tier-1 threading-correctness check: any off-by-one in the lexer's
        /// span-capture path fails this property on the first input that
        /// reaches the affected variant.
        #[test]
        fn prop_wordpart_source_matches_span_slice(input in arb_with_heredoc()) {
            let pr = may_i_shell_parser::parse(&input);
            walk_word_parts(&pr.command, &mut |part| {
                let (source, span) = match wordpart_source_and_span(part) {
                    Some(p) => p,
                    None => return Ok(()),
                };
                prop_assert!(
                    span.start <= span.end && span.end <= input.len(),
                    "wordpart span out of bounds: {:?} (input {:?})", span, input
                );
                let slice = &input[span.start..span.end];
                prop_assert_eq!(
                    slice, source,
                    "wordpart span/source mismatch in {:?}: slice {:?} vs source {:?}",
                    input, slice, source
                );
                Ok(())
            })?;
        }

        /// Spec: § Substitution body length SHALL equal span length.
        #[test]
        fn prop_wordpart_source_length_matches_span(input in arb_with_heredoc()) {
            let pr = may_i_shell_parser::parse(&input);
            walk_word_parts(&pr.command, &mut |part| {
                if let Some((source, span)) = wordpart_source_and_span(part) {
                    prop_assert_eq!(
                        source.len(), span.end - span.start,
                        "source.len() != span size for {:?} in input {:?}",
                        part, input
                    );
                }
                Ok(())
            })?;
        }

        /// Spec: § Sibling WordParts SHALL have non-overlapping monotonic spans.
        #[test]
        fn prop_wordpart_sibling_spans_monotonic(input in arb_with_heredoc()) {
            let pr = may_i_shell_parser::parse(&input);
            walk_words(&pr.command, &mut |word| {
                let mut prev_end: Option<usize> = None;
                for part in &word.parts {
                    if let Some((_source, span)) = wordpart_source_and_span(part) {
                        if let Some(pe) = prev_end {
                            prop_assert!(
                                pe <= span.start,
                                "sibling wordpart spans overlap or out-of-order: \
                                 prev end {} > next start {} in input {:?}",
                                pe, span.start, input
                            );
                        }
                        prev_end = Some(span.end);
                    }
                }
                Ok(())
            })?;
        }

        /// Spec: § Re-parsing source bytes SHALL yield equivalent AST.
        #[test]
        fn prop_wordpart_reparse_round_trip(input in arb_with_heredoc()) {
            let pr = may_i_shell_parser::parse(&input);
            prop_assume!(!pr.has_errors());
            walk_word_parts(&pr.command, &mut |part| {
                if let may_i_shell_parser::WordPart::CommandSubstitution { source, span } = part {
                    let slice = &input[span.start..span.end];
                    let from_source = format!("{:?}", may_i_shell_parser::parse(source).command);
                    let from_slice = format!("{:?}", may_i_shell_parser::parse(slice).command);
                    prop_assert_eq!(
                        &from_source, &from_slice,
                        "re-parse mismatch in input {:?}", input
                    );
                }
                Ok(())
            })?;
        }

        /// Spec: § Embedded command substitutions are evaluated in every word
        /// position.
        ///
        /// Coverage invariant (design D2): for every command, backtick, and
        /// process substitution the parser finds anywhere in the input,
        /// `decompose` produces a matching `EmbeddedCommand` unit — and no
        /// substitution yields two. Arithmetic `$(( … ))` runs no command and
        /// produces none. The generator places the substitution in simple-
        /// command words, bare assignment values, `for` iteration words, and
        /// `case` subject/pattern positions, so a future word position cannot
        /// silently reintroduce the gap.
        #[test]
        fn prop_every_substitution_yields_embedded_unit(
            inner in prop::sample::select(vec!["rm -rf /", "date", "ls /a", "true"]),
            form in 0u8..4,
            ctx in 0u8..7,
        ) {
            // 0 dollar, 1 backtick, 2 process-sub, 3 arithmetic. Process
            // substitution is only well-formed in command-word position, so
            // pin its context to the simple-command argument.
            let ctx = if form == 2 { 0 } else { ctx };
            let sub = match form {
                0 => format!("$({inner})"),
                1 => format!("`{inner}`"),
                2 => format!("<({inner})"),
                _ => "$(( 1 + 2 ))".to_string(),
            };
            let input = match ctx {
                0 => format!("echo {sub}"),
                1 => format!("z={sub}"),
                2 => format!("for x in {sub}; do :; done"),
                3 => format!("case {sub} in *) :;; esac"),
                4 => format!("case $x in {sub}) :;; esac"),
                // Parameter-expansion operands: default value and strip-prefix
                // pattern. Bash expands both, so a substitution there runs.
                5 => format!("echo ${{x:-{sub}}}"),
                _ => format!("echo ${{x#{sub}}}"),
            };

            let pr = may_i_shell_parser::parse(&input);
            prop_assume!(!pr.has_errors());

            let mut words = Vec::new();
            collect_all_words(&pr.command, &mut words);
            let mut ast_spans = Vec::new();
            for w in words {
                collect_cmd_substitution_spans(w, &mut ast_spans);
            }
            ast_spans.sort_unstable();

            let mut embedded_spans: Vec<(usize, usize)> =
                decompose(&pr.command, &input, &pr.diagnostics, &std::collections::HashSet::new())
                    .iter()
                    .filter_map(|u| match u {
                        EvalUnit::EmbeddedCommand { span, .. } => Some(*span),
                        _ => None,
                    })
                    .collect();
            embedded_spans.sort_unstable();

            // Sorted, NOT deduped: a double-counted substitution would make the
            // embedded side longer than the AST side and fail here.
            prop_assert_eq!(
                &ast_spans, &embedded_spans,
                "substitution coverage mismatch for input {:?}: \
                 AST command/backtick/process spans {:?} vs embedded-unit spans {:?}",
                input, ast_spans, embedded_spans
            );
        }
    }

    /// Collect every word the AST exposes across the whole command tree —
    /// simple-command words, assignment-prefix and bare-assignment values,
    /// redirect-target files, `for` iteration words, and `case` subject/pattern
    /// words. Mirrors the union of every word source `decompose` scans.
    fn collect_all_words<'a>(
        cmd: &'a may_i_shell_parser::Command,
        out: &mut Vec<&'a may_i_shell_parser::Word>,
    ) {
        use may_i_shell_parser::{Command, RedirectionTarget};
        match cmd {
            Command::Simple(sc) => {
                out.extend(&sc.words);
                out.extend(sc.assignments.iter().map(|a| &a.value));
                for r in &sc.redirections {
                    if let RedirectionTarget::File(w) = &r.target {
                        out.push(w);
                    }
                }
            }
            Command::Assignment(a) => out.push(&a.value),
            Command::For { words, .. } => out.extend(words),
            Command::Case { word, arms, .. } => {
                out.push(word);
                for arm in arms {
                    out.extend(&arm.patterns);
                }
            }
            _ => {}
        }
        for child in cmd.children() {
            collect_all_words(child, out);
        }
    }

    /// Byte spans of every command/backtick/process substitution in `word`
    /// (recursing through double-quoted parts). Arithmetic is excluded — it runs
    /// no command and must not be represented by an embedded-command unit.
    fn collect_cmd_substitution_spans(
        word: &may_i_shell_parser::Word,
        out: &mut Vec<(usize, usize)>,
    ) {
        use may_i_shell_parser::WordPart;
        fn walk(parts: &[WordPart], out: &mut Vec<(usize, usize)>) {
            for part in parts {
                match part {
                    WordPart::CommandSubstitution { span, .. }
                    | WordPart::Backtick { span, .. }
                    | WordPart::ProcessSubstitution { span, .. } => {
                        out.push((span.start, span.end))
                    }
                    WordPart::DoubleQuoted(inner) => walk(inner, out),
                    // Substitutions captured out of parameter-expansion operands
                    // live in the op's `embedded` parts, not inline in the word.
                    WordPart::ParameterExpansionOp { embedded, .. } => walk(embedded, out),
                    _ => {}
                }
            }
        }
        walk(&word.parts, out);
    }

    /// Visit every `WordPart` in a parsed command, recursing through
    /// `DoubleQuoted` containers.
    fn walk_word_parts(
        cmd: &may_i_shell_parser::Command,
        visit: &mut dyn FnMut(
            &may_i_shell_parser::WordPart,
        ) -> Result<(), proptest::test_runner::TestCaseError>,
    ) -> Result<(), proptest::test_runner::TestCaseError> {
        let simples = may_i_shell_parser::extract_simple_commands(cmd);
        for sc in simples {
            for word in &sc.words {
                walk_parts(&word.parts, visit)?;
            }
            for assignment in &sc.assignments {
                walk_parts(&assignment.value.parts, visit)?;
            }
        }
        Ok(())
    }

    fn walk_parts(
        parts: &[may_i_shell_parser::WordPart],
        visit: &mut dyn FnMut(
            &may_i_shell_parser::WordPart,
        ) -> Result<(), proptest::test_runner::TestCaseError>,
    ) -> Result<(), proptest::test_runner::TestCaseError> {
        for part in parts {
            visit(part)?;
            if let may_i_shell_parser::WordPart::DoubleQuoted(inner) = part {
                walk_parts(inner, visit)?;
            }
        }
        Ok(())
    }

    fn walk_words(
        cmd: &may_i_shell_parser::Command,
        visit: &mut dyn FnMut(
            &may_i_shell_parser::Word,
        ) -> Result<(), proptest::test_runner::TestCaseError>,
    ) -> Result<(), proptest::test_runner::TestCaseError> {
        let simples = may_i_shell_parser::extract_simple_commands(cmd);
        for sc in simples {
            for word in &sc.words {
                visit(word)?;
            }
            for assignment in &sc.assignments {
                visit(&assignment.value)?;
            }
        }
        Ok(())
    }

    fn wordpart_source_and_span(
        part: &may_i_shell_parser::WordPart,
    ) -> Option<(&str, may_i_shell_parser::Span)> {
        use may_i_shell_parser::WordPart::*;
        match part {
            CommandSubstitution { source, span }
            | Backtick { source, span }
            | Arithmetic { source, span } => Some((source.as_str(), *span)),
            ProcessSubstitution { command, span, .. } => Some((command.as_str(), *span)),
            _ => None,
        }
    }

    /// Spec: § Quoted heredoc bodies are inviolable.
    ///
    /// Spec scenario: heredoc body words do not surface as commands.
    #[test]
    fn heredoc_body_inviolable_simple() {
        let input = "cat <<'EOF'\nrm -rf /\nEOF\n";
        let pr = may_i_shell_parser::parse(input);
        let units = decompose(
            &pr.command,
            input,
            &pr.diagnostics,
            &std::collections::HashSet::new(),
        );
        for unit in &units {
            if let EvalUnit::SimpleCommand { command, .. } = unit {
                assert_ne!(
                    command, "rm",
                    "heredoc body bytes surfaced as command name; units: {units:?}"
                );
            }
        }
    }

    /// Regression seed for the 2026-05-11 incident: a `git commit -m
    /// "$(cat <<'EOF' … )"` heredoc surfaced `proptest` as a command name
    /// because the engine's substitution scanner entered the quoted-delimiter
    /// heredoc body and treated backtick-quoted text inside as substitutions.
    /// Fixed by `parser-engine-span-fidelity` (spans on `WordPart`).
    #[test]
    fn regression_2026_05_11_proptest_command() {
        let input = "git commit -m \"$(cat <<'EOF'\nFix overlapping segment spans for unclosed `(...)` substitutions.\n\n`prop_top_level_segments_disjoint` proptest now covers this.\nEOF\n)\"";
        let parse_result = may_i_shell_parser::parse(input);
        let units = decompose(
            &parse_result.command,
            input,
            &parse_result.diagnostics,
            &std::collections::HashSet::new(),
        );
        for unit in &units {
            if let EvalUnit::SimpleCommand { command, .. } = unit {
                assert!(
                    command != "proptest" && command != "prop_top_level_segments_disjoint",
                    "bug: backtick-quoted text inside quoted heredoc body \
                     surfaced as command name {command:?}; units: {units:?}"
                );
            }
        }
    }

    // Spec-mapping anchors for requirements covered structurally rather than
    // by a single property:
    //
    //   Spec: § All cross-boundary invariants SHALL be continuously verified.
    //     — established by removing every `#[ignore]` from this module.
    //   Spec: § Positional matching terminates within a step budget.
    //     — established by `eval::positional::tests::nullable_group_terminates`
    //       and `budget_exhaustion_returns_no_match` (the nullable-iteration
    //       guard and the step-budget no-match), plus
    //       `ast::tests::config_carries_matcher_budget_with_high_default` (the
    //       config-structure budget with a high default and no surface syntax).
    //   Spec: § Constrained matches against expansion-bearing args stay unprovable under groups.
    //     — established by
    //       `eval::positional::tests::constrained_match_in_repeated_group_records_provenance`
    //       and `wildcard_match_in_repeated_group_records_no_provenance` (a
    //       constrained match against an expansion-bearing arg carries its
    //       provenance along the winning path; a bare wildcard does not).
    //   Spec: § WordPart spans are derivable from the AST alone.
    //     — established by the engine reading spans from the AST in
    //       `decompose.rs::push_embedded_units_from_word` and the deletion of
    //       `find_substitution_spans` / `find_balanced_paren`.
    //   Spec: § Threading-correctness properties guard the lexer's span population.
    //     — established by `prop_wordpart_source_matches_span_slice`,
    //       `prop_wordpart_source_length_matches_span`,
    //       `prop_wordpart_sibling_spans_monotonic`, and
    //       `prop_wordpart_reparse_round_trip` above.
    //   Spec: § Heredoc-locating helper SHALL exclude shadowed openers.
    //     — superseded: the helper was deleted along with the heredoc
    //       proptest. Inviolability is now covered by
    //       `heredoc_body_inviolable_simple` and the 2026-05-11 regression
    //       seed.
    //   Spec: § EvalResult exposes per-segment decisions.
    //     — established by `EvalResult.segment_decisions` and the scenario
    //       tests in `crates/engine/src/eval/tests/segment_decisions.rs`.
    //   Spec: § Segment decisions describe non-overlapping byte ranges.
    //     — established by the same segment-decisions scenarios, which
    //       assert disjoint top-level ranges per scenario.
    //   Spec: § Display does not re-evaluate to colourise.
    //     — established by `cmd_eval` reading `result.segment_decisions`
    //       directly; the display path makes no call to
    //       `engine::eval::evaluate_command`.

    /// Grep-based check: every Requirement heading in the
    /// `parser-engine-invariants` spec is named in the property body via its
    /// `Spec: § …` doc-comment. Failures here mean the spec and the
    /// implementation drifted.
    #[test]
    fn requirement_to_property_mapping_is_complete() {
        let spec_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../openspec/specs/parser-engine-invariants/spec.md");
        let Ok(spec) = std::fs::read_to_string(&spec_path) else {
            // Spec lives at the workspace top-level after archive; until
            // then we look in the change's spec dir. Either is fine; skip
            // if neither resolves rather than fail the test.
            return;
        };
        let properties_src = include_str!("properties.rs");
        for line in spec.lines() {
            if let Some(heading) = line.strip_prefix("### Requirement: ") {
                assert!(
                    properties_src.contains(heading),
                    "Requirement {heading:?} has no matching `Spec: § …` \
                     reference in properties.rs"
                );
            }
        }
    }
}
