
use super::*;
use crate::eval::{
    self, EvalContext, Evaluator, PredicateResult, evaluate, evaluate_predicate,
};
use may_i_core::ast::EffectResult;

fn make_ctx<'a>(
    command: &'a str,
    args: &'a [String],
    facts: &'a ContextFacts,
) -> EvalContext<'a> {
    EvalContext::new(command, args, facts)
}

fn eval_effect(effect: &Effect, ctx: &EvalContext) -> EffectResult {
    let rule = Rule {
        command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
            ctx.command.to_string(),
        ))),
        effect: spanned(effect.clone()),
        checks: vec![],
        span: dummy_span(),
    };
    let rules = [rule];
    let evaluator = Evaluator::new(&rules);
    let result = evaluator.evaluate(&mut crate::fold::PureFold, ctx).unwrap();
    EffectResult::Decision(result.decision, result.reason)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

    #[test]
    fn terminal_effects_return_correct_decision(
        decision in any_decision(),
        reason in proptest::option::of("[a-zA-Z ]{1,20}"),
    ) {
        let effect = match decision {
            Decision::Allow => Effect::Allow(reason.clone()),
            Decision::Ask => Effect::Ask(reason.clone()),
            Decision::Deny => Effect::Deny(reason.clone()),
        };
        let args: Vec<String> = vec![];
        let facts = ContextFacts::default();
        let ctx = make_ctx("test", &args, &facts);
        let result = eval_effect(&effect, &ctx);
        match result {
            EffectResult::Decision(d, r) => {
                prop_assert_eq!(d, decision);
                prop_assert_eq!(r, reason);
            }
            EffectResult::Nil => prop_assert!(false, "Terminal effect returned Nil"),
        }
    }

    #[test]
    fn evaluate_never_panics_on_valid_config(
        config in any_config(5),
        data in any_eval_context_data(),
    ) {
        let (cmd, args, facts) = data;
        let _ = evaluate(&cmd, &args, &config, &facts).unwrap();
    }

    #[test]
    fn evaluate_returns_valid_result(
        config in any_config(3),
        data in any_eval_context_data(),
    ) {
        let (cmd, args, facts) = data;
        let result = evaluate(&cmd, &args, &config, &facts).unwrap();
        prop_assert!(
            matches!(result.decision, Decision::Allow | Decision::Ask | Decision::Deny)
        );
    }

    #[test]
    fn empty_config_returns_ask(data in any_eval_context_data()) {
        let (cmd, args, facts) = data;
        let config = Config::default();
        let result = evaluate(&cmd, &args, &config, &facts).unwrap();
        prop_assert_eq!(result.decision, Decision::Ask);
    }

    // 4.2.3 Property: And returns Nil if any effect returns Nil
    #[test]
    fn and_returns_nil_if_any_nil(
        terminal in any_terminal_effect(),
        data in any_eval_context_data(),
    ) {
        let (cmd, args, facts) = data;
        let ctx = make_ctx(&cmd, &args, &facts);
        // A non-matching command pattern returns Nil
        let nil_effect = Effect::CommandPattern(CommandPattern::Literal("__never_matches__".into()));
        let and_effect = Effect::And {
            effects: vec![spanned(terminal), spanned(nil_effect)],
        };
        let result = eval::evaluate_effect(&and_effect, &ctx, &[]).unwrap();
        prop_assert!(result.is_nil(), "And with Nil should return Nil, got {:?}", result);
    }

    // 4.2.4 Property: And returns last result if all non-Nil
    #[test]
    fn and_returns_last_if_all_non_nil(
        decisions in prop::collection::vec(any_decision(), 2..4),
        data in any_eval_context_data(),
    ) {
        let (cmd, args, facts) = data;
        let ctx = make_ctx(&cmd, &args, &facts);
        let effects: Vec<_> = decisions.iter().map(|d| {
            let eff = match d {
                Decision::Allow => Effect::Allow(None),
                Decision::Ask => Effect::Ask(None),
                Decision::Deny => Effect::Deny(None),
            };
            spanned(eff)
        }).collect();
        let and_effect = Effect::And { effects };
        let result = eval::evaluate_effect(&and_effect, &ctx, &[]).unwrap();
        let expected = decisions.last().unwrap();
        match result {
            EffectResult::Decision(d, _) => prop_assert_eq!(d, *expected),
            EffectResult::Nil => prop_assert!(false, "Expected decision, got Nil"),
        }
    }

    // 4.2.5 Property: Or returns first non-Nil result
    #[test]
    fn or_returns_first_non_nil(
        decision in any_decision(),
        data in any_eval_context_data(),
    ) {
        let (cmd, args, facts) = data;
        let ctx = make_ctx(&cmd, &args, &facts);
        let nil_effect = Effect::CommandPattern(CommandPattern::Literal("__never_matches__".into()));
        let terminal = match decision {
            Decision::Allow => Effect::Allow(None),
            Decision::Ask => Effect::Ask(None),
            Decision::Deny => Effect::Deny(None),
        };
        let or_effect = Effect::Or {
            effects: vec![spanned(nil_effect), spanned(terminal)],
        };
        let result = eval::evaluate_effect(&or_effect, &ctx, &[]).unwrap();
        match result {
            EffectResult::Decision(d, _) => prop_assert_eq!(d, decision),
            EffectResult::Nil => prop_assert!(false, "Expected decision, got Nil"),
        }
    }

    // 4.2.6 Property: Or returns Nil if all Nil
    #[test]
    fn or_returns_nil_if_all_nil(data in any_eval_context_data()) {
        let (cmd, args, facts) = data;
        let ctx = make_ctx(&cmd, &args, &facts);
        let nil1 = Effect::CommandPattern(CommandPattern::Literal("__no_match_1__".into()));
        let nil2 = Effect::CommandPattern(CommandPattern::Literal("__no_match_2__".into()));
        let or_effect = Effect::Or {
            effects: vec![spanned(nil1), spanned(nil2)],
        };
        let result = eval::evaluate_effect(&or_effect, &ctx, &[]).unwrap();
        prop_assert!(result.is_nil(), "Or of all-Nil should be Nil, got {:?}", result);
    }

    // 4.2.7 Property: Not inverts Allow<->Nil, preserves Ask/Deny
    #[test]
    fn not_inverts_allow_nil(data in any_eval_context_data()) {
        let (cmd, args, facts) = data;
        let ctx = make_ctx(&cmd, &args, &facts);

        // Not(Allow) -> Nil
        let not_allow = Effect::Not { effect: Box::new(spanned(Effect::Allow(None))) };
        let result = eval::evaluate_effect(&not_allow, &ctx, &[]).unwrap();
        prop_assert!(result.is_nil(), "Not(Allow) should be Nil, got {:?}", result);

        // Not(Nil) -> Allow
        let nil = Effect::CommandPattern(CommandPattern::Literal("__no_match__".into()));
        let not_nil = Effect::Not { effect: Box::new(spanned(nil)) };
        let result = eval::evaluate_effect(&not_nil, &ctx, &[]).unwrap();
        prop_assert_eq!(result.decision(), Some(Decision::Allow));

        // Not(Ask) -> Ask
        let not_ask = Effect::Not { effect: Box::new(spanned(Effect::Ask(None))) };
        let result = eval::evaluate_effect(&not_ask, &ctx, &[]).unwrap();
        prop_assert_eq!(result.decision(), Some(Decision::Ask));

        // Not(Deny) -> Deny
        let not_deny = Effect::Not { effect: Box::new(spanned(Effect::Deny(None))) };
        let result = eval::evaluate_effect(&not_deny, &ctx, &[]).unwrap();
        prop_assert_eq!(result.decision(), Some(Decision::Deny));
    }

    // 4.2.8 Property: CommandPattern matches appropriate commands
    #[test]
    fn command_pattern_matches_literal(
        name in "[a-zA-Z][a-zA-Z0-9]{0,9}",
        other in "[a-zA-Z][a-zA-Z0-9]{0,9}",
    ) {
        let args: Vec<String> = vec![];
        let facts = ContextFacts::default();
        let effect = Effect::CommandPattern(CommandPattern::Literal(name.clone()));

        let ctx = make_ctx(&name, &args, &facts);
        let result = eval::evaluate_effect(&effect, &ctx, &[]).unwrap();
        prop_assert!(result.is_decision(), "Should match literal command");

        if name != other {
            let ctx2 = make_ctx(&other, &args, &facts);
            let result2 = eval::evaluate_effect(&effect, &ctx2, &[]).unwrap();
            prop_assert!(result2.is_nil(), "Should not match different command");
        }
    }

    // 4.2.9 Property: ArgPattern matches appropriate arguments
    #[test]
    fn arg_pattern_anywhere_matches(
        target in "[a-zA-Z][a-zA-Z0-9]{0,9}",
        other_args in prop::collection::vec("[a-zA-Z][a-zA-Z0-9]{0,9}", 0..3),
    ) {
        let mut args = other_args;
        args.push(target.clone());
        let facts = ContextFacts::default();
        let ctx = make_ctx("test", &args, &facts);

        let pattern = may_i_core::pattern::ArgPattern::Anywhere(vec![
            may_i_core::pattern::Expr::Literal(target),
        ]);
        let effect = Effect::ArgPattern(pattern);
        let result = eval::evaluate_effect(&effect, &ctx, &[]).unwrap();
        prop_assert!(result.is_decision(), "Anywhere should match when arg present");
    }

    // 4.2.10 Property: When evaluates effect only if predicate matches
    #[test]
    fn when_evaluates_only_if_predicate_matches(
        key in any_keyword(),
        data in any_eval_context_data(),
    ) {
        let (cmd, args, facts) = data;

        // Predicate: fact :key is present
        let pred = Predicate::Fact(may_i_core::FactQuery::Presence {
            key: key.clone(),
            vector_syntax: false,
        });
        let inner = Effect::Allow(Some("when-matched".into()));
        let when_effect = Effect::When {
            predicate: spanned(pred.clone()),
            effect: Box::new(spanned(inner)),
        };

        let ctx = make_ctx(&cmd, &args, &facts);
        let pred_result = evaluate_predicate(&pred, &ctx).unwrap();
        let effect_result = eval::evaluate_effect(&when_effect, &ctx, &[]).unwrap();

        if pred_result == PredicateResult::Match {
            prop_assert!(effect_result.is_decision(), "When should eval effect on match");
        } else {
            prop_assert!(effect_result.is_nil(), "When should return Nil on no match");
        }
    }

    // 4.2.11 Property: Unless evaluates effect only if predicate doesn't match
    #[test]
    fn unless_evaluates_only_if_predicate_no_match(
        key in any_keyword(),
        data in any_eval_context_data(),
    ) {
        let (cmd, args, facts) = data;

        let pred = Predicate::Fact(may_i_core::FactQuery::Presence {
            key: key.clone(),
            vector_syntax: false,
        });
        let inner = Effect::Allow(Some("unless-matched".into()));
        let unless_effect = Effect::Unless {
            predicate: spanned(pred.clone()),
            effect: Box::new(spanned(inner)),
        };

        let ctx = make_ctx(&cmd, &args, &facts);
        let pred_result = evaluate_predicate(&pred, &ctx).unwrap();
        let effect_result = eval::evaluate_effect(&unless_effect, &ctx, &[]).unwrap();

        if pred_result == PredicateResult::NoMatch {
            prop_assert!(effect_result.is_decision(), "Unless should eval on no match");
        } else {
            prop_assert!(effect_result.is_nil(), "Unless should return Nil on match");
        }
    }

    // 4.2.12 Property: If chooses correct branch based on predicate
    #[test]
    fn if_chooses_branch_based_on_predicate(
        key in any_keyword(),
        data in any_eval_context_data(),
    ) {
        let (cmd, args, facts) = data;

        let pred = Predicate::Fact(may_i_core::FactQuery::Presence {
            key: key.clone(),
            vector_syntax: false,
        });
        let then_eff = Effect::Allow(Some("then".into()));
        let else_eff = Effect::Deny(Some("else".into()));
        let if_effect = Effect::If {
            predicate: spanned(pred.clone()),
            then_effect: Box::new(spanned(then_eff)),
            else_effect: Box::new(spanned(else_eff)),
        };

        let ctx = make_ctx(&cmd, &args, &facts);
        let pred_result = evaluate_predicate(&pred, &ctx).unwrap();
        let effect_result = eval::evaluate_effect(&if_effect, &ctx, &[]).unwrap();

        match pred_result {
            PredicateResult::Match => {
                prop_assert_eq!(effect_result.decision(), Some(Decision::Allow));
            }
            PredicateResult::NoMatch => {
                prop_assert_eq!(effect_result.decision(), Some(Decision::Deny));
            }
        }
    }

    // 4.2.13 Property: Cond chooses first matching branch
    #[test]
    fn cond_chooses_first_matching_branch(
        key in any_keyword(),
        data in any_eval_context_data(),
    ) {
        let (cmd, args, facts) = data;
        let ctx = make_ctx(&cmd, &args, &facts);

        // Always-true predicate (wildcard fact presence won't work, use a trick)
        // Use Predicate::Not(Not(Fact)) which is equivalent to the fact check
        // Instead, build a cond with a guaranteed-matching first branch
        let always_true = Predicate::Or(vec![
            Predicate::Fact(may_i_core::FactQuery::Presence {
                key: key.clone(),
                vector_syntax: false,
            }),
            Predicate::Not(Box::new(Predicate::Fact(may_i_core::FactQuery::Presence {
                key: key.clone(),
                vector_syntax: false,
            }))),
        ]);

        let cond_effect = Effect::Cond {
            branches: vec![
                (spanned(always_true), spanned(Effect::Allow(Some("first".into())))),
                (spanned(Predicate::Fact(may_i_core::FactQuery::Presence {
                    key: Keyword::new(":other").unwrap(),
                    vector_syntax: false,
                })), spanned(Effect::Deny(Some("second".into())))),
            ],
            fallback: Some(Box::new(spanned(Effect::Ask(Some("fallback".into()))))),
        };

        let result = eval::evaluate_effect(&cond_effect, &ctx, &[]).unwrap();
        prop_assert_eq!(result.decision(), Some(Decision::Allow), "First matching branch should win");
    }

    // 4.2.14 Property: MayI recurses correctly with pattern match
    #[test]
    fn may_i_recurses_with_pattern(
        inner_cmd in "[a-zA-Z][a-zA-Z0-9]{0,9}",
    ) {
        let args: Vec<String> = vec![inner_cmd.clone()];
        let facts = ContextFacts::default();
        let ctx = make_ctx("wrapper", &args, &facts);

        // Create a rule that matches the inner command
        let inner_rule = Rule {
            command_effect: spanned(Effect::CommandPattern(
                CommandPattern::Literal(inner_cmd),
            )),
            effect: spanned(Effect::Allow(Some("inner-allowed".into()))),
            checks: vec![],
            span: dummy_span(),
        };
        let rules = [inner_rule];

        let may_i = Effect::MayI {
            pattern: may_i_core::pattern::ArgPattern::Positional {
                patterns: vec![],
                continuation: None,
            },
        };
        let result = eval::evaluate_effect(&may_i, &ctx, &rules).unwrap();
        // MayI extracts inner command and evaluates it
        prop_assert!(result.is_decision(), "MayI should produce a decision");
    }

    // 4.2.15 Property: Recursion limit is respected
    #[test]
    fn recursion_limit_respected(
        cmd_name in "[a-zA-Z][a-zA-Z0-9]{0,9}",
    ) {
        let args: Vec<String> = vec![cmd_name.clone()];
        let facts = ContextFacts::default();
        let mut ctx = make_ctx(&cmd_name, &args, &facts);
        ctx.recursion_limit = 1;
        ctx.recursion_depth = 1;

        let evaluator = Evaluator::new(&[]);
        let result = evaluator.evaluate(&mut crate::fold::PureFold, &ctx).unwrap();
        prop_assert_eq!(result.decision, Decision::Ask, "Should return Ask when recursion limit hit");
    }

    #[test]
    fn evaluation_is_deterministic(
        config in any_config(3),
        data in any_eval_context_data(),
    ) {
        let (cmd, args, facts) = data;
        let r1 = evaluate(&cmd, &args, &config, &facts).unwrap();
        let r2 = evaluate(&cmd, &args, &config, &facts).unwrap();
        prop_assert_eq!(r1.decision, r2.decision);
        prop_assert_eq!(r1.reason, r2.reason);
    }

    // 4.3.4 Property: First matching rule wins
    #[test]
    fn first_matching_rule_wins(
        cmd_name in "[a-zA-Z][a-zA-Z0-9]{0,9}",
    ) {
        let args: Vec<String> = vec![];
        let facts = ContextFacts::default();
        let config = Config {
            rules: vec![
                Rule {
                    command_effect: spanned(Effect::CommandPattern(
                        CommandPattern::Literal(cmd_name.clone()),
                    )),
                    effect: spanned(Effect::Allow(Some("first".into()))),
                    checks: vec![],
                    span: dummy_span(),
                },
                Rule {
                    command_effect: spanned(Effect::CommandPattern(
                        CommandPattern::Literal(cmd_name.clone()),
                    )),
                    effect: spanned(Effect::Deny(Some("second".into()))),
                    checks: vec![],
                    span: dummy_span(),
                },
            ],
            ..Config::default()
        };
        let result = evaluate(&cmd_name, &args, &config, &facts).unwrap();
        prop_assert_eq!(result.decision, Decision::Allow);
        prop_assert_eq!(result.reason, Some("first".to_string()));
    }

    // 4.3.5 Property: Facts are correctly bound and available
    #[test]
    fn facts_are_available_in_predicates(
        key in any_keyword(),
        value in "[a-zA-Z0-9]{1,10}",
        cmd_name in "[a-zA-Z][a-zA-Z0-9]{0,9}",
    ) {
        let args: Vec<String> = vec![];
        let mut facts = ContextFacts::default();
        facts.insert_scalar(key.clone(), &value);

        let pred = Predicate::Fact(may_i_core::FactQuery::Value {
            key: key.clone(),
            pattern: may_i_core::FactPattern::Literal(value),
        });
        let config = Config {
            rules: vec![Rule {
                command_effect: spanned(Effect::CommandPattern(
                    CommandPattern::Literal(cmd_name.clone()),
                )),
                effect: spanned(Effect::When {
                    predicate: spanned(pred),
                    effect: Box::new(spanned(Effect::Allow(Some("fact-matched".into())))),
                }),
                checks: vec![],
                span: dummy_span(),
            }],
            ..Config::default()
        };
        let result = evaluate(&cmd_name, &args, &config, &facts).unwrap();
        prop_assert_eq!(result.decision, Decision::Allow);
    }

    // 4.3.6 Property: Command context is correctly passed through
    #[test]
    fn command_context_passed_through(
        cmd_name in "[a-zA-Z][a-zA-Z0-9]{0,9}",
        other in "[a-zA-Z][a-zA-Z0-9]{0,9}",
    ) {
        let args: Vec<String> = vec![];
        let facts = ContextFacts::default();
        let config = Config {
            rules: vec![Rule {
                command_effect: spanned(Effect::CommandPattern(
                    CommandPattern::Literal(cmd_name.clone()),
                )),
                effect: spanned(Effect::Allow(Some("matched".into()))),
                checks: vec![],
                span: dummy_span(),
            }],
            ..Config::default()
        };
        let result = evaluate(&cmd_name, &args, &config, &facts).unwrap();
        prop_assert_eq!(result.decision, Decision::Allow);

        if cmd_name != other {
            let result2 = evaluate(&other, &args, &config, &facts).unwrap();
            prop_assert_eq!(result2.decision, Decision::Ask, "Non-matching command should Ask");
        }
    }

    // 4.3.7 Property: Arg context is correctly passed through
    #[test]
    fn arg_context_passed_through(
        cmd_name in "[a-zA-Z][a-zA-Z0-9]{0,9}",
        target_arg in "[a-zA-Z][a-zA-Z0-9]{0,9}",
    ) {
        let args: Vec<String> = vec![target_arg.clone()];
        let facts = ContextFacts::default();
        let config = Config {
            rules: vec![Rule {
                command_effect: spanned(Effect::CommandPattern(
                    CommandPattern::Literal(cmd_name.clone()),
                )),
                effect: spanned(Effect::ArgPattern(
                    may_i_core::pattern::ArgPattern::Anywhere(vec![
                        may_i_core::pattern::Expr::Literal(target_arg),
                    ]),
                )),
                checks: vec![],
                span: dummy_span(),
            }],
            ..Config::default()
        };
        let result = evaluate(&cmd_name, &args, &config, &facts).unwrap();
        prop_assert_eq!(result.decision, Decision::Allow);
    }
}
