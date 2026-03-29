//! Proptest generators for engine evaluation types.
//!
//! Re-exports core generators and adds engine-specific generators
//! for Effect, Predicate, EvalContext, Rule, and Config.

use proptest::prelude::*;

use may_i_core::ast::{Check, Config, Effect, Predicate, Rule, SecurityConfig, Spanned};
use may_i_core::pattern::CommandPattern;
use may_i_core::{ContextFacts, Decision, Span};

// Re-export core generators.
pub use may_i_core::test_generators::*;

/// Shell keywords that the parser treats as tokens rather than command names.
/// Generated command names must avoid these to prevent parse mismatches in
/// check tests (where the shell parser is invoked on the command string).
const SHELL_KEYWORDS: &[&str] = &[
    "if", "then", "elif", "else", "fi", "for", "in", "while", "until", "do", "done", "case",
    "esac", "function",
];

fn is_shell_keyword(s: &str) -> bool {
    SHELL_KEYWORDS.contains(&s)
}

/// Generate a command name that is not a shell keyword.
fn any_command_name() -> impl Strategy<Value = String> {
    "[a-zA-Z][a-zA-Z0-9]{0,9}".prop_filter("not a shell keyword", |s| !is_shell_keyword(s))
}

fn dummy_span() -> Span {
    Span::new(0, 0)
}

fn spanned<T>(value: T) -> Spanned<T> {
    Spanned::new(value, dummy_span())
}

/// Generate terminal effects (Allow, Ask, Deny) with optional reasons.
pub fn any_terminal_effect() -> BoxedStrategy<Effect> {
    let reason = proptest::option::of("[a-zA-Z ]{1,30}");
    prop_oneof![
        reason.clone().prop_map(Effect::Allow),
        reason.clone().prop_map(Effect::Ask),
        reason.prop_map(Effect::Deny),
    ]
    .boxed()
}

/// Generate pattern effects (CommandPattern, ArgPattern).
pub fn any_pattern_effect(depth: u32) -> BoxedStrategy<Effect> {
    prop_oneof![
        any_command_pattern(depth).prop_map(Effect::CommandPattern),
        any_arg_pattern(depth).prop_map(Effect::ArgPattern),
    ]
    .boxed()
}

/// Generate recursive Effect trees with depth limiting.
pub fn any_effect(depth: u32) -> BoxedStrategy<Effect> {
    let leaf = prop_oneof![any_terminal_effect(), any_pattern_effect(0),];

    if depth == 0 {
        leaf.boxed()
    } else {
        leaf.prop_recursive(depth, 32, 8, move |inner| {
            let spanned_inner = inner.clone().prop_map(spanned);

            prop_oneof![
                // And combinator
                prop::collection::vec(spanned_inner.clone(), 1..5)
                    .prop_map(|effects| Effect::And { effects }),
                // Or combinator
                prop::collection::vec(spanned_inner.clone(), 1..5)
                    .prop_map(|effects| Effect::Or { effects }),
                // Not combinator
                spanned_inner.clone().prop_map(|e| Effect::Not {
                    effect: Box::new(e)
                }),
                // When conditional
                (
                    any_predicate(depth.saturating_sub(1)),
                    spanned_inner.clone()
                )
                    .prop_map(|(pred, effect)| Effect::When {
                        predicate: spanned(pred),
                        effect: Box::new(effect),
                    }),
                // Unless conditional
                (
                    any_predicate(depth.saturating_sub(1)),
                    spanned_inner.clone()
                )
                    .prop_map(|(pred, effect)| Effect::Unless {
                        predicate: spanned(pred),
                        effect: Box::new(effect),
                    }),
                // If conditional
                (
                    any_predicate(depth.saturating_sub(1)),
                    spanned_inner.clone(),
                    spanned_inner.clone()
                )
                    .prop_map(|(pred, then_eff, else_eff)| Effect::If {
                        predicate: spanned(pred),
                        then_effect: Box::new(then_eff),
                        else_effect: Box::new(else_eff),
                    }),
                // MayI recursive
                any_arg_pattern(depth.saturating_sub(1))
                    .prop_map(|pattern| Effect::MayI { pattern }),
            ]
        })
        .boxed()
    }
}

/// Generate Predicate trees with depth limiting.
pub fn any_predicate(depth: u32) -> BoxedStrategy<Predicate> {
    let leaf = prop_oneof![
        any_fact_query().prop_map(Predicate::Fact),
        any_arg_pattern(1).prop_map(Predicate::Arg),
    ];

    if depth == 0 {
        leaf.boxed()
    } else {
        leaf.prop_recursive(depth, 16, 4, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 2..5).prop_map(Predicate::And),
                prop::collection::vec(inner.clone(), 2..5).prop_map(Predicate::Or),
                inner.prop_map(|p| Predicate::Not(Box::new(p))),
            ]
        })
        .boxed()
    }
}

/// Generate owned evaluation context data (command, args, facts).
pub fn any_eval_context_data() -> impl Strategy<Value = (String, Vec<String>, ContextFacts)> {
    (
        "[a-zA-Z][a-zA-Z0-9_-]{0,19}",
        prop::collection::vec("[a-zA-Z0-9_/-]{1,20}", 0..10),
        any_context_facts(),
    )
}

/// Generate a vector of Rules.
pub fn any_rule_set(size: usize) -> BoxedStrategy<Vec<Rule>> {
    prop::collection::vec(
        (any_effect(2), prop::collection::vec(any_effect(2), 0..3)).prop_map(
            |(cmd_effect, effects)| Rule {
                command_effect: spanned(cmd_effect),
                effects: effects.into_iter().map(spanned).collect(),
                checks: vec![],
                span: dummy_span(),
            },
        ),
        0..size,
    )
    .boxed()
}

/// Generate complete Config structures.
pub fn any_config(size: usize) -> BoxedStrategy<Config> {
    any_rule_set(size)
        .prop_map(|rules| Config {
            defines: vec![],
            rules,
            security: SecurityConfig::default(),
            checks: vec![],
        })
        .boxed()
}

// --- Phase 4: Engine Property Tests ---

#[cfg(test)]
mod predicate_eval_tests {
    use super::*;
    use crate::eval::{EvalContext, PredicateResult, evaluate_predicate};

    fn make_ctx<'a>(
        command: &'a str,
        args: &'a [String],
        facts: &'a ContextFacts,
    ) -> EvalContext<'a> {
        EvalContext::new(command, args, facts)
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        #[test]
        fn evaluate_predicate_never_panics(
            pred in any_predicate(3).prop_filter("no Named predicates", |p| !contains_named(p)),
            data in any_eval_context_data(),
        ) {
            let (cmd, args, facts) = data;
            let ctx = make_ctx(&cmd, &args, &facts);
            let _ = evaluate_predicate(&pred, &ctx);
        }

        #[test]
        fn evaluate_predicate_returns_match_or_nomatch(
            pred in any_predicate(2).prop_filter("no Named predicates", |p| !contains_named(p)),
            data in any_eval_context_data(),
        ) {
            let (cmd, args, facts) = data;
            let ctx = make_ctx(&cmd, &args, &facts);
            let result = evaluate_predicate(&pred, &ctx);
            prop_assert!(result == PredicateResult::Match || result == PredicateResult::NoMatch);
        }

        #[test]
        fn not_predicate_inverts(
            pred in any_predicate(2).prop_filter("no Named predicates", |p| !contains_named(p)),
            data in any_eval_context_data(),
        ) {
            let (cmd, args, facts) = data;
            let ctx = make_ctx(&cmd, &args, &facts);
            let result = evaluate_predicate(&pred, &ctx);
            let not_result = evaluate_predicate(&Predicate::Not(Box::new(pred)), &ctx);
            match (result, not_result) {
                (PredicateResult::Match, PredicateResult::NoMatch) |
                (PredicateResult::NoMatch, PredicateResult::Match) => {},
                (r1, r2) => prop_assert!(false, "Not did not invert: {:?} -> {:?}", r1, r2),
            }
        }

        #[test]
        fn and_predicate_matches_iff_all(
            preds in prop::collection::vec(
                any_predicate(1).prop_filter("no Named", |p| !contains_named(p)),
                2..4,
            ),
            data in any_eval_context_data(),
        ) {
            let (cmd, args, facts) = data;
            let ctx = make_ctx(&cmd, &args, &facts);
            let all_match = preds.iter().all(|p| evaluate_predicate(p, &ctx) == PredicateResult::Match);
            let and_result = evaluate_predicate(&Predicate::And(preds), &ctx);
            prop_assert_eq!(and_result == PredicateResult::Match, all_match);
        }

        #[test]
        fn or_predicate_matches_iff_any(
            preds in prop::collection::vec(
                any_predicate(1).prop_filter("no Named", |p| !contains_named(p)),
                2..4,
            ),
            data in any_eval_context_data(),
        ) {
            let (cmd, args, facts) = data;
            let ctx = make_ctx(&cmd, &args, &facts);
            let any_match = preds.iter().any(|p| evaluate_predicate(p, &ctx) == PredicateResult::Match);
            let or_result = evaluate_predicate(&Predicate::Or(preds), &ctx);
            prop_assert_eq!(or_result == PredicateResult::Match, any_match);
        }

        #[test]
        fn fact_presence_matches_when_key_present(key in any_keyword()) {
            let mut facts = ContextFacts::default();
            facts.insert_present(key.as_str());
            let args: Vec<String> = vec![];
            let ctx = make_ctx("test", &args, &facts);
            let pred = Predicate::Fact(may_i_core::FactQuery::Presence {
                key: key.as_str().to_string(),
                vector_syntax: false,
            });
            prop_assert_eq!(evaluate_predicate(&pred, &ctx), PredicateResult::Match);
        }

        #[test]
        fn fact_value_matches_when_value_matches(
            key in any_keyword(),
            value in "[a-zA-Z0-9]{1,20}",
        ) {
            let mut facts = ContextFacts::default();
            facts.insert_scalar(key.as_str(), &value);
            let args: Vec<String> = vec![];
            let ctx = make_ctx("test", &args, &facts);
            let pred = Predicate::Fact(may_i_core::FactQuery::Value {
                key: key.as_str().to_string(),
                pattern: may_i_core::FactPattern::Literal(value),
            });
            prop_assert_eq!(evaluate_predicate(&pred, &ctx), PredicateResult::Match);
        }
    }

    // 4.1.6 Property: And is associative
    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        #[test]
        fn and_predicate_is_associative(
            a in any_predicate(1).prop_filter("no Named", |p| !contains_named(p)),
            b in any_predicate(1).prop_filter("no Named", |p| !contains_named(p)),
            c in any_predicate(1).prop_filter("no Named", |p| !contains_named(p)),
            data in any_eval_context_data(),
        ) {
            let (cmd, args, facts) = data;
            let ctx = make_ctx(&cmd, &args, &facts);
            // (a AND b) AND c
            let ab_c = Predicate::And(vec![
                Predicate::And(vec![a.clone(), b.clone()]),
                c.clone(),
            ]);
            // a AND (b AND c)
            let a_bc = Predicate::And(vec![
                a,
                Predicate::And(vec![b, c]),
            ]);
            prop_assert_eq!(evaluate_predicate(&ab_c, &ctx), evaluate_predicate(&a_bc, &ctx));
        }

        #[test]
        fn or_predicate_is_associative(
            a in any_predicate(1).prop_filter("no Named", |p| !contains_named(p)),
            b in any_predicate(1).prop_filter("no Named", |p| !contains_named(p)),
            c in any_predicate(1).prop_filter("no Named", |p| !contains_named(p)),
            data in any_eval_context_data(),
        ) {
            let (cmd, args, facts) = data;
            let ctx = make_ctx(&cmd, &args, &facts);
            // (a OR b) OR c
            let ab_c = Predicate::Or(vec![
                Predicate::Or(vec![a.clone(), b.clone()]),
                c.clone(),
            ]);
            // a OR (b OR c)
            let a_bc = Predicate::Or(vec![
                a,
                Predicate::Or(vec![b, c]),
            ]);
            prop_assert_eq!(evaluate_predicate(&ab_c, &ctx), evaluate_predicate(&a_bc, &ctx));
        }

        #[test]
        fn de_morgans_laws_hold(
            a in any_predicate(1).prop_filter("no Named", |p| !contains_named(p)),
            b in any_predicate(1).prop_filter("no Named", |p| !contains_named(p)),
            data in any_eval_context_data(),
        ) {
            let (cmd, args, facts) = data;
            let ctx = make_ctx(&cmd, &args, &facts);

            // not(a and b) == (not a) or (not b)
            let not_and = Predicate::Not(Box::new(Predicate::And(vec![a.clone(), b.clone()])));
            let or_nots = Predicate::Or(vec![
                Predicate::Not(Box::new(a.clone())),
                Predicate::Not(Box::new(b.clone())),
            ]);
            prop_assert_eq!(
                evaluate_predicate(&not_and, &ctx),
                evaluate_predicate(&or_nots, &ctx),
                "not(a and b) != (not a) or (not b)"
            );

            // not(a or b) == (not a) and (not b)
            let not_or = Predicate::Not(Box::new(Predicate::Or(vec![a.clone(), b.clone()])));
            let and_nots = Predicate::And(vec![
                Predicate::Not(Box::new(a)),
                Predicate::Not(Box::new(b)),
            ]);
            prop_assert_eq!(
                evaluate_predicate(&not_or, &ctx),
                evaluate_predicate(&and_nots, &ctx),
                "not(a or b) != (not a) and (not b)"
            );
        }
    }

    fn contains_named(pred: &Predicate) -> bool {
        match pred {
            Predicate::Named(_) => true,
            Predicate::And(preds) | Predicate::Or(preds) => preds.iter().any(contains_named),
            Predicate::Not(inner) => contains_named(inner),
            _ => false,
        }
    }
}

#[cfg(test)]
mod effect_eval_tests {
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
            effects: vec![spanned(effect.clone())],
            checks: vec![],
            span: dummy_span(),
        };
        let rules = [rule];
        let evaluator = Evaluator::new(&rules);
        let result = evaluator.evaluate(&mut crate::fold::PureFold, ctx);
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
            let _ = evaluate(&cmd, &args, &config, &facts);
        }

        #[test]
        fn evaluate_returns_valid_result(
            config in any_config(3),
            data in any_eval_context_data(),
        ) {
            let (cmd, args, facts) = data;
            let result = evaluate(&cmd, &args, &config, &facts);
            prop_assert!(
                matches!(result.decision, Decision::Allow | Decision::Ask | Decision::Deny)
            );
        }

        #[test]
        fn empty_config_returns_ask(data in any_eval_context_data()) {
            let (cmd, args, facts) = data;
            let config = Config::default();
            let result = evaluate(&cmd, &args, &config, &facts);
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
            let result = eval::evaluate_effect(&and_effect, &ctx, &[]);
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
            let result = eval::evaluate_effect(&and_effect, &ctx, &[]);
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
            let result = eval::evaluate_effect(&or_effect, &ctx, &[]);
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
            let result = eval::evaluate_effect(&or_effect, &ctx, &[]);
            prop_assert!(result.is_nil(), "Or of all-Nil should be Nil, got {:?}", result);
        }

        // 4.2.7 Property: Not inverts Allow<->Nil, preserves Ask/Deny
        #[test]
        fn not_inverts_allow_nil(data in any_eval_context_data()) {
            let (cmd, args, facts) = data;
            let ctx = make_ctx(&cmd, &args, &facts);

            // Not(Allow) -> Nil
            let not_allow = Effect::Not { effect: Box::new(spanned(Effect::Allow(None))) };
            let result = eval::evaluate_effect(&not_allow, &ctx, &[]);
            prop_assert!(result.is_nil(), "Not(Allow) should be Nil, got {:?}", result);

            // Not(Nil) -> Allow
            let nil = Effect::CommandPattern(CommandPattern::Literal("__no_match__".into()));
            let not_nil = Effect::Not { effect: Box::new(spanned(nil)) };
            let result = eval::evaluate_effect(&not_nil, &ctx, &[]);
            prop_assert_eq!(result.decision(), Some(Decision::Allow));

            // Not(Ask) -> Ask
            let not_ask = Effect::Not { effect: Box::new(spanned(Effect::Ask(None))) };
            let result = eval::evaluate_effect(&not_ask, &ctx, &[]);
            prop_assert_eq!(result.decision(), Some(Decision::Ask));

            // Not(Deny) -> Deny
            let not_deny = Effect::Not { effect: Box::new(spanned(Effect::Deny(None))) };
            let result = eval::evaluate_effect(&not_deny, &ctx, &[]);
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
            let result = eval::evaluate_effect(&effect, &ctx, &[]);
            prop_assert!(result.is_decision(), "Should match literal command");

            if name != other {
                let ctx2 = make_ctx(&other, &args, &facts);
                let result2 = eval::evaluate_effect(&effect, &ctx2, &[]);
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
            let result = eval::evaluate_effect(&effect, &ctx, &[]);
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
                key: key.as_str().to_string(),
                vector_syntax: false,
            });
            let inner = Effect::Allow(Some("when-matched".into()));
            let when_effect = Effect::When {
                predicate: spanned(pred.clone()),
                effect: Box::new(spanned(inner)),
            };

            let ctx = make_ctx(&cmd, &args, &facts);
            let pred_result = evaluate_predicate(&pred, &ctx);
            let effect_result = eval::evaluate_effect(&when_effect, &ctx, &[]);

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
                key: key.as_str().to_string(),
                vector_syntax: false,
            });
            let inner = Effect::Allow(Some("unless-matched".into()));
            let unless_effect = Effect::Unless {
                predicate: spanned(pred.clone()),
                effect: Box::new(spanned(inner)),
            };

            let ctx = make_ctx(&cmd, &args, &facts);
            let pred_result = evaluate_predicate(&pred, &ctx);
            let effect_result = eval::evaluate_effect(&unless_effect, &ctx, &[]);

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
                key: key.as_str().to_string(),
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
            let pred_result = evaluate_predicate(&pred, &ctx);
            let effect_result = eval::evaluate_effect(&if_effect, &ctx, &[]);

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
                    key: key.as_str().to_string(),
                    vector_syntax: false,
                }),
                Predicate::Not(Box::new(Predicate::Fact(may_i_core::FactQuery::Presence {
                    key: key.as_str().to_string(),
                    vector_syntax: false,
                }))),
            ]);

            let cond_effect = Effect::Cond {
                branches: vec![
                    (spanned(always_true), spanned(Effect::Allow(Some("first".into())))),
                    (spanned(Predicate::Fact(may_i_core::FactQuery::Presence {
                        key: ":other".to_string(),
                        vector_syntax: false,
                    })), spanned(Effect::Deny(Some("second".into())))),
                ],
                fallback: Some(Box::new(spanned(Effect::Ask(Some("fallback".into()))))),
            };

            let result = eval::evaluate_effect(&cond_effect, &ctx, &[]);
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
                effects: vec![spanned(Effect::Allow(Some("inner-allowed".into())))],
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
            let result = eval::evaluate_effect(&may_i, &ctx, &rules);
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
            let result = evaluator.evaluate(&mut crate::fold::PureFold, &ctx);
            prop_assert_eq!(result.decision, Decision::Ask, "Should return Ask when recursion limit hit");
        }

        #[test]
        fn evaluation_is_deterministic(
            config in any_config(3),
            data in any_eval_context_data(),
        ) {
            let (cmd, args, facts) = data;
            let r1 = evaluate(&cmd, &args, &config, &facts);
            let r2 = evaluate(&cmd, &args, &config, &facts);
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
                        effects: vec![spanned(Effect::Allow(Some("first".into())))],
                        checks: vec![],
                        span: dummy_span(),
                    },
                    Rule {
                        command_effect: spanned(Effect::CommandPattern(
                            CommandPattern::Literal(cmd_name.clone()),
                        )),
                        effects: vec![spanned(Effect::Deny(Some("second".into())))],
                        checks: vec![],
                        span: dummy_span(),
                    },
                ],
                ..Config::default()
            };
            let result = evaluate(&cmd_name, &args, &config, &facts);
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
            facts.insert_scalar(key.as_str(), &value);

            let pred = Predicate::Fact(may_i_core::FactQuery::Value {
                key: key.as_str().to_string(),
                pattern: may_i_core::FactPattern::Literal(value),
            });
            let config = Config {
                rules: vec![Rule {
                    command_effect: spanned(Effect::CommandPattern(
                        CommandPattern::Literal(cmd_name.clone()),
                    )),
                    effects: vec![spanned(Effect::When {
                        predicate: spanned(pred),
                        effect: Box::new(spanned(Effect::Allow(Some("fact-matched".into())))),
                    })],
                    checks: vec![],
                    span: dummy_span(),
                }],
                ..Config::default()
            };
            let result = evaluate(&cmd_name, &args, &config, &facts);
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
                    effects: vec![spanned(Effect::Allow(Some("matched".into())))],
                    checks: vec![],
                    span: dummy_span(),
                }],
                ..Config::default()
            };
            let result = evaluate(&cmd_name, &args, &config, &facts);
            prop_assert_eq!(result.decision, Decision::Allow);

            if cmd_name != other {
                let result2 = evaluate(&other, &args, &config, &facts);
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
                    effects: vec![spanned(Effect::ArgPattern(
                        may_i_core::pattern::ArgPattern::Anywhere(vec![
                            may_i_core::pattern::Expr::Literal(target_arg),
                        ]),
                    ))],
                    checks: vec![],
                    span: dummy_span(),
                }],
                ..Config::default()
            };
            let result = evaluate(&cmd_name, &args, &config, &facts);
            prop_assert_eq!(result.decision, Decision::Allow);
        }
    }
}

#[cfg(test)]
mod check_tests {
    use super::*;
    use crate::check::run_checks;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, max_shrink_iters: 50, .. ProptestConfig::default() })]

        #[test]
        fn run_checks_never_panics(config in any_config(5)) {
            let _ = run_checks(&config);
        }

        #[test]
        fn check_allow_evaluates_correctly(
            cmd_name in any_command_name(),
        ) {
            let config = Config {
                rules: vec![Rule {
                    command_effect: spanned(Effect::CommandPattern(
                        CommandPattern::Literal(cmd_name.clone()),
                    )),
                    effects: vec![spanned(Effect::Allow(Some("allowed".into())))],
                    checks: vec![],
                    span: dummy_span(),
                }],
                checks: vec![Check {
                    command: cmd_name,
                    expected: Decision::Allow,
                    context: ContextFacts::default(),
                    span: dummy_span(),
                }],
                ..Config::default()
            };
            let results = run_checks(&config);
            for r in &results {
                prop_assert!(r.passed, "Check should pass: expected {:?}, got {:?}", r.expected, r.actual);
            }
        }

        // 4.4.3 Test: Failing checks have passed=false
        #[test]
        fn failing_check_has_passed_false(
            cmd_name in any_command_name(),
        ) {
            let config = Config {
                rules: vec![Rule {
                    command_effect: spanned(Effect::CommandPattern(
                        CommandPattern::Literal(cmd_name.clone()),
                    )),
                    effects: vec![spanned(Effect::Deny(Some("denied".into())))],
                    checks: vec![],
                    span: dummy_span(),
                }],
                checks: vec![Check {
                    command: cmd_name,
                    expected: Decision::Allow, // Expect Allow but get Deny
                    context: ContextFacts::default(),
                    span: dummy_span(),
                }],
                ..Config::default()
            };
            let results = run_checks(&config);
            for r in &results {
                prop_assert!(!r.passed, "Check should fail: expected {:?}, got {:?}", r.expected, r.actual);
            }
        }

        // 4.4.5 Test: Check with expected=Ask evaluates correctly
        #[test]
        fn check_ask_evaluates_correctly(
            cmd_name in any_command_name(),
        ) {
            // No rules match -> default Ask
            let config = Config {
                rules: vec![],
                checks: vec![Check {
                    command: cmd_name,
                    expected: Decision::Ask,
                    context: ContextFacts::default(),
                    span: dummy_span(),
                }],
                ..Config::default()
            };
            let results = run_checks(&config);
            for r in &results {
                prop_assert!(r.passed, "Check should pass: expected {:?}, got {:?}", r.expected, r.actual);
            }
        }

        // 4.4.7 Property: Check result matches expected decision
        #[test]
        fn check_result_matches_expected(
            cmd_name in any_command_name(),
            decision in any_decision(),
        ) {
            let effect = match decision {
                Decision::Allow => Effect::Allow(Some("test".into())),
                Decision::Ask => Effect::Ask(Some("test".into())),
                Decision::Deny => Effect::Deny(Some("test".into())),
            };
            let config = Config {
                rules: vec![Rule {
                    command_effect: spanned(Effect::CommandPattern(
                        CommandPattern::Literal(cmd_name.clone()),
                    )),
                    effects: vec![spanned(effect)],
                    checks: vec![],
                    span: dummy_span(),
                }],
                checks: vec![Check {
                    command: cmd_name,
                    expected: decision,
                    context: ContextFacts::default(),
                    span: dummy_span(),
                }],
                ..Config::default()
            };
            let results = run_checks(&config);
            for r in &results {
                prop_assert!(r.passed, "Check should pass: expected {:?}, got {:?}", r.expected, r.actual);
                prop_assert_eq!(r.actual, decision);
            }
        }

        #[test]
        fn check_deny_evaluates_correctly(
            cmd_name in any_command_name(),
        ) {
            let config = Config {
                rules: vec![Rule {
                    command_effect: spanned(Effect::CommandPattern(
                        CommandPattern::Literal(cmd_name.clone()),
                    )),
                    effects: vec![spanned(Effect::Deny(Some("denied".into())))],
                    checks: vec![],
                    span: dummy_span(),
                }],
                checks: vec![Check {
                    command: cmd_name,
                    expected: Decision::Deny,
                    context: ContextFacts::default(),
                    span: dummy_span(),
                }],
                ..Config::default()
            };
            let results = run_checks(&config);
            for r in &results {
                prop_assert!(r.passed, "Check should pass: expected {:?}, got {:?}", r.expected, r.actual);
            }
        }
    }
}

// --- Phase 5: Unit Test Backfill ---

#[cfg(test)]
mod edge_case_tests {
    use super::*;
    use crate::eval::{self, EvalContext, evaluate_predicate};

    fn make_ctx<'a>(
        command: &'a str,
        args: &'a [String],
        facts: &'a ContextFacts,
    ) -> EvalContext<'a> {
        EvalContext::new(command, args, facts)
    }

    // 5.1.1 Unit test: Named predicate panic path
    #[test]
    #[should_panic(expected = "Named predicates should be resolved")]
    fn named_predicate_panics() {
        let args: Vec<String> = vec![];
        let facts = ContextFacts::default();
        let ctx = make_ctx("test", &args, &facts);
        let pred = Predicate::Named("undefined".to_string());
        let _ = evaluate_predicate(&pred, &ctx);
    }

    // 5.1.2 Unit test: Invalid regex in pattern (error handling)
    #[test]
    fn invalid_regex_command_pattern() {
        // CommandPattern::Regex with a valid Regex (regex crate validates at construction)
        // Test that a regex that matches nothing still returns Nil
        let re = regex::Regex::new("^$").unwrap();
        let effect = Effect::CommandPattern(CommandPattern::Regex(re));
        let args: Vec<String> = vec![];
        let facts = ContextFacts::default();
        let ctx = make_ctx("notempty", &args, &facts);
        let result = eval::evaluate_effect(&effect, &ctx, &[]);
        assert!(result.is_nil());
    }

    // 5.1.3 Unit test: Deeply nested effect overflow protection
    #[test]
    fn deeply_nested_effect_doesnt_panic() {
        let args: Vec<String> = vec![];
        let facts = ContextFacts::default();
        let ctx = make_ctx("test", &args, &facts);

        // Build a deeply nested Not chain
        let mut effect = Effect::Allow(None);
        for _ in 0..50 {
            effect = Effect::Not {
                effect: Box::new(spanned(effect)),
            };
        }
        let result = eval::evaluate_effect(&effect, &ctx, &[]);
        // Should not panic, just alternate between Allow and Nil
        assert!(result.is_nil() || result.is_decision());
    }

    // 5.1.4 Unit test: Malformed argument patterns (edge cases)
    #[test]
    fn empty_args_with_positional_pattern() {
        let args: Vec<String> = vec![];
        let facts = ContextFacts::default();
        let ctx = make_ctx("test", &args, &facts);

        let pattern = may_i_core::pattern::ArgPattern::Positional {
            patterns: vec![may_i_core::pattern::PositionalArg {
                quantifier: may_i_core::Quantifier::One,
                pattern: may_i_core::pattern::Expr::Wildcard,
                recursive: false,
            }],
            continuation: None,
        };
        let effect = Effect::ArgPattern(pattern);
        let result = eval::evaluate_effect(&effect, &ctx, &[]);
        assert!(result.is_nil(), "No args should not match One pattern");
    }

    // 5.1.5 Unit test: Empty And/Or effects behavior
    #[test]
    fn empty_and_returns_allow() {
        let args: Vec<String> = vec![];
        let facts = ContextFacts::default();
        let ctx = make_ctx("test", &args, &facts);

        let and_effect = Effect::And { effects: vec![] };
        let result = eval::evaluate_effect(&and_effect, &ctx, &[]);
        // Empty And: no Nil encountered, last_result stays at default Allow
        assert_eq!(result.decision(), Some(Decision::Allow));
    }

    #[test]
    fn empty_or_returns_nil() {
        let args: Vec<String> = vec![];
        let facts = ContextFacts::default();
        let ctx = make_ctx("test", &args, &facts);

        let or_effect = Effect::Or { effects: vec![] };
        let result = eval::evaluate_effect(&or_effect, &ctx, &[]);
        assert!(result.is_nil(), "Empty Or should return Nil");
    }

    // 5.1.6 Unit test: Cond with empty branches
    #[test]
    fn cond_empty_branches_no_fallback() {
        let args: Vec<String> = vec![];
        let facts = ContextFacts::default();
        let ctx = make_ctx("test", &args, &facts);

        let cond = Effect::Cond {
            branches: vec![],
            fallback: None,
        };
        let result = eval::evaluate_effect(&cond, &ctx, &[]);
        assert!(result.is_nil(), "Empty Cond with no fallback should be Nil");
    }

    #[test]
    fn cond_empty_branches_with_fallback() {
        let args: Vec<String> = vec![];
        let facts = ContextFacts::default();
        let ctx = make_ctx("test", &args, &facts);

        let cond = Effect::Cond {
            branches: vec![],
            fallback: Some(Box::new(spanned(Effect::Deny(Some("fallback".into()))))),
        };
        let result = eval::evaluate_effect(&cond, &ctx, &[]);
        assert_eq!(result.decision(), Some(Decision::Deny));
    }
}

#[cfg(test)]
mod additional_properties {
    use super::*;
    use crate::eval::evaluate;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        // 7.2.1 Property: Evaluation is deterministic (same input → same output)
        // Already tested as evaluation_is_deterministic in effect_eval_tests

        // 7.2.2 Property: Trace generation is complete
        // The evaluate function always returns an EvalResult with a decision
        #[test]
        fn evaluate_always_produces_decision(
            config in any_config(3),
            data in any_eval_context_data(),
        ) {
            let (cmd, args, facts) = data;
            let result = evaluate(&cmd, &args, &config, &facts);
            prop_assert!(
                matches!(result.decision, Decision::Allow | Decision::Ask | Decision::Deny),
                "evaluate must always produce a valid decision"
            );
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::eval::evaluate;

    // 5.2.1 Integration test: Complex nested conditionals
    #[test]
    fn complex_nested_conditionals() {
        let args: Vec<String> = vec!["src".into()];
        let mut facts = ContextFacts::default();
        facts.insert_scalar(":env", "prod");

        // Rule: when env=prod, if arg is "src" -> allow, else deny
        let config = Config {
            rules: vec![Rule {
                command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                    "deploy".into(),
                ))),
                effects: vec![spanned(Effect::When {
                    predicate: spanned(Predicate::Fact(may_i_core::FactQuery::Value {
                        key: ":env".to_string(),
                        pattern: may_i_core::FactPattern::Literal("prod".to_string()),
                    })),
                    effect: Box::new(spanned(Effect::If {
                        predicate: spanned(Predicate::Arg(
                            may_i_core::pattern::ArgPattern::Anywhere(vec![
                                may_i_core::pattern::Expr::Literal("src".to_string()),
                            ]),
                        )),
                        then_effect: Box::new(spanned(Effect::Allow(Some(
                            "prod deploy allowed".into(),
                        )))),
                        else_effect: Box::new(spanned(Effect::Deny(Some(
                            "prod deploy denied".into(),
                        )))),
                    })),
                })],
                checks: vec![],
                span: dummy_span(),
            }],
            ..Config::default()
        };

        let result = evaluate("deploy", &args, &config, &facts);
        assert_eq!(result.decision, Decision::Allow);

        // Without the fact
        let empty_facts = ContextFacts::default();
        let result2 = evaluate("deploy", &args, &config, &empty_facts);
        assert_eq!(result2.decision, Decision::Ask); // When doesn't match -> Nil -> Ask
    }

    // 5.2.2 Integration test: Multiple fact bindings
    #[test]
    fn multiple_fact_bindings() {
        let args: Vec<String> = vec![];
        let mut facts = ContextFacts::default();
        facts.insert_scalar(":role", "admin");
        facts.insert_present(":verified");

        let config = Config {
            rules: vec![Rule {
                command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                    "admin-cmd".into(),
                ))),
                effects: vec![spanned(Effect::When {
                    predicate: spanned(Predicate::And(vec![
                        Predicate::Fact(may_i_core::FactQuery::Value {
                            key: ":role".to_string(),
                            pattern: may_i_core::FactPattern::Literal("admin".to_string()),
                        }),
                        Predicate::Fact(may_i_core::FactQuery::Presence {
                            key: ":verified".to_string(),
                            vector_syntax: false,
                        }),
                    ])),
                    effect: Box::new(spanned(Effect::Allow(Some("admin verified".into())))),
                })],
                checks: vec![],
                span: dummy_span(),
            }],
            ..Config::default()
        };

        let result = evaluate("admin-cmd", &args, &config, &facts);
        assert_eq!(result.decision, Decision::Allow);

        // Missing :verified
        let mut partial_facts = ContextFacts::default();
        partial_facts.insert_scalar(":role", "admin");
        let result2 = evaluate("admin-cmd", &args, &config, &partial_facts);
        assert_eq!(result2.decision, Decision::Ask);
    }

    // 5.2.3 Integration test: Recursive MayI with context
    #[test]
    fn recursive_may_i_with_context() {
        let args: Vec<String> = vec!["inner-cmd".into(), "arg1".into()];
        let facts = ContextFacts::default();

        let config = Config {
            rules: vec![
                // Wrapper rule: matches "wrapper", recurses into inner command
                Rule {
                    command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                        "wrapper".into(),
                    ))),
                    effects: vec![spanned(Effect::MayI {
                        pattern: may_i_core::pattern::ArgPattern::Positional {
                            patterns: vec![],
                            continuation: None,
                        },
                    })],
                    checks: vec![],
                    span: dummy_span(),
                },
                // Inner rule: matches "inner-cmd"
                Rule {
                    command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                        "inner-cmd".into(),
                    ))),
                    effects: vec![spanned(Effect::Allow(Some("inner allowed".into())))],
                    checks: vec![],
                    span: dummy_span(),
                },
            ],
            ..Config::default()
        };

        let result = evaluate("wrapper", &args, &config, &facts);
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.reason, Some("inner allowed".to_string()));
    }

    // 5.2.4 Integration test: Combined And/Or/Not in single rule
    #[test]
    fn combined_and_or_not_in_rule() {
        let args: Vec<String> = vec![];
        let facts = ContextFacts::default();

        // Rule: cmd matches AND (Allow OR (NOT Deny))
        // This should resolve to Allow
        let config = Config {
            rules: vec![Rule {
                command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(
                    "test".into(),
                ))),
                effects: vec![spanned(Effect::And {
                    effects: vec![
                        spanned(Effect::Or {
                            effects: vec![
                                spanned(Effect::Allow(Some("or-allow".into()))),
                                spanned(Effect::Not {
                                    effect: Box::new(spanned(Effect::Deny(Some(
                                        "inner-deny".into(),
                                    )))),
                                }),
                            ],
                        }),
                        spanned(Effect::Allow(Some("and-second".into()))),
                    ],
                })],
                checks: vec![],
                span: dummy_span(),
            }],
            ..Config::default()
        };

        let result = evaluate("test", &args, &config, &facts);
        // Or returns first non-Nil = Allow("or-allow")
        // And returns last = Allow("and-second")
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.reason, Some("and-second".to_string()));
    }
}

#[cfg(test)]
mod fold_properties {
    use super::*;
    use crate::eval::{self, EvalContext, Evaluator};
    use crate::fold::PureFold;
    use may_i_core::ast::EffectResult;

    fn make_ctx<'a>(
        command: &'a str,
        args: &'a [String],
        facts: &'a ContextFacts,
    ) -> EvalContext<'a> {
        EvalContext::new(command, args, facts)
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        // Property: PureFold is an identity — evaluate_effect_fold with PureFold
        // produces the same result as the convenience evaluate_effect wrapper.
        #[test]
        fn pure_fold_is_identity(
            effect in any_effect(2).prop_filter("no MayI", |e| !contains_may_i(e)),
            data in any_eval_context_data(),
        ) {
            let (cmd, args, facts) = data;
            let ctx = make_ctx(&cmd, &args, &facts);

            let direct = eval::evaluate_effect(&effect, &ctx, &[]);
            let via_fold = eval::evaluate_effect_fold(&mut PureFold, &effect, &ctx, &[]);

            prop_assert_eq!(direct, via_fold,
                "PureFold should produce identical result to direct evaluation");
        }

        // Property: PureFold identity holds at whole-config level too.
        #[test]
        fn pure_fold_agrees_with_evaluate(
            config in any_config(3),
            data in any_eval_context_data(),
        ) {
            let (cmd, args, facts) = data;
            let result_convenience = eval::evaluate(&cmd, &args, &config, &facts);

            let ctx = EvalContext::new(&cmd, &args, &facts);
            let evaluator = Evaluator::new(&config.rules);
            let result_fold = evaluator.evaluate(&mut PureFold, &ctx);

            prop_assert_eq!(result_convenience.decision, result_fold.decision);
            prop_assert_eq!(result_convenience.reason, result_fold.reason);
        }

        // Property: Forbidden pattern yields Deny when any forbidden token is
        // present in args, Allow when none are present.
        #[test]
        fn forbidden_pattern_semantics(
            tokens in prop::collection::vec("[a-zA-Z][a-zA-Z0-9]{0,9}", 1..4),
            extra_args in prop::collection::vec("[a-zA-Z][a-zA-Z0-9]{0,9}", 0..3),
            include_forbidden: bool,
        ) {
            let pattern = may_i_core::pattern::ArgPattern::Forbidden(
                tokens.iter().map(|t| may_i_core::pattern::Expr::Literal(t.clone())).collect(),
            );
            let effect = Effect::ArgPattern(pattern);

            let mut args = extra_args.clone();
            // Ensure no accidental overlap when testing absence.
            if !include_forbidden {
                args.retain(|a| !tokens.contains(a));
            } else {
                // Inject one of the forbidden tokens.
                args.push(tokens[0].clone());
            }

            let facts = ContextFacts::default();
            let ctx = make_ctx("test", &args, &facts);
            let result = eval::evaluate_effect(&effect, &ctx, &[]);

            let any_present = args.iter().any(|a| tokens.contains(a));
            if any_present {
                // Forbidden token found → predicate fails → Nil
                prop_assert_eq!(result.decision(), None,
                    "Forbidden token present → should be Nil (predicate fails)");
            } else {
                prop_assert_eq!(result.decision(), Some(Decision::Allow),
                    "No forbidden token → should Allow (predicate passes)");
            }
        }
    }

    fn contains_may_i(effect: &Effect) -> bool {
        match effect {
            Effect::MayI { .. } => true,
            Effect::And { effects } | Effect::Or { effects } => {
                effects.iter().any(|e| contains_may_i(&e.value))
            }
            Effect::Not { effect } => contains_may_i(&effect.value),
            Effect::When { effect, .. } | Effect::Unless { effect, .. } => {
                contains_may_i(&effect.value)
            }
            Effect::If {
                then_effect,
                else_effect,
                ..
            } => contains_may_i(&then_effect.value) || contains_may_i(&else_effect.value),
            Effect::Cond {
                branches, fallback, ..
            } => {
                branches.iter().any(|(_, e)| contains_may_i(&e.value))
                    || fallback
                        .as_ref()
                        .map_or(false, |f| contains_may_i(&f.value))
            }
            _ => false,
        }
    }
}
