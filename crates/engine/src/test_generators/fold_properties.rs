use super::*;
use crate::eval::{self, EvalContext, Evaluator};
use crate::fold::PureFold;

fn make_ctx<'a>(command: &'a str, args: &'a [String], facts: &'a ContextFacts) -> EvalContext<'a> {
    EvalContext::new(command, args, facts, Default::default())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

    // Property: PureFold is an identity — evaluate_effect_fold with PureFold
    // produces the same result as the convenience evaluate_effect wrapper.
    #[test]
    fn pure_fold_is_identity(
        effect in any_effect(2),
        data in any_eval_context_data(),
    ) {
        let (cmd, args, facts) = data;
        let ctx = make_ctx(&cmd, &args, &facts);

        let direct = eval::evaluate_effect(&effect, &ctx, &[]).unwrap();
        let via_fold = eval::evaluate_effect_fold(&mut PureFold, &effect, &ctx, &[]).unwrap();

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
        let result_convenience = eval::evaluate(&cmd, &args, &config, &facts).unwrap();

        // Must expand flags to match the convenience wrapper's behavior.
        let expanded = eval::entry::tokenise(&args, &vec![None; args.len()], &may_i_core::ast::ResolvedParser::synthetic_gnu("any")).0;
        let ctx = EvalContext::new(&cmd, &expanded, &facts, EvalContext::build_bindings(&config.defines));
        let evaluator = Evaluator::new(&config.rules);
        let result_fold = evaluator.evaluate(&mut PureFold, &ctx).unwrap();

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
        let result = eval::evaluate_effect(&effect, &ctx, &[]).unwrap();

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

    // Property: Optional patterns can be skipped when fewer args than patterns.
    #[test]
    fn optional_patterns_skippable(
        required in "[a-z]{1,5}",
        optional_vals in prop::collection::vec("[a-z]{1,5}", 1..3),
    ) {
        use may_i_core::pattern::{PositionalArg, Expr};

        let mut patterns: Vec<PositionalArg> = optional_vals.iter()
            .map(|v| PositionalArg::with_quantifier(
                Expr::Literal(v.clone()),
                may_i_core::Quantifier::Optional,
            ))
            .collect();
        patterns.push(PositionalArg::one(Expr::Literal(required.clone())));

        // With just the required arg, all optionals should be skipped.
        let args_owned = [required.clone()];
        let args: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();
        let (matched, consumed, _) = eval::positional::match_pos_lit(&args, &patterns);
        prop_assert!(matched, "Required arg should match when optionals are skipped");
        prop_assert_eq!(consumed, 1, "Only the required arg should be consumed");
    }

    // Property: ZeroOrMore with backtracking allows subsequent patterns to match.
    #[test]
    fn zero_or_more_backtracks(
        prefix_count in 0usize..4,
        suffix in "[a-z]{1,5}",
    ) {
        use may_i_core::pattern::{PositionalArg, Expr};

        let patterns = vec![
            PositionalArg::with_quantifier(
                Expr::Wildcard,
                may_i_core::Quantifier::ZeroOrMore,
            ),
            PositionalArg::one(Expr::Literal(suffix.clone())),
        ];

        let mut args_owned: Vec<String> = (0..prefix_count)
            .map(|i| format!("arg{i}"))
            .collect();
        args_owned.push(suffix.clone());
        let args: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();

        let (matched, consumed, _) = eval::positional::match_pos_lit(&args, &patterns);
        prop_assert!(matched,
            "Wildcard * should backtrack to let the literal suffix match");
        prop_assert_eq!(consumed, args_owned.len(),
            "All args should be consumed");
    }

    // Property: consumed_count equals the actual number of args matched.
    #[test]
    fn consumed_count_is_accurate(
        pattern_count in 1usize..4,
        arg_count in 0usize..6,
    ) {
        use may_i_core::pattern::{PositionalArg, Expr};

        // Build `pattern_count` required literal patterns.
        let patterns: Vec<PositionalArg> = (0..pattern_count)
            .map(|i| PositionalArg::one(Expr::Literal(format!("p{i}"))))
            .collect();

        // Build args: first `arg_count` matching, then stop.
        let args_owned: Vec<String> = (0..arg_count).map(|i| format!("p{i}")).collect();
        let args: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();

        let (matched, consumed, _) = eval::positional::match_pos_lit(&args, &patterns);
        if arg_count >= pattern_count {
            prop_assert!(matched);
            prop_assert_eq!(consumed, pattern_count);
        } else {
            prop_assert!(!matched);
            prop_assert!(consumed <= arg_count);
        }
    }

    // Property: expand_combined_flags preserves individual flags and non-flag args.
    #[test]
    fn expand_flags_roundtrip(
        flags in prop::collection::vec("[a-zA-Z]", 1..5),
    ) {
        let combined = format!("-{}", flags.join(""));
        let args = vec![combined.clone()];
        let expanded = eval::entry::tokenise(&args, &vec![None; args.len()], &may_i_core::ast::ResolvedParser::synthetic_gnu("any")).0;

        // Each flag should be present as -X
        for f in &flags {
            let expected = format!("-{f}");
            prop_assert!(expanded.contains(&expected),
                "Expanded flags should contain {expected}, got {expanded:?}");
        }
        prop_assert_eq!(expanded.len(), flags.len());
    }

    // Property: expand_combined_flags output preserves all flag characters
    // and non-flag args from the input.
    #[test]
    fn expand_flags_preserves_all_chars_and_nonflag_args(
        nonflag_args in prop::collection::vec("[a-zA-Z0-9_./]{1,10}", 0..4),
        flag_chars in prop::collection::vec("[a-zA-Z]", 2..6),
        single_flags in prop::collection::vec("-[a-zA-Z]", 0..3),
    ) {
        let combined = format!("-{}", flag_chars.join(""));
        let mut args: Vec<String> = nonflag_args.clone();
        args.push(combined);
        args.extend(single_flags.clone());

        let expanded = eval::entry::tokenise(&args, &vec![None; args.len()], &may_i_core::ast::ResolvedParser::synthetic_gnu("any")).0;

        // All non-flag args are preserved verbatim
        for nf in &nonflag_args {
            prop_assert!(expanded.contains(nf),
                "non-flag arg {nf:?} missing from expanded: {expanded:?}");
        }
        // All flag characters appear as individual -X entries
        for ch in &flag_chars {
            let expected = format!("-{ch}");
            prop_assert!(expanded.contains(&expected),
                "flag char {ch:?} missing from expanded: {expanded:?}");
        }
        // Single flags preserved
        for sf in &single_flags {
            prop_assert!(expanded.contains(sf),
                "single flag {sf:?} missing from expanded: {expanded:?}");
        }
    }

    // Property: expand_combined_flags leaves long options unchanged.
    #[test]
    fn expand_flags_preserves_long_options(
        opt in "--[a-zA-Z]{1,10}",
    ) {
        let args = vec![opt.clone()];
        let expanded = eval::entry::tokenise(&args, &vec![None; args.len()], &may_i_core::ast::ResolvedParser::synthetic_gnu("any")).0;
        prop_assert_eq!(expanded, args, "Long options should not be expanded");
    }

    // Property: positional_args excludes flags and long-option values.
    #[test]
    fn positional_args_skips_option_values(
        opt_name in "[a-zA-Z]{1,8}",
        opt_value in "[a-zA-Z]{1,8}",
        positional in "[a-zA-Z]{1,8}",
    ) {
        // When opt_value == positional the assertions contradict, so skip.
        prop_assume!(opt_value != positional);

        let args = vec![
            format!("--{opt_name}"),
            opt_value.clone(),
            positional.clone(),
        ];
        let parser = may_i_core::ast::ResolvedParser::synthetic_gnu("any");
        let result = eval::entry::parser_positional_args(&args, &parser);

        prop_assert!(!result.contains(&opt_value.as_str()),
            "Option value should be excluded from positional args");
        prop_assert!(result.contains(&positional.as_str()),
            "Positional arg should be included");
    }

    // Property: Arg predicate Allow continues, non-predicate Allow terminates.
    // A rule with (anywhere X) :effect [:allow "reason"] should produce the
    // terminal's reason, not just bare Allow from the predicate.
    #[test]
    fn arg_predicate_continues_to_terminal(
        cmd in any_command_name(),
        target in "[a-zA-Z]{1,5}",
        reason in "[a-zA-Z ]{1,20}",
    ) {
        let args = vec![target.clone()];
        let facts = ContextFacts::default();
        let config = Config {
            rules: vec![Rule {
                command_effect: spanned(Effect::CommandPattern(
                    CommandPattern::Literal(cmd.clone()),
                )),
                effect: spanned(Effect::And {
                    effects: vec![
                        spanned(Effect::ArgPattern(
                            may_i_core::pattern::ArgPattern::Anywhere(vec![
                                may_i_core::pattern::Expr::Literal(target),
                            ]),
                        )),
                        spanned(Effect::Terminal { decision: Decision::Allow, reason: Some(reason.clone()) }),
                    ],
                }),
                checks: vec![],
                span: dummy_span(),
                provenance: may_i_core::ast::Provenance::PrimaryConfig,
            }],
            ..Config::default()
        };
        let result = eval::evaluate(&cmd, &args, &config, &facts).unwrap();
        prop_assert_eq!(result.decision, Decision::Allow);
        prop_assert_eq!(result.reason, Some(reason),
            "Should use terminal effect's reason, not bare predicate Allow");
    }

    // Property: Arg predicate Nil skips rule, falls through to next rule.
    #[test]
    fn arg_predicate_nil_skips_to_next_rule(
        cmd in any_command_name(),
        target in "[a-zA-Z]{1,5}",
    ) {
        let args = vec![format!("NOT_{target}")];
        let facts = ContextFacts::default();
        let config = Config {
            rules: vec![
                Rule {
                    command_effect: spanned(Effect::CommandPattern(
                        CommandPattern::Literal(cmd.clone()),
                    )),
                    effect: spanned(Effect::And {
                        effects: vec![
                            spanned(Effect::ArgPattern(
                                may_i_core::pattern::ArgPattern::Anywhere(vec![
                                    may_i_core::pattern::Expr::Literal(target),
                                ]),
                            )),
                            spanned(Effect::Terminal { decision: Decision::Deny, reason: Some("should not reach".into()) }),
                        ],
                    }),
                    checks: vec![],
                    span: dummy_span(),
                    provenance: may_i_core::ast::Provenance::PrimaryConfig,
                },
                Rule {
                    command_effect: spanned(Effect::CommandPattern(
                        CommandPattern::Literal(cmd.clone()),
                    )),
                    effect: spanned(Effect::Terminal { decision: Decision::Ask, reason: Some("fallback".into()) }),
                    checks: vec![],
                    span: dummy_span(),
                    provenance: may_i_core::ast::Provenance::PrimaryConfig,
                },
            ],
            ..Config::default()
        };
        let result = eval::evaluate(&cmd, &args, &config, &facts).unwrap();
        prop_assert_eq!(result.decision, Decision::Ask);
        prop_assert_eq!(result.reason, Some("fallback".into()),
            "Should skip first rule and match second");
    }
}
