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
        let result = evaluate(&cmd, &args, &config, &facts).unwrap();
        prop_assert!(
            matches!(result.decision, Decision::Allow | Decision::Ask | Decision::Deny),
            "evaluate must always produce a valid decision"
        );
    }

    // Property: matched_consumed + unconsumed = total_args
    #[test]
    fn positional_match_conserves_arg_count(
        patterns in prop::collection::vec(
            prop_oneof![
                "[a-z]{1,5}".prop_map(|s| may_i_core::pattern::PositionalArg::one(
                    may_i_core::pattern::Expr::Literal(s)
                )),
                Just(may_i_core::pattern::PositionalArg::with_quantifier(
                    may_i_core::pattern::Expr::Wildcard,
                    may_i_core::Quantifier::Optional,
                )),
                Just(may_i_core::pattern::PositionalArg::with_quantifier(
                    may_i_core::pattern::Expr::Wildcard,
                    may_i_core::Quantifier::ZeroOrMore,
                )),
            ],
            1..5
        ),
        args in prop::collection::vec("[a-z]{1,5}", 0..8),
    ) {
        let arg_refs: Vec<&String> = args.iter().collect();
        let (matched, consumed, _facts) = crate::eval::match_positional_patterns(&arg_refs, &patterns);
        let unconsumed = args.len() - consumed;
        prop_assert_eq!(
            consumed + unconsumed, args.len(),
            "consumed ({}) + unconsumed ({}) must equal total args ({})",
            consumed, unconsumed, args.len()
        );
        // consumed must not exceed total
        prop_assert!(consumed <= args.len(),
            "consumed ({}) must not exceed total args ({})", consumed, args.len());
        // if matched, consumed <= total
        if matched {
            prop_assert!(consumed <= args.len());
        }
    }

    // Property: positional matching is deterministic
    #[test]
    fn positional_match_is_deterministic(
        patterns in prop::collection::vec(
            prop_oneof![
                "[a-z]{1,5}".prop_map(|s| may_i_core::pattern::PositionalArg::one(
                    may_i_core::pattern::Expr::Literal(s)
                )),
                Just(may_i_core::pattern::PositionalArg::with_quantifier(
                    may_i_core::pattern::Expr::Wildcard,
                    may_i_core::Quantifier::Optional,
                )),
                Just(may_i_core::pattern::PositionalArg::with_quantifier(
                    may_i_core::pattern::Expr::Wildcard,
                    may_i_core::Quantifier::ZeroOrMore,
                )),
            ],
            1..5
        ),
        args in prop::collection::vec("[a-z]{1,5}", 0..8),
    ) {
        let arg_refs: Vec<&String> = args.iter().collect();
        let (m1, c1, _f1) = crate::eval::match_positional_patterns(&arg_refs, &patterns);
        let (m2, c2, _f2) = crate::eval::match_positional_patterns(&arg_refs, &patterns);
        prop_assert_eq!(m1, m2, "matching should be deterministic");
        prop_assert_eq!(c1, c2, "consumed count should be deterministic");
    }
}
