
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
}
