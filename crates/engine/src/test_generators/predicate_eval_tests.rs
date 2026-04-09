use super::*;
use crate::eval::{EvalContext, PredicateResult, evaluate_predicate};

fn make_ctx<'a>(command: &'a str, args: &'a [String], facts: &'a ContextFacts) -> EvalContext<'a> {
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
        let _ = evaluate_predicate(&pred, &ctx).unwrap();
    }

    #[test]
    fn evaluate_predicate_returns_match_or_nomatch(
        pred in any_predicate(2).prop_filter("no Named predicates", |p| !contains_named(p)),
        data in any_eval_context_data(),
    ) {
        let (cmd, args, facts) = data;
        let ctx = make_ctx(&cmd, &args, &facts);
        let result = evaluate_predicate(&pred, &ctx).unwrap();
        prop_assert!(result == PredicateResult::Match || result == PredicateResult::NoMatch);
    }

    #[test]
    fn not_predicate_inverts(
        pred in any_predicate(2).prop_filter("no Named predicates", |p| !contains_named(p)),
        data in any_eval_context_data(),
    ) {
        let (cmd, args, facts) = data;
        let ctx = make_ctx(&cmd, &args, &facts);
        let result = evaluate_predicate(&pred, &ctx).unwrap();
        let not_result = evaluate_predicate(&Predicate::Not(Box::new(pred)), &ctx).unwrap();
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
        let all_match = preds.iter().all(|p| evaluate_predicate(p, &ctx).unwrap() == PredicateResult::Match);
        let and_result = evaluate_predicate(&Predicate::And(preds), &ctx).unwrap();
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
        let any_match = preds.iter().any(|p| evaluate_predicate(p, &ctx).unwrap() == PredicateResult::Match);
        let or_result = evaluate_predicate(&Predicate::Or(preds), &ctx).unwrap();
        prop_assert_eq!(or_result == PredicateResult::Match, any_match);
    }

    #[test]
    fn fact_presence_matches_when_key_present(key in any_keyword()) {
        let mut facts = ContextFacts::default();
        facts.insert_present(key.clone());
        let args: Vec<String> = vec![];
        let ctx = make_ctx("test", &args, &facts);
        let pred = Predicate::Fact(may_i_core::FactQuery::Presence {
            key: key.clone(),
            vector_syntax: false,
        });
        prop_assert_eq!(evaluate_predicate(&pred, &ctx).unwrap(), PredicateResult::Match);
    }

    #[test]
    fn fact_value_matches_when_value_matches(
        key in any_keyword(),
        value in "[a-zA-Z0-9]{1,20}",
    ) {
        let mut facts = ContextFacts::default();
        facts.insert_scalar(key.clone(), &value);
        let args: Vec<String> = vec![];
        let ctx = make_ctx("test", &args, &facts);
        let pred = Predicate::Fact(may_i_core::FactQuery::Value {
            key: key.clone(),
            pattern: may_i_core::FactPattern::Literal(value),
        });
        prop_assert_eq!(evaluate_predicate(&pred, &ctx).unwrap(), PredicateResult::Match);
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
        prop_assert_eq!(evaluate_predicate(&ab_c, &ctx).unwrap(), evaluate_predicate(&a_bc, &ctx).unwrap());
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
        prop_assert_eq!(evaluate_predicate(&ab_c, &ctx).unwrap(), evaluate_predicate(&a_bc, &ctx).unwrap());
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
            evaluate_predicate(&not_and, &ctx).unwrap(),
            evaluate_predicate(&or_nots, &ctx).unwrap(),
            "not(a and b) != (not a) or (not b)"
        );

        // not(a or b) == (not a) and (not b)
        let not_or = Predicate::Not(Box::new(Predicate::Or(vec![a.clone(), b.clone()])));
        let and_nots = Predicate::And(vec![
            Predicate::Not(Box::new(a)),
            Predicate::Not(Box::new(b)),
        ]);
        prop_assert_eq!(
            evaluate_predicate(&not_or, &ctx).unwrap(),
            evaluate_predicate(&and_nots, &ctx).unwrap(),
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
