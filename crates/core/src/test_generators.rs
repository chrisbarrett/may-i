//! Proptest generators for core types.
//!
//! Provides strategies for generating arbitrary instances of core types
//! for use in property-based tests. All recursive generators use depth
//! limiting to prevent infinite recursion.

use proptest::prelude::*;

use crate::ast::Effect;
use crate::context::ContextFacts;
use crate::pattern::{ArgPattern, CommandPattern, Expr, MatchMode, PositionalArg, Quantifier};
use crate::predicates::{FactPattern, FactQuery};
use crate::primitives::{Decision, Keyword};

/// Generate valid Keyword values (strings starting with `:`).
pub fn any_keyword() -> impl Strategy<Value = Keyword> {
    "[a-z][a-z0-9/_-]{0,19}".prop_map(|s| Keyword::new(format!(":{s}")).unwrap())
}

/// Generate Decision enum values with uniform distribution.
pub fn any_decision() -> impl Strategy<Value = Decision> {
    prop_oneof![
        Just(Decision::Allow),
        Just(Decision::Ask),
        Just(Decision::Deny),
    ]
}

/// Generate ContextFacts with 0-10 entries.
pub fn any_context_facts() -> impl Strategy<Value = ContextFacts> {
    prop::collection::vec(
        (
            any_keyword(),
            prop_oneof![Just(None), "[a-zA-Z0-9_-]{1,30}".prop_map(Some),],
        ),
        0..10,
    )
    .prop_map(|entries| {
        let mut facts = ContextFacts::default();
        for (k, v) in entries {
            match v {
                None => facts.insert_present(k),
                Some(s) => facts.insert_scalar(k, s),
            }
        }
        facts
    })
}

/// Generate Quantifier enum values.
pub fn any_quantifier() -> impl Strategy<Value = Quantifier> {
    prop_oneof![
        Just(Quantifier::One),
        Just(Quantifier::Optional),
        Just(Quantifier::OneOrMore),
        Just(Quantifier::ZeroOrMore),
    ]
}

/// Generate recursive FactPattern trees with depth limiting.
pub fn any_fact_pattern(depth: u32) -> BoxedStrategy<FactPattern> {
    let leaf = prop_oneof![
        "[a-zA-Z0-9_-]{1,20}".prop_map(FactPattern::Literal),
        Just(FactPattern::Wildcard),
        prop_oneof!["[a-z]+", "[a-z]{1,5}\\.[a-z]+", "\\^[a-z]+\\$"]
            .prop_filter_map("valid regex", |s| {
                regex::Regex::new(&s).ok().map(FactPattern::Regex)
            }),
    ];

    if depth == 0 {
        leaf.boxed()
    } else {
        leaf.prop_recursive(depth, 16, 4, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 1..4).prop_map(FactPattern::And),
                prop::collection::vec(inner.clone(), 1..4).prop_map(FactPattern::Or),
                inner.prop_map(|p| FactPattern::Not(Box::new(p))),
            ]
        })
        .boxed()
    }
}

/// Generate FactQuery variants.
pub fn any_fact_query() -> BoxedStrategy<FactQuery> {
    prop_oneof![
        (any_keyword(), proptest::bool::ANY).prop_map(|(k, vector)| {
            FactQuery::Presence {
                key: k,
                vector_syntax: vector,
            }
        }),
        (any_keyword(), any_fact_pattern(3))
            .prop_map(|(k, pattern)| { FactQuery::Value { key: k, pattern } }),
    ]
    .boxed()
}

/// Generate recursive Expr<E> trees with depth limiting.
pub fn any_expr(depth: u32) -> BoxedStrategy<Expr<Effect>> {
    let leaf = prop_oneof![
        "[a-zA-Z0-9_-]{1,20}".prop_map(Expr::Literal),
        Just(Expr::Wildcard),
    ];

    if depth == 0 {
        leaf.boxed()
    } else {
        leaf.prop_recursive(depth, 16, 4, move |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 1..4).prop_map(Expr::And),
                prop::collection::vec(inner.clone(), 1..4).prop_map(Expr::Or),
                inner.clone().prop_map(|e| Expr::Not(Box::new(e))),
                (any_keyword(), inner.clone()).prop_map(|(key, expr)| Expr::Bind {
                    key,
                    expr: Box::new(expr),
                }),
            ]
        })
        .boxed()
    }
}

/// Generate PositionalArg values.
pub fn any_positional_arg(depth: u32) -> BoxedStrategy<PositionalArg> {
    (any_quantifier(), any_expr(depth), proptest::bool::ANY)
        .prop_map(|(quantifier, pattern, recursive)| PositionalArg {
            quantifier,
            pattern,
            recursive,
        })
        .boxed()
}

/// Generate recursive CommandPattern trees with depth limiting.
pub fn any_command_pattern(depth: u32) -> BoxedStrategy<CommandPattern> {
    let leaf = prop_oneof![
        "[a-zA-Z][a-zA-Z0-9_-]{0,19}".prop_map(CommandPattern::Literal),
        prop_oneof!["[a-z]+", "\\^[a-z]+"].prop_filter_map("valid regex", |s| {
            regex::Regex::new(&s).ok().map(CommandPattern::Regex)
        }),
    ];

    if depth == 0 {
        leaf.boxed()
    } else {
        prop_oneof![
            leaf.clone(),
            prop::collection::vec(leaf, 2..4).prop_map(CommandPattern::Or),
        ]
        .boxed()
    }
}

/// Generate a simple string suitable for matching against patterns.
pub fn any_match_string() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_-]{1,20}"
}

/// Generate ArgPattern variants with depth limiting.
pub fn any_arg_pattern(depth: u32) -> BoxedStrategy<ArgPattern> {
    let expr_depth = depth.min(2);
    prop_oneof![
        prop::collection::vec(any_positional_arg(expr_depth), 0..4).prop_map(|patterns| {
            ArgPattern::Ordered {
                mode: MatchMode::Positional,
                patterns,
                continuation: None,
            }
        }),
        prop::collection::vec(any_positional_arg(expr_depth), 0..4).prop_map(|patterns| {
            ArgPattern::Ordered {
                mode: MatchMode::Exact,
                patterns,
                continuation: None,
            }
        }),
        prop::collection::vec(any_expr(expr_depth), 1..4).prop_map(ArgPattern::Anywhere),
        prop::collection::vec(any_expr(expr_depth), 1..4).prop_map(ArgPattern::Forbidden),
    ]
    .boxed()
}

// --- Phase 2: Core Property Tests ---

#[cfg(test)]
mod fact_pattern_tests {
    use super::*;
    use crate::predicates::FactPattern;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        #[test]
        fn is_literal_returns_true_only_for_literal(pat in any_fact_pattern(3)) {
            match &pat {
                FactPattern::Literal(_) => prop_assert!(pat.is_literal()),
                _ => prop_assert!(!pat.is_literal()),
            }
        }

        #[test]
        fn to_source_produces_nonempty_string(pat in any_fact_pattern(3)) {
            let source = pat.to_source();
            prop_assert!(!source.is_empty(), "to_source() was empty for {:?}", pat);
        }

        #[test]
        fn literal_matches_only_exact_string(value in "[a-zA-Z0-9_-]{1,20}", other in "[a-zA-Z0-9_-]{1,20}") {
            let pat = FactPattern::Literal(value.clone());
            prop_assert!(match_fact_pattern(&pat, &value));
            if value != other {
                prop_assert!(!match_fact_pattern(&pat, &other));
            }
        }

        #[test]
        fn wildcard_matches_any_string(value in "[a-zA-Z0-9_-]{0,50}") {
            prop_assert!(match_fact_pattern(&FactPattern::Wildcard, &value));
        }

        #[test]
        fn and_matches_iff_all_match(
            pats in prop::collection::vec(any_fact_pattern(1), 1..4),
            value in "[a-zA-Z0-9_-]{1,20}",
        ) {
            let and_pat = FactPattern::And(pats.clone());
            let all_match = pats.iter().all(|p| match_fact_pattern(p, &value));
            prop_assert_eq!(match_fact_pattern(&and_pat, &value), all_match);
        }

        #[test]
        fn or_matches_iff_any_match(
            pats in prop::collection::vec(any_fact_pattern(1), 1..4),
            value in "[a-zA-Z0-9_-]{1,20}",
        ) {
            let or_pat = FactPattern::Or(pats.clone());
            let any_match = pats.iter().any(|p| match_fact_pattern(p, &value));
            prop_assert_eq!(match_fact_pattern(&or_pat, &value), any_match);
        }

        #[test]
        fn not_inverts_match(pat in any_fact_pattern(2), value in "[a-zA-Z0-9_-]{1,20}") {
            let not_pat = FactPattern::Not(Box::new(pat.clone()));
            prop_assert_ne!(
                match_fact_pattern(&pat, &value),
                match_fact_pattern(&not_pat, &value)
            );
        }

        #[test]
        fn regex_pattern_matches_according_to_regex(
            pattern_str in "[a-z]{1,5}",
            value in "[a-z]{1,10}",
        ) {
            if let Ok(re) = regex::Regex::new(&pattern_str) {
                let pat = FactPattern::Regex(re.clone());
                prop_assert_eq!(match_fact_pattern(&pat, &value), re.is_match(&value));
            }
        }

        #[test]
        fn nested_patterns_dont_panic(pat in any_fact_pattern(5), value in "[a-zA-Z0-9_-]{1,20}") {
            let _ = match_fact_pattern(&pat, &value);
        }
    }

    fn match_fact_pattern(pattern: &FactPattern, value: &str) -> bool {
        match pattern {
            FactPattern::Wildcard => true,
            FactPattern::Literal(s) => s == value,
            FactPattern::Regex(re) => re.is_match(value),
            FactPattern::And(pats) => pats.iter().all(|p| match_fact_pattern(p, value)),
            FactPattern::Or(pats) => pats.iter().any(|p| match_fact_pattern(p, value)),
            FactPattern::Not(inner) => !match_fact_pattern(inner, value),
        }
    }
}

#[cfg(test)]
mod context_facts_tests {
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        #[test]
        fn has_returns_true_for_inserted_keys(key in any_keyword(), has_value: bool, value in "[a-zA-Z0-9]{1,20}") {
            let mut facts = ContextFacts::default();
            if has_value {
                facts.insert_scalar(key.clone(), &value);
            } else {
                facts.insert_present(key.clone());
            }
            prop_assert!(facts.has(&key));
        }

        #[test]
        fn has_returns_false_for_absent_keys(
            key in any_keyword(),
            other_key in any_keyword(),
        ) {
            let mut facts = ContextFacts::default();
            facts.insert_present(key.clone());
            if key != other_key {
                prop_assert!(!facts.has(&other_key));
            }
        }

        #[test]
        fn get_scalar_returns_some_only_for_scalar(key in any_keyword(), value in "[a-zA-Z0-9]{1,20}") {
            let mut facts = ContextFacts::default();
            facts.insert_scalar(key.clone(), &value);
            prop_assert_eq!(facts.get_scalar(&key), Some(value.as_str()));

            let mut facts2 = ContextFacts::default();
            facts2.insert_present(key.clone());
            prop_assert_eq!(facts2.get_scalar(&key), None);
        }

        #[test]
        fn merge_combines_contexts(a in any_context_facts(), b in any_context_facts()) {
            let merged = a.merge(&b);
            for (k, _v) in b.iter() {
                prop_assert!(merged.has(k));
            }
            for (k, _v) in a.iter() {
                prop_assert!(merged.has(k));
            }
        }

        #[test]
        fn merge_unions_sets(
            key in any_keyword(),
            val1 in "[a-z]{1,10}",
            val2 in "[a-z]{1,10}",
        ) {
            let mut a = ContextFacts::default();
            a.insert_scalar(key.clone(), &val1);
            let mut b = ContextFacts::default();
            b.insert_scalar(key.clone(), &val2);
            let merged = a.merge(&b);
            prop_assert!(merged.contains(&key, &val1));
            prop_assert!(merged.contains(&key, &val2));
        }

        #[test]
        fn merge_is_associative(a in any_context_facts(), b in any_context_facts(), c in any_context_facts()) {
            let ab_c = a.merge(&b).merge(&c);
            let a_bc = a.merge(&b.merge(&c));
            for (k, _) in ab_c.iter() {
                prop_assert!(a_bc.has(k), "key {} missing from a_bc", k);
            }
            for (k, _) in a_bc.iter() {
                prop_assert!(ab_c.has(k), "key {} missing from ab_c", k);
            }
            for (k, v) in ab_c.iter() {
                prop_assert_eq!(a_bc.get(k), Some(v));
            }
        }

        #[test]
        fn merge_with_empty_is_identity(facts in any_context_facts()) {
            let empty = ContextFacts::default();
            let merged_right = facts.merge(&empty);
            let merged_left = empty.merge(&facts);
            for (k, v) in facts.iter() {
                prop_assert_eq!(merged_right.get(k), Some(v));
                prop_assert_eq!(merged_left.get(k), Some(v));
            }
        }
    }
}

#[cfg(test)]
mod pattern_tests {
    use super::*;
    use crate::pattern::ExprBranch;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        #[test]
        fn command_literal_matches_exact(name in "[a-zA-Z][a-zA-Z0-9_-]{0,19}", other in "[a-zA-Z][a-zA-Z0-9_-]{0,19}") {
            let pat = CommandPattern::Literal(name.clone());
            prop_assert!(pat.is_match(&name));
            if name != other {
                prop_assert!(!pat.is_match(&other));
            }
        }

        #[test]
        fn command_regex_matches_per_regex(
            pattern_str in "[a-z]{1,5}",
            cmd in "[a-z]{1,10}",
        ) {
            if let Ok(re) = regex::Regex::new(&pattern_str) {
                let pat = CommandPattern::Regex(re.clone());
                prop_assert_eq!(pat.is_match(&cmd), re.is_match(&cmd));
            }
        }

        #[test]
        fn command_or_matches_if_any(
            names in prop::collection::vec("[a-zA-Z][a-zA-Z0-9]{0,9}", 2..4),
            cmd in "[a-zA-Z][a-zA-Z0-9]{0,9}",
        ) {
            let pats: Vec<CommandPattern> = names.iter().map(|n| CommandPattern::Literal(n.clone())).collect();
            let or_pat = CommandPattern::Or(pats);
            let expected = names.iter().any(|n| n == &cmd);
            prop_assert_eq!(or_pat.is_match(&cmd), expected);
        }

        #[test]
        fn expr_is_match_never_panics(expr in any_expr(3), text in any_match_string()) {
            let _ = expr.is_match(&text);
        }

        #[test]
        fn expr_literal_matches_exact(value in any_match_string(), text in any_match_string()) {
            let expr = Expr::<Effect>::Literal(value.clone());
            prop_assert_eq!(expr.is_match(&text), value == text);
        }

        #[test]
        fn expr_wildcard_matches_everything(text in any_match_string()) {
            prop_assert!(Expr::<Effect>::Wildcard.is_match(&text));
        }

        #[test]
        fn expr_and_matches_iff_all(
            exprs in prop::collection::vec(any_expr(1), 1..4),
            text in any_match_string(),
        ) {
            let and_expr = Expr::<Effect>::And(exprs.clone());
            let all_match = exprs.iter().all(|e| e.is_match(&text));
            prop_assert_eq!(and_expr.is_match(&text), all_match);
        }

        #[test]
        fn expr_or_matches_iff_any(
            exprs in prop::collection::vec(any_expr(1), 1..4),
            text in any_match_string(),
        ) {
            let or_expr = Expr::<Effect>::Or(exprs.clone());
            let any_match = exprs.iter().any(|e| e.is_match(&text));
            prop_assert_eq!(or_expr.is_match(&text), any_match);
        }

        #[test]
        fn expr_not_inverts(expr in any_expr(2), text in any_match_string()) {
            let not_expr = Expr::<Effect>::Not(Box::new(expr.clone()));
            prop_assert_ne!(expr.is_match(&text), not_expr.is_match(&text));
        }

        #[test]
        fn quantifier_min_correct(q in any_quantifier()) {
            match q {
                Quantifier::One | Quantifier::OneOrMore => prop_assert_eq!(q.min(), 1),
                Quantifier::Optional | Quantifier::ZeroOrMore => prop_assert_eq!(q.min(), 0),
            }
        }

        #[test]
        fn quantifier_is_repeating_correct(q in any_quantifier()) {
            match q {
                Quantifier::OneOrMore | Quantifier::ZeroOrMore => prop_assert!(q.is_repeating()),
                Quantifier::One | Quantifier::Optional => prop_assert!(!q.is_repeating()),
            }
        }

        #[test]
        fn expr_find_effect_cond_returns_matching_branch(text in any_match_string()) {
            let branch = ExprBranch {
                test: Expr::Wildcard,
                effect: Effect::Terminal { decision: Decision::Allow, reason: Some("matched".into()) },
            };
            let expr = Expr::Cond(vec![branch]);
            let found = expr.find_effect(&text);
            prop_assert!(found.is_some());
        }
    }
}
