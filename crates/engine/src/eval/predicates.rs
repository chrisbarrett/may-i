use may_i_core::ast::Predicate;
use may_i_core::pattern::{ArgPattern, MatchMode};
use may_i_core::{FactPattern, FactQuery};

use crate::EvalError;
#[cfg(test)]
use crate::fold::PureFold;
use crate::fold::{ChildResult, EvalFold, build_fact_detail};

use super::context::{EvalContext, PredicateResult};
use super::effects::{matcher_scope, scan_until_double_dash};
use super::entry::parser_positional_args;
use super::positional::match_positional_patterns;

/// Evaluate a predicate against the context (non-generic, uses PureFold).
#[cfg(test)]
pub(crate) fn evaluate_predicate(
    predicate: &Predicate,
    ctx: &EvalContext,
) -> Result<PredicateResult, EvalError> {
    let mut fold = PureFold;
    let out = evaluate_predicate_fold(&mut fold, predicate, ctx)?;
    Ok(PureFold::predicate_result(&out))
}

/// Evaluate a predicate with a fold.
pub(crate) fn evaluate_predicate_fold<F: EvalFold>(
    fold: &mut F,
    predicate: &Predicate,
    ctx: &EvalContext,
) -> Result<F::PredicateOut, EvalError> {
    match predicate {
        Predicate::Fact(query) => {
            let result = evaluate_fact_query(query, ctx);
            let detail = build_fact_detail(query, ctx.facts);
            Ok(fold.predicate_fact(query, result, detail))
        }
        Predicate::Arg(pattern) => {
            let result = evaluate_arg_pattern_predicate(pattern, ctx);
            Ok(fold.predicate_arg(pattern, ctx.args, result))
        }
        Predicate::And(predicates) => {
            let mut children = Vec::new();
            let mut result = PredicateResult::Match;
            let mut short_circuited = false;

            for p in predicates {
                if short_circuited {
                    children.push(ChildResult::Skipped);
                } else {
                    let out = evaluate_predicate_fold(fold, p, ctx)?;
                    let r = F::predicate_result(&out);
                    if r == PredicateResult::NoMatch {
                        result = PredicateResult::NoMatch;
                        short_circuited = true;
                    }
                    children.push(ChildResult::Evaluated(out));
                }
            }
            Ok(fold.predicate_and(children, result))
        }
        Predicate::Or(predicates) => {
            let mut children = Vec::new();
            let mut result = PredicateResult::NoMatch;
            let mut short_circuited = false;

            for p in predicates {
                if short_circuited {
                    children.push(ChildResult::Skipped);
                } else {
                    let out = evaluate_predicate_fold(fold, p, ctx)?;
                    let r = F::predicate_result(&out);
                    if r == PredicateResult::Match {
                        result = PredicateResult::Match;
                        short_circuited = true;
                    }
                    children.push(ChildResult::Evaluated(out));
                }
            }
            Ok(fold.predicate_or(children, result))
        }
        Predicate::Not(inner) => {
            let out = evaluate_predicate_fold(fold, inner, ctx)?;
            let r = F::predicate_result(&out);
            let result = match r {
                PredicateResult::Match => PredicateResult::NoMatch,
                PredicateResult::NoMatch => PredicateResult::Match,
            };
            Ok(fold.predicate_not(out, result))
        }
        Predicate::Named(name) => {
            if let Some(body) = ctx.bindings.get(name.as_str()) {
                let child_out = evaluate_predicate_fold(fold, body, ctx)?;
                let result = F::predicate_result(&child_out);
                Ok(fold.predicate_named(name, child_out, result))
            } else {
                Err(EvalError::UnresolvedPredicate { name: name.clone() })
            }
        }
        // `(bound? #var)` — `#var` resolves to a non-empty value.
        Predicate::Bound { binding } => {
            let result = if ctx.parser_bindings.is_bound(binding) {
                PredicateResult::Match
            } else {
                PredicateResult::NoMatch
            };
            Ok(fold.predicate_bound(binding, result))
        }
        // `(matches? #var PAT)` — `#var` resolves, and its
        // string-coerced value matches `PAT`. `Tokens` values are
        // joined with single spaces (mirrors the recurse semantics).
        Predicate::Matches { binding, pattern } => {
            let value = ctx.parser_bindings.get(binding);
            let result = match value.as_joined() {
                Some(s) if pattern.is_match(&s) => PredicateResult::Match,
                _ => PredicateResult::NoMatch,
            };
            Ok(fold.predicate_matches(binding, pattern, result))
        }
        // `(every? #var PRED)` — `PRED` matches every element of the
        // collection bound to `#var`. Vacuously true on empty.
        Predicate::Every { binding, pattern } => {
            let value = ctx.parser_bindings.get(binding);
            let matched = value
                .as_collection()
                .iter()
                .all(|tok| pattern.is_match(tok));
            let result = if matched {
                PredicateResult::Match
            } else {
                PredicateResult::NoMatch
            };
            Ok(fold.predicate_every(binding, pattern, result))
        }
        // `(some? #var PRED)` — `PRED` matches at least one element.
        // False on empty.
        Predicate::Some { binding, pattern } => {
            let value = ctx.parser_bindings.get(binding);
            let matched = value
                .as_collection()
                .iter()
                .any(|tok| pattern.is_match(tok));
            let result = if matched {
                PredicateResult::Match
            } else {
                PredicateResult::NoMatch
            };
            Ok(fold.predicate_some(binding, pattern, result))
        }
        // `Predicate` is `#[non_exhaustive]`; future variants must be
        // added here explicitly.
        _ => unreachable!("unknown Predicate variant"),
    }
}

/// Evaluate a fact query against the context.
fn evaluate_fact_query(query: &FactQuery, ctx: &EvalContext) -> PredicateResult {
    match query {
        FactQuery::Presence { key, .. } => {
            if ctx.facts.has(key) {
                PredicateResult::Match
            } else {
                PredicateResult::NoMatch
            }
        }
        FactQuery::Value { key, pattern } => {
            if let Some(set) = ctx.facts.get(key) {
                if set.iter().any(|s| match_fact_pattern(pattern, s)) {
                    PredicateResult::Match
                } else {
                    PredicateResult::NoMatch
                }
            } else {
                PredicateResult::NoMatch
            }
        }
    }
}

/// Match a fact pattern against a value.
pub(crate) fn match_fact_pattern(pattern: &FactPattern, value: &str) -> bool {
    match pattern {
        FactPattern::Wildcard => true,
        FactPattern::Literal(s) => s == value,
        FactPattern::Regex(re) => re.is_match(value),
        FactPattern::And(patterns) => patterns.iter().all(|p| match_fact_pattern(p, value)),
        FactPattern::Or(patterns) => patterns.iter().any(|p| match_fact_pattern(p, value)),
        FactPattern::Not(inner) => !match_fact_pattern(inner, value),
        _ => false,
    }
}

/// Evaluate an arg pattern as a predicate (returns Match/NoMatch).
pub(super) fn evaluate_arg_pattern_predicate(
    pattern: &ArgPattern,
    ctx: &EvalContext,
) -> PredicateResult {
    let outer_args = matcher_scope(ctx);
    match pattern {
        ArgPattern::Ordered {
            mode,
            patterns,
            continuation: _,
        } => {
            let pos_args: Vec<&str> = parser_positional_args(outer_args, &ctx.parser);
            let (pat_matched, consumed, _) = match_positional_patterns(&pos_args, patterns);
            let matched =
                pat_matched && (*mode == MatchMode::Positional || consumed == pos_args.len());
            if matched {
                PredicateResult::Match
            } else {
                PredicateResult::NoMatch
            }
        }
        ArgPattern::Anywhere(exprs) => {
            let outer = scan_until_double_dash(outer_args);
            for expr in exprs {
                if outer.iter().any(|arg| expr.is_match(arg)) {
                    return PredicateResult::Match;
                }
            }
            PredicateResult::NoMatch
        }
        ArgPattern::Forbidden(exprs) => {
            let outer = scan_until_double_dash(outer_args);
            for expr in exprs {
                if outer.iter().any(|arg| expr.is_match(arg)) {
                    return PredicateResult::NoMatch;
                }
            }
            PredicateResult::Match
        }
        ArgPattern::Flag { names } => {
            if super::effects::flag_present_in_for_predicate(outer_args, names, &ctx.parser) {
                PredicateResult::Match
            } else {
                PredicateResult::NoMatch
            }
        }
        ArgPattern::Parameter { names, form } => {
            // In predicate position, only the value-shape forms are
            // meaningful — `(may-i …)` returns a Decision, which has no
            // Match/NoMatch projection.
            match super::effects::find_parameter_value_for_predicate(outer_args, names, &ctx.parser)
            {
                Some(value) => match form {
                    may_i_core::pattern::ParameterForm::Match(expr) => {
                        if expr.is_match(&value) {
                            PredicateResult::Match
                        } else {
                            PredicateResult::NoMatch
                        }
                    }
                    may_i_core::pattern::ParameterForm::Authorise => PredicateResult::NoMatch,
                },
                None => PredicateResult::NoMatch,
            }
        }
        // (tail (authorise)) yields a Decision via recursion — it has no
        // Match/NoMatch projection in predicate position.
        ArgPattern::Tail => PredicateResult::NoMatch,
    }
}

#[cfg(test)]
mod quantifier_tests {
    use super::*;
    use crate::eval::bindings::BindingValue;
    use may_i_core::ast::BindingName;
    use may_i_core::pattern::Expr;
    use may_i_core::{ContextFacts, ast::Predicate};
    use std::collections::HashMap;

    fn bn(s: &str) -> BindingName {
        BindingName::parse(s).unwrap()
    }

    fn tmp_regex() -> Expr {
        Expr::Regex(regex::Regex::new("^/tmp/").unwrap())
    }

    /// Build a context whose `opts` binding holds the given collection.
    fn ctx_with_collection<'a>(
        facts: &'a ContextFacts,
        args: &'a [String],
        toks: Vec<&str>,
    ) -> EvalContext<'a> {
        let mut ctx = EvalContext::new("rm", args, facts, HashMap::new());
        ctx.parser_bindings.insert(
            bn("opts"),
            BindingValue::Tokens(toks.into_iter().map(String::from).collect()),
        );
        ctx
    }

    #[test]
    fn every_all_match_is_match() {
        let facts = ContextFacts::default();
        let args: Vec<String> = vec![];
        let ctx = ctx_with_collection(&facts, &args, vec!["/tmp/a", "/tmp/b"]);
        let pred = Predicate::Every {
            binding: bn("opts"),
            pattern: tmp_regex(),
        };
        assert_eq!(
            evaluate_predicate(&pred, &ctx).unwrap(),
            PredicateResult::Match
        );
    }

    #[test]
    fn every_one_fails_is_no_match() {
        let facts = ContextFacts::default();
        let args: Vec<String> = vec![];
        let ctx = ctx_with_collection(&facts, &args, vec!["/tmp/a", "/etc/passwd"]);
        let pred = Predicate::Every {
            binding: bn("opts"),
            pattern: tmp_regex(),
        };
        assert_eq!(
            evaluate_predicate(&pred, &ctx).unwrap(),
            PredicateResult::NoMatch
        );
    }

    #[test]
    fn every_empty_is_vacuously_true() {
        let facts = ContextFacts::default();
        let args: Vec<String> = vec![];
        let ctx = ctx_with_collection(&facts, &args, vec![]);
        let pred = Predicate::Every {
            binding: bn("opts"),
            pattern: tmp_regex(),
        };
        assert_eq!(
            evaluate_predicate(&pred, &ctx).unwrap(),
            PredicateResult::Match
        );
    }

    #[test]
    fn some_one_matches_is_match() {
        let facts = ContextFacts::default();
        let args: Vec<String> = vec![];
        let ctx = ctx_with_collection(&facts, &args, vec!["/etc/x", "/tmp/y"]);
        let pred = Predicate::Some {
            binding: bn("opts"),
            pattern: tmp_regex(),
        };
        assert_eq!(
            evaluate_predicate(&pred, &ctx).unwrap(),
            PredicateResult::Match
        );
    }

    #[test]
    fn some_none_matches_is_no_match() {
        let facts = ContextFacts::default();
        let args: Vec<String> = vec![];
        let ctx = ctx_with_collection(&facts, &args, vec!["/etc/x", "/var/y"]);
        let pred = Predicate::Some {
            binding: bn("opts"),
            pattern: tmp_regex(),
        };
        assert_eq!(
            evaluate_predicate(&pred, &ctx).unwrap(),
            PredicateResult::NoMatch
        );
    }

    #[test]
    fn some_empty_is_false() {
        let facts = ContextFacts::default();
        let args: Vec<String> = vec![];
        let ctx = ctx_with_collection(&facts, &args, vec![]);
        let pred = Predicate::Some {
            binding: bn("opts"),
            pattern: tmp_regex(),
        };
        assert_eq!(
            evaluate_predicate(&pred, &ctx).unwrap(),
            PredicateResult::NoMatch
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config { cases: 256, ..Default::default() })]

        /// `every?`/`some?` fold semantics match a reference fold over
        /// a literal predicate.
        #[test]
        fn fold_matches_reference(
            toks in proptest::collection::vec("[a-c]{1,3}", 0..8),
            target in "[a-c]{1,3}",
        ) {
            let facts = ContextFacts::default();
            let args: Vec<String> = vec![];
            let ctx = ctx_with_collection(
                &facts, &args, toks.iter().map(String::as_str).collect());
            let pat = Expr::Literal(target.clone());

            let every_ref = toks.iter().all(|t| t == &target);
            let some_ref = toks.iter().any(|t| t == &target);

            let every = evaluate_predicate(
                &Predicate::Every { binding: bn("opts"), pattern: pat.clone() }, &ctx).unwrap();
            let some = evaluate_predicate(
                &Predicate::Some { binding: bn("opts"), pattern: pat }, &ctx).unwrap();

            proptest::prop_assert_eq!(every == PredicateResult::Match, every_ref);
            proptest::prop_assert_eq!(some == PredicateResult::Match, some_ref);
        }
    }
}
