use may_i_core::ast::Predicate;
use may_i_core::pattern::{ArgPattern, MatchMode};
use may_i_core::{FactPattern, FactQuery};

use crate::EvalError;
#[cfg(test)]
use crate::fold::PureFold;
use crate::fold::{ChildResult, EvalFold, build_fact_detail};

use super::context::{EvalContext, PredicateResult};
use super::entry::positional_args;
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
    match pattern {
        ArgPattern::Ordered {
            mode,
            patterns,
            continuation: _,
        } => {
            let pos_args: Vec<&String> = positional_args(ctx.args);
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
            for expr in exprs {
                if ctx.args.iter().any(|arg| expr.is_match(arg)) {
                    return PredicateResult::Match;
                }
            }
            PredicateResult::NoMatch
        }
        ArgPattern::Forbidden(exprs) => {
            for expr in exprs {
                if ctx.args.iter().any(|arg| expr.is_match(arg)) {
                    return PredicateResult::NoMatch;
                }
            }
            PredicateResult::Match
        }
        _ => unreachable!("unknown ArgPattern variant"),
    }
}
