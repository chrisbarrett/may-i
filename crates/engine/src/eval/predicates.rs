use may_i_core::ast::{EnvScopeMatcher, Predicate};
use may_i_core::pattern::{ArgPattern, MatchMode};
use may_i_core::{FactPattern, FactQuery};

use super::context::EnvScope;

use crate::EvalError;
use crate::fold::PureFold;
use crate::fold::{ChildResult, EvalFold, build_fact_detail};

use super::context::{EvalContext, PredicateResult};
use super::effects::{matcher_scope, scan_until_double_dash};

/// Whether the write's raw `scope` satisfies a `(scope …)` `matcher`.
/// `ReachesChild` is the disjunction of all reaching forms — and a unit only
/// exists for a reaching write — so it matches any scope.
fn scope_matches(matcher: EnvScopeMatcher, scope: EnvScope) -> bool {
    match matcher {
        EnvScopeMatcher::ReachesChild => true,
        EnvScopeMatcher::Prefix => scope == EnvScope::Prefix,
        EnvScopeMatcher::Export => scope == EnvScope::Export,
        EnvScopeMatcher::Bare => scope == EnvScope::Bare,
    }
}

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
            let (result, elements) = evaluate_arg_pattern_predicate(pattern, ctx);
            Ok(fold.predicate_arg(pattern, ctx.args, result, elements))
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
        Predicate::Bound { binding, .. } => {
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
        Predicate::Matches {
            binding, pattern, ..
        } => {
            let value = ctx.parser_bindings.get(binding);
            let result = match value.as_joined() {
                Some(s) if pattern.is_match(&s) => {
                    // A match against a capture with expansion-bearing
                    // provenance is unprovable for the runtime value.
                    if !pattern.matches_any_value()
                        && let Some(display) = value.first_expansion()
                    {
                        ctx.record_unresolved(display);
                    }
                    PredicateResult::Match
                }
                _ => PredicateResult::NoMatch,
            };
            Ok(fold.predicate_matches(binding, pattern, result))
        }
        // `(every? #var PRED)` — `PRED` matches every element of the
        // collection bound to `#var`. Vacuously true on empty.
        Predicate::Every {
            binding, pattern, ..
        } => {
            let value = ctx.parser_bindings.get(binding);
            let matched = value
                .as_collection()
                .iter()
                .all(|tok| pattern.is_match(&tok.text));
            if matched && !pattern.matches_any_value() {
                // The universal claim covers expansion-bearing elements
                // it cannot prove; record them for the allow-floor.
                for tok in value.as_collection() {
                    if let Some(display) = &tok.expansion {
                        ctx.record_unresolved(display);
                    }
                }
            }
            let result = if matched {
                PredicateResult::Match
            } else {
                PredicateResult::NoMatch
            };
            Ok(fold.predicate_every(binding, pattern, result))
        }
        // `(some? #var PRED)` — `PRED` matches at least one element.
        // False on empty.
        Predicate::Some {
            binding, pattern, ..
        } => {
            let value = ctx.parser_bindings.get(binding);
            let matched = value
                .as_collection()
                .iter()
                .any(|tok| pattern.is_match(&tok.text));
            if matched && !pattern.matches_any_value() {
                // Provable only if some literal element matches; when
                // every matching element is expansion-bearing, record
                // the first for the allow-floor.
                let provable = value
                    .as_collection()
                    .iter()
                    .any(|tok| tok.expansion.is_none() && pattern.is_match(&tok.text));
                if !provable
                    && let Some(display) = value
                        .as_collection()
                        .iter()
                        .find(|tok| pattern.is_match(&tok.text))
                        .and_then(|tok| tok.expansion.as_deref())
                {
                    ctx.record_unresolved(display);
                }
            }
            let result = if matched {
                PredicateResult::Match
            } else {
                PredicateResult::NoMatch
            };
            Ok(fold.predicate_some(binding, pattern, result))
        }
        // `(scope …)` — matches the scope of the env write under evaluation.
        // `ctx.env_scope` is `Some` exactly when an env write is being
        // evaluated (always a reaching write), so `reaches-child` matches any
        // present scope; the raw matchers compare for equality. Outside an env
        // decision `env_scope` is `None` and nothing matches.
        Predicate::Scope(matcher) => {
            let matched = ctx
                .env_scope
                .is_some_and(|scope| scope_matches(*matcher, scope));
            let result = if matched {
                PredicateResult::Match
            } else {
                PredicateResult::NoMatch
            };
            Ok(fold.predicate_scope(*matcher, result))
        }
        // `Predicate` is `#[non_exhaustive]`; future variants must be
        // added here explicitly.
        _ => unreachable!("unknown Predicate variant"),
    }
}

/// Collect the facts a *matched* predicate captures via fact-binding
/// patterns under quantifiers (`(every? #v [:k *])` / `(some? #v …)`).
///
/// Per the `patterns` spec: `every?` contributes every element's
/// captures when the whole fold matched; `some?` contributes the
/// captures of each matching element. Fact sets dedupe (union via
/// [`ContextFacts::merge`]). The caller invokes this only on the
/// predicate of a branch that matched.
pub(crate) fn captured_facts(pred: &Predicate, ctx: &EvalContext) -> may_i_core::ContextFacts {
    let mut out = may_i_core::ContextFacts::default();
    collect_captures(pred, ctx, &mut out);
    out
}

fn collect_captures(pred: &Predicate, ctx: &EvalContext, out: &mut may_i_core::ContextFacts) {
    use super::positional::match_expr_with_binding;
    // `Predicate` is `#[non_exhaustive]`; only the quantifier and boolean
    // combinator arms below capture facts — all others bind nothing.
    #[allow(clippy::wildcard_enum_match_arm)]
    match pred {
        Predicate::Every {
            binding, pattern, ..
        } => {
            let value = ctx.parser_bindings.get(binding);
            let coll = value.as_collection();
            if coll.iter().all(|t| pattern.is_match(&t.text)) {
                for t in coll {
                    let (_m, f) = match_expr_with_binding(pattern, &t.text);
                    *out = out.merge(&f);
                }
            }
        }
        Predicate::Some {
            binding, pattern, ..
        } => {
            let value = ctx.parser_bindings.get(binding);
            for t in value.as_collection() {
                let (matched, f) = match_expr_with_binding(pattern, &t.text);
                if matched {
                    *out = out.merge(&f);
                }
            }
        }
        // The caller only reaches here for a matched predicate, so an
        // `and` means every child matched — recurse into all of them.
        Predicate::And(preds) => {
            for p in preds {
                collect_captures(p, ctx, out);
            }
        }
        // For `or`, only the disjuncts that actually matched contribute.
        Predicate::Or(preds) => {
            for p in preds {
                let mut fold = PureFold;
                if let Ok(r) = evaluate_predicate_fold(&mut fold, p, ctx)
                    && PureFold::predicate_result(&r) == PredicateResult::Match
                {
                    collect_captures(p, ctx, out);
                }
            }
        }
        // Negation captures nothing; other predicates bind no quantifier.
        _ => {}
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

/// Evaluate an arg pattern as a predicate, returning the Match/NoMatch verdict
/// and — for `(positional …)` / `(exact …)` — the per-element match detail for
/// annotation (empty for other pattern kinds).
pub(super) fn evaluate_arg_pattern_predicate(
    pattern: &ArgPattern,
    ctx: &EvalContext,
) -> (PredicateResult, Vec<crate::fold::PositionalElementDetail>) {
    let outer_args = matcher_scope(ctx);

    // Ordered patterns carry per-element detail; handle them up front so the
    // single match drives both the verdict and the annotation.
    if let ArgPattern::Ordered {
        mode,
        patterns,
        continuation: _,
    } = pattern
    {
        let outer_exp = ctx.expansions_for_prefix(outer_args.len());
        let pos_idx = super::entry::parser_positional_indices(outer_args, &ctx.parser);
        let pos_args: Vec<&str> = pos_idx.iter().map(|&i| outer_args[i].as_str()).collect();
        let pos_exp: Vec<&super::decompose::Expansion> =
            pos_idx.iter().map(|&i| &outer_exp[i]).collect();
        let m = super::positional::match_positional_patterns_budgeted(
            &pos_args,
            &pos_exp,
            patterns,
            ctx.matcher_budget(),
        );
        let matched = m.matched && (*mode == MatchMode::Positional || m.consumed == pos_args.len());
        let elements =
            super::positional::build_positional_element_details(&pos_args, patterns, &m.elements);
        let result = if matched {
            for w in &m.unresolved {
                ctx.record_unresolved(w);
            }
            PredicateResult::Match
        } else {
            PredicateResult::NoMatch
        };
        return (result, elements);
    }

    let result = match pattern {
        ArgPattern::Ordered { .. } => unreachable!("Ordered handled above"),
        ArgPattern::Anywhere(exprs) => {
            let outer = scan_until_double_dash(outer_args);
            let outer_exp = ctx.expansions_for_prefix(outer.len());
            for expr in exprs {
                if super::effects::anywhere_match(expr, outer, outer_exp, ctx) {
                    return (PredicateResult::Match, vec![]);
                }
            }
            PredicateResult::NoMatch
        }
        ArgPattern::Forbidden(exprs) => {
            let outer = scan_until_double_dash(outer_args);
            for expr in exprs {
                if outer.iter().any(|arg| expr.is_match(arg)) {
                    return (PredicateResult::NoMatch, vec![]);
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
            let outer_exp = ctx.expansions_for_prefix(outer_args.len());
            match super::effects::find_parameter_value_for_predicate(
                outer_args,
                outer_exp,
                names,
                &ctx.parser,
            ) {
                Some((value, expansion)) => match form {
                    may_i_core::pattern::ParameterForm::Match(expr) => {
                        if expr.is_match(&value) {
                            if !expr.matches_any_value()
                                && let Some(display) = &expansion
                            {
                                ctx.record_unresolved(display);
                            }
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
    };
    (result, vec![])
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

    fn key(s: &str) -> may_i_core::Keyword {
        may_i_core::Keyword::new(s).unwrap()
    }

    fn bind(k: &str, inner: Expr) -> Expr {
        Expr::Bind {
            key: key(k),
            expr: Box::new(inner),
        }
    }

    // ── shape-typed-bindings: fact capture under quantifiers (5.3) ──

    #[test]
    fn every_with_fact_binding_accumulates_all_values() {
        let facts = ContextFacts::default();
        let args: Vec<String> = vec![];
        let ctx = ctx_with_collection(&facts, &args, vec!["BatchMode=yes", "ConnectTimeout=10"]);
        let pred = Predicate::Every {
            binding: bn("opts"),
            binding_span: may_i_core::Span::new(0, 0),
            pattern: bind(":ssh/opt", Expr::Wildcard),
        };
        let captured = captured_facts(&pred, &ctx);
        let set = captured.get(&key(":ssh/opt")).expect("fact present");
        assert!(set.contains("BatchMode=yes"));
        assert!(set.contains("ConnectTimeout=10"));
    }

    #[test]
    fn every_with_one_failing_element_retains_no_captures() {
        let facts = ContextFacts::default();
        let args: Vec<String> = vec![];
        let ctx = ctx_with_collection(&facts, &args, vec!["/tmp/a", "/etc/passwd"]);
        // every? requires all to match the regex; one fails ⇒ no fact.
        let pred = Predicate::Every {
            binding: bn("opts"),
            binding_span: may_i_core::Span::new(0, 0),
            pattern: Expr::And(vec![tmp_regex(), bind(":path", Expr::Wildcard)]),
        };
        let captured = captured_facts(&pred, &ctx);
        assert!(captured.is_empty(), "no captures when the fold fails");
    }

    #[test]
    fn some_with_fact_binding_accumulates_matching_only() {
        let facts = ContextFacts::default();
        let args: Vec<String> = vec![];
        let ctx = ctx_with_collection(
            &facts,
            &args,
            vec!["BatchMode=yes", "ProxyCommand=nc h p", "ProxyCommand=other"],
        );
        let pred = Predicate::Some {
            binding: bn("opts"),
            binding_span: may_i_core::Span::new(0, 0),
            pattern: Expr::And(vec![
                Expr::Regex(regex::Regex::new("^ProxyCommand=").unwrap()),
                bind(":ssh/proxy", Expr::Wildcard),
            ]),
        };
        let captured = captured_facts(&pred, &ctx);
        let set = captured.get(&key(":ssh/proxy")).expect("fact present");
        assert!(set.contains("ProxyCommand=nc h p"));
        assert!(set.contains("ProxyCommand=other"));
        assert!(
            !set.contains("BatchMode=yes"),
            "non-matching value excluded"
        );
    }

    /// Build a context whose `opts` binding holds the given collection.
    fn ctx_with_collection<'a>(
        facts: &'a ContextFacts,
        args: &'a [String],
        toks: Vec<&str>,
    ) -> EvalContext<'a> {
        let mut ctx = EvalContext::new("rm", args, facts, HashMap::new());
        ctx.parser_bindings
            .insert(bn("opts"), BindingValue::tokens(toks));
        ctx
    }

    #[test]
    fn every_all_match_is_match() {
        let facts = ContextFacts::default();
        let args: Vec<String> = vec![];
        let ctx = ctx_with_collection(&facts, &args, vec!["/tmp/a", "/tmp/b"]);
        let pred = Predicate::Every {
            binding: bn("opts"),
            binding_span: may_i_core::Span::new(0, 0),
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
            binding_span: may_i_core::Span::new(0, 0),
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
            binding_span: may_i_core::Span::new(0, 0),
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
            binding_span: may_i_core::Span::new(0, 0),
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
            binding_span: may_i_core::Span::new(0, 0),
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
            binding_span: may_i_core::Span::new(0, 0),
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
                &Predicate::Every { binding: bn("opts"), binding_span: may_i_core::Span::new(0, 0), pattern: pat.clone() }, &ctx).unwrap();
            let some = evaluate_predicate(
                &Predicate::Some { binding: bn("opts"), binding_span: may_i_core::Span::new(0, 0), pattern: pat }, &ctx).unwrap();

            proptest::prop_assert_eq!(every == PredicateResult::Match, every_ref);
            proptest::prop_assert_eq!(some == PredicateResult::Match, some_ref);
        }
    }
}
