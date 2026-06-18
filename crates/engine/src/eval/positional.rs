use may_i_core::ContextFacts;
use may_i_core::ast::Effect;
use may_i_core::pattern::PositionalArg;

use super::decompose::Expansion;

/// Per-element record of how a pattern element fared on the match's
/// winning (backtracking) path. Used to annotate traces against the
/// argument each element was actually tested with — a forward greedy
/// walk cannot reproduce this for quantifiers that give args back.
#[derive(Debug, Clone)]
pub(crate) struct ElementMatch {
    /// Index into the positional args of the value at the cursor when this
    /// element was evaluated — the value it was tested against. `None` when
    /// the cursor was already past the end of the arguments.
    pub(crate) tested: Option<usize>,
    /// Number of args this element consumed on the winning path.
    pub(crate) consumed: usize,
    /// Whether this element matched (false for the element a failed match
    /// stopped on).
    pub(crate) matched: bool,
}

/// Outcome of matching positional patterns against args.
pub(crate) struct PositionalMatch {
    pub(crate) matched: bool,
    /// Number of args consumed.
    pub(crate) consumed: usize,
    /// Facts captured from `Expr::Bind` expressions along the
    /// successful match path.
    pub(crate) facts: ContextFacts,
    /// Display texts of expansion-bearing args that a non-wildcard
    /// pattern element matched along the successful path. Such a match
    /// is not provable for the runtime value, so it cannot contribute
    /// to `:allow` (the rule evaluator floors on these).
    pub(crate) unresolved: Vec<String>,
    /// Per-element trace along the returned path (in pattern order). For a
    /// successful match this covers every element; for a failed match it
    /// covers the prefix up to and including the element that failed.
    pub(crate) elements: Vec<ElementMatch>,
}

/// Match positional patterns against args, capturing bound facts.
/// `expansions` is per-arg expansion provenance aligned with `args`.
///
/// Uses backtracking for Optional/ZeroOrMore/OneOrMore quantifiers: tries the
/// greedy match first, then progressively shorter matches if subsequent
/// patterns fail.
pub(crate) fn match_positional_patterns(
    args: &[&str],
    expansions: &[&Expansion],
    patterns: &[PositionalArg],
) -> PositionalMatch {
    debug_assert_eq!(args.len(), expansions.len());
    match_positional_recursive(
        args,
        expansions,
        patterns,
        0,
        0,
        ContextFacts::default(),
        Vec::new(),
    )
}

/// Positional match with all-literal expansion provenance, returning the
/// tuple shape the pre-provenance tests asserted on. Test-only adapter.
#[cfg(test)]
pub(crate) fn match_pos_lit(
    args: &[&str],
    patterns: &[PositionalArg],
) -> (bool, usize, ContextFacts) {
    const NONE_EXP: Expansion = None;
    let exps: Vec<&Expansion> = vec![&NONE_EXP; args.len()];
    let m = match_positional_patterns(args, &exps, patterns);
    (m.matched, m.consumed, m.facts)
}

/// Display text of `expansions[i]` when the match of `pattern` against
/// that arg is unprovable: the arg is expansion-bearing and the pattern
/// constrains the value (anything but a bare wildcard).
fn unprovable_match<'a, E: std::fmt::Debug + may_i_core::ToDoc>(
    pattern: &may_i_core::pattern::Expr<E>,
    expansions: &[&'a Expansion],
    i: usize,
) -> Option<&'a str> {
    if pattern.matches_any_value() {
        return None;
    }
    expansions[i].as_deref()
}

#[allow(clippy::too_many_arguments)]
fn match_positional_recursive(
    args: &[&str],
    expansions: &[&Expansion],
    patterns: &[PositionalArg],
    pat_idx: usize,
    arg_idx: usize,
    facts: ContextFacts,
    unresolved: Vec<String>,
) -> PositionalMatch {
    // Index of the value at the cursor, or None when past the end.
    let tested_at = |i: usize| if i < args.len() { Some(i) } else { None };
    // Prepend this element's record to a child result built deeper in the
    // pattern, so the returned trace is in pattern order along the path taken.
    let with_element = |mut child: PositionalMatch, el: ElementMatch| {
        child.elements.insert(0, el);
        child
    };

    // All patterns consumed → success
    if pat_idx >= patterns.len() {
        return PositionalMatch {
            matched: true,
            consumed: arg_idx,
            facts,
            unresolved,
            elements: Vec::new(),
        };
    }

    let pattern = &patterns[pat_idx];
    let no_match = |facts: ContextFacts, unresolved: Vec<String>| PositionalMatch {
        matched: false,
        consumed: arg_idx,
        facts,
        unresolved,
        elements: vec![ElementMatch {
            tested: tested_at(arg_idx),
            consumed: 0,
            matched: false,
        }],
    };

    match &pattern.quantifier {
        may_i_core::Quantifier::One => {
            if arg_idx >= args.len() {
                return no_match(facts, unresolved);
            }
            let (matched, f) = match_expr_with_binding(&pattern.pattern, args[arg_idx]);
            if !matched {
                return no_match(facts, unresolved);
            }
            let mut unresolved = unresolved;
            if let Some(w) = unprovable_match(&pattern.pattern, expansions, arg_idx) {
                unresolved.push(w.to_string());
            }
            let child = match_positional_recursive(
                args,
                expansions,
                patterns,
                pat_idx + 1,
                arg_idx + 1,
                facts.merge(&f),
                unresolved,
            );
            with_element(
                child,
                ElementMatch {
                    tested: Some(arg_idx),
                    consumed: 1,
                    matched: true,
                },
            )
        }
        may_i_core::Quantifier::Optional => {
            // Try consuming one arg first (greedy), then try skipping
            if arg_idx < args.len() {
                let (matched, f) = match_expr_with_binding(&pattern.pattern, args[arg_idx]);
                if matched {
                    let mut u = unresolved.clone();
                    if let Some(w) = unprovable_match(&pattern.pattern, expansions, arg_idx) {
                        u.push(w.to_string());
                    }
                    let result = match_positional_recursive(
                        args,
                        expansions,
                        patterns,
                        pat_idx + 1,
                        arg_idx + 1,
                        facts.merge(&f),
                        u,
                    );
                    if result.matched {
                        return with_element(
                            result,
                            ElementMatch {
                                tested: Some(arg_idx),
                                consumed: 1,
                                matched: true,
                            },
                        );
                    }
                }
            }
            // Skip (consume zero): the optional was still tested at the cursor.
            let child = match_positional_recursive(
                args,
                expansions,
                patterns,
                pat_idx + 1,
                arg_idx,
                facts,
                unresolved,
            );
            with_element(
                child,
                ElementMatch {
                    tested: tested_at(arg_idx),
                    consumed: 0,
                    matched: true,
                },
            )
        }
        may_i_core::Quantifier::ZeroOrMore => {
            // Count maximum matching args
            let mut max_consume = 0;
            while arg_idx + max_consume < args.len() {
                let (matched, _) =
                    match_expr_with_binding(&pattern.pattern, args[arg_idx + max_consume]);
                if !matched {
                    break;
                }
                max_consume += 1;
            }
            // Try from greedy (max) down to 0, backtracking
            let mut last = None;
            for consume in (0..=max_consume).rev() {
                let mut f = facts.clone();
                let mut u = unresolved.clone();
                for i in 0..consume {
                    let (_, fi) = match_expr_with_binding(&pattern.pattern, args[arg_idx + i]);
                    f = f.merge(&fi);
                    if let Some(w) = unprovable_match(&pattern.pattern, expansions, arg_idx + i) {
                        u.push(w.to_string());
                    }
                }
                let result = match_positional_recursive(
                    args,
                    expansions,
                    patterns,
                    pat_idx + 1,
                    arg_idx + consume,
                    f,
                    u,
                );
                let el = ElementMatch {
                    tested: tested_at(arg_idx),
                    consumed: consume,
                    matched: true,
                };
                if result.matched {
                    return with_element(result, el);
                }
                last = Some((result, el));
            }
            // No consume count led to an overall match. Keep the last (zero-
            // consume) child's downstream failure under this satisfiable `*`.
            let (child, el) = last.expect("range 0..=max always yields consume 0");
            with_element(child, el)
        }
        may_i_core::Quantifier::OneOrMore => {
            if arg_idx >= args.len() {
                return no_match(facts, unresolved);
            }
            let (first_matched, _) = match_expr_with_binding(&pattern.pattern, args[arg_idx]);
            if !first_matched {
                return no_match(facts, unresolved);
            }
            // Count maximum matching args (starting from 1)
            let mut max_consume = 1;
            while arg_idx + max_consume < args.len() {
                let (matched, _) =
                    match_expr_with_binding(&pattern.pattern, args[arg_idx + max_consume]);
                if !matched {
                    break;
                }
                max_consume += 1;
            }
            // Try from greedy (max) down to 1, backtracking
            let mut last = None;
            for consume in (1..=max_consume).rev() {
                let mut f = facts.clone();
                let mut u = unresolved.clone();
                for i in 0..consume {
                    let (_, fi) = match_expr_with_binding(&pattern.pattern, args[arg_idx + i]);
                    f = f.merge(&fi);
                    if let Some(w) = unprovable_match(&pattern.pattern, expansions, arg_idx + i) {
                        u.push(w.to_string());
                    }
                }
                let result = match_positional_recursive(
                    args,
                    expansions,
                    patterns,
                    pat_idx + 1,
                    arg_idx + consume,
                    f,
                    u,
                );
                let el = ElementMatch {
                    tested: Some(arg_idx),
                    consumed: consume,
                    matched: true,
                };
                if result.matched {
                    return with_element(result, el);
                }
                last = Some((result, el));
            }
            let (child, el) = last.expect("range 1..=max always yields consume 1");
            with_element(child, el)
        }
    }
}

/// Match a single expression against a value, capturing bound facts.
/// Returns (matched, bound_facts) where bound_facts contains any facts
/// captured from Expr::Bind expressions.
pub(crate) fn match_expr_with_binding<E: std::fmt::Debug + may_i_core::ToDoc>(
    expr: &may_i_core::pattern::Expr<E>,
    value: &str,
) -> (bool, ContextFacts) {
    use may_i_core::pattern::Expr;
    let mut facts = ContextFacts::default();

    let matched = match expr {
        Expr::Literal(s) => s == value,
        Expr::Wildcard => true,
        Expr::Regex(re) => re.is_match(value),
        Expr::And(exprs) => {
            let mut all_match = true;
            for e in exprs {
                let (m, f) = match_expr_with_binding(e, value);
                facts = facts.merge(&f);
                if !m {
                    all_match = false;
                }
            }
            all_match
        }
        Expr::Or(exprs) => {
            for e in exprs {
                let (m, f) = match_expr_with_binding(e, value);
                if m {
                    facts = facts.merge(&f);
                    return (true, facts);
                }
            }
            false
        }
        Expr::Not(inner) => {
            let (m, _) = match_expr_with_binding(inner, value);
            !m
        }
        Expr::Bind { key, expr: inner } => {
            // First check if the inner expression matches
            let (inner_matched, inner_facts) = match_expr_with_binding(inner, value);
            facts = facts.merge(&inner_facts);

            if inner_matched {
                // Capture the matched value as a fact
                facts.insert_scalar(key.clone(), value);
                true
            } else {
                false
            }
        }
        Expr::Cond(branches) => {
            // Match if any branch's test expression matches the value
            branches
                .iter()
                .any(|b| match_expr_with_binding(&b.test, value).0)
        }
        _ => false,
    };

    (matched, facts)
}

/// Build per-element match details for positional patterns from the trace the
/// matcher recorded along its winning path. Each detail carries the argument
/// the element was tested against, the args it consumed, and any binding /
/// expression match info for annotation purposes.
pub(crate) fn build_positional_element_details(
    args: &[&str],
    patterns: &[PositionalArg],
    elements: &[ElementMatch],
) -> Vec<crate::fold::PositionalElementDetail> {
    use may_i_core::pattern::Expr;

    let mut details = Vec::new();

    for (pat_idx, element) in elements.iter().enumerate() {
        let pattern = &patterns[pat_idx];
        let element_matched = element.matched;
        let tested_arg = element.tested.map(|i| args[i].to_string());

        // Consumed args start at the cursor (`tested`) and run for `consumed`.
        let start = element.tested.unwrap_or(0);
        let consumed_args: Vec<String> = (0..element.consumed)
            .map(|i| args[start + i].to_string())
            .collect();

        let binding = if let Expr::Bind { key, expr: inner } = &pattern.pattern
            && !consumed_args.is_empty()
        {
            let value = consumed_args.first().map(|v| v.to_string());
            let inner_match = value
                .as_ref()
                .and_then(|v| build_expr_match_detail(inner, v));
            Some(crate::fold::BindDetail {
                key: key.clone(),
                value,
                inner_match,
            })
        } else {
            None
        };

        // Key the match detail off the value the element was tested against,
        // not what it consumed: an element that failed (or a skipped optional)
        // consumed nothing yet was still compared against `tested_arg`, and
        // that comparison is exactly what the trace needs to show.
        let probe = tested_arg.as_deref();
        let match_kind = if let Expr::Cond(branches) = &pattern.pattern
            && let Some(value) = probe
        {
            branches
                .iter()
                .position(|b| match_expr_with_binding(&b.test, value).0)
                .map(crate::fold::PositionalMatchKind::CondBranch)
                .unwrap_or(crate::fold::PositionalMatchKind::None)
        } else if binding.is_none()
            && let Some(value) = probe
        {
            build_expr_match_detail(&pattern.pattern, value)
                .map(crate::fold::PositionalMatchKind::Expr)
                .unwrap_or(crate::fold::PositionalMatchKind::None)
        } else {
            crate::fold::PositionalMatchKind::None
        };

        details.push(crate::fold::PositionalElementDetail {
            pattern_index: pat_idx,
            consumed_args,
            tested_arg,
            binding,
            match_kind,
            matched: element_matched,
        });
    }

    details
}

/// Build expression match detail for a single expression against a value.
pub(crate) fn build_expr_match_detail<E: std::fmt::Debug + may_i_core::ToDoc>(
    expr: &may_i_core::pattern::Expr<E>,
    value: &str,
) -> Option<crate::fold::ExprMatchDetail> {
    use may_i_core::pattern::Expr;
    match expr {
        Expr::Literal(s) => Some(crate::fold::ExprMatchDetail::Literal {
            expected: s.clone(),
            actual: value.to_string(),
            matched: s == value,
        }),
        Expr::Regex(re) => Some(crate::fold::ExprMatchDetail::Regex {
            pattern: re.as_str().to_string(),
            actual: value.to_string(),
            matched: re.is_match(value),
        }),
        Expr::Wildcard => Some(crate::fold::ExprMatchDetail::Wildcard {
            actual: value.to_string(),
        }),
        // For compound expressions, don't generate top-level detail
        _ => None,
    }
}

/// Find the effect from a matching Expr::Cond branch for a given arg value.
/// Returns the effect from the first branch whose test matches, or the wildcard
/// (else) branch's effect if no specific branch matches.
fn find_cond_branch_effect<'a>(
    branches: &'a [may_i_core::pattern::ExprBranch<Effect>],
    value: &str,
) -> Option<&'a Effect> {
    for branch in branches {
        if match_expr_with_binding(&branch.test, value).0 {
            return Some(&branch.effect);
        }
    }
    None
}

/// If the last positional pattern is an `Expr::Cond`, find the matching branch's
/// effect for the last consumed arg. Returns None if the last pattern isn't a Cond
/// or no branch matched.
pub(super) fn resolve_trailing_cond_effect<'a>(
    patterns: &'a [may_i_core::pattern::PositionalArg],
    positional_args: &[&str],
    consumed: usize,
) -> Option<&'a Effect> {
    if consumed == 0 {
        return None;
    }
    let last_pattern = patterns.last()?;
    if let may_i_core::pattern::Expr::Cond(branches) = &last_pattern.pattern {
        let last_arg = positional_args.get(consumed - 1)?;
        find_cond_branch_effect(branches, last_arg)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::pattern::{Expr, PositionalArg, Quantifier};
    use may_i_core::test_generators::{any_match_string, any_positional_arg};
    use proptest::prelude::*;

    /// Build string args owned, then borrow for matching (no expansion
    /// provenance — all tokens literal).
    fn match_owned(args: &[String], patterns: &[PositionalArg]) -> (bool, usize, ContextFacts) {
        const NONE_EXP: Expansion = None;
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let exps: Vec<&Expansion> = vec![&NONE_EXP; refs.len()];
        let m = match_positional_patterns(&refs, &exps, patterns);
        (m.matched, m.consumed, m.facts)
    }

    fn match_full(args: &[&str], patterns: &[PositionalArg]) -> PositionalMatch {
        const NONE_EXP: Expansion = None;
        let exps: Vec<&Expansion> = vec![&NONE_EXP; args.len()];
        match_positional_patterns(args, &exps, patterns)
    }

    fn lit(s: &str) -> Expr {
        Expr::Literal(s.into())
    }

    /// When a `*` must give back an argument so a following required element
    /// can match, the per-element trace reflects the WINNING (backtracked)
    /// path: the required element is recorded as tested at the arg it actually
    /// matched, not the one the greedy `*` first swallowed.
    #[test]
    fn element_trace_follows_the_backtracked_path() {
        let patterns = vec![
            PositionalArg::with_quantifier(lit("a"), Quantifier::ZeroOrMore),
            PositionalArg::one(lit("a")),
        ];
        let m = match_full(&["a"], &patterns);
        assert!(m.matched);
        assert_eq!(m.consumed, 1);
        let tested: Vec<Option<usize>> = m.elements.iter().map(|e| e.tested).collect();
        let consumed: Vec<usize> = m.elements.iter().map(|e| e.consumed).collect();
        // `*` gave back its greedy match (consumed 0), the required `a` took arg 0.
        assert_eq!(tested, vec![Some(0), Some(0)]);
        assert_eq!(consumed, vec![0, 1]);
    }

    /// A failed match records the prefix up to and including the element that
    /// failed, and nothing after it.
    #[test]
    fn element_trace_stops_at_the_failing_element() {
        let patterns = vec![
            PositionalArg::one(lit("checkout")),
            PositionalArg::one(lit("--")),
        ];
        let m = match_full(&["status"], &patterns);
        assert!(!m.matched);
        // Only the first element was reached; it was tested against "status".
        assert_eq!(m.elements.len(), 1);
        assert_eq!(m.elements[0].tested, Some(0));
        assert!(!m.elements[0].matched);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// matched + unconsumed = original arg count.
        #[test]
        fn matched_plus_unconsumed_eq_total(
            patterns in prop::collection::vec(any_positional_arg(1), 0..4),
            args in prop::collection::vec(any_match_string(), 0..8),
        ) {
            let (matched, consumed, _) = match_owned(&args, &patterns);
            if matched {
                prop_assert!(consumed <= args.len(),
                    "consumed ({}) > total ({})", consumed, args.len());
            }
            prop_assert!(consumed <= args.len(),
                "consumed ({}) exceeds arg count ({})", consumed, args.len());
        }

        /// ZeroOrMore is greedy: it consumes the maximal matching prefix
        /// when the remaining patterns still succeed.
        #[test]
        fn zero_or_more_is_greedy(
            args in prop::collection::vec(any_match_string(), 1..6),
        ) {
            // Pattern: (*)* — a ZeroOrMore wildcard followed by nothing.
            // Should consume all args.
            let patterns = vec![PositionalArg::with_quantifier(
                Expr::Wildcard,
                Quantifier::ZeroOrMore,
            )];
            let (matched, consumed, _) = match_owned(&args, &patterns);
            prop_assert!(matched, "wildcard ZeroOrMore should match anything");
            prop_assert_eq!(consumed, args.len(),
                "ZeroOrMore wildcard should greedily consume all {} args, got {}",
                args.len(), consumed);
        }

        /// Matching is deterministic: same inputs → same output.
        #[test]
        fn matching_is_deterministic(
            patterns in prop::collection::vec(any_positional_arg(1), 0..4),
            args in prop::collection::vec(any_match_string(), 0..6),
        ) {
            let r1 = match_owned(&args, &patterns);
            let r2 = match_owned(&args, &patterns);
            prop_assert_eq!(r1.0, r2.0, "matched differs between runs");
            prop_assert_eq!(r1.1, r2.1, "consumed differs between runs");
        }
    }
}
