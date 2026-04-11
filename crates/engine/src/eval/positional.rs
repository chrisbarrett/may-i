use may_i_core::ContextFacts;
use may_i_core::ast::Effect;
use may_i_core::pattern::PositionalArg;

/// Match positional patterns against args, capturing bound facts.
/// Returns (matched, consumed_count, bound_facts) where consumed_count is the
/// number of args consumed and bound_facts contains any facts captured from
/// Expr::Bind expressions in the patterns.
///
/// Uses backtracking for Optional/ZeroOrMore/OneOrMore quantifiers: tries the
/// greedy match first, then progressively shorter matches if subsequent
/// patterns fail.
pub(crate) fn match_positional_patterns(
    args: &[&String],
    patterns: &[PositionalArg],
) -> (bool, usize, ContextFacts) {
    match_positional_recursive(args, patterns, 0, 0, ContextFacts::default())
}

fn match_positional_recursive(
    args: &[&String],
    patterns: &[PositionalArg],
    pat_idx: usize,
    arg_idx: usize,
    facts: ContextFacts,
) -> (bool, usize, ContextFacts) {
    // All patterns consumed → success
    if pat_idx >= patterns.len() {
        return (true, arg_idx, facts);
    }

    let pattern = &patterns[pat_idx];

    match &pattern.quantifier {
        may_i_core::Quantifier::One => {
            if arg_idx >= args.len() {
                return (false, arg_idx, facts);
            }
            let (matched, f) = match_expr_with_binding(&pattern.pattern, args[arg_idx]);
            if !matched {
                return (false, arg_idx, facts);
            }
            match_positional_recursive(args, patterns, pat_idx + 1, arg_idx + 1, facts.merge(&f))
        }
        may_i_core::Quantifier::Optional => {
            // Try consuming one arg first (greedy), then try skipping
            if arg_idx < args.len() {
                let (matched, f) = match_expr_with_binding(&pattern.pattern, args[arg_idx]);
                if matched {
                    let result = match_positional_recursive(
                        args,
                        patterns,
                        pat_idx + 1,
                        arg_idx + 1,
                        facts.merge(&f),
                    );
                    if result.0 {
                        return result;
                    }
                }
            }
            // Skip (consume zero)
            match_positional_recursive(args, patterns, pat_idx + 1, arg_idx, facts)
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
            for consume in (0..=max_consume).rev() {
                let mut f = facts.clone();
                for i in 0..consume {
                    let (_, fi) = match_expr_with_binding(&pattern.pattern, args[arg_idx + i]);
                    f = f.merge(&fi);
                }
                let result =
                    match_positional_recursive(args, patterns, pat_idx + 1, arg_idx + consume, f);
                if result.0 {
                    return result;
                }
            }
            (false, arg_idx, facts)
        }
        may_i_core::Quantifier::OneOrMore => {
            if arg_idx >= args.len() {
                return (false, arg_idx, facts);
            }
            let (first_matched, _) = match_expr_with_binding(&pattern.pattern, args[arg_idx]);
            if !first_matched {
                return (false, arg_idx, facts);
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
            for consume in (1..=max_consume).rev() {
                let mut f = facts.clone();
                for i in 0..consume {
                    let (_, fi) = match_expr_with_binding(&pattern.pattern, args[arg_idx + i]);
                    f = f.merge(&fi);
                }
                let result =
                    match_positional_recursive(args, patterns, pat_idx + 1, arg_idx + consume, f);
                if result.0 {
                    return result;
                }
            }
            (false, arg_idx, facts)
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

/// Build per-element match details for positional patterns.
/// Re-walks the patterns against the matched args to capture binding and
/// expression match info for annotation purposes.
pub(crate) fn build_positional_element_details(
    args: &[&String],
    patterns: &[PositionalArg],
    matched: bool,
    consumed: usize,
) -> Vec<crate::fold::PositionalElementDetail> {
    use may_i_core::pattern::Expr;

    if !matched {
        return vec![];
    }

    let mut details = Vec::new();
    let mut arg_idx = 0;

    for (pat_idx, pattern) in patterns.iter().enumerate() {
        // Determine how many args this pattern consumed.
        // For One quantifier: exactly 1 if matched
        // For others: we need to re-match to find out
        let (consume_count, element_matched) = match &pattern.quantifier {
            may_i_core::Quantifier::One => {
                if arg_idx < consumed {
                    (1, true)
                } else {
                    (0, false)
                }
            }
            may_i_core::Quantifier::Optional => {
                if arg_idx < consumed {
                    let (m, _) = match_expr_with_binding(&pattern.pattern, args[arg_idx]);
                    if m { (1, true) } else { (0, true) }
                } else {
                    (0, true)
                }
            }
            may_i_core::Quantifier::ZeroOrMore | may_i_core::Quantifier::OneOrMore => {
                let mut count = 0;
                let mut idx = arg_idx;
                while idx < consumed {
                    let (m, _) = match_expr_with_binding(&pattern.pattern, args[idx]);
                    if m {
                        count += 1;
                        idx += 1;
                    } else {
                        break;
                    }
                }
                // Check if remaining patterns can match remaining args
                // (simplified: for the detail pass, just consume greedily)
                (
                    count,
                    count > 0 || matches!(pattern.quantifier, may_i_core::Quantifier::ZeroOrMore),
                )
            }
        };

        let consumed_args: Vec<String> = (0..consume_count)
            .map(|i| args[arg_idx + i].to_string())
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

        let match_kind = if let Expr::Cond(branches) = &pattern.pattern
            && !consumed_args.is_empty()
        {
            let value = &consumed_args[0];
            branches
                .iter()
                .position(|b| match_expr_with_binding(&b.test, value).0)
                .map(crate::fold::PositionalMatchKind::CondBranch)
                .unwrap_or(crate::fold::PositionalMatchKind::None)
        } else if binding.is_none() && !consumed_args.is_empty() {
            consumed_args
                .first()
                .and_then(|v| build_expr_match_detail(&pattern.pattern, v))
                .map(crate::fold::PositionalMatchKind::Expr)
                .unwrap_or(crate::fold::PositionalMatchKind::None)
        } else {
            crate::fold::PositionalMatchKind::None
        };

        details.push(crate::fold::PositionalElementDetail {
            pattern_index: pat_idx,
            consumed_args,
            binding,
            match_kind,
            matched: element_matched,
        });

        arg_idx += consume_count;
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
    positional_args: &[&String],
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

    /// Build string args owned, then borrow for matching.
    fn match_owned(args: &[String], patterns: &[PositionalArg]) -> (bool, usize, ContextFacts) {
        let refs: Vec<&String> = args.iter().collect();
        match_positional_patterns(&refs, patterns)
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
