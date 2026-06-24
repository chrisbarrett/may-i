use may_i_core::ContextFacts;
use may_i_core::ast::Effect;
use may_i_core::pattern::{PosTerm, PosTermView, Quantifier};

use super::decompose::Expansion;

/// Default positional-matcher step budget when no config value is supplied
/// (test adapters and recursion entry points). High enough that only
/// pathological nested-quantifier Patterns reach it; see the termination
/// invariant in `parser-engine-invariants`.
#[cfg(test)]
pub(crate) const DEFAULT_STEP_BUDGET: u64 = 100_000;

/// Per-element record of how a pattern element fared on the match's
/// winning (backtracking) path. Used to annotate traces against the
/// argument each element was actually tested with — a forward greedy
/// walk cannot reproduce this for quantifiers that give args back.
///
/// One record is produced per *top-level* term. A sequence group records a
/// single summary element (tested at its entry cursor, `consumed` = the args
/// the whole group claimed); its inner elements are not surfaced separately.
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

/// Fused evidence of a successful element/sequence match along a path: the
/// facts bound by `Expr::Bind`, plus the provenance (display texts) of every
/// constrained match performed against an expansion-bearing arg.
///
/// `match_token` is the *only* constructor, and it always computes
/// `unresolved` from `pattern.matches_any_value()` and the arg's expansion.
/// `and` merges *both* fields. A successful path therefore cannot exist
/// without its provenance: the unsound matched-without-provenance state is
/// unconstructible, so forgetting to thread provenance on a new group path
/// turns into "produced no evidence, so the path cannot succeed" rather than
/// a silent soundness hole. (design.md D4.)
#[derive(Clone, Default)]
pub(crate) struct MatchEvidence {
    facts: ContextFacts,
    unresolved: Vec<String>,
}

impl MatchEvidence {
    /// The empty evidence: no facts, no unresolved provenance. The identity of
    /// `and`.
    pub(crate) fn empty() -> Self {
        Self::default()
    }

    /// Combine two pieces of evidence: union the facts, concatenate the
    /// unresolved provenance. Total (never fails) and associative.
    pub(crate) fn and(mut self, other: Self) -> Self {
        self.facts = self.facts.merge(&other.facts);
        self.unresolved.extend(other.unresolved);
        self
    }

    fn into_parts(self) -> (ContextFacts, Vec<String>) {
        (self.facts, self.unresolved)
    }

    #[cfg(test)]
    pub(crate) fn from_parts(facts: ContextFacts, unresolved: Vec<String>) -> Self {
        Self { facts, unresolved }
    }

    #[cfg(test)]
    pub(crate) fn unresolved(&self) -> &[String] {
        &self.unresolved
    }

    #[cfg(test)]
    pub(crate) fn facts(&self) -> &ContextFacts {
        &self.facts
    }
}

/// Evidence of matching `pattern` against `token`, or `None` if it does not
/// match. The sole way to obtain element-match evidence — see
/// [`MatchEvidence`].
pub(crate) fn match_token<E: std::fmt::Debug + may_i_core::ToDoc>(
    pattern: &may_i_core::pattern::Expr<E>,
    token: &str,
    expansion: &Expansion,
) -> Option<MatchEvidence> {
    let (matched, facts) = match_expr_with_binding(pattern, token);
    if !matched {
        return None;
    }
    let mut unresolved = Vec::new();
    // A constrained (non-wildcard) match against an expansion-bearing arg is
    // not provable for the runtime value; record it so the decision floors.
    if !pattern.matches_any_value()
        && let Some(word) = expansion.as_deref()
    {
        unresolved.push(word.to_string());
    }
    Some(MatchEvidence { facts, unresolved })
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
    /// successful match this covers every top-level term; for a failed match
    /// it covers the prefix up to and including the term that failed.
    pub(crate) elements: Vec<ElementMatch>,
}

/// Match positional patterns against args, capturing bound facts. Uses the
/// default step budget; production callers thread the config budget via
/// [`match_positional_patterns_budgeted`].
///
/// `expansions` is per-arg expansion provenance aligned with `args`.
#[cfg(test)]
pub(crate) fn match_positional_patterns(
    args: &[&str],
    expansions: &[&Expansion],
    patterns: &[PosTerm],
) -> PositionalMatch {
    match_positional_patterns_budgeted(args, expansions, patterns, DEFAULT_STEP_BUDGET)
}

/// Match positional patterns against args with an explicit step budget.
///
/// Uses backtracking for the `?`/`*`/`+` quantifiers and for sequence groups:
/// tries greedy matches first, then progressively shorter ones if subsequent
/// patterns fail. Matching is guaranteed to terminate: a `+`/`*` iteration
/// that consumes zero args stops the repetition (nullable guard), and every
/// recursive step decrements `budget` — on exhaustion the attempt returns
/// no-match rather than continue.
pub(crate) fn match_positional_patterns_budgeted(
    args: &[&str],
    expansions: &[&Expansion],
    patterns: &[PosTerm],
    budget: u64,
) -> PositionalMatch {
    debug_assert_eq!(args.len(), expansions.len());
    let mut budget = budget;
    match_positional_recursive(
        args,
        expansions,
        patterns,
        0,
        0,
        MatchEvidence::empty(),
        &mut budget,
    )
}

/// Positional match with all-literal expansion provenance, returning the
/// tuple shape the pre-provenance tests asserted on. Test-only adapter.
#[cfg(test)]
pub(crate) fn match_pos_lit(args: &[&str], patterns: &[PosTerm]) -> (bool, usize, ContextFacts) {
    const NONE_EXP: Expansion = None;
    let exps: Vec<&Expansion> = vec![&NONE_EXP; args.len()];
    let m = match_positional_patterns(args, &exps, patterns);
    (m.matched, m.consumed, m.facts)
}

/// Top-level backtracking driver. Each top-level term yields exactly one
/// `ElementMatch`. For each term we enumerate its consumption candidates
/// (greedy-first) and recurse on the remaining terms; the first candidate that
/// leads to an overall match wins.
fn match_positional_recursive(
    args: &[&str],
    expansions: &[&Expansion],
    patterns: &[PosTerm],
    pat_idx: usize,
    arg_idx: usize,
    evidence: MatchEvidence,
    budget: &mut u64,
) -> PositionalMatch {
    let tested_at = |i: usize| if i < args.len() { Some(i) } else { None };
    let with_element = |mut child: PositionalMatch, el: ElementMatch| {
        child.elements.insert(0, el);
        child
    };
    let succeed = |evidence: MatchEvidence| {
        let (facts, unresolved) = evidence.into_parts();
        PositionalMatch {
            matched: true,
            consumed: arg_idx,
            facts,
            unresolved,
            elements: Vec::new(),
        }
    };
    let no_match = |evidence: MatchEvidence, matched_element: bool| {
        let (facts, unresolved) = evidence.into_parts();
        PositionalMatch {
            matched: false,
            consumed: arg_idx,
            facts,
            unresolved,
            elements: vec![ElementMatch {
                tested: tested_at(arg_idx),
                consumed: 0,
                matched: matched_element,
            }],
        }
    };

    // All terms consumed → success. Checked before the budget guard so that a
    // budget that runs out exactly at the base case still succeeds, rather than
    // emitting a phantom no-match element for a non-existent term (which would
    // push `elements.len()` past `patterns.len()`).
    if pat_idx >= patterns.len() {
        return succeed(evidence);
    }

    // Budget exhaustion: return no-match (the decision floors to :ask).
    if *budget == 0 {
        return no_match(evidence, false);
    }
    *budget -= 1;

    let term = &patterns[pat_idx];
    let candidates = term_candidates(args, expansions, term, arg_idx, budget);

    let mut last = None;
    for (consumed, step_ev) in candidates {
        let child = match_positional_recursive(
            args,
            expansions,
            patterns,
            pat_idx + 1,
            arg_idx + consumed,
            evidence.clone().and(step_ev),
            budget,
        );
        let el = ElementMatch {
            tested: tested_at(arg_idx),
            consumed,
            matched: true,
        };
        if child.matched {
            return with_element(child, el);
        }
        last = Some((child, el));
    }

    match last {
        // A satisfiable quantifier/group consumed its minimum but downstream
        // failed: keep that child's failure under this (matched) element.
        Some((child, el)) => with_element(child, el),
        // The term could not match at all at this position.
        None => no_match(evidence, false),
    }
}

/// Consumption candidates for one term at `start`, greedy-first: each entry is
/// `(args consumed, evidence)`. The driver tries them in order.
fn term_candidates(
    args: &[&str],
    expansions: &[&Expansion],
    term: &PosTerm,
    start: usize,
    budget: &mut u64,
) -> Vec<(usize, MatchEvidence)> {
    match term.view() {
        PosTermView::Single {
            quantifier,
            pattern,
        } => single_candidates(args, expansions, pattern, quantifier, start),
        PosTermView::Group { quantifier, seq } => {
            group_candidates(args, expansions, seq, quantifier, start, budget)
        }
    }
}

/// Candidates for a single quantified pattern. Each consumed token must match
/// `pattern`; evidence accumulates left to right.
fn single_candidates<E: std::fmt::Debug + may_i_core::ToDoc>(
    args: &[&str],
    expansions: &[&Expansion],
    pattern: &may_i_core::pattern::Expr<E>,
    quantifier: Quantifier,
    start: usize,
) -> Vec<(usize, MatchEvidence)> {
    // cumulative[k] = evidence of matching the first k tokens from `start`.
    let mut cumulative = vec![MatchEvidence::empty()];
    let mut acc = MatchEvidence::empty();
    let mut max = 0;
    while start + max < args.len() {
        match match_token(pattern, args[start + max], expansions[start + max]) {
            Some(ev) => {
                acc = acc.and(ev);
                cumulative.push(acc.clone());
                max += 1;
            }
            None => break,
        }
    }

    let take = |k: usize| (k, cumulative[k].clone());
    match quantifier {
        Quantifier::One => {
            if max >= 1 {
                vec![take(1)]
            } else {
                vec![]
            }
        }
        Quantifier::Optional => {
            let mut v = Vec::new();
            if max >= 1 {
                v.push(take(1));
            }
            v.push((0, MatchEvidence::empty()));
            v
        }
        Quantifier::ZeroOrMore => (0..=max).rev().map(take).collect(),
        Quantifier::OneOrMore => {
            if max >= 1 {
                (1..=max).rev().map(take).collect()
            } else {
                vec![]
            }
        }
    }
}

/// Candidates for a sequence group: repeat the sub-sequence per the
/// quantifier, greedy-first. `(consumed, evidence)` where `consumed` is the
/// number of args the whole group claimed from `start`.
fn group_candidates(
    args: &[&str],
    expansions: &[&Expansion],
    seq: &[PosTerm],
    quantifier: Quantifier,
    start: usize,
    budget: &mut u64,
) -> Vec<(usize, MatchEvidence)> {
    let (min_reps, max_reps): (usize, usize) = match quantifier {
        Quantifier::One => (1, 1),
        Quantifier::Optional => (0, 1),
        Quantifier::OneOrMore => (1, usize::MAX),
        Quantifier::ZeroOrMore => (0, usize::MAX),
    };
    let mut out = Vec::new();
    repeat_group(
        args,
        expansions,
        seq,
        start,
        start,
        0,
        min_reps,
        max_reps,
        budget,
        MatchEvidence::empty(),
        &mut out,
    );
    out
}

/// Recursively enumerate the ways a sequence group repeats, greedy-first.
/// `pos` is the current cursor; `reps` is occurrences matched so far; results
/// (consumed-from-`start`, evidence) are appended to `out`.
#[allow(clippy::too_many_arguments)]
fn repeat_group(
    args: &[&str],
    expansions: &[&Expansion],
    seq: &[PosTerm],
    start: usize,
    pos: usize,
    reps: usize,
    min_reps: usize,
    max_reps: usize,
    budget: &mut u64,
    acc: MatchEvidence,
    out: &mut Vec<(usize, MatchEvidence)>,
) {
    if *budget == 0 {
        return;
    }
    *budget -= 1;

    // Greedy: try to consume one more occurrence first.
    if reps < max_reps {
        for (end, occ_ev) in seq_ends(args, expansions, seq, 0, pos, budget) {
            // Nullable-iteration guard: a zero-consuming occurrence cannot
            // extend the repetition (would loop forever).
            if end == pos {
                continue;
            }
            repeat_group(
                args,
                expansions,
                seq,
                start,
                end,
                reps + 1,
                min_reps,
                max_reps,
                budget,
                acc.clone().and(occ_ev),
                out,
            );
        }
    }

    // Then stop here, if we have enough occurrences.
    if reps >= min_reps {
        out.push((pos - start, acc));
    }
}

/// Enumerate the ways the sub-sequence `seq[ti..]` matches a contiguous prefix
/// of args from `pos`, greedy-first. Each entry is `(end position, evidence)`.
fn seq_ends(
    args: &[&str],
    expansions: &[&Expansion],
    seq: &[PosTerm],
    ti: usize,
    pos: usize,
    budget: &mut u64,
) -> Vec<(usize, MatchEvidence)> {
    if *budget == 0 {
        return Vec::new();
    }
    *budget -= 1;

    if ti >= seq.len() {
        return vec![(pos, MatchEvidence::empty())];
    }

    let mut out = Vec::new();
    for (consumed, ev) in term_candidates(args, expansions, &seq[ti], pos, budget) {
        for (end, tail_ev) in seq_ends(args, expansions, seq, ti + 1, pos + consumed, budget) {
            out.push((end, ev.clone().and(tail_ev)));
        }
    }
    out
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
///
/// Group terms have no single pattern expression, so they surface as a summary
/// detail (the consumed args, no binding, no per-expression match kind); their
/// inner structure is not re-walked (design.md open question, resolved to the
/// summary form).
pub(crate) fn build_positional_element_details(
    args: &[&str],
    patterns: &[PosTerm],
    elements: &[ElementMatch],
) -> Vec<crate::fold::PositionalElementDetail> {
    use may_i_core::pattern::Expr;

    let mut details = Vec::new();

    for (pat_idx, element) in elements.iter().enumerate() {
        let term = &patterns[pat_idx];
        let element_matched = element.matched;
        let tested_arg = element.tested.map(|i| args[i].to_string());

        // Consumed args start at the cursor (`tested`) and run for `consumed`.
        let start = element.tested.unwrap_or(0);
        let consumed_args: Vec<String> = (0..element.consumed)
            .map(|i| args[start + i].to_string())
            .collect();

        // Group terms have no single pattern; emit a bare summary detail.
        let PosTermView::Single { pattern, .. } = term.view() else {
            details.push(crate::fold::PositionalElementDetail {
                pattern_index: pat_idx,
                consumed_args,
                tested_arg,
                binding: None,
                match_kind: crate::fold::PositionalMatchKind::None,
                matched: element_matched,
            });
            continue;
        };

        let binding = if let Expr::Bind { key, expr: inner } = pattern
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
        let match_kind = if let Expr::Cond(branches) = pattern
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
            build_expr_match_detail(pattern, value)
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
    // `Expr` is `#[non_exhaustive]`; only literal/regex/wildcard yield detail.
    #[allow(clippy::wildcard_enum_match_arm)]
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

/// If the last positional term is a `Single` whose pattern is an `Expr::Cond`,
/// find the matching branch's effect for the last consumed arg. Returns None
/// if the last term isn't such a Cond or no branch matched.
pub(super) fn resolve_trailing_cond_effect<'a>(
    patterns: &'a [PosTerm],
    positional_args: &[&str],
    consumed: usize,
) -> Option<&'a Effect> {
    if consumed == 0 {
        return None;
    }
    let last_pattern = patterns.last()?;
    if let PosTermView::Single {
        pattern: may_i_core::pattern::Expr::Cond(branches),
        ..
    } = last_pattern.view()
    {
        let last_arg = positional_args.get(consumed - 1)?;
        find_cond_branch_effect(branches, last_arg)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::pattern::{Expr, PosTerm, Quantifier};
    use may_i_core::test_generators::{any_match_string, any_pos_term};
    use proptest::prelude::*;

    /// Build string args owned, then borrow for matching (no expansion
    /// provenance — all tokens literal).
    fn match_owned(args: &[String], patterns: &[PosTerm]) -> (bool, usize, ContextFacts) {
        const NONE_EXP: Expansion = None;
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let exps: Vec<&Expansion> = vec![&NONE_EXP; refs.len()];
        let m = match_positional_patterns(&refs, &exps, patterns);
        (m.matched, m.consumed, m.facts)
    }

    fn match_full(args: &[&str], patterns: &[PosTerm]) -> PositionalMatch {
        const NONE_EXP: Expansion = None;
        let exps: Vec<&Expansion> = vec![&NONE_EXP; args.len()];
        match_positional_patterns(args, &exps, patterns)
    }

    /// Match with explicit per-arg expansion provenance.
    fn match_with_exp(args: &[&str], exps: &[&Expansion], patterns: &[PosTerm]) -> PositionalMatch {
        match_positional_patterns(args, exps, patterns)
    }

    fn lit(s: &str) -> Expr {
        Expr::Literal(s.into())
    }

    fn group(q: Quantifier, seq: Vec<PosTerm>) -> PosTerm {
        PosTerm::group(q, seq).expect("non-empty group")
    }

    /// The motivating Pattern `(? "run" (? "--")) *`.
    fn run_dashdash_then_star() -> Vec<PosTerm> {
        vec![
            group(
                Quantifier::Optional,
                vec![
                    PosTerm::one(lit("run")),
                    PosTerm::single(Quantifier::Optional, lit("--")),
                ],
            ),
            PosTerm::single(Quantifier::ZeroOrMore, Expr::Wildcard),
        ]
    }

    // --- Task 3.1: the four (? "run" (? "--")) * scenarios ---

    #[test]
    fn optional_group_skipped() {
        let (matched, _, _) = match_owned(&["state".into()], &run_dashdash_then_star());
        assert!(matched);
    }

    #[test]
    fn optional_group_partial_inner() {
        let m = match_full(&["run", "state"], &run_dashdash_then_star());
        assert!(m.matched);
        // The group consumed `run`; the `*` consumed `state`.
        assert_eq!(m.elements[0].consumed, 1);
    }

    #[test]
    fn optional_group_full_inner() {
        let m = match_full(&["run", "--", "state"], &run_dashdash_then_star());
        assert!(m.matched);
        assert_eq!(m.elements[0].consumed, 2);
    }

    #[test]
    fn sequence_group_requires_leading_element() {
        // `-- state`: the group's leading `run` is absent, so the group
        // consumes zero and the `*` swallows everything.
        let m = match_full(&["--", "state"], &run_dashdash_then_star());
        assert!(m.matched);
        assert_eq!(m.elements[0].consumed, 0);
    }

    // --- Task 3.2: repeated groups ---

    #[test]
    fn one_or_more_group_repeats() {
        // (+ "--opt" *) over `--opt a --opt b` → two occurrences.
        let patterns = vec![group(
            Quantifier::OneOrMore,
            vec![
                PosTerm::one(lit("--opt")),
                PosTerm::single(Quantifier::ZeroOrMore, Expr::Wildcard),
            ],
        )];
        let (matched, consumed, _) = match_owned(
            &["--opt".into(), "a".into(), "--opt".into(), "b".into()],
            &patterns,
        );
        assert!(matched);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn zero_or_more_group_repeats() {
        let patterns = vec![group(
            Quantifier::ZeroOrMore,
            vec![
                PosTerm::one(lit("--opt")),
                PosTerm::single(Quantifier::ZeroOrMore, Expr::Wildcard),
            ],
        )];
        let (matched, consumed, _) = match_owned(
            &["--opt".into(), "a".into(), "--opt".into(), "b".into()],
            &patterns,
        );
        assert!(matched);
        assert_eq!(consumed, 4);
    }

    // --- Task 3.6: nullable-iteration guard ---

    #[test]
    fn nullable_group_terminates() {
        // (* (? "x")) against args that never match: must terminate, not loop.
        let patterns = vec![group(
            Quantifier::ZeroOrMore,
            vec![PosTerm::single(Quantifier::Optional, lit("x"))],
        )];
        let (matched, _, _) = match_owned(&["y".into(), "z".into()], &patterns);
        assert!(matched); // `*` of an optional matches zero occurrences fine.
    }

    // --- Task 3.7: step budget floors to no-match ---

    #[test]
    fn budget_exhaustion_returns_no_match() {
        // A catastrophic nested repetition over a GENUINELY non-matching input:
        // (* (* (+ "a"))) "b" with no "b" present. The matcher must terminate and
        // floor to no-match at every budget — never hang, never falsely allow.
        const NONE_EXP: Expansion = None;
        let patterns = vec![
            group(
                Quantifier::ZeroOrMore,
                vec![group(
                    Quantifier::ZeroOrMore,
                    vec![PosTerm::single(Quantifier::OneOrMore, lit("a"))],
                )],
            ),
            PosTerm::one(lit("b")),
        ];
        let args: Vec<String> = (0..12).map(|_| "a".to_string()).collect();
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let exps: Vec<&Expansion> = vec![&NONE_EXP; refs.len()];
        for budget in [10u64, 50, 1000, 100_000] {
            let m = match_positional_patterns_budgeted(&refs, &exps, &patterns, budget);
            assert!(
                !m.matched,
                "non-matching catastrophic input must floor to no-match (budget {budget})"
            );
        }
    }

    #[test]
    fn tiny_budget_floors_satisfiable_match_to_no_match() {
        // Same pattern + args; budget is the only variable. A budget too small to
        // reach the second mandatory term floors to no-match (conservative); an
        // adequate budget finds the match.
        const NONE_EXP: Expansion = None;
        let patterns = vec![PosTerm::one(lit("a")), PosTerm::one(lit("b"))];
        let args = ["a", "b"];
        let exps: Vec<&Expansion> = vec![&NONE_EXP; args.len()];

        let floored = match_positional_patterns_budgeted(&args, &exps, &patterns, 1);
        assert!(!floored.matched, "budget 1 cannot reach the second term");

        let adequate = match_positional_patterns_budgeted(&args, &exps, &patterns, 100);
        assert!(adequate.matched, "adequate budget matches");
    }

    #[test]
    fn budget_exhaustion_at_base_case_yields_no_phantom_element() {
        // Regression (fuzz crash-14657a19): with budget exactly 1, the matcher
        // decrements at pat_idx 0, then hits the all-terms-consumed base case at
        // pat_idx 1 with budget 0. The base case must win there — emitting a
        // phantom no-match element for a non-existent term used to push
        // `elements.len()` past `patterns.len()`, panicking the trace builder.
        let patterns = vec![PosTerm::one(lit("a"))];
        let args = ["a"];
        const NONE_EXP: Expansion = None;
        let exps: Vec<&Expansion> = vec![&NONE_EXP; args.len()];

        let m = match_positional_patterns_budgeted(&args, &exps, &patterns, 1);

        assert!(
            m.elements.len() <= patterns.len(),
            "each term yields at most one element: got {} elements for {} patterns",
            m.elements.len(),
            patterns.len()
        );
        // Must not panic (this is the crash the fuzzer found).
        let _ = build_positional_element_details(&args, &patterns, &m.elements);
    }

    // --- Task 3.8: provenance for constrained matches inside a repeated group ---

    #[test]
    fn constrained_match_in_repeated_group_records_provenance() {
        // (+ "--opt") over an expansion-bearing arg whose display is "$OPT".
        let patterns = vec![group(
            Quantifier::OneOrMore,
            vec![PosTerm::one(lit("--opt"))],
        )];
        let exp: Expansion = Some("$OPT".to_string());
        let m = match_with_exp(&["--opt"], &[&exp], &patterns);
        assert!(m.matched);
        assert_eq!(m.unresolved, vec!["$OPT".to_string()]);
    }

    /// Task 5.1: a rule-body `Expr::Bind` inside a repeated group accumulates
    /// into `ContextFacts` by set-union across occurrences (no correlation),
    /// exactly as the flat repeating quantifier does.
    #[test]
    fn bind_in_repeated_group_set_unions() {
        use may_i_core::Keyword;
        // (+ [:item *]) over `a b` → :item = {a, b}.
        let bind = Expr::Bind {
            key: Keyword::new(":item").unwrap(),
            expr: Box::new(Expr::Wildcard),
        };
        let patterns = vec![group(Quantifier::OneOrMore, vec![PosTerm::one(bind)])];
        let (matched, consumed, facts) = match_owned(&["a".into(), "b".into()], &patterns);
        assert!(matched);
        assert_eq!(consumed, 2);
        let key = Keyword::new(":item").unwrap();
        assert!(facts.contains(&key, "a"));
        assert!(facts.contains(&key, "b"));
    }

    #[test]
    fn wildcard_match_in_repeated_group_records_no_provenance() {
        // (+ *) over an expansion-bearing arg: a bare wildcard constrains
        // nothing, so no provenance is recorded.
        let patterns = vec![group(
            Quantifier::OneOrMore,
            vec![PosTerm::one(Expr::Wildcard)],
        )];
        let exp: Expansion = Some("$ANY".to_string());
        let m = match_with_exp(&["whatever"], &[&exp], &patterns);
        assert!(m.matched);
        assert!(m.unresolved.is_empty());
    }

    /// When a `*` must give back an argument so a following required element
    /// can match, the per-element trace reflects the WINNING (backtracked)
    /// path: the required element is recorded as tested at the arg it actually
    /// matched, not the one the greedy `*` first swallowed.
    #[test]
    fn element_trace_follows_the_backtracked_path() {
        let patterns = vec![
            PosTerm::single(Quantifier::ZeroOrMore, lit("a")),
            PosTerm::one(lit("a")),
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

    /// A `One` group (match the sub-sequence exactly once, required) has no
    /// surface syntax — the parser never produces it and the generators
    /// exclude it — so this covers `group_candidates`' `One` arm directly.
    #[test]
    fn one_group_matches_sub_sequence_once() {
        let patterns = vec![group(
            Quantifier::One,
            vec![PosTerm::one(lit("a")), PosTerm::one(lit("b"))],
        )];
        let (matched, consumed, _) = match_owned(&["a".into(), "b".into()], &patterns);
        assert!(matched);
        assert_eq!(consumed, 2);
        // Required: a partial sub-sequence does not match.
        let (m2, _, _) = match_owned(&["a".into()], &patterns);
        assert!(!m2);
    }

    /// `resolve_trailing_cond_effect` returns the matching branch's effect when
    /// the last term is a `Single` carrying an `Expr::Cond`, and `None` when
    /// nothing was consumed.
    #[test]
    fn trailing_cond_effect_resolution() {
        use may_i_core::Decision;
        use may_i_core::ast::Effect;
        use may_i_core::pattern::ExprBranch;

        let cond = Expr::Cond(vec![ExprBranch {
            test: lit("status"),
            effect: Effect::Terminal {
                decision: Decision::Allow,
                reason: Some("read-only".into()),
            },
        }]);
        let patterns = vec![PosTerm::one(lit("git")), PosTerm::one(cond)];

        let resolved = resolve_trailing_cond_effect(&patterns, &["git", "status"], 2);
        assert!(matches!(
            resolved,
            Some(Effect::Terminal {
                decision: Decision::Allow,
                ..
            })
        ));

        // No branch matches → None.
        assert!(resolve_trailing_cond_effect(&patterns, &["git", "push"], 2).is_none());
        // Nothing consumed → None.
        assert!(resolve_trailing_cond_effect(&patterns, &[], 0).is_none());
    }

    /// A failed match records the prefix up to and including the element that
    /// failed, and nothing after it.
    #[test]
    fn element_trace_stops_at_the_failing_element() {
        let patterns = vec![PosTerm::one(lit("checkout")), PosTerm::one(lit("--"))];
        let m = match_full(&["status"], &patterns);
        assert!(!m.matched);
        // Only the first element was reached; it was tested against "status".
        assert_eq!(m.elements.len(), 1);
        assert_eq!(m.elements[0].tested, Some(0));
        assert!(!m.elements[0].matched);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Task 3.4: `and` is total and associative over arbitrary evidence.
        #[test]
        fn match_evidence_and_is_associative(
            fa in may_i_core::test_generators::any_context_facts(),
            ua in prop::collection::vec(any_match_string(), 0..4),
            fb in may_i_core::test_generators::any_context_facts(),
            ub in prop::collection::vec(any_match_string(), 0..4),
            fc in may_i_core::test_generators::any_context_facts(),
            uc in prop::collection::vec(any_match_string(), 0..4),
        ) {
            let a = || MatchEvidence::from_parts(fa.clone(), ua.clone());
            let b = || MatchEvidence::from_parts(fb.clone(), ub.clone());
            let c = || MatchEvidence::from_parts(fc.clone(), uc.clone());

            let left = a().and(b()).and(c());
            let right = a().and(b().and(c()));

            // unresolved: list concatenation is associative.
            prop_assert_eq!(left.unresolved(), right.unresolved());
            // facts: merge is associative (same keys present, same values).
            for (k, v) in left.facts().iter() {
                prop_assert_eq!(right.facts().get(k), Some(v));
            }
            for (k, v) in right.facts().iter() {
                prop_assert_eq!(left.facts().get(k), Some(v));
            }
        }

        /// matched + unconsumed = original arg count.
        #[test]
        fn matched_plus_unconsumed_eq_total(
            patterns in prop::collection::vec(any_pos_term(1), 0..4),
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
            let patterns = vec![PosTerm::single(
                Quantifier::ZeroOrMore,
                Expr::Wildcard,
            )];
            let (matched, consumed, _) = match_owned(&args, &patterns);
            prop_assert!(matched, "wildcard ZeroOrMore should match anything");
            prop_assert_eq!(consumed, args.len(),
                "ZeroOrMore wildcard should greedily consume all {} args, got {}",
                args.len(), consumed);
        }

        /// Matching always terminates (within the budget) and is deterministic:
        /// same inputs → same output. Generated patterns include nested groups.
        #[test]
        fn matching_is_deterministic(
            patterns in prop::collection::vec(any_pos_term(2), 0..4),
            args in prop::collection::vec(any_match_string(), 0..6),
        ) {
            let r1 = match_owned(&args, &patterns);
            let r2 = match_owned(&args, &patterns);
            prop_assert_eq!(r1.0, r2.0, "matched differs between runs");
            prop_assert_eq!(r1.1, r2.1, "consumed differs between runs");
        }
    }
}
