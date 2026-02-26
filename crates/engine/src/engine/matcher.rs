// Rule matching — given a resolved command and config, find the applicable rule.
// Pure matching logic: no AST walking, no variable resolution.

use may_i_shell_parser::{SimpleCommand, Word};
use may_i_core::{ArgMatcher, CommandMatcher, Config, Effect, Expr, ExprBranch, PosExpr, WrapperStep};

/// A resolved argument that may be a known literal or an opaque (safe but unknown) value.
#[derive(Debug, Clone, PartialEq)]
pub(in crate::engine) enum ResolvedArg {
    Literal(String),
    Opaque,
}

// ── Match outcome and events ───────────────────────────────────────

/// The result of matching args against an ArgMatcher.
#[derive(Debug)]
pub(in crate::engine) enum MatchOutcome {
    /// Matched, with an embedded effect (from Expr::Cond or ArgMatcher::Cond).
    Matched(Effect),
    /// Matched, no embedded effect.
    MatchedNoEffect,
    /// Did not match.
    NoMatch,
}

impl MatchOutcome {
    fn is_match(&self) -> bool {
        !matches!(self, MatchOutcome::NoMatch)
    }
}

/// Events emitted during matching for tracing/debugging.
///
/// Some variants carry payloads used only for `Debug` output in tests.
/// The trace collector in `mod.rs` ignores `EnterOptional`, `LeaveOptional`,
/// `EnterCond`, and `LeaveCond` — they exist as structured hooks for richer
/// tracing if needed later.
#[derive(Debug)]
pub(in crate::engine) enum MatchEvent<'a> {
    ExprVsArg { expr: &'a Expr, arg: &'a ResolvedArg, matched: bool },
    EnterOptional,
    LeaveOptional,
    Quantifier { pexpr: &'a PosExpr, count: usize, matched: bool },
    Missing { pexpr: &'a PosExpr },
    EnterCond,
    ExprCondBranch { test: &'a Expr, matched: bool, effect: &'a Effect },
    MatcherCondBranch { matched: bool, effect: &'a Effect },
    MatcherCondElse { effect: &'a Effect },
    LeaveCond,
    Anywhere { expr: &'a Expr, matched: bool },
    ExactRemainder { count: usize },
}

// ── Formatting helpers ─────────────────────────────────────────────

use may_i_pp::Doc;

pub(in crate::engine) const PP_WIDTH: usize = 72;

/// Format a CommandMatcher for display in traces.
/// `indent` is the column where the expression starts (e.g. after "rule ").
pub(in crate::engine) fn format_command_matcher(m: &CommandMatcher, indent: usize) -> String {
    let doc = match m {
        CommandMatcher::Exact(s) => Doc::list(vec![Doc::atom("command"), Doc::atom(format!("\"{s}\""))]),
        CommandMatcher::Regex(re) => Doc::list(vec![Doc::atom("command"), Doc::atom(format!("#\"{}\"", re.as_str()))]),
        CommandMatcher::List(names) => {
            let mut or_children = vec![Doc::atom("or")];
            or_children.extend(names.iter().map(|n| Doc::atom(format!("\"{n}\""))));
            Doc::list(vec![Doc::atom("command"), Doc::list(or_children)])
        }
    };
    may_i_pp::pretty(&doc, indent, &may_i_pp::Format { width: PP_WIDTH, ..Default::default() })
}

/// Build a Doc tree from an Expr.
pub(in crate::engine) fn expr_to_doc(e: &Expr) -> Doc {
    match e {
        Expr::Literal(s) => Doc::atom(format!("\"{s}\"")),
        Expr::Regex(re) => Doc::atom(format!("#\"{}\"", re.as_str())),
        Expr::Wildcard => Doc::atom("*"),
        Expr::And(exprs) => {
            let mut children = vec![Doc::atom("and")];
            children.extend(exprs.iter().map(expr_to_doc));
            Doc::list(children)
        }
        Expr::Or(exprs) => {
            let mut children = vec![Doc::atom("or")];
            children.extend(exprs.iter().map(expr_to_doc));
            Doc::list(children)
        }
        Expr::Not(inner) => Doc::list(vec![Doc::atom("not"), expr_to_doc(inner)]),
        Expr::Cond(branches) => {
            let mut children = vec![Doc::atom("cond")];
            for b in branches {
                children.push(Doc::list(vec![
                    expr_to_doc(&b.test),
                    Doc::atom("=>"),
                    Doc::atom(b.effect.decision.to_string()),
                ]));
            }
            Doc::list(children)
        }
    }
}

/// Build a Doc tree from a PosExpr.
pub(in crate::engine) fn pos_expr_to_doc(pe: &PosExpr) -> Doc {
    match pe {
        PosExpr::One(e) => expr_to_doc(e),
        PosExpr::Optional(e) => Doc::list(vec![Doc::atom("?"), expr_to_doc(e)]),
        PosExpr::OneOrMore(e) => Doc::list(vec![Doc::atom("+"), expr_to_doc(e)]),
        PosExpr::ZeroOrMore(e) => Doc::list(vec![Doc::atom("*"), expr_to_doc(e)]),
    }
}

/// Build a Doc atom from a ResolvedArg.
pub(in crate::engine) fn resolved_arg_to_doc(a: &ResolvedArg) -> Doc {
    match a {
        ResolvedArg::Literal(s) => Doc::atom(format!("\"{s}\"")),
        ResolvedArg::Opaque => Doc::atom("<opaque>"),
    }
}

// ── Core matching ──────────────────────────────────────────────────

/// Check if a command name matches a command matcher.
pub(in crate::engine) fn command_matches(name: &str, matcher: &CommandMatcher) -> bool {
    match matcher {
        CommandMatcher::Exact(s) => name == s,
        CommandMatcher::Regex(re) => re.is_match(name),
        CommandMatcher::List(names) => names.iter().any(|n| n == name),
    }
}

/// Pure boolean: does this expr match this resolved arg?
fn expr_matches_resolved(expr: &Expr, arg: &ResolvedArg) -> bool {
    match arg {
        ResolvedArg::Literal(s) => expr.is_wildcard() || expr.is_match(s),
        ResolvedArg::Opaque => expr.is_wildcard(),
    }
}

/// Match a single Expr against a single ResolvedArg, handling Expr::Cond specially.
/// Emits events and may return Matched(effect) when a Cond branch matches.
fn match_expr_arg(
    expr: &Expr,
    arg: &ResolvedArg,
    emit: &mut dyn for<'e> FnMut(MatchEvent<'e>),
) -> MatchOutcome {
    if let Expr::Cond(branches) = expr {
        emit(MatchEvent::EnterCond);
        let outcome = match arg {
            ResolvedArg::Literal(s) => {
                match_expr_cond_branches(branches, s, emit)
            }
            ResolvedArg::Opaque => {
                // Opaque args can't match specific cond branches
                for branch in branches {
                    emit(MatchEvent::ExprCondBranch {
                        test: &branch.test,
                        matched: false,
                        effect: &branch.effect,
                    });
                }
                MatchOutcome::NoMatch
            }
        };
        emit(MatchEvent::LeaveCond);
        return outcome;
    }

    let matched = expr_matches_resolved(expr, arg);
    emit(MatchEvent::ExprVsArg { expr, arg, matched });

    if !matched {
        return MatchOutcome::NoMatch;
    }

    // Check for nested Cond effects inside And/Or/Not
    if let ResolvedArg::Literal(s) = arg
        && let Some(eff) = expr.find_effect(s)
    {
        return MatchOutcome::Matched(eff.clone());
    }

    MatchOutcome::MatchedNoEffect
}

/// Test Expr::Cond branches against a literal string.
fn match_expr_cond_branches(
    branches: &[ExprBranch],
    text: &str,
    emit: &mut dyn for<'e> FnMut(MatchEvent<'e>),
) -> MatchOutcome {
    for branch in branches {
        let matched = branch.test.is_match(text);
        emit(MatchEvent::ExprCondBranch {
            test: &branch.test,
            matched,
            effect: &branch.effect,
        });
        if matched {
            return MatchOutcome::Matched(branch.effect.clone());
        }
    }
    MatchOutcome::NoMatch
}

/// Unified arg matching: walks the ArgMatcher tree, emits events, returns outcome.
pub(in crate::engine) fn match_args(
    matcher: &ArgMatcher,
    args: &[ResolvedArg],
    emit: &mut dyn for<'e> FnMut(MatchEvent<'e>),
) -> MatchOutcome {
    match matcher {
        ArgMatcher::Positional(patterns) => match_positional(patterns, args, false, emit),
        ArgMatcher::ExactPositional(patterns) => match_positional(patterns, args, true, emit),

        ArgMatcher::Anywhere(tokens) => {
            // Any of the listed tokens appears anywhere in args (OR semantics).
            for token in tokens {
                let matched = args.iter().any(|a| expr_matches_resolved(token, a));
                emit(MatchEvent::Anywhere { expr: token, matched });
                if matched {
                    // Check for effect in the matching arg
                    if let Expr::Cond(branches) = token {
                        // For Anywhere + Cond, find the first matching arg and extract its effect
                        for a in args {
                            if let ResolvedArg::Literal(s) = a {
                                for branch in branches {
                                    if branch.test.is_match(s) {
                                        return MatchOutcome::Matched(branch.effect.clone());
                                    }
                                }
                            }
                        }
                    }
                    // Check for nested cond effects
                    for a in args {
                        if let ResolvedArg::Literal(s) = a
                            && let Some(eff) = token.find_effect(s)
                        {
                            return MatchOutcome::Matched(eff.clone());
                        }
                    }
                    return MatchOutcome::MatchedNoEffect;
                }
            }
            MatchOutcome::NoMatch
        }

        ArgMatcher::And(matchers) => {
            let mut first_effect: Option<Effect> = None;
            for m in matchers {
                let outcome = match_args(m, args, emit);
                match outcome {
                    MatchOutcome::NoMatch => return MatchOutcome::NoMatch,
                    MatchOutcome::Matched(eff) if first_effect.is_none() => {
                        first_effect = Some(eff);
                    }
                    _ => {}
                }
            }
            match first_effect {
                Some(eff) => MatchOutcome::Matched(eff),
                None => MatchOutcome::MatchedNoEffect,
            }
        }

        ArgMatcher::Or(matchers) => {
            for m in matchers {
                let outcome = match_args(m, args, emit);
                if outcome.is_match() {
                    return outcome;
                }
            }
            MatchOutcome::NoMatch
        }

        ArgMatcher::Not(inner) => {
            // Not inverts the match result but doesn't propagate effects
            let inner_outcome = match_args(inner, args, &mut |_| {});
            if inner_outcome.is_match() {
                MatchOutcome::NoMatch
            } else {
                MatchOutcome::MatchedNoEffect
            }
        }

        ArgMatcher::Cond(branches) => {
            emit(MatchEvent::EnterCond);
            for branch in branches {
                match &branch.matcher {
                    None => {
                        // Catch-all (else) branch
                        emit(MatchEvent::MatcherCondElse { effect: &branch.effect });
                        emit(MatchEvent::LeaveCond);
                        return MatchOutcome::Matched(branch.effect.clone());
                    }
                    Some(m) => {
                        let matched = match_args(m, args, emit).is_match();
                        emit(MatchEvent::MatcherCondBranch {
                            matched,
                            effect: &branch.effect,
                        });
                        if matched {
                            emit(MatchEvent::LeaveCond);
                            return MatchOutcome::Matched(branch.effect.clone());
                        }
                    }
                }
            }
            emit(MatchEvent::LeaveCond);
            MatchOutcome::NoMatch
        }
    }
}

/// Walk positional patterns against extracted positional args.
fn match_positional(
    patterns: &[PosExpr],
    args: &[ResolvedArg],
    exact: bool,
    emit: &mut dyn for<'e> FnMut(MatchEvent<'e>),
) -> MatchOutcome {
    let positional = extract_positional_args(args);
    let mut pos = 0;
    let mut first_effect: Option<Effect> = None;

    for pexpr in patterns {
        match pexpr {
            PosExpr::One(e) => {
                match positional.get(pos) {
                    Some(arg) => {
                        let outcome = match_expr_arg(e, arg, emit);
                        match outcome {
                            MatchOutcome::NoMatch => return MatchOutcome::NoMatch,
                            MatchOutcome::Matched(eff) if first_effect.is_none() => {
                                first_effect = Some(eff);
                            }
                            _ => {}
                        }
                        pos += 1;
                    }
                    None => {
                        emit(MatchEvent::Missing { pexpr });
                        return MatchOutcome::NoMatch;
                    }
                }
            }
            PosExpr::Optional(e) => {
                emit(MatchEvent::EnterOptional);
                if let Some(arg) = positional.get(pos) {
                    let outcome = match_expr_arg(e, arg, emit);
                    if outcome.is_match() {
                        if let MatchOutcome::Matched(eff) = outcome
                            && first_effect.is_none()
                        {
                            first_effect = Some(eff);
                        }
                        pos += 1;
                        emit(MatchEvent::LeaveOptional);
                    } else {
                        emit(MatchEvent::LeaveOptional);
                    }
                } else {
                    emit(MatchEvent::LeaveOptional);
                }
            }
            PosExpr::OneOrMore(e) => {
                // Must match at least one
                match positional.get(pos) {
                    Some(arg) => {
                        if !expr_matches_resolved(e, arg) {
                            emit(MatchEvent::Quantifier { pexpr, count: 0, matched: false });
                            return MatchOutcome::NoMatch;
                        }
                    }
                    None => {
                        emit(MatchEvent::Quantifier { pexpr, count: 0, matched: false });
                        return MatchOutcome::NoMatch;
                    }
                }
                // Consume as many as possible, checking for effects
                let start = pos;
                while let Some(arg) = positional.get(pos) {
                    if !expr_matches_resolved(e, arg) {
                        break;
                    }
                    if first_effect.is_none()
                        && let ResolvedArg::Literal(s) = arg
                        && let Some(eff) = e.find_effect(s)
                    {
                        first_effect = Some(eff.clone());
                    }
                    pos += 1;
                }
                let count = pos - start;
                emit(MatchEvent::Quantifier { pexpr, count, matched: true });
            }
            PosExpr::ZeroOrMore(e) => {
                let start = pos;
                while let Some(arg) = positional.get(pos) {
                    if !expr_matches_resolved(e, arg) {
                        break;
                    }
                    if first_effect.is_none()
                        && let ResolvedArg::Literal(s) = arg
                        && let Some(eff) = e.find_effect(s)
                    {
                        first_effect = Some(eff.clone());
                    }
                    pos += 1;
                }
                let count = pos - start;
                emit(MatchEvent::Quantifier { pexpr, count, matched: true });
            }
        }
    }

    if exact && pos != positional.len() {
        let remainder = positional.len() - pos;
        emit(MatchEvent::ExactRemainder { count: remainder });
        return MatchOutcome::NoMatch;
    }

    match first_effect {
        Some(eff) => MatchOutcome::Matched(eff),
        None => MatchOutcome::MatchedNoEffect,
    }
}

/// Convenience wrapper: pure boolean match (no tracing, no effect extraction).
#[cfg(test)]
pub(in crate::engine) fn matcher_matches(matcher: &ArgMatcher, args: &[ResolvedArg]) -> bool {
    match_args(matcher, args, &mut |_| {}).is_match()
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::{CondBranch, Decision};

    fn lit(s: &str) -> ResolvedArg {
        ResolvedArg::Literal(s.into())
    }

    fn allow_effect(reason: &str) -> Effect {
        Effect { decision: Decision::Allow, reason: Some(reason.into()) }
    }

    fn deny_effect(reason: &str) -> Effect {
        Effect { decision: Decision::Deny, reason: Some(reason.into()) }
    }

    fn cond_expr(branches: Vec<(Expr, Effect)>) -> Expr {
        Expr::Cond(branches.into_iter().map(|(test, effect)| ExprBranch { test, effect }).collect())
    }

    /// Collect events from a match_args call.
    fn match_with_events(matcher: &ArgMatcher, args: &[ResolvedArg]) -> (MatchOutcome, Vec<String>) {
        let mut events = Vec::new();
        let outcome = match_args(matcher, args, &mut |ev| {
            events.push(format!("{ev:?}"));
        });
        (outcome, events)
    }

    // ── expr_matches_resolved ────────────────────────────────────────

    #[test]
    fn expr_resolved_literal_match() {
        assert!(expr_matches_resolved(&Expr::Literal("foo".into()), &lit("foo")));
    }

    #[test]
    fn expr_resolved_literal_no_match() {
        assert!(!expr_matches_resolved(&Expr::Literal("foo".into()), &lit("bar")));
    }

    #[test]
    fn expr_resolved_wildcard_matches_any_literal() {
        assert!(expr_matches_resolved(&Expr::Wildcard, &lit("anything")));
    }

    #[test]
    fn expr_resolved_wildcard_matches_opaque() {
        assert!(expr_matches_resolved(&Expr::Wildcard, &ResolvedArg::Opaque));
    }

    #[test]
    fn expr_resolved_literal_rejects_opaque() {
        assert!(!expr_matches_resolved(&Expr::Literal("foo".into()), &ResolvedArg::Opaque));
    }

    #[test]
    fn expr_resolved_regex_rejects_opaque() {
        let re = Expr::Regex(regex::Regex::new(".*").unwrap());
        assert!(!expr_matches_resolved(&re, &ResolvedArg::Opaque));
    }

    #[test]
    fn expr_resolved_regex_match() {
        let re = Expr::Regex(regex::Regex::new("^foo").unwrap());
        assert!(expr_matches_resolved(&re, &lit("foobar")));
        assert!(!expr_matches_resolved(&re, &lit("barfoo")));
    }

    #[test]
    fn expr_resolved_and() {
        let e = Expr::And(vec![
            Expr::Regex(regex::Regex::new("^f").unwrap()),
            Expr::Regex(regex::Regex::new("o$").unwrap()),
        ]);
        assert!(expr_matches_resolved(&e, &lit("foo")));
        assert!(!expr_matches_resolved(&e, &lit("fox")));
    }

    #[test]
    fn expr_resolved_or() {
        let e = Expr::Or(vec![Expr::Literal("a".into()), Expr::Literal("b".into())]);
        assert!(expr_matches_resolved(&e, &lit("a")));
        assert!(expr_matches_resolved(&e, &lit("b")));
        assert!(!expr_matches_resolved(&e, &lit("c")));
    }

    #[test]
    fn expr_resolved_not() {
        let e = Expr::Not(Box::new(Expr::Literal("bad".into())));
        assert!(expr_matches_resolved(&e, &lit("good")));
        assert!(!expr_matches_resolved(&e, &lit("bad")));
    }

    // ── match_expr_arg ───────────────────────────────────────────────

    #[test]
    fn match_expr_arg_simple_match() {
        let outcome = match_expr_arg(&Expr::Literal("x".into()), &lit("x"), &mut |_| {});
        assert!(outcome.is_match());
        assert!(matches!(outcome, MatchOutcome::MatchedNoEffect));
    }

    #[test]
    fn match_expr_arg_simple_no_match() {
        let outcome = match_expr_arg(&Expr::Literal("x".into()), &lit("y"), &mut |_| {});
        assert!(!outcome.is_match());
    }

    #[test]
    fn match_expr_arg_cond_matching_branch() {
        let expr = cond_expr(vec![
            (Expr::Literal("safe".into()), allow_effect("safe")),
            (Expr::Wildcard, deny_effect("fallback")),
        ]);
        let outcome = match_expr_arg(&expr, &lit("safe"), &mut |_| {});
        match outcome {
            MatchOutcome::Matched(eff) => {
                assert_eq!(eff.decision, Decision::Allow);
                assert_eq!(eff.reason.as_deref(), Some("safe"));
            }
            _ => panic!("expected Matched"),
        }
    }

    #[test]
    fn match_expr_arg_cond_fallthrough() {
        let expr = cond_expr(vec![
            (Expr::Literal("safe".into()), allow_effect("safe")),
            (Expr::Wildcard, deny_effect("fallback")),
        ]);
        let outcome = match_expr_arg(&expr, &lit("danger"), &mut |_| {});
        match outcome {
            MatchOutcome::Matched(eff) => {
                assert_eq!(eff.decision, Decision::Deny);
            }
            _ => panic!("expected Matched with fallback"),
        }
    }

    #[test]
    fn match_expr_arg_cond_no_matching_branch() {
        let expr = cond_expr(vec![
            (Expr::Literal("a".into()), allow_effect("a")),
        ]);
        let outcome = match_expr_arg(&expr, &lit("z"), &mut |_| {});
        assert!(!outcome.is_match());
    }

    #[test]
    fn match_expr_arg_cond_opaque_rejects_all_branches() {
        let expr = cond_expr(vec![
            (Expr::Literal("a".into()), allow_effect("a")),
            (Expr::Literal("b".into()), deny_effect("b")),
        ]);
        let outcome = match_expr_arg(&expr, &ResolvedArg::Opaque, &mut |_| {});
        assert!(!outcome.is_match());
    }

    #[test]
    fn match_expr_arg_nested_cond_in_and() {
        // And([Cond([...]), Literal]) — find_effect extracts cond effect
        let inner_cond = cond_expr(vec![
            (Expr::Wildcard, allow_effect("nested")),
        ]);
        let expr = Expr::And(vec![inner_cond, Expr::Wildcard]);
        let outcome = match_expr_arg(&expr, &lit("x"), &mut |_| {});
        match outcome {
            MatchOutcome::Matched(eff) => {
                assert_eq!(eff.reason.as_deref(), Some("nested"));
            }
            _ => panic!("expected Matched from nested cond"),
        }
    }

    #[test]
    fn match_expr_arg_nested_cond_in_or() {
        let inner_cond = cond_expr(vec![
            (Expr::Literal("x".into()), deny_effect("found")),
        ]);
        let expr = Expr::Or(vec![Expr::Literal("z".into()), inner_cond]);
        let outcome = match_expr_arg(&expr, &lit("x"), &mut |_| {});
        match outcome {
            MatchOutcome::Matched(eff) => {
                assert_eq!(eff.decision, Decision::Deny);
            }
            _ => panic!("expected Matched from nested cond in Or"),
        }
    }

    // ── match_args: Positional effect extraction ─────────────────────
    // (replaces deleted find_expr_effect tests)

    #[test]
    fn positional_cond_effect_extracted() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr::One(Expr::Literal("cmd".into())),
            PosExpr::One(cond_expr(vec![
                (Expr::Literal("safe".into()), allow_effect("safe")),
                (Expr::Wildcard, deny_effect("bad")),
            ])),
        ]);
        let args = vec![lit("cmd"), lit("safe")];
        match match_args(&matcher, &args, &mut |_| {}) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Allow),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn positional_cond_fallback_effect() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr::One(cond_expr(vec![
                (Expr::Literal("a".into()), allow_effect("a")),
                (Expr::Wildcard, deny_effect("fallback")),
            ])),
        ]);
        match match_args(&matcher, &[lit("z")], &mut |_| {}) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Deny),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn exact_positional_cond_effect() {
        let matcher = ArgMatcher::ExactPositional(vec![
            PosExpr::One(cond_expr(vec![
                (Expr::Wildcard, allow_effect("any")),
            ])),
        ]);
        match match_args(&matcher, &[lit("x")], &mut |_| {}) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Allow),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn exact_positional_rejects_extra_despite_cond() {
        let matcher = ArgMatcher::ExactPositional(vec![
            PosExpr::One(cond_expr(vec![
                (Expr::Wildcard, allow_effect("any")),
            ])),
        ]);
        // Too many args
        assert!(!match_args(&matcher, &[lit("x"), lit("y")], &mut |_| {}).is_match());
        // Too few args
        assert!(!match_args(&matcher, &[], &mut |_| {}).is_match());
    }

    #[test]
    fn optional_cond_effect_when_matched() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr::Optional(cond_expr(vec![
                (Expr::Literal("hit".into()), deny_effect("hit")),
            ])),
        ]);
        match match_args(&matcher, &[lit("hit")], &mut |_| {}) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Deny),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn optional_no_arg_no_effect() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr::Optional(cond_expr(vec![
                (Expr::Literal("hit".into()), deny_effect("hit")),
            ])),
        ]);
        // No args — optional is skipped, no effect
        match match_args(&matcher, &[], &mut |_| {}) {
            MatchOutcome::MatchedNoEffect => {}
            other => panic!("expected MatchedNoEffect, got {other:?}"),
        }
    }

    #[test]
    fn one_or_more_cond_effect() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr::OneOrMore(cond_expr(vec![
                (Expr::Wildcard, allow_effect("any")),
            ])),
        ]);
        match match_args(&matcher, &[lit("a")], &mut |_| {}) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Allow),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn one_or_more_no_args_fails() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr::OneOrMore(Expr::Wildcard),
        ]);
        assert!(!match_args(&matcher, &[], &mut |_| {}).is_match());
    }

    #[test]
    fn zero_or_more_cond_effect() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr::ZeroOrMore(cond_expr(vec![
                (Expr::Literal("match".into()), deny_effect("matched")),
            ])),
        ]);
        match match_args(&matcher, &[lit("match")], &mut |_| {}) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Deny),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn zero_or_more_no_args_no_effect() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr::ZeroOrMore(cond_expr(vec![
                (Expr::Wildcard, allow_effect("any")),
            ])),
        ]);
        match match_args(&matcher, &[], &mut |_| {}) {
            MatchOutcome::MatchedNoEffect => {}
            other => panic!("expected MatchedNoEffect, got {other:?}"),
        }
    }

    #[test]
    fn positional_skips_flags_for_effect() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr::One(cond_expr(vec![
                (Expr::Literal("val".into()), allow_effect("got it")),
            ])),
        ]);
        // --flag consumes next arg, so "val" is the first positional
        let args = vec![lit("--flag"), lit("flagval"), lit("val")];
        match match_args(&matcher, &args, &mut |_| {}) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Allow),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    // ── match_args: And/Or/Not effect propagation ────────────────────

    #[test]
    fn and_propagates_first_effect() {
        let cond = cond_expr(vec![(Expr::Wildcard, allow_effect("from cond"))]);
        let matcher = ArgMatcher::And(vec![
            ArgMatcher::Positional(vec![PosExpr::One(cond)]),
            ArgMatcher::Positional(vec![PosExpr::One(Expr::Wildcard)]),
        ]);
        match match_args(&matcher, &[lit("x")], &mut |_| {}) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.reason.as_deref(), Some("from cond")),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn and_short_circuits_on_no_match() {
        let matcher = ArgMatcher::And(vec![
            ArgMatcher::Positional(vec![PosExpr::One(Expr::Literal("a".into()))]),
            ArgMatcher::Positional(vec![PosExpr::One(Expr::Literal("b".into()))]),
        ]);
        assert!(!match_args(&matcher, &[lit("x")], &mut |_| {}).is_match());
    }

    #[test]
    fn or_returns_first_match_with_effect() {
        let cond = cond_expr(vec![(Expr::Wildcard, deny_effect("from second"))]);
        let matcher = ArgMatcher::Or(vec![
            ArgMatcher::Positional(vec![PosExpr::One(Expr::Literal("nope".into()))]),
            ArgMatcher::Positional(vec![PosExpr::One(cond)]),
        ]);
        match match_args(&matcher, &[lit("x")], &mut |_| {}) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Deny),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn or_no_match() {
        let matcher = ArgMatcher::Or(vec![
            ArgMatcher::Positional(vec![PosExpr::One(Expr::Literal("a".into()))]),
            ArgMatcher::Positional(vec![PosExpr::One(Expr::Literal("b".into()))]),
        ]);
        assert!(!match_args(&matcher, &[lit("z")], &mut |_| {}).is_match());
    }

    #[test]
    fn not_inverts_match() {
        let matcher = ArgMatcher::Not(Box::new(
            ArgMatcher::Anywhere(vec![Expr::Literal("--force".into())]),
        ));
        assert!(match_args(&matcher, &[lit("push")], &mut |_| {}).is_match());
        assert!(!match_args(&matcher, &[lit("--force")], &mut |_| {}).is_match());
    }

    #[test]
    fn not_does_not_propagate_effects() {
        let cond = cond_expr(vec![(Expr::Wildcard, allow_effect("should not appear"))]);
        let matcher = ArgMatcher::Not(Box::new(
            ArgMatcher::Positional(vec![PosExpr::One(cond)]),
        ));
        // Inner matches (with effect), so Not inverts → NoMatch
        assert!(!match_args(&matcher, &[lit("x")], &mut |_| {}).is_match());
    }

    // ── match_args: ArgMatcher::Cond ─────────────────────────────────

    #[test]
    fn matcher_cond_first_branch() {
        let matcher = ArgMatcher::Cond(vec![
            CondBranch {
                matcher: Some(ArgMatcher::Positional(vec![PosExpr::One(Expr::Literal("a".into()))])),
                effect: allow_effect("branch a"),
            },
            CondBranch {
                matcher: None,
                effect: deny_effect("else"),
            },
        ]);
        match match_args(&matcher, &[lit("a")], &mut |_| {}) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.reason.as_deref(), Some("branch a")),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn matcher_cond_else_branch() {
        let matcher = ArgMatcher::Cond(vec![
            CondBranch {
                matcher: Some(ArgMatcher::Positional(vec![PosExpr::One(Expr::Literal("a".into()))])),
                effect: allow_effect("branch a"),
            },
            CondBranch {
                matcher: None,
                effect: deny_effect("else"),
            },
        ]);
        match match_args(&matcher, &[lit("z")], &mut |_| {}) {
            MatchOutcome::Matched(eff) => {
                assert_eq!(eff.decision, Decision::Deny);
                assert_eq!(eff.reason.as_deref(), Some("else"));
            }
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn matcher_cond_no_match_no_else() {
        let matcher = ArgMatcher::Cond(vec![
            CondBranch {
                matcher: Some(ArgMatcher::Positional(vec![PosExpr::One(Expr::Literal("a".into()))])),
                effect: allow_effect("a"),
            },
        ]);
        assert!(!match_args(&matcher, &[lit("z")], &mut |_| {}).is_match());
    }

    // ── match_args: Anywhere with effects ────────────────────────────

    #[test]
    fn anywhere_cond_extracts_effect() {
        let cond = cond_expr(vec![
            (Expr::Literal("--safe".into()), allow_effect("safe")),
            (Expr::Wildcard, deny_effect("unsafe")),
        ]);
        let matcher = ArgMatcher::Anywhere(vec![cond]);
        match match_args(&matcher, &[lit("--safe")], &mut |_| {}) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Allow),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn anywhere_nested_cond_effect() {
        // Anywhere with Expr::Or containing a Cond (find_effect path)
        let inner_cond = cond_expr(vec![
            (Expr::Literal("x".into()), allow_effect("found x")),
        ]);
        let expr = Expr::Or(vec![Expr::Literal("z".into()), inner_cond]);
        let matcher = ArgMatcher::Anywhere(vec![expr]);
        match match_args(&matcher, &[lit("x")], &mut |_| {}) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.reason.as_deref(), Some("found x")),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn anywhere_no_match() {
        let matcher = ArgMatcher::Anywhere(vec![Expr::Literal("--force".into())]);
        assert!(!match_args(&matcher, &[lit("push")], &mut |_| {}).is_match());
    }

    // ── Event emission ───────────────────────────────────────────────

    #[test]
    fn events_emitted_for_positional_match() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr::One(Expr::Literal("a".into())),
        ]);
        let (outcome, events) = match_with_events(&matcher, &[lit("a")]);
        assert!(outcome.is_match());
        assert_eq!(events.len(), 1);
        assert!(events[0].contains("ExprVsArg"));
        assert!(events[0].contains("matched: true"));
    }

    #[test]
    fn events_emitted_for_missing_arg() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr::One(Expr::Literal("a".into())),
        ]);
        let (outcome, events) = match_with_events(&matcher, &[]);
        assert!(!outcome.is_match());
        assert_eq!(events.len(), 1);
        assert!(events[0].contains("Missing"));
    }

    #[test]
    fn events_emitted_for_optional() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr::Optional(Expr::Literal("opt".into())),
        ]);
        let (_, events) = match_with_events(&matcher, &[lit("opt")]);
        // Should see: EnterOptional, ExprVsArg, LeaveOptional
        assert!(events.iter().any(|e| e.contains("EnterOptional")));
        assert!(events.iter().any(|e| e.contains("ExprVsArg")));
        assert!(events.iter().any(|e| e.contains("LeaveOptional")));
    }

    #[test]
    fn events_emitted_for_cond() {
        let cond = cond_expr(vec![
            (Expr::Literal("a".into()), allow_effect("a")),
            (Expr::Wildcard, deny_effect("else")),
        ]);
        let matcher = ArgMatcher::Positional(vec![PosExpr::One(cond)]);
        let (_, events) = match_with_events(&matcher, &[lit("a")]);
        assert!(events.iter().any(|e| e.contains("EnterCond")));
        assert!(events.iter().any(|e| e.contains("ExprCondBranch")));
        assert!(events.iter().any(|e| e.contains("LeaveCond")));
    }

    #[test]
    fn events_emitted_for_matcher_cond() {
        let matcher = ArgMatcher::Cond(vec![
            CondBranch {
                matcher: Some(ArgMatcher::Positional(vec![PosExpr::One(Expr::Literal("a".into()))])),
                effect: allow_effect("a"),
            },
            CondBranch {
                matcher: None,
                effect: deny_effect("else"),
            },
        ]);
        let (_, events) = match_with_events(&matcher, &[lit("z")]);
        assert!(events.iter().any(|e| e.contains("EnterCond")));
        // First branch: inner events + MatcherCondBranch
        assert!(events.iter().any(|e| e.contains("MatcherCondBranch")));
        // Second branch: else
        assert!(events.iter().any(|e| e.contains("MatcherCondElse")));
        assert!(events.iter().any(|e| e.contains("LeaveCond")));
    }

    #[test]
    fn events_emitted_for_anywhere() {
        let matcher = ArgMatcher::Anywhere(vec![Expr::Literal("--force".into())]);
        let (_, events) = match_with_events(&matcher, &[lit("push"), lit("--force")]);
        assert!(events.iter().any(|e| e.contains("Anywhere")));
        assert!(events.iter().any(|e| e.contains("matched: true")));
    }

    #[test]
    fn events_emitted_for_exact_remainder() {
        let matcher = ArgMatcher::ExactPositional(vec![
            PosExpr::One(Expr::Literal("a".into())),
        ]);
        let (_, events) = match_with_events(&matcher, &[lit("a"), lit("extra")]);
        assert!(events.iter().any(|e| e.contains("ExactRemainder")));
    }

    #[test]
    fn events_emitted_for_quantifier() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr::ZeroOrMore(Expr::Literal("x".into())),
        ]);
        let (_, events) = match_with_events(&matcher, &[lit("x"), lit("x")]);
        assert!(events.iter().any(|e| e.contains("Quantifier")));
        assert!(events.iter().any(|e| e.contains("count: 2")));
    }

    #[test]
    fn noop_callback_still_produces_correct_outcome() {
        // Verify that the noop callback (hook mode) produces the same match result
        let cond = cond_expr(vec![
            (Expr::Literal("safe".into()), allow_effect("safe")),
            (Expr::Wildcard, deny_effect("fallback")),
        ]);
        let matcher = ArgMatcher::Positional(vec![PosExpr::One(cond)]);

        let outcome = match_args(&matcher, &[lit("safe")], &mut |_| {});
        match outcome {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Allow),
            other => panic!("expected Matched, got {other:?}"),
        }
    }
}

/// Extract positional args from a resolved argument list, skipping flags and their values.
pub(in crate::engine) fn extract_positional_args(args: &[ResolvedArg]) -> Vec<ResolvedArg> {
    let mut positional = Vec::new();
    let mut skip_next = false;
    let mut flags_done = false;
    for arg in args {
        let s = match arg {
            ResolvedArg::Literal(s) => s.as_str(),
            ResolvedArg::Opaque => {
                // Opaque values are always positional (we can't tell if they're flags)
                positional.push(arg.clone());
                continue;
            }
        };
        if flags_done {
            positional.push(arg.clone());
            continue;
        }
        if skip_next {
            skip_next = false;
            continue;
        }
        if s == "--" {
            positional.push(arg.clone());
            flags_done = true;
            continue;
        }
        if s.starts_with("--") {
            if !s.contains('=') {
                skip_next = true;
            }
            continue;
        }
        if s.starts_with('-') && s.len() > 1 {
            continue;
        }
        positional.push(arg.clone());
    }
    positional
}

/// R8: Expand combined short flags: -abc → -a -b -c
/// Words with opaque parts produce a single Opaque arg.
pub(in crate::engine) fn expand_flags(args: &[Word]) -> Vec<ResolvedArg> {
    let mut result = Vec::new();
    for arg in args {
        if arg.has_opaque_parts() {
            result.push(ResolvedArg::Opaque);
        } else {
            let s = arg.to_str();
            if s.starts_with('-') && !s.starts_with("--") && s.len() > 2 {
                for ch in s[1..].chars() {
                    result.push(ResolvedArg::Literal(format!("-{ch}")));
                }
            } else {
                result.push(ResolvedArg::Literal(s));
            }
        }
    }
    result
}

/// R9: Attempt to unwrap a wrapper command, returning the inner command.
pub(in crate::engine) fn unwrap_wrapper(sc: &SimpleCommand, config: &Config) -> Option<SimpleCommand> {
    let cmd_name = sc.command_name()?;

    'wrapper: for wrapper in &config.wrappers {
        if wrapper.command != cmd_name {
            continue;
        }

        // Positional args (non-flag words) paired with their index in sc.words[1..].
        let positionals: Vec<(usize, String)> = sc.words[1..]
            .iter()
            .enumerate()
            .filter(|(_, w)| !w.to_str().starts_with('-'))
            .map(|(i, w)| (i, w.to_str()))
            .collect();

        let mut pos_cursor = 0; // index into `positionals`
        let mut inner_start: Option<usize> = None; // index into sc.words[1..]

        for step in &wrapper.steps {
            match step {
                WrapperStep::Positional { patterns, capture } => {
                    for pat in patterns {
                        match positionals.get(pos_cursor) {
                            Some((_, arg)) if pat.is_match(arg) => pos_cursor += 1,
                            _ => continue 'wrapper, // pattern mismatch
                        }
                    }
                    if let Some(_kind) = capture {
                        inner_start = if pos_cursor == 0 {
                            // No patterns consumed — start from first positional.
                            positionals.first().map(|(idx, _)| *idx)
                        } else {
                            // Start from the arg immediately after the last matched positional.
                            Some(positionals[pos_cursor - 1].0 + 1)
                        };
                    }
                }
                WrapperStep::Flag { name, capture: _ } => {
                    match sc.words[1..].iter().position(|w| w.to_str() == *name) {
                        Some(flag_idx) => inner_start = Some(flag_idx + 1),
                        None => continue 'wrapper, // delimiter/flag not found
                    }
                }
            }
        }

        if let Some(start) = inner_start {
            // `start` is an index into sc.words[1..]; add 1 to get index into sc.words.
            let words_start = start + 1;
            if words_start < sc.words.len() {
                return Some(SimpleCommand {
                    assignments: vec![],
                    words: sc.words[words_start..].to_vec(),
                    redirections: sc.redirections.clone(),
                });
            }
        }
    }

    None
}
