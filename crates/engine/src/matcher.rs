// Rule matching — given a resolved command and config, find the applicable rule.
// Pure matching logic: no AST walking, no variable resolution.

use may_i_shell_parser::{SimpleCommand, Word};
use may_i_core::{CommandMatcher, Config, Effect, Expr, WrapperStep};

/// A resolved argument that may be a known literal or an opaque (safe but unknown) value.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ResolvedArg {
    Literal(String),
    Opaque,
}

// ── Match outcome ─────────────────────────────────────────────────

/// The result of matching args against an ArgMatcher.
#[derive(Debug)]
pub(crate) enum MatchOutcome {
    /// Matched, with an embedded effect (from Expr::Cond or ArgMatcher::Cond).
    Matched(Effect),
    /// Matched, no embedded effect.
    MatchedNoEffect,
    /// Did not match.
    NoMatch,
}

impl MatchOutcome {
    pub(crate) fn is_match(&self) -> bool {
        !matches!(self, MatchOutcome::NoMatch)
    }
}

// ── Core matching ──────────────────────────────────────────────────

/// Check if a command name matches a command matcher.
pub(crate) fn command_matches(name: &str, matcher: &CommandMatcher) -> bool {
    match matcher {
        CommandMatcher::Exact(s) => name == s,
        CommandMatcher::Regex(re) => re.is_match(name),
        CommandMatcher::List(names) => names.iter().any(|n| n == name),
    }
}

/// Pure boolean: does this expr match this resolved arg?
pub(crate) fn expr_matches_resolved(expr: &Expr, arg: &ResolvedArg) -> bool {
    match arg {
        ResolvedArg::Literal(s) => expr.is_wildcard() || expr.is_match(s),
        ResolvedArg::Opaque => expr.is_wildcard(),
    }
}

/// State machine for parsing flags vs positional args.
enum FlagParseState {
    /// Scanning flags and positional args.
    Scanning,
    /// The previous token was a long flag without `=`; skip this token (its value).
    SkipFlagValue,
    /// `--` was seen; all remaining tokens are positional.
    AllPositional,
}

/// Extract positional args from a resolved argument list, skipping flags and their values.
pub(crate) fn extract_positional_args(args: &[ResolvedArg]) -> Vec<ResolvedArg> {
    let mut positional = Vec::new();
    let mut state = FlagParseState::Scanning;
    for arg in args {
        let s = match arg {
            ResolvedArg::Literal(s) => s.as_str(),
            ResolvedArg::Opaque => {
                // Opaque values are always positional (we can't tell if they're flags)
                positional.push(arg.clone());
                continue;
            }
        };
        match state {
            FlagParseState::AllPositional => {
                positional.push(arg.clone());
            }
            FlagParseState::SkipFlagValue => {
                state = FlagParseState::Scanning;
            }
            FlagParseState::Scanning => {
                if s == "--" {
                    positional.push(arg.clone());
                    state = FlagParseState::AllPositional;
                } else if s.starts_with("--") {
                    if !s.contains('=') {
                        state = FlagParseState::SkipFlagValue;
                    }
                } else if s.starts_with('-') && s.len() > 1 {
                    // short flag, skip
                } else {
                    positional.push(arg.clone());
                }
            }
        }
    }
    positional
}

/// Convenience wrapper: pure boolean match (no tracing, no effect extraction).
/// Delegates to the annotated matcher and discards the Doc tree.
#[cfg(test)]
pub(crate) fn matcher_matches(matcher: &may_i_core::ArgMatcher, args: &[ResolvedArg]) -> bool {
    crate::annotate::annotate_matcher(matcher, args).1.is_match()
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::{ArgMatcher, CondArm, CondBranch, Decision, ExprBranch, PosExpr, Quantifier};

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

    /// Match args via the annotated matcher (single source of matching logic).
    fn match_args(matcher: &ArgMatcher, args: &[ResolvedArg]) -> MatchOutcome {
        crate::annotate::annotate_matcher(matcher, args).1
    }

    /// Match a single expr against a single arg via the annotated matcher.
    fn match_expr_arg(expr: &Expr, arg: &ResolvedArg) -> MatchOutcome {
        crate::annotate::annotate_expr_arg(expr, arg).1
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

    // ── match_expr_arg (delegates to annotate) ───────────────────────

    #[test]
    fn match_expr_arg_simple_match() {
        let outcome = match_expr_arg(&Expr::Literal("x".into()), &lit("x"));
        assert!(outcome.is_match());
        assert!(matches!(outcome, MatchOutcome::MatchedNoEffect));
    }

    #[test]
    fn match_expr_arg_simple_no_match() {
        assert!(!match_expr_arg(&Expr::Literal("x".into()), &lit("y")).is_match());
    }

    #[test]
    fn match_expr_arg_cond_matching_branch() {
        let expr = cond_expr(vec![
            (Expr::Literal("safe".into()), allow_effect("safe")),
            (Expr::Wildcard, deny_effect("fallback")),
        ]);
        match match_expr_arg(&expr, &lit("safe")) {
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
        match match_expr_arg(&expr, &lit("danger")) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Deny),
            _ => panic!("expected Matched with fallback"),
        }
    }

    #[test]
    fn match_expr_arg_cond_no_matching_branch() {
        let expr = cond_expr(vec![
            (Expr::Literal("a".into()), allow_effect("a")),
        ]);
        assert!(!match_expr_arg(&expr, &lit("z")).is_match());
    }

    #[test]
    fn match_expr_arg_cond_opaque_rejects_all_branches() {
        let expr = cond_expr(vec![
            (Expr::Literal("a".into()), allow_effect("a")),
            (Expr::Literal("b".into()), deny_effect("b")),
        ]);
        assert!(!match_expr_arg(&expr, &ResolvedArg::Opaque).is_match());
    }

    #[test]
    fn match_expr_arg_nested_cond_in_and() {
        let inner_cond = cond_expr(vec![
            (Expr::Wildcard, allow_effect("nested")),
        ]);
        let expr = Expr::And(vec![inner_cond, Expr::Wildcard]);
        match match_expr_arg(&expr, &lit("x")) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.reason.as_deref(), Some("nested")),
            _ => panic!("expected Matched from nested cond"),
        }
    }

    #[test]
    fn match_expr_arg_nested_cond_in_or() {
        let inner_cond = cond_expr(vec![
            (Expr::Literal("x".into()), deny_effect("found")),
        ]);
        let expr = Expr::Or(vec![Expr::Literal("z".into()), inner_cond]);
        match match_expr_arg(&expr, &lit("x")) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Deny),
            _ => panic!("expected Matched from nested cond in Or"),
        }
    }

    // ── match_args: Positional effect extraction ─────────────────────

    #[test]
    fn positional_cond_effect_extracted() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr::one(Expr::Literal("cmd".into())),
            PosExpr::one(cond_expr(vec![
                (Expr::Literal("safe".into()), allow_effect("safe")),
                (Expr::Wildcard, deny_effect("bad")),
            ])),
        ]);
        match match_args(&matcher, &[lit("cmd"), lit("safe")]) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Allow),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn positional_cond_fallback_effect() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr::one(cond_expr(vec![
                (Expr::Literal("a".into()), allow_effect("a")),
                (Expr::Wildcard, deny_effect("fallback")),
            ])),
        ]);
        match match_args(&matcher, &[lit("z")]) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Deny),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn exact_positional_cond_effect() {
        let matcher = ArgMatcher::ExactPositional(vec![
            PosExpr::one(cond_expr(vec![
                (Expr::Wildcard, allow_effect("any")),
            ])),
        ]);
        match match_args(&matcher, &[lit("x")]) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Allow),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn exact_positional_rejects_extra_despite_cond() {
        let matcher = ArgMatcher::ExactPositional(vec![
            PosExpr::one(cond_expr(vec![
                (Expr::Wildcard, allow_effect("any")),
            ])),
        ]);
        assert!(!match_args(&matcher, &[lit("x"), lit("y")]).is_match());
        assert!(!match_args(&matcher, &[]).is_match());
    }

    #[test]
    fn optional_cond_effect_when_matched() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr { quantifier: Quantifier::Optional, expr: cond_expr(vec![
                (Expr::Literal("hit".into()), deny_effect("hit")),
            ]) },
        ]);
        match match_args(&matcher, &[lit("hit")]) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Deny),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn optional_no_arg_no_effect() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr { quantifier: Quantifier::Optional, expr: cond_expr(vec![
                (Expr::Literal("hit".into()), deny_effect("hit")),
            ]) },
        ]);
        match match_args(&matcher, &[]) {
            MatchOutcome::MatchedNoEffect => {}
            other => panic!("expected MatchedNoEffect, got {other:?}"),
        }
    }

    #[test]
    fn one_or_more_cond_effect() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr { quantifier: Quantifier::OneOrMore, expr: cond_expr(vec![
                (Expr::Wildcard, allow_effect("any")),
            ]) },
        ]);
        match match_args(&matcher, &[lit("a")]) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Allow),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn one_or_more_no_args_fails() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr { quantifier: Quantifier::OneOrMore, expr: Expr::Wildcard },
        ]);
        assert!(!match_args(&matcher, &[]).is_match());
    }

    #[test]
    fn zero_or_more_cond_effect() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr { quantifier: Quantifier::ZeroOrMore, expr: cond_expr(vec![
                (Expr::Literal("match".into()), deny_effect("matched")),
            ]) },
        ]);
        match match_args(&matcher, &[lit("match")]) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Deny),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn zero_or_more_no_args_no_effect() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr { quantifier: Quantifier::ZeroOrMore, expr: cond_expr(vec![
                (Expr::Wildcard, allow_effect("any")),
            ]) },
        ]);
        match match_args(&matcher, &[]) {
            MatchOutcome::MatchedNoEffect => {}
            other => panic!("expected MatchedNoEffect, got {other:?}"),
        }
    }

    #[test]
    fn positional_skips_flags_for_effect() {
        let matcher = ArgMatcher::Positional(vec![
            PosExpr::one(cond_expr(vec![
                (Expr::Literal("val".into()), allow_effect("got it")),
            ])),
        ]);
        let args = vec![lit("--flag"), lit("flagval"), lit("val")];
        match match_args(&matcher, &args) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Allow),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    // ── And/Or/Not effect propagation ────────────────────────────────

    #[test]
    fn and_propagates_first_effect() {
        let cond = cond_expr(vec![(Expr::Wildcard, allow_effect("from cond"))]);
        let matcher = ArgMatcher::And(vec![
            ArgMatcher::Positional(vec![PosExpr::one(cond)]),
            ArgMatcher::Positional(vec![PosExpr::one(Expr::Wildcard)]),
        ]);
        match match_args(&matcher, &[lit("x")]) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.reason.as_deref(), Some("from cond")),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn and_short_circuits_on_no_match() {
        let matcher = ArgMatcher::And(vec![
            ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal("a".into()))]),
            ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal("b".into()))]),
        ]);
        assert!(!match_args(&matcher, &[lit("x")]).is_match());
    }

    #[test]
    fn or_returns_first_match_with_effect() {
        let cond = cond_expr(vec![(Expr::Wildcard, deny_effect("from second"))]);
        let matcher = ArgMatcher::Or(vec![
            ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal("nope".into()))]),
            ArgMatcher::Positional(vec![PosExpr::one(cond)]),
        ]);
        match match_args(&matcher, &[lit("x")]) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Deny),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn or_no_match() {
        let matcher = ArgMatcher::Or(vec![
            ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal("a".into()))]),
            ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal("b".into()))]),
        ]);
        assert!(!match_args(&matcher, &[lit("z")]).is_match());
    }

    #[test]
    fn not_inverts_match() {
        let matcher = ArgMatcher::Not(Box::new(
            ArgMatcher::Anywhere(vec![Expr::Literal("--force".into())]),
        ));
        assert!(match_args(&matcher, &[lit("push")]).is_match());
        assert!(!match_args(&matcher, &[lit("--force")]).is_match());
    }

    #[test]
    fn not_does_not_propagate_effects() {
        let cond = cond_expr(vec![(Expr::Wildcard, allow_effect("should not appear"))]);
        let matcher = ArgMatcher::Not(Box::new(
            ArgMatcher::Positional(vec![PosExpr::one(cond)]),
        ));
        assert!(!match_args(&matcher, &[lit("x")]).is_match());
    }

    // ── ArgMatcher::Cond ─────────────────────────────────────────────

    #[test]
    fn matcher_cond_first_branch() {
        let matcher = ArgMatcher::Cond(CondArm {
            branches: vec![CondBranch {
                matcher: ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal("a".into()))]),
                effect: allow_effect("branch a"),
            }],
            fallback: Some(deny_effect("else")),
        });
        match match_args(&matcher, &[lit("a")]) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.reason.as_deref(), Some("branch a")),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn matcher_cond_else_branch() {
        let matcher = ArgMatcher::Cond(CondArm {
            branches: vec![CondBranch {
                matcher: ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal("a".into()))]),
                effect: allow_effect("branch a"),
            }],
            fallback: Some(deny_effect("else")),
        });
        match match_args(&matcher, &[lit("z")]) {
            MatchOutcome::Matched(eff) => {
                assert_eq!(eff.decision, Decision::Deny);
                assert_eq!(eff.reason.as_deref(), Some("else"));
            }
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn matcher_cond_no_match_no_else() {
        let matcher = ArgMatcher::Cond(CondArm {
            branches: vec![CondBranch {
                matcher: ArgMatcher::Positional(vec![PosExpr::one(Expr::Literal("a".into()))]),
                effect: allow_effect("a"),
            }],
            fallback: None,
        });
        assert!(!match_args(&matcher, &[lit("z")]).is_match());
    }

    // ── Anywhere with effects ────────────────────────────────────────

    #[test]
    fn anywhere_cond_extracts_effect() {
        let cond = cond_expr(vec![
            (Expr::Literal("--safe".into()), allow_effect("safe")),
            (Expr::Wildcard, deny_effect("unsafe")),
        ]);
        let matcher = ArgMatcher::Anywhere(vec![cond]);
        match match_args(&matcher, &[lit("--safe")]) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.decision, Decision::Allow),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn anywhere_nested_cond_effect() {
        let inner_cond = cond_expr(vec![
            (Expr::Literal("x".into()), allow_effect("found x")),
        ]);
        let expr = Expr::Or(vec![Expr::Literal("z".into()), inner_cond]);
        let matcher = ArgMatcher::Anywhere(vec![expr]);
        match match_args(&matcher, &[lit("x")]) {
            MatchOutcome::Matched(eff) => assert_eq!(eff.reason.as_deref(), Some("found x")),
            other => panic!("expected Matched, got {other:?}"),
        }
    }

    #[test]
    fn anywhere_no_match() {
        let matcher = ArgMatcher::Anywhere(vec![Expr::Literal("--force".into())]);
        assert!(!match_args(&matcher, &[lit("push")]).is_match());
    }
}

/// R8: Expand combined short flags: -abc → -a -b -c
/// Words with opaque parts produce a single Opaque arg.
pub(crate) fn expand_flags(args: &[Word]) -> Vec<ResolvedArg> {
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
pub(crate) fn unwrap_wrapper(sc: &SimpleCommand, config: &Config) -> Option<SimpleCommand> {
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
                    if *capture {
                        inner_start = if pos_cursor == 0 {
                            // No patterns consumed — start from first positional.
                            positionals.first().map(|(idx, _)| *idx)
                        } else {
                            // Start from the arg immediately after the last matched positional.
                            Some(positionals[pos_cursor - 1].0 + 1)
                        };
                    }
                }
                WrapperStep::Flag { name } => {
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
