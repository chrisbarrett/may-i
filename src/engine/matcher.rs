// Rule matching — given a resolved command and config, find the applicable rule.
// Pure matching logic: no AST walking, no variable resolution.

use crate::parser::{SimpleCommand, Word};
use crate::types::{ArgMatcher, CommandMatcher, Config, PosExpr, WrapperStep};

/// A resolved argument that may be a known literal or an opaque (safe but unknown) value.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum ResolvedArg {
    Literal(String),
    Opaque,
}

/// Format a CommandMatcher for display in traces.
pub(super) fn format_command_matcher(m: &CommandMatcher) -> String {
    match m {
        CommandMatcher::Exact(s) => format!("(command \"{s}\")"),
        CommandMatcher::Regex(re) => format!("(command #\"{}\")", re.as_str()),
        CommandMatcher::List(names) => {
            let quoted: Vec<String> = names.iter().map(|n| format!("\"{n}\"")).collect();
            format!("(command (or {}))", quoted.join(" "))
        }
    }
}

/// Format an Expr for display in traces.
fn format_expr(e: &crate::types::Expr) -> String {
    use crate::types::Expr;
    match e {
        Expr::Literal(s) => format!("\"{s}\""),
        Expr::Regex(re) => format!("#\"{}\"", re.as_str()),
        Expr::Wildcard => "_".into(),
        Expr::And(exprs) => {
            let inner: Vec<String> = exprs.iter().map(format_expr).collect();
            format!("(and {})", inner.join(" "))
        }
        Expr::Or(exprs) => {
            let inner: Vec<String> = exprs.iter().map(format_expr).collect();
            format!("(or {})", inner.join(" "))
        }
        Expr::Not(expr) => format!("(not {})", format_expr(expr)),
        Expr::Cond(branches) => {
            let inner: Vec<String> = branches
                .iter()
                .map(|b| format!("({} => {})", format_expr(&b.test), b.effect.decision))
                .collect();
            format!("(cond {})", inner.join(" "))
        }
    }
}

/// Format a PosExpr for display in traces.
fn format_pos_expr(pe: &PosExpr) -> String {
    match pe {
        PosExpr::One(e) => format_expr(e),
        PosExpr::Optional(e) => format!("(? {})", format_expr(e)),
        PosExpr::OneOrMore(e) => format!("(+ {})", format_expr(e)),
        PosExpr::ZeroOrMore(e) => format!("(* {})", format_expr(e)),
    }
}

/// Result of a traced match: did it match, and what was evaluated.
pub(super) struct MatchTrace {
    pub matched: bool,
    pub steps: Vec<String>,
}

/// Like `matcher_matches`, but also produces trace entries showing what was evaluated.
pub(super) fn matcher_matches_traced(matcher: &ArgMatcher, args: &[ResolvedArg]) -> MatchTrace {
    match matcher {
        ArgMatcher::Positional(patterns) | ArgMatcher::ExactPositional(patterns) => {
            let exact = matches!(matcher, ArgMatcher::ExactPositional(_));
            let positional = extract_positional_args(args);
            trace_positional(patterns, &positional, exact)
        }
        ArgMatcher::Anywhere(tokens) => {
            let mut steps = Vec::new();
            let matched = tokens.iter().any(|token| {
                let found = args.iter().any(|a| match a {
                    ResolvedArg::Literal(s) => token.is_match(s),
                    ResolvedArg::Opaque => token.is_wildcard(),
                });
                steps.push(format!(
                    "(anywhere {}) => {}",
                    format_expr(token),
                    if found { "yes" } else { "no" }
                ));
                found
            });
            MatchTrace { matched, steps }
        }
        ArgMatcher::And(matchers) => {
            let mut steps = Vec::new();
            let mut all_matched = true;
            for m in matchers {
                let sub = matcher_matches_traced(m, args);
                steps.extend(sub.steps);
                if !sub.matched {
                    all_matched = false;
                    break;
                }
            }
            MatchTrace { matched: all_matched, steps }
        }
        ArgMatcher::Or(matchers) => {
            let mut steps = Vec::new();
            let mut any_matched = false;
            for m in matchers {
                let sub = matcher_matches_traced(m, args);
                steps.extend(sub.steps);
                if sub.matched {
                    any_matched = true;
                    break;
                }
            }
            MatchTrace { matched: any_matched, steps }
        }
        ArgMatcher::Not(inner) => {
            let sub = matcher_matches_traced(inner, args);
            MatchTrace { matched: !sub.matched, steps: sub.steps }
        }
        ArgMatcher::Cond(branches) => {
            let mut steps = Vec::new();
            let mut any_matched = false;
            for b in branches {
                match &b.matcher {
                    None => {
                        steps.push(format!("(else => {}) => yes", b.effect.decision));
                        any_matched = true;
                        break;
                    }
                    Some(m) => {
                        let sub = matcher_matches_traced(m, args);
                        let matched = sub.matched;
                        steps.extend(sub.steps);
                        if matched {
                            any_matched = true;
                            break;
                        }
                    }
                }
            }
            MatchTrace { matched: any_matched, steps }
        }
    }
}

/// Trace positional matching, showing each pattern and whether it matched.
fn trace_positional(patterns: &[PosExpr], positional: &[ResolvedArg], exact: bool) -> MatchTrace {
    let mut steps = Vec::new();
    let mut pos = 0;

    for pexpr in patterns {
        let label = format_pos_expr(pexpr);
        match pexpr {
            PosExpr::One(e) => {
                match positional.get(pos) {
                    Some(ResolvedArg::Literal(s)) => {
                        let matched = e.is_wildcard() || e.is_match(s);
                        steps.push(format!("{label} vs \"{s}\" => {}", if matched { "yes" } else { "no" }));
                        if !matched {
                            return MatchTrace { matched: false, steps };
                        }
                    }
                    Some(ResolvedArg::Opaque) => {
                        let matched = e.is_wildcard();
                        steps.push(format!("{label} vs <opaque> => {}", if matched { "yes" } else { "no" }));
                        if !matched {
                            return MatchTrace { matched: false, steps };
                        }
                    }
                    None => {
                        steps.push(format!("{label} vs <missing> => no"));
                        return MatchTrace { matched: false, steps };
                    }
                }
                pos += 1;
            }
            PosExpr::Optional(e) => {
                if let Some(arg) = positional.get(pos) {
                    let m = match arg {
                        ResolvedArg::Literal(s) => e.is_wildcard() || e.is_match(s),
                        ResolvedArg::Opaque => e.is_wildcard(),
                    };
                    let arg_str = match arg {
                        ResolvedArg::Literal(s) => format!("\"{s}\""),
                        ResolvedArg::Opaque => "<opaque>".into(),
                    };
                    steps.push(format!("{label} vs {arg_str} => {}", if m { "yes" } else { "skip" }));
                    if m {
                        pos += 1;
                    }
                } else {
                    steps.push(format!("{label} => skip (no more args)"));
                }
            }
            PosExpr::OneOrMore(e) | PosExpr::ZeroOrMore(e) => {
                let required = matches!(pexpr, PosExpr::OneOrMore(_));
                let mut count = 0;
                while let Some(arg) = positional.get(pos) {
                    let m = match arg {
                        ResolvedArg::Literal(s) => e.is_wildcard() || e.is_match(s),
                        ResolvedArg::Opaque => e.is_wildcard(),
                    };
                    if !m {
                        break;
                    }
                    count += 1;
                    pos += 1;
                }
                if required && count == 0 {
                    steps.push(format!("{label} => no (matched 0, need 1+)"));
                    return MatchTrace { matched: false, steps };
                }
                steps.push(format!("{label} => yes (matched {count})"));
            }
        }
    }

    let matched = if exact { pos == positional.len() } else { true };
    if exact && !matched {
        steps.push(format!("exact: {} positional args remaining", positional.len() - pos));
    }
    MatchTrace { matched, steps }
}

/// Check if a command name matches a command matcher.
pub(super) fn command_matches(name: &str, matcher: &CommandMatcher) -> bool {
    match matcher {
        CommandMatcher::Exact(s) => name == s,
        CommandMatcher::Regex(re) => re.is_match(name),
        CommandMatcher::List(names) => names.iter().any(|n| n == name),
    }
}

pub(super) fn match_positional(patterns: &[PosExpr], args: &[ResolvedArg], exact: bool) -> bool {
    let positional = extract_positional_args(args);
    let mut pos = 0;

    for pexpr in patterns {
        match pexpr {
            PosExpr::One(e) => {
                match positional.get(pos) {
                    Some(ResolvedArg::Literal(s)) => {
                        if !(e.is_wildcard() || e.is_match(s)) {
                            return false;
                        }
                    }
                    Some(ResolvedArg::Opaque) => {
                        // Opaque only matches wildcards
                        if !e.is_wildcard() {
                            return false;
                        }
                    }
                    None => return false,
                }
                pos += 1;
            }
            PosExpr::Optional(e) => {
                if let Some(arg) = positional.get(pos) {
                    let matches = match arg {
                        ResolvedArg::Literal(s) => e.is_wildcard() || e.is_match(s),
                        ResolvedArg::Opaque => e.is_wildcard(),
                    };
                    if matches {
                        pos += 1;
                    }
                }
            }
            PosExpr::OneOrMore(e) => {
                match positional.get(pos) {
                    Some(ResolvedArg::Literal(s)) => {
                        if !(e.is_wildcard() || e.is_match(s)) {
                            return false;
                        }
                    }
                    Some(ResolvedArg::Opaque) => {
                        if !e.is_wildcard() {
                            return false;
                        }
                    }
                    None => return false,
                }
                pos += 1;
                while let Some(arg) = positional.get(pos) {
                    let matches = match arg {
                        ResolvedArg::Literal(s) => e.is_wildcard() || e.is_match(s),
                        ResolvedArg::Opaque => e.is_wildcard(),
                    };
                    if !matches {
                        break;
                    }
                    pos += 1;
                }
            }
            PosExpr::ZeroOrMore(e) => {
                while let Some(arg) = positional.get(pos) {
                    let matches = match arg {
                        ResolvedArg::Literal(s) => e.is_wildcard() || e.is_match(s),
                        ResolvedArg::Opaque => e.is_wildcard(),
                    };
                    if !matches {
                        break;
                    }
                    pos += 1;
                }
            }
        }
    }

    if exact {
        pos == positional.len()
    } else {
        pos <= positional.len()
    }
}

pub(super) fn matcher_matches(matcher: &ArgMatcher, args: &[ResolvedArg]) -> bool {
    match matcher {
        ArgMatcher::Positional(patterns) => match_positional(patterns, args, false),
        ArgMatcher::ExactPositional(patterns) => match_positional(patterns, args, true),
        ArgMatcher::Anywhere(tokens) => {
            // Any of the listed tokens appears anywhere in args (OR semantics).
            // Opaque args never match literal/regex tokens.
            tokens.iter().any(|token| {
                args.iter().any(|a| match a {
                    ResolvedArg::Literal(s) => token.is_match(s),
                    ResolvedArg::Opaque => token.is_wildcard(),
                })
            })
        }
        ArgMatcher::And(matchers) => matchers.iter().all(|m| matcher_matches(m, args)),
        ArgMatcher::Or(matchers) => matchers.iter().any(|m| matcher_matches(m, args)),
        ArgMatcher::Not(inner) => !matcher_matches(inner, args),
        ArgMatcher::Cond(branches) => branches.iter().any(|b| match &b.matcher {
            None => true,
            Some(m) => matcher_matches(m, args),
        }),
    }
}

/// Extract positional args from a resolved argument list, skipping flags and their values.
pub(super) fn extract_positional_args(args: &[ResolvedArg]) -> Vec<ResolvedArg> {
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
pub(super) fn expand_flags(args: &[Word]) -> Vec<ResolvedArg> {
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
pub(super) fn unwrap_wrapper(sc: &SimpleCommand, config: &Config) -> Option<SimpleCommand> {
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
