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
