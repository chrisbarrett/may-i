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
/// `indent` is the column where the expression starts (e.g. after "rule ").
pub(super) fn format_command_matcher(m: &CommandMatcher, indent: usize) -> String {
    let pp = match m {
        CommandMatcher::Exact(s) => PP::List(vec![PP::Atom("command".into()), PP::Atom(format!("\"{s}\""))]),
        CommandMatcher::Regex(re) => PP::List(vec![PP::Atom("command".into()), PP::Atom(format!("#\"{}\"", re.as_str()))]),
        CommandMatcher::List(names) => {
            let mut or_children = vec![PP::Atom("or".into())];
            or_children.extend(names.iter().map(|n| PP::Atom(format!("\"{n}\""))));
            PP::List(vec![PP::Atom("command".into()), PP::List(or_children)])
        }
    };
    pp.pretty(indent, PP_WIDTH)
}

// --- S-expression pretty-printer ---

/// S-expression tree for pretty-printing.
enum PP {
    Atom(String),
    List(Vec<PP>),
}

impl PP {
    /// Render as a compact single-line string.
    fn flat(&self) -> String {
        match self {
            PP::Atom(s) => s.clone(),
            PP::List(children) => {
                let inner: Vec<String> = children.iter().map(|c| c.flat()).collect();
                format!("({})", inner.join(" "))
            }
        }
    }

    /// Pretty-print with wrapping. Returns a multi-line string.
    /// `indent` is the column at which this form starts.
    fn pretty(&self, indent: usize, max_width: usize) -> String {
        match self {
            PP::Atom(s) => s.clone(),
            PP::List(children) if children.is_empty() => "()".into(),
            PP::List(children) => {
                // Try compact first.
                let compact = self.flat();
                if indent + compact.len() <= max_width {
                    return compact;
                }
                // Break: (head first\n<align>rest...)
                // Align subsequent args under the first arg.
                let head = children[0].flat();
                let align = indent + head.len() + 2; // "(" + head + " "
                let mut parts = vec![format!("({head}")];
                for (i, child) in children[1..].iter().enumerate() {
                    let child_str = child.pretty(align, max_width);
                    if i == 0 {
                        parts[0].push(' ');
                        parts[0].push_str(&child_str);
                    } else {
                        parts.push(format!("{:indent$}{child_str}", "", indent = align));
                    }
                }
                parts.last_mut().unwrap().push(')');
                parts.join("\n")
            }
        }
    }
}

/// Build a PP tree from an Expr.
fn expr_to_pp(e: &crate::types::Expr) -> PP {
    use crate::types::Expr;
    match e {
        Expr::Literal(s) => PP::Atom(format!("\"{s}\"")),
        Expr::Regex(re) => PP::Atom(format!("#\"{}\"", re.as_str())),
        Expr::Wildcard => PP::Atom("_".into()),
        Expr::And(exprs) => {
            let mut children = vec![PP::Atom("and".into())];
            children.extend(exprs.iter().map(expr_to_pp));
            PP::List(children)
        }
        Expr::Or(exprs) => {
            let mut children = vec![PP::Atom("or".into())];
            children.extend(exprs.iter().map(expr_to_pp));
            PP::List(children)
        }
        Expr::Not(expr) => PP::List(vec![PP::Atom("not".into()), expr_to_pp(expr)]),
        Expr::Cond(branches) => {
            let mut children = vec![PP::Atom("cond".into())];
            for b in branches {
                children.push(PP::List(vec![
                    expr_to_pp(&b.test),
                    PP::Atom("=>".into()),
                    PP::Atom(b.effect.decision.to_string()),
                ]));
            }
            PP::List(children)
        }
    }
}

const PP_WIDTH: usize = 72;

/// Format an Expr for display in traces, with pretty-printing.
/// `indent` is the column at which the expression will be displayed.
fn format_expr_at(e: &crate::types::Expr, indent: usize) -> String {
    expr_to_pp(e).pretty(indent, PP_WIDTH)
}

fn format_expr(e: &crate::types::Expr) -> String {
    format_expr_at(e, 0)
}

/// Format a PosExpr for display in traces.
fn format_pos_expr(pe: &PosExpr) -> String {
    let pp = match pe {
        PosExpr::One(e) => expr_to_pp(e),
        PosExpr::Optional(e) => PP::List(vec![PP::Atom("?".into()), expr_to_pp(e)]),
        PosExpr::OneOrMore(e) => PP::List(vec![PP::Atom("+".into()), expr_to_pp(e)]),
        PosExpr::ZeroOrMore(e) => PP::List(vec![PP::Atom("*".into()), expr_to_pp(e)]),
    };
    pp.pretty(0, PP_WIDTH)
}

/// Result of a traced match: did it match, and what was evaluated.
pub(super) struct MatchTrace {
    pub matched: bool,
    pub steps: Vec<String>,
}

/// Format a resolved arg for display in traces.
fn format_resolved_arg(arg: &ResolvedArg) -> String {
    match arg {
        ResolvedArg::Literal(s) => format!("\"{s}\""),
        ResolvedArg::Opaque => "<opaque>".into(),
    }
}

/// Build a trace step from a potentially multi-line pretty-printed body.
/// The prefix is prepended to the first line; continuation lines use the
/// pretty-printer's own indentation. The suffix is appended to the last line.
/// Multi-line results are joined with "\n" and stored as a single step.
fn push_multiline(steps: &mut Vec<String>, prefix: &str, body: &str, suffix: &str) {
    let lines: Vec<&str> = body.lines().collect();
    let mut result = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let pfx = if i == 0 { prefix } else { "" };
        let sfx = if i == lines.len() - 1 { suffix } else { "" };
        result.push(format!("{pfx}{line}{sfx}"));
    }
    steps.push(result.join("\n"));
}

/// Trace matching an Expr against a resolved arg.
/// For Cond exprs, expands branches into nested trace lines.
fn trace_expr_vs_arg(
    e: &crate::types::Expr,
    arg: &ResolvedArg,
    steps: &mut Vec<String>,
) -> bool {
    use crate::types::Expr;
    let arg_str = format_resolved_arg(arg);

    match e {
        Expr::Cond(branches) => {
            steps.push(format!("cond vs {arg_str}"));
            for b in branches {
                // "  " prefix = 2 columns indent
                let test_label = format_expr_at(&b.test, 2);
                let matched = match arg {
                    ResolvedArg::Literal(s) => b.test.is_match(s),
                    ResolvedArg::Opaque => b.test.is_wildcard(),
                };
                if matched {
                    push_multiline(steps, "  ", &test_label, &format!(" => yes [{}]", b.effect.decision));
                    return true;
                }
                push_multiline(steps, "  ", &test_label, " => no");
            }
            false
        }
        _ => {
            let label = format_expr(e);
            let matched = match arg {
                ResolvedArg::Literal(s) => e.is_wildcard() || e.is_match(s),
                ResolvedArg::Opaque => e.is_wildcard(),
            };
            let judgement = if matched { "yes" } else { "no" };
            push_multiline(steps, "", &label, &format!(" vs {arg_str} => {judgement}"));
            matched
        }
    }
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
                let label = format_expr(token);
                let judgement = if found { "yes" } else { "no" };
                push_multiline(&mut steps, "(anywhere ", &label, &format!(") => {judgement}"));
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
            steps.push("cond".into());
            for b in branches {
                match &b.matcher {
                    None => {
                        steps.push(format!("  else => yes [{}]", b.effect.decision));
                        any_matched = true;
                        break;
                    }
                    Some(m) => {
                        let sub = matcher_matches_traced(m, args);
                        let matched = sub.matched;
                        for step in &sub.steps {
                            steps.push(format!("  {step}"));
                        }
                        if matched {
                            steps.push(format!("  => yes [{}]", b.effect.decision));
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
        match pexpr {
            PosExpr::One(e) => {
                match positional.get(pos) {
                    Some(arg) => {
                        let matched = trace_expr_vs_arg(e, arg, &mut steps);
                        if !matched {
                            return MatchTrace { matched: false, steps };
                        }
                    }
                    None => {
                        let label = format_pos_expr(pexpr);
                        steps.push(format!("{label} vs <missing> => no"));
                        return MatchTrace { matched: false, steps };
                    }
                }
                pos += 1;
            }
            PosExpr::Optional(e) => {
                if let Some(arg) = positional.get(pos) {
                    let before = steps.len();
                    let matched = trace_expr_vs_arg(e, arg, &mut steps);
                    if matched {
                        pos += 1;
                    } else {
                        // Rewrite the last judgement: for Optional, a non-match
                        // just means skip, not failure. Wrap the label.
                        if let Some(last) = steps.last_mut() {
                            *last = format!("(? …) {last}");
                        }
                        // If trace_expr_vs_arg produced a cond group, prefix header
                        if steps.len() - before > 1 {
                            steps[before] = format!("(? …) {}", steps[before]);
                        }
                    }
                } else {
                    let label = format_pos_expr(pexpr);
                    steps.push(format!("{label} => no (no more args)"));
                }
            }
            PosExpr::OneOrMore(e) | PosExpr::ZeroOrMore(e) => {
                let label = format_pos_expr(pexpr);
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
