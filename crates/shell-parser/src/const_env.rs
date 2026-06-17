use crate::ast::{Command, SimpleCommand, Word, WordPart};
use std::collections::HashMap;

/// Build the set of variables whose value is *provably constant* for the whole
/// command. A variable qualifies only when it has exactly one straight-line,
/// static-literal assignment that executes unconditionally before any use, and
/// is never reassigned or `unset`.
///
/// The analysis is a structural walk, not a path enumeration: an assignment
/// inside a conditional, loop, function body, subshell, or pipeline stage is
/// treated as "not provable" and disqualifies the variable. Anything uncertain
/// (a substitution RHS, an unresolved variable, a glob, a loop variable, a
/// prefix assignment, a reassignment) keeps the variable out of the result, so
/// callers fall back to treating its uses as dynamic.
pub fn constant_env(cmd: &Command) -> HashMap<String, String> {
    let mut occ: HashMap<String, Occurrence> = HashMap::new();
    collect(cmd, false, &mut occ);
    occ.into_iter()
        .filter_map(|(name, o)| match o {
            Occurrence::Constant(value) => Some((name, value)),
            Occurrence::Disqualified => None,
        })
        .collect()
}

/// What we have learned about a variable so far. The first qualifying
/// assignment makes it `Constant`; any second occurrence of any kind, or any
/// disqualifying occurrence, makes it `Disqualified` for good.
enum Occurrence {
    Constant(String),
    Disqualified,
}

/// Record a binding whose RHS is a proven static literal at straight-line
/// top level. A second binding of the same name flips it to disqualified.
fn record_constant(occ: &mut HashMap<String, Occurrence>, name: &str, value: String) {
    occ.entry(name.to_string())
        .and_modify(|e| *e = Occurrence::Disqualified)
        .or_insert(Occurrence::Constant(value));
}

/// Record an occurrence that can never qualify (nested, prefix, non-literal,
/// reassignment, loop variable, or `unset`). It permanently disqualifies the
/// name, including over a previously-recorded constant.
fn record_disqualified(occ: &mut HashMap<String, Occurrence>, name: &str) {
    occ.insert(name.to_string(), Occurrence::Disqualified);
}

fn collect(cmd: &Command, nested: bool, occ: &mut HashMap<String, Occurrence>) {
    match cmd {
        Command::Assignment(a) => record_assignment(&a.name, &a.value, nested, occ),
        Command::Simple(sc) => collect_simple(sc, nested, occ),
        Command::For { var, body, .. } => {
            // The loop variable is rebound on each iteration — never constant.
            record_disqualified(occ, var);
            collect(body, true, occ);
        }
        // Straight-line composition keeps the current nesting level.
        Command::Sequence(cmds) => {
            for c in cmds {
                collect(c, nested, occ);
            }
        }
        Command::Redirected { command, .. } => collect(command, nested, occ),
        // Everything else (pipelines, subshells, brace groups, conditionals,
        // loops, function bodies, `&&`/`||`, background) is conditional or
        // runs in a subshell: assignments within may not execute, may execute
        // out of order, or may not persist. Treat their contents as nested.
        other => {
            for child in other.children() {
                collect(child, true, occ);
            }
        }
    }
}

fn collect_simple(sc: &SimpleCommand, nested: bool, occ: &mut HashMap<String, Occurrence>) {
    // A prefix assignment (`VAR=lit cmd`) binds only the invoked command's
    // environment and does not persist, so it can never be the constant
    // binding for a later use. Recording it as an occurrence also disqualifies
    // a name that is otherwise assigned at top level (ambiguous).
    for a in &sc.assignments {
        record_disqualified(occ, &a.name);
    }

    match sc.command_name() {
        Some("export") => {
            for word in sc.words.iter().skip(1) {
                if let Some((name, value)) = parse_assignment_word(word) {
                    record_assignment(&name, &value, nested, occ);
                }
                // A bare `export FOO` re-exports an existing value without
                // rebinding it, so it is left alone.
            }
        }
        Some("unset") => {
            for word in sc.words.iter().skip(1) {
                if let Some(name) = literal_name(word) {
                    record_disqualified(occ, &name);
                }
            }
        }
        _ => {}
    }
}

fn record_assignment(
    name: &str,
    value: &Word,
    nested: bool,
    occ: &mut HashMap<String, Occurrence>,
) {
    match literal_value(value) {
        Some(v) if !nested => record_constant(occ, name, v),
        _ => record_disqualified(occ, name),
    }
}

/// The value of an assignment RHS when it is provably a non-empty static
/// literal. Resolving against an empty env routes parameter expansions through
/// `resolve_param_op`; with nothing to resolve, any expansion, substitution,
/// glob, or opaque part keeps the word non-literal and yields `None`.
fn literal_value(value: &Word) -> Option<String> {
    let resolved = value.resolve(&HashMap::new());
    if !resolved.is_literal() {
        return None;
    }
    let v = resolved.to_str();
    (!v.is_empty()).then_some(v)
}

/// Split a single `NAME=VALUE` word (as it appears in `export NAME=VALUE`)
/// into the name and a value word. Returns `None` for a bare `NAME` (no `=`)
/// or an invalid name. The value word preserves any dynamic trailing parts so
/// `export X=$(cmd)` resolves to a non-literal value and is disqualified.
fn parse_assignment_word(word: &Word) -> Option<(String, Word)> {
    let WordPart::Literal(lit) = word.parts.first()? else {
        return None;
    };
    let eq = lit.find('=')?;
    let name = &lit[..eq];
    if !is_valid_name(name) {
        return None;
    }
    let mut value_parts = Vec::new();
    let rest = &lit[eq + 1..];
    if !rest.is_empty() {
        value_parts.push(WordPart::Literal(rest.to_string()));
    }
    value_parts.extend(word.parts.iter().skip(1).cloned());
    Some((name.to_string(), Word { parts: value_parts }))
}

/// The plain variable name of a `unset NAME` argument, when it is a static
/// literal naming a valid identifier.
fn literal_name(word: &Word) -> Option<String> {
    if !word.is_literal() {
        return None;
    }
    let name = word.to_str();
    is_valid_name(&name).then_some(name)
}

fn is_valid_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}
