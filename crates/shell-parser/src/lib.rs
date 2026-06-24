mod ast;
mod const_env;
mod diagnostic;
mod glob;
mod lexer;
mod parse;
pub(crate) mod resolve;
mod segment;

// Tests assert a value is one variant and `panic!` on anything else; a
// catch-all arm is the point, not an oversight, so the exhaustive-match lint
// does not apply here.
#[cfg(test)]
#[allow(clippy::wildcard_enum_match_arm)]
mod tests;

pub use ast::*;
pub use const_env::{ConstLookup, ConstValue, constant_env, enumerable_for_values};
pub use diagnostic::*;
use parse::Parser;
pub use segment::{Segment, segment};

/// Parse a shell command string into an AST with diagnostics.
/// Returns a partial AST on malformed input (never panics).
pub fn parse(input: &str) -> ParseResult {
    let mut parser = Parser::new(input);
    let command = parser.parse_complete();
    ParseResult {
        command,
        diagnostics: parser.diagnostics,
    }
}

/// Parse a shell string and extract the command name and arguments from a
/// simple command. Returns `None` for empty, assignment-only, or compound
/// commands.
pub fn parse_simple_command(input: &str) -> Option<(String, Vec<String>)> {
    // The first arm guards `Command::Simple` on a non-empty word list; the
    // catch-all must still cover `Simple` with empty words, so enumerating
    // variants alone cannot reproduce the behaviour.
    #[allow(clippy::wildcard_enum_match_arm)]
    match parse(input).command {
        Command::Simple(sc) if !sc.words.is_empty() => {
            let cmd = sc.words[0].to_str();
            let args: Vec<String> = sc.words[1..].iter().map(|w| w.to_str()).collect();
            Some((cmd, args))
        }
        _ => None,
    }
}

/// Run the lexer's `$()` body matcher starting just after a `$(` opener at
/// the given byte offset. Returns the byte offset of the matched closing
/// `)`, or `None` if EOF was reached without one.
///
/// Exposed for cross-crate property tests that compare this matcher to the
/// engine's `find_balanced_paren`. Not part of the stable API.
#[doc(hidden)]
pub fn debug_lexer_paren_close(input: &str, body_start: usize) -> Option<usize> {
    let mut lex = lexer::Lexer::new(input);
    while lex.byte_pos < body_start {
        lex.advance()?;
    }
    if lex.byte_pos != body_start {
        return None;
    }
    let (_body, found) = lex.debug_read_balanced_parens();
    if found { Some(lex.byte_pos - 1) } else { None }
}

/// Extract all simple commands from an AST by recursing through `children()`.
pub fn extract_simple_commands(cmd: &Command) -> Vec<&SimpleCommand> {
    let mut result = Vec::new();
    collect_simple_commands(cmd, &mut result);
    result
}

fn collect_simple_commands<'a>(cmd: &'a Command, out: &mut Vec<&'a SimpleCommand>) {
    if let Command::Simple(sc) = cmd {
        out.push(sc);
    }
    for child in cmd.children() {
        collect_simple_commands(child, out);
    }
}

/// Collect the names of every function the command defines, anywhere in the
/// tree — both `name() { … }` and `function name { … }` forms, including
/// definitions nested inside another function's body. A sibling of
/// [`extract_simple_commands`]; used to recognise calls to script-local
/// functions as internal rather than as unknown external programs.
pub fn defined_function_names(cmd: &Command) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    collect_function_names(cmd, &mut names);
    names
}

fn collect_function_names(cmd: &Command, out: &mut std::collections::HashSet<String>) {
    if let Command::FunctionDef { name, .. } = cmd {
        // A malformed `function () { … }` parses with an empty name. An empty
        // name must never enter the set: a quoted-empty first word (`"" arg`)
        // stringifies to `""` and would otherwise be misclassified as an
        // internal call. A real definition always has a non-empty name.
        if !name.is_empty() {
            out.insert(name.clone());
        }
    }
    for child in cmd.children() {
        collect_function_names(child, out);
    }
}

#[cfg(test)]
pub(crate) fn extract_all_words(cmd: &Command) -> Vec<&Word> {
    let mut result = Vec::new();
    collect_all_words(cmd, &mut result);
    result
}

#[cfg(test)]
fn collect_all_words<'a>(cmd: &'a Command, out: &mut Vec<&'a Word>) {
    match cmd {
        Command::Simple(sc) => {
            out.extend(&sc.words);
            out.extend(sc.assignments.iter().flat_map(|a| a.value.words()));
            for r in &sc.redirections {
                if let RedirectionTarget::File(w) = &r.target {
                    out.push(w);
                }
            }
        }
        Command::For { words, .. } => {
            out.extend(words);
        }
        Command::Case { word, arms, .. } => {
            out.push(word);
            for arm in arms {
                out.extend(&arm.patterns);
            }
        }
        Command::Redirected { redirections, .. } => {
            for r in redirections {
                if let RedirectionTarget::File(w) = &r.target {
                    out.push(w);
                }
            }
        }
        Command::Assignment(a) => {
            out.extend(a.value.words());
        }
        Command::Pipeline(_)
        | Command::And(_, _)
        | Command::Or(_, _)
        | Command::Sequence(_)
        | Command::Background(_)
        | Command::Subshell(_)
        | Command::BraceGroup(_)
        | Command::If { .. }
        | Command::Loop { .. }
        | Command::FunctionDef { .. } => {}
    }
    for child in cmd.children() {
        collect_all_words(child, out);
    }
}

#[cfg(test)]
pub(crate) fn find_structural_dynamic_parts(
    cmd: &Command,
    env: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    let mut out = Vec::new();
    collect_structural_dynamic_parts(cmd, env, &mut out);
    out
}

#[cfg(test)]
fn collect_structural_dynamic_parts(
    cmd: &Command,
    env: &std::collections::HashMap<String, String>,
    out: &mut Vec<String>,
) {
    match cmd {
        Command::For { words, .. } => {
            for w in words {
                out.extend(w.resolve(env).dynamic_parts());
            }
        }
        Command::Case { word, arms, .. } => {
            out.extend(word.resolve(env).dynamic_parts());
            for arm in arms {
                for p in &arm.patterns {
                    out.extend(p.resolve(env).dynamic_parts());
                }
            }
        }
        Command::Simple(_)
        | Command::Pipeline(_)
        | Command::And(_, _)
        | Command::Or(_, _)
        | Command::Sequence(_)
        | Command::Background(_)
        | Command::Subshell(_)
        | Command::BraceGroup(_)
        | Command::If { .. }
        | Command::Loop { .. }
        | Command::FunctionDef { .. }
        | Command::Redirected { .. }
        | Command::Assignment(_) => {}
    }
    for child in cmd.children() {
        collect_structural_dynamic_parts(child, env, out);
    }
}
