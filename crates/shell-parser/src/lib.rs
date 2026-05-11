mod ast;
mod diagnostic;
#[cfg(test)]
mod glob;
mod lexer;
mod parse;
#[cfg(test)]
pub(crate) mod resolve;
mod segment;

#[cfg(test)]
mod tests;

pub use ast::*;
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
            out.extend(sc.assignments.iter().map(|a| &a.value));
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
            out.push(&a.value);
        }
        _ => {}
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
        _ => {}
    }
    for child in cmd.children() {
        collect_structural_dynamic_parts(child, env, out);
    }
}
