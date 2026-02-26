mod ast;
mod glob;
mod lexer;
mod parse;
pub(crate) mod resolve;
mod segment;

pub use resolve::resolve_param_op;

#[cfg(test)]
mod tests;

pub use ast::*;
pub use segment::{Segment, segment};
use parse::Parser;

/// Parse a shell command string into an AST.
/// Returns a partial AST on malformed input (never panics).
pub fn parse(input: &str) -> Command {
    let mut parser = Parser::new(input);
    parser.parse_complete()
}

// ── Test-only helpers ────────────────────────────────────────────────

#[cfg(test)]
pub(crate) fn extract_simple_commands(cmd: &Command) -> Vec<&SimpleCommand> {
    let mut result = Vec::new();
    collect_simple_commands(cmd, &mut result);
    result
}

#[cfg(test)]
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
