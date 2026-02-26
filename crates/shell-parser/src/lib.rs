mod ast;
mod glob;
mod lexer;
mod parse;
pub(crate) mod resolve;

pub use resolve::resolve_param_op;

#[cfg(test)]
mod tests;

pub use ast::*;
use parse::Parser;

/// Parse a shell command string into an AST.
/// Returns a partial AST on malformed input (never panics).
pub fn parse(input: &str) -> Command {
    let mut parser = Parser::new(input);
    parser.parse_complete()
}

/// Extract all simple commands from a compound command AST.
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

/// Extract all words from all positions in the AST (for security scanning).
/// Includes arguments, redirect targets, for-loop words, assignment values, etc.
pub fn extract_all_words(cmd: &Command) -> Vec<&Word> {
    let mut result = Vec::new();
    collect_all_words(cmd, &mut result);
    result
}

fn collect_all_words<'a>(cmd: &'a Command, out: &mut Vec<&'a Word>) {
    // Collect words from the current node's variant-specific data
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
    // Recurse into child commands
    for child in cmd.children() {
        collect_all_words(child, out);
    }
}

/// A segment of a shell command for display purposes.
#[derive(Debug, Clone)]
pub struct Segment {
    /// Byte range in the original input.
    pub start: usize,
    pub end: usize,
    /// True if this segment is an operator (|, &&, ||, ;, &), false if a command.
    pub is_operator: bool,
}

/// Split a shell command into segments at top-level operators.
/// Returns alternating command and operator segments with their byte ranges.
pub fn segment(input: &str) -> Vec<Segment> {
    use lexer::{Lexer, Token};

    let mut lex = Lexer::new(input);
    let tokens = lex.tokenize_with_offsets();

    let mut segments = Vec::new();
    let mut depth: i32 = 0;
    let mut cmd_start: Option<usize> = None;

    for (tok, byte_off) in &tokens {
        match tok {
            Token::Eof => {
                // Flush any pending command segment
                if let Some(start) = cmd_start {
                    let end = input[start..].trim_end().len() + start;
                    if end > start {
                        segments.push(Segment { start, end, is_operator: false });
                    }
                }
            }
            // Depth-increasing tokens
            Token::LParen | Token::If | Token::For | Token::While | Token::Until
            | Token::Case | Token::Do | Token::LBrace => {
                depth += 1;
                if cmd_start.is_none() {
                    cmd_start = Some(*byte_off);
                }
            }
            // Depth-decreasing tokens
            Token::RParen | Token::Fi | Token::Done | Token::Esac | Token::RBrace => {
                depth -= 1;
                if cmd_start.is_none() {
                    cmd_start = Some(*byte_off);
                }
            }
            // Top-level operators split segments
            Token::Pipe | Token::And | Token::Or | Token::Semi | Token::Amp
                if depth <= 0 =>
            {
                // Flush the command segment before this operator
                if let Some(start) = cmd_start.take() {
                    let end = trim_end_offset(input, start, *byte_off);
                    if end > start {
                        segments.push(Segment { start, end, is_operator: false });
                    }
                }
                // Add the operator segment
                let op_len = match tok {
                    Token::And | Token::Or => 2,
                    _ => 1,
                };
                segments.push(Segment { start: *byte_off, end: byte_off + op_len, is_operator: true });
            }
            // Newlines are treated like semicolons at depth 0
            Token::Newline if depth <= 0 => {
                if let Some(start) = cmd_start.take() {
                    let end = trim_end_offset(input, start, *byte_off);
                    if end > start {
                        segments.push(Segment { start, end, is_operator: false });
                    }
                }
            }
            // Everything else is part of a command
            _ => {
                if cmd_start.is_none() {
                    cmd_start = Some(*byte_off);
                }
            }
        }
    }

    segments
}

/// Find the end of a command segment by trimming trailing whitespace.
fn trim_end_offset(input: &str, start: usize, operator_start: usize) -> usize {
    let between = &input[start..operator_start];
    start + between.trim_end().len()
}

pub fn find_structural_dynamic_parts(
    cmd: &Command,
    env: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    let mut out = Vec::new();
    collect_structural_dynamic_parts(cmd, env, &mut out);
    out
}

fn collect_structural_dynamic_parts(
    cmd: &Command,
    env: &std::collections::HashMap<String, String>,
    out: &mut Vec<String>,
) {
    // Collect dynamic parts from structural positions (for-loop words, case discriminants/patterns)
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
    // Recurse into child commands
    for child in cmd.children() {
        collect_structural_dynamic_parts(child, env, out);
    }
}
