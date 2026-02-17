mod ast;
mod glob;
mod lexer;
mod parse;
mod resolve;

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
    match cmd {
        Command::Simple(sc) => out.push(sc),
        Command::Pipeline(cmds) | Command::Sequence(cmds) => {
            for c in cmds {
                collect_simple_commands(c, out);
            }
        }
        Command::And(a, b) | Command::Or(a, b) => {
            collect_simple_commands(a, out);
            collect_simple_commands(b, out);
        }
        Command::Background(c) | Command::Subshell(c) | Command::BraceGroup(c) => {
            collect_simple_commands(c, out);
        }
        Command::If { condition, then_branch, elif_branches, else_branch } => {
            collect_simple_commands(condition, out);
            collect_simple_commands(then_branch, out);
            for (cond, body) in elif_branches {
                collect_simple_commands(cond, out);
                collect_simple_commands(body, out);
            }
            if let Some(eb) = else_branch {
                collect_simple_commands(eb, out);
            }
        }
        Command::For { body, .. } | Command::While { body, .. } | Command::Until { body, .. } => {
            collect_simple_commands(body, out);
        }
        Command::Case { arms, .. } => {
            for arm in arms {
                if let Some(body) = &arm.body {
                    collect_simple_commands(body, out);
                }
            }
        }
        Command::FunctionDef { body, .. } => {
            collect_simple_commands(body, out);
        }
        Command::Redirected { command, .. } => {
            collect_simple_commands(command, out);
        }
        Command::Assignment(_) => {}
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
    match cmd {
        Command::Simple(sc) => {
            for w in &sc.words {
                out.push(w);
            }
            for a in &sc.assignments {
                out.push(&a.value);
            }
            for r in &sc.redirections {
                match &r.target {
                    RedirectionTarget::File(w) => out.push(w),
                    RedirectionTarget::Heredoc(_) => {
                        // Treat heredoc content as a synthetic word for scanning
                        // (handled separately since it's a String, not Word)
                    }
                    RedirectionTarget::Fd(_) => {}
                }
            }
        }
        Command::Pipeline(cmds) | Command::Sequence(cmds) => {
            for c in cmds {
                collect_all_words(c, out);
            }
        }
        Command::And(a, b) | Command::Or(a, b) => {
            collect_all_words(a, out);
            collect_all_words(b, out);
        }
        Command::Background(c) | Command::Subshell(c) | Command::BraceGroup(c) => {
            collect_all_words(c, out);
        }
        Command::If { condition, then_branch, elif_branches, else_branch } => {
            collect_all_words(condition, out);
            collect_all_words(then_branch, out);
            for (cond, body) in elif_branches {
                collect_all_words(cond, out);
                collect_all_words(body, out);
            }
            if let Some(eb) = else_branch {
                collect_all_words(eb, out);
            }
        }
        Command::For { words, body, .. } => {
            for w in words {
                out.push(w);
            }
            collect_all_words(body, out);
        }
        Command::While { condition, body } | Command::Until { condition, body } => {
            collect_all_words(condition, out);
            collect_all_words(body, out);
        }
        Command::Case { word, arms } => {
            out.push(word);
            for arm in arms {
                for p in &arm.patterns {
                    out.push(p);
                }
                if let Some(body) = &arm.body {
                    collect_all_words(body, out);
                }
            }
        }
        Command::FunctionDef { body, .. } => {
            collect_all_words(body, out);
        }
        Command::Redirected { command, redirections } => {
            collect_all_words(command, out);
            for r in redirections {
                match &r.target {
                    RedirectionTarget::File(w) => out.push(w),
                    RedirectionTarget::Heredoc(_) => {}
                    RedirectionTarget::Fd(_) => {}
                }
            }
        }
        Command::Assignment(a) => {
            out.push(&a.value);
        }
    }
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
    match cmd {
        Command::For { words, body, .. } => {
            for w in words {
                out.extend(w.resolve(env).dynamic_parts());
            }
            collect_structural_dynamic_parts(body, env, out);
        }
        Command::Case { word, arms } => {
            out.extend(word.resolve(env).dynamic_parts());
            for arm in arms {
                for p in &arm.patterns {
                    out.extend(p.resolve(env).dynamic_parts());
                }
                if let Some(body) = &arm.body {
                    collect_structural_dynamic_parts(body, env, out);
                }
            }
        }
        Command::Pipeline(cmds) | Command::Sequence(cmds) => {
            for c in cmds {
                collect_structural_dynamic_parts(c, env, out);
            }
        }
        Command::And(a, b) | Command::Or(a, b) => {
            collect_structural_dynamic_parts(a, env, out);
            collect_structural_dynamic_parts(b, env, out);
        }
        Command::Background(c) | Command::Subshell(c) | Command::BraceGroup(c) => {
            collect_structural_dynamic_parts(c, env, out);
        }
        Command::If { condition, then_branch, elif_branches, else_branch } => {
            collect_structural_dynamic_parts(condition, env, out);
            collect_structural_dynamic_parts(then_branch, env, out);
            for (cond, body) in elif_branches {
                collect_structural_dynamic_parts(cond, env, out);
                collect_structural_dynamic_parts(body, env, out);
            }
            if let Some(eb) = else_branch {
                collect_structural_dynamic_parts(eb, env, out);
            }
        }
        Command::While { condition, body } | Command::Until { condition, body } => {
            collect_structural_dynamic_parts(condition, env, out);
            collect_structural_dynamic_parts(body, env, out);
        }
        Command::FunctionDef { body, .. } => collect_structural_dynamic_parts(body, env, out),
        Command::Redirected { command, .. } => {
            collect_structural_dynamic_parts(command, env, out);
        }
        Command::Simple(_) | Command::Assignment(_) => {}
    }
}
