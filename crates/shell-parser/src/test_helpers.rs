//! Shared test utilities for shell-parser tests.

use crate::ast::{Command, RedirectionTarget, SimpleCommand, Word};
use crate::parse::Parser;

/// Parse a shell command string into an AST.
/// Panics on parse errors - use only in tests where input is known to be valid.
pub fn parse_cmd(input: &str) -> Command {
    let mut parser = Parser::new(input);
    parser.parse_complete()
}

/// Extract all words from a command, including from assignments, redirections, etc.
pub fn extract_all_words(cmd: &Command) -> Vec<&Word> {
    let mut result = Vec::new();
    collect_all_words(cmd, &mut result);
    result
}

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

/// Assert that a command contains the expected words (as string representations).
/// Checks that all expected words are present among all words in the command.
pub fn assert_words(cmd: &Command, expected: &[&str]) {
    let words = extract_all_words(cmd);
    let word_strings: Vec<String> = words
        .iter()
        .map(|w| {
            w.parts
                .iter()
                .map(|p| format!("{:?}", p))
                .collect::<Vec<_>>()
                .join("")
        })
        .collect();

    for exp in expected {
        let found = word_strings.iter().any(|w| w.contains(exp));
        assert!(
            found,
            "Expected word '{}' not found in command words: {:?}",
            exp, word_strings
        );
    }
}

/// Assert that a command has no dynamic parts (parameter expansions, command substitutions, etc.).
pub fn assert_no_dynamic(cmd: &Command) {
    use crate::ast::WordPart;

    let words = extract_all_words(cmd);
    for word in words {
        for part in &word.parts {
            let is_dynamic = matches!(
                part,
                WordPart::Parameter(_)
                    | WordPart::ParameterExpansion(_)
                    | WordPart::ParameterExpansionOp { .. }
                    | WordPart::CommandSubstitution(_)
                    | WordPart::Backtick(_)
                    | WordPart::Arithmetic(_)
                    | WordPart::ProcessSubstitution { .. }
            );
            assert!(
                !is_dynamic,
                "Expected no dynamic parts, but found {:?} in word {:?}",
                part, word
            );
        }
    }
}

/// Extract simple commands from a command tree.
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

/// Get the command name from a simple command, if present.
pub fn get_command_name(cmd: &Command) -> Option<&str> {
    match cmd {
        Command::Simple(sc) => sc.command_name(),
        _ => None,
    }
}

/// Assert that a parsed command is a simple command with the given name.
pub fn assert_simple_command<'a>(cmd: &'a Command, expected_name: &str) -> &'a SimpleCommand {
    match cmd {
        Command::Simple(sc) => {
            assert_eq!(
                sc.command_name(),
                Some(expected_name),
                "Expected command name '{}', got {:?}",
                expected_name,
                sc.command_name()
            );
            sc
        }
        _ => panic!("Expected simple command, got {:?}", cmd),
    }
}
