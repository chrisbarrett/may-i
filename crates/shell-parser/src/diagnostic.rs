use serde::Serialize;

use crate::ast::Command;

/// Byte-offset span within the original input string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// Severity of a parse diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Structurally incomplete but AST is likely correct (e.g. missing `fi`).
    Warning,
    /// Parse boundary is ambiguous — AST may not reflect intent (e.g. unterminated quote).
    Error,
}

/// What kind of issue was detected during parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseDiagnosticKind {
    UnterminatedDoubleQuote,
    UnterminatedSingleQuote,
    UnterminatedBacktick,
    UnterminatedCommandSubstitution,
    UnterminatedArithmetic,
    UnterminatedParameterExpansion,
    MissingClosingKeyword { expected: &'static str },
    EmptyCommand,
}

/// A diagnostic emitted during parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParseDiagnostic {
    pub span: Span,
    pub kind: ParseDiagnosticKind,
    pub severity: Severity,
}

impl ParseDiagnostic {
    pub fn message(&self) -> String {
        match &self.kind {
            ParseDiagnosticKind::UnterminatedDoubleQuote => "unterminated double quote".to_string(),
            ParseDiagnosticKind::UnterminatedSingleQuote => "unterminated single quote".to_string(),
            ParseDiagnosticKind::UnterminatedBacktick => "unterminated backtick".to_string(),
            ParseDiagnosticKind::UnterminatedCommandSubstitution => {
                "unterminated command substitution".to_string()
            }
            ParseDiagnosticKind::UnterminatedArithmetic => {
                "unterminated arithmetic expansion".to_string()
            }
            ParseDiagnosticKind::UnterminatedParameterExpansion => {
                "unterminated parameter expansion".to_string()
            }
            ParseDiagnosticKind::MissingClosingKeyword { expected } => {
                format!("missing closing keyword `{expected}`")
            }
            ParseDiagnosticKind::EmptyCommand => "empty command".to_string(),
        }
    }
}

/// Result of parsing a shell command string.
///
/// Always contains a best-effort AST. May also contain diagnostics
/// if the input was malformed.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseResult {
    pub command: Command,
    pub diagnostics: Vec<ParseDiagnostic>,
}

impl ParseResult {
    /// Discard diagnostics and return just the command AST.
    pub fn into_command(self) -> Command {
        self.command
    }

    /// Whether any diagnostic has Error severity.
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity == Severity::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Command, SimpleCommand};

    fn empty_command() -> Command {
        Command::Simple(SimpleCommand {
            assignments: vec![],
            words: vec![],
            redirections: vec![],
            span: Span { start: 0, end: 0 },
        })
    }

    #[test]
    fn into_command_discards_diagnostics() {
        let result = ParseResult {
            command: empty_command(),
            diagnostics: vec![ParseDiagnostic {
                span: Span { start: 0, end: 5 },
                kind: ParseDiagnosticKind::UnterminatedDoubleQuote,
                severity: Severity::Error,
            }],
        };
        let _cmd = result.into_command();
    }

    #[test]
    fn has_errors_with_error() {
        let result = ParseResult {
            command: empty_command(),
            diagnostics: vec![ParseDiagnostic {
                span: Span { start: 0, end: 5 },
                kind: ParseDiagnosticKind::UnterminatedDoubleQuote,
                severity: Severity::Error,
            }],
        };
        assert!(result.has_errors());
    }

    #[test]
    fn has_errors_with_warning_only() {
        let result = ParseResult {
            command: empty_command(),
            diagnostics: vec![ParseDiagnostic {
                span: Span { start: 0, end: 5 },
                kind: ParseDiagnosticKind::MissingClosingKeyword { expected: "fi" },
                severity: Severity::Warning,
            }],
        };
        assert!(!result.has_errors());
    }

    #[test]
    fn has_errors_empty_diagnostics() {
        let result = ParseResult {
            command: empty_command(),
            diagnostics: vec![],
        };
        assert!(!result.has_errors());
    }

    #[test]
    fn diagnostic_messages() {
        assert_eq!(
            ParseDiagnostic {
                span: Span { start: 0, end: 0 },
                kind: ParseDiagnosticKind::UnterminatedDoubleQuote,
                severity: Severity::Error,
            }
            .message(),
            "unterminated double quote"
        );
        assert_eq!(
            ParseDiagnostic {
                span: Span { start: 0, end: 0 },
                kind: ParseDiagnosticKind::MissingClosingKeyword { expected: "fi" },
                severity: Severity::Warning,
            }
            .message(),
            "missing closing keyword `fi`"
        );
        assert_eq!(
            ParseDiagnostic {
                span: Span { start: 0, end: 0 },
                kind: ParseDiagnosticKind::EmptyCommand,
                severity: Severity::Warning,
            }
            .message(),
            "empty command"
        );
    }
}
