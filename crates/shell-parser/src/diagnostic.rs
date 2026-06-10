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
    MissingClosingKeyword {
        expected: &'static str,
    },
    EmptyCommand,
    /// A token the grammar could not place (e.g. a reserved word outside any
    /// construct, or an unbalanced delimiter). Emitted instead of silently
    /// dropping the token so the decision floors to ask.
    UnexpectedToken,
}

/// A diagnostic emitted during parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParseDiagnostic {
    pub span: Span,
    pub kind: ParseDiagnosticKind,
    pub severity: Severity,
}

/// Max chars in the excerpt window on either side of `span.start`.
const EXCERPT_BEFORE: usize = 20;
const EXCERPT_AFTER: usize = 30;

impl ParseDiagnostic {
    /// Single-line, source-aware reason of the form
    /// `"<kind message> at line L, column C: '<excerpt>'"`.
    ///
    /// L, C are 1-based, counted by Unicode scalar values from
    /// `span.start` against `src`. The excerpt is a short window
    /// around `span.start` with control characters escaped and
    /// truncated content ellipsised. Designed for the hook
    /// `permissionDecisionReason` and `may-i eval` headline reason
    /// — not the miette renderer.
    pub fn format_with_source(&self, src: &str) -> String {
        // Clamp + snap span.start to a valid char boundary. Spans
        // produced by the parser are already on boundaries; the
        // snap guards against callers passing synthesised spans.
        let raw_start = self.span.start.min(src.len());
        let start = (0..=raw_start)
            .rev()
            .find(|&i| src.is_char_boundary(i))
            .unwrap_or(0);

        let preceding = &src[..start];
        let line = 1 + preceding.matches('\n').count();
        let col = 1 + preceding
            .rsplit('\n')
            .next()
            .map(|s| s.chars().count())
            .unwrap_or(0);

        let before_chars: Vec<char> = preceding.chars().collect();
        let before_truncated = before_chars.len() > EXCERPT_BEFORE;
        let before_tail: Vec<char> = before_chars
            .iter()
            .rev()
            .take(EXCERPT_BEFORE)
            .rev()
            .copied()
            .collect();

        let mut after_iter = src[start..].chars();
        let after_head: Vec<char> = after_iter.by_ref().take(EXCERPT_AFTER).collect();
        let after_truncated = after_iter.next().is_some();

        let mut excerpt = String::new();
        if before_truncated {
            excerpt.push('…');
        }
        for c in before_tail.iter().chain(after_head.iter()) {
            push_escaped(&mut excerpt, *c);
        }
        if after_truncated {
            excerpt.push('…');
        }

        format!(
            "{} at line {line}, column {col}: '{excerpt}'",
            self.message()
        )
    }

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
            ParseDiagnosticKind::UnexpectedToken => "unexpected token".to_string(),
        }
    }
}

fn push_escaped(buf: &mut String, c: char) {
    match c {
        '\n' => buf.push_str("\\n"),
        '\t' => buf.push_str("\\t"),
        '\r' => buf.push_str("\\r"),
        '\0' => buf.push_str("\\0"),
        c if c.is_control() => {
            use std::fmt::Write;
            let _ = write!(buf, "\\u{{{:x}}}", c as u32);
        }
        c => buf.push(c),
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
    fn format_with_source_basic_shape() {
        let src = "echo a\necho b\necho 'oops\n";
        let start = src.find('\'').unwrap();
        let diag = ParseDiagnostic {
            span: Span {
                start,
                end: start + 1,
            },
            kind: ParseDiagnosticKind::UnterminatedSingleQuote,
            severity: Severity::Error,
        };
        let formatted = diag.format_with_source(src);
        assert!(
            formatted.starts_with("unterminated single quote at line 3, column 6: '"),
            "got: {formatted}"
        );
        assert!(formatted.ends_with('\''), "got: {formatted}");
        assert!(!formatted.contains('\n'), "got: {formatted}");
        // Control characters in the excerpt window must be escaped.
        assert!(formatted.contains("\\n"), "got: {formatted}");
    }

    #[test]
    fn format_with_source_multibyte_safe() {
        // `│` is U+2502 (3 bytes UTF-8). The excerpt window must include
        // it without panicking and the result must be valid UTF-8.
        let src = "cat │ grep 'unterm";
        let start = src.find('\'').unwrap();
        let diag = ParseDiagnostic {
            span: Span {
                start,
                end: start + 1,
            },
            kind: ParseDiagnosticKind::UnterminatedSingleQuote,
            severity: Severity::Error,
        };
        let formatted = diag.format_with_source(src);
        assert!(
            formatted.contains('│'),
            "expected multibyte char preserved, got: {formatted}"
        );
    }

    #[test]
    fn format_with_source_truncates_with_ellipsis() {
        // Long preceding source → ellipsis on the left; long trailing
        // source → ellipsis on the right.
        let src = format!("{}'{}", "a".repeat(50), "b".repeat(50));
        let start = 50;
        let diag = ParseDiagnostic {
            span: Span {
                start,
                end: start + 1,
            },
            kind: ParseDiagnosticKind::UnterminatedSingleQuote,
            severity: Severity::Error,
        };
        let formatted = diag.format_with_source(&src);
        assert!(formatted.contains('…'), "got: {formatted}");
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 256,
            max_shrink_iters: 64,
            ..proptest::test_runner::Config::default()
        })]

        #[test]
        fn prop_format_with_source_shape(
            src in "\\PC{0,200}",
            boundary_seed in proptest::prelude::any::<usize>(),
        ) {
            use proptest::prelude::*;
            let target = if src.is_empty() { 0 } else { boundary_seed % (src.len() + 1) };
            // Snap to a valid char boundary at or below `target`.
            let start = (0..=target).rev().find(|&i| src.is_char_boundary(i)).unwrap_or(0);
            let diag = ParseDiagnostic {
                span: Span { start, end: start },
                kind: ParseDiagnosticKind::UnterminatedSingleQuote,
                severity: Severity::Error,
            };
            let s = diag.format_with_source(&src);
            prop_assert!(!s.contains('\n'), "embedded newline in: {s}");
            prop_assert!(s.contains(&diag.message()), "missing kind message in: {s}");
            let preceding = &src[..start];
            let line = 1 + preceding.matches('\n').count();
            let col = 1 + preceding
                .rsplit('\n')
                .next()
                .map(|s| s.chars().count())
                .unwrap_or(0);
            let needle = format!("at line {line}, column {col}:");
            prop_assert!(s.contains(&needle), "expected `{needle}` in: {s}");
        }
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
