use may_i_shell_parser::{ParseDiagnostic, ParseDiagnosticKind, Severity};
use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

/// miette-compatible diagnostic for shell parse issues.
#[derive(Debug, Error, Diagnostic)]
#[error("{message}")]
pub struct ShellParseError {
    message: String,
    #[source_code]
    src: NamedSource<String>,
    #[label]
    span: SourceSpan,
    #[help]
    help: Option<String>,
}

impl ShellParseError {
    pub fn from_diagnostic(diag: &ParseDiagnostic, source: &str) -> Self {
        let start = diag.span.start;
        let len = diag.span.end.saturating_sub(diag.span.start).max(1);
        Self {
            message: diag.message(),
            src: NamedSource::new("command", source.to_string()),
            span: SourceSpan::new(start.into(), len),
            help: Some(help_text(&diag.kind, diag.severity)),
        }
    }
}

fn help_text(kind: &ParseDiagnosticKind, severity: Severity) -> String {
    let base = match kind {
        ParseDiagnosticKind::UnterminatedDoubleQuote => {
            "the parser treated EOF as the closing quote, but this may hide operators"
        }
        ParseDiagnosticKind::UnterminatedSingleQuote => {
            "the parser treated EOF as the closing quote, but this may hide operators"
        }
        ParseDiagnosticKind::UnterminatedBacktick => {
            "the parser treated EOF as the closing backtick, but this may hide operators"
        }
        ParseDiagnosticKind::UnterminatedCommandSubstitution => {
            "the parser treated EOF as the closing ), but this may hide operators"
        }
        ParseDiagnosticKind::UnterminatedArithmetic => {
            "the parser treated EOF as the closing )), but this may change the parse boundary"
        }
        ParseDiagnosticKind::UnterminatedParameterExpansion => {
            "the parser treated EOF as the closing }, but this may hide operators"
        }
        ParseDiagnosticKind::MissingClosingKeyword { expected } => {
            return format!(
                "the parser continued without `{expected}`, which is likely fine for incomplete input"
            );
        }
        ParseDiagnosticKind::EmptyCommand => "an empty command was parsed at this position",
        ParseDiagnosticKind::UnexpectedToken => {
            "the parser could not place this token in any command, so it was left unevaluated"
        }
    };
    match severity {
        Severity::Error => format!("{base} — the command boundary may be ambiguous"),
        Severity::Warning => base.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_shell_parser::Span;

    #[test]
    fn from_diagnostic_produces_valid_error() {
        let diag = ParseDiagnostic {
            span: Span { start: 5, end: 11 },
            kind: ParseDiagnosticKind::UnterminatedDoubleQuote,
            severity: Severity::Error,
        };
        let err = ShellParseError::from_diagnostic(&diag, "echo \"hello");
        assert!(err.message.contains("unterminated double quote"));
        assert!(err.help.is_some());
        assert!(err.help.as_ref().unwrap().contains("ambiguous"));
    }

    #[test]
    fn warning_help_text_no_ambiguous() {
        let diag = ParseDiagnostic {
            span: Span { start: 0, end: 24 },
            kind: ParseDiagnosticKind::MissingClosingKeyword { expected: "fi" },
            severity: Severity::Warning,
        };
        let err = ShellParseError::from_diagnostic(&diag, "if true; then echo hello");
        assert!(err.help.as_ref().unwrap().contains("fi"));
    }

    #[test]
    fn miette_rendering() {
        let diag = ParseDiagnostic {
            span: Span { start: 5, end: 11 },
            kind: ParseDiagnosticKind::UnterminatedDoubleQuote,
            severity: Severity::Error,
        };
        let err = ShellParseError::from_diagnostic(&diag, "echo \"hello");
        let rendered = format!("{:?}", miette::Report::new(err));
        assert!(rendered.contains("unterminated double quote"));
    }
}
