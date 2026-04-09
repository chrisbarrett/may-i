// Error types for config parsing diagnostics.

use may_i_core::Span;
use may_i_sexpr::RawError;
use miette::{Diagnostic, LabeledSpan, NamedSource, SourceSpan};
use thiserror::Error;

/// User-facing diagnostic error with source context.
#[derive(Debug, Error, Diagnostic)]
#[error("{message}")]
pub struct ConfigError {
    message: String,
    #[source_code]
    src: NamedSource<String>,
    #[label(collection)]
    labels: Vec<LabeledSpan>,
    #[help]
    help: Option<String>,
}

fn span_to_source_span(s: Span) -> SourceSpan {
    SourceSpan::new(s.start.into(), s.end - s.start)
}

impl ConfigError {
    /// Build from a `RawError` plus the original source text and filename.
    pub fn from_raw(raw: RawError, source: &str, filename: &str) -> Self {
        let primary_label = raw.label.unwrap_or_else(|| "here".to_string());
        let mut labels = vec![LabeledSpan::at(
            span_to_source_span(raw.span),
            primary_label,
        )];
        if let Some(secondary) = raw.secondary {
            let (span, label) = *secondary;
            labels.push(LabeledSpan::at(span_to_source_span(span), label));
        }
        Self {
            message: raw.message,
            src: NamedSource::new(filename, source.to_string()),
            labels,
            help: raw.help,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_from_raw_with_primary_label() {
        let raw = RawError::new("test error", Span::new(5, 10)).with_label("primary label");
        let err = ConfigError::from_raw(raw, "source code here", "test.lisp");
        assert!(err.message.contains("test error"));
        assert_eq!(err.labels.len(), 1);
    }

    #[test]
    fn config_error_from_raw_with_default_label() {
        let raw = RawError::new("test error", Span::new(5, 10));
        let err = ConfigError::from_raw(raw, "source code here", "test.lisp");
        assert!(err.message.contains("test error"));
        assert_eq!(err.labels.len(), 1);
    }

    #[test]
    fn config_error_from_raw_with_secondary_label() {
        let raw = RawError::new("test error", Span::new(5, 10))
            .with_label("primary")
            .with_secondary(Span::new(15, 20), "secondary label");
        let err = ConfigError::from_raw(raw, "source code here", "test.lisp");
        assert_eq!(err.labels.len(), 2);
    }

    #[test]
    fn config_error_from_raw_with_help() {
        let raw = RawError::new("test error", Span::new(5, 10))
            .with_label("primary")
            .with_help("try this instead");
        let err = ConfigError::from_raw(raw, "source code here", "test.lisp");
        assert!(err.help.is_some());
        assert!(err.help.unwrap().contains("try this"));
    }

    #[test]
    fn config_error_display_includes_message() {
        let raw = RawError::new("test error message", Span::new(0, 5));
        let err = ConfigError::from_raw(raw, "source", "test.lisp");
        let display = format!("{}", err);
        assert!(display.contains("test error message"));
    }
}
