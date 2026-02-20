// Error types for config parsing diagnostics.
// The miette Diagnostic derive generates code that triggers unused_assignments
// false positives on struct fields.
#![allow(unused_assignments)]

use miette::{Diagnostic, LabeledSpan, NamedSource, SourceSpan};
use thiserror::Error;

/// Byte-offset span within source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

impl From<Span> for SourceSpan {
    fn from(s: Span) -> Self {
        SourceSpan::new(s.start.into(), s.end - s.start)
    }
}

/// Internal error carrying a span but no source text.
/// Used inside the sexpr and config_parse modules; converted to `ConfigError`
/// at the API boundary where the source text and filename are known.
#[derive(Debug, Clone)]
pub struct RawError {
    pub message: String,
    pub span: Span,
    pub label: Option<String>,
    pub help: Option<String>,
    pub secondary: Option<Box<(Span, String)>>,
}

impl RawError {
    pub fn new(message: impl Into<String>, span: Span) -> Self {
        Self {
            message: message.into(),
            span,
            label: None,
            help: None,
            secondary: None,
        }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    pub fn with_secondary(mut self, span: Span, label: impl Into<String>) -> Self {
        self.secondary = Some(Box::new((span, label.into())));
        self
    }
}

impl std::fmt::Display for RawError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

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

impl ConfigError {
    /// Build from a `RawError` plus the original source text and filename.
    pub fn from_raw(raw: RawError, source: &str, filename: &str) -> Self {
        let primary_label = raw.label.unwrap_or_else(|| "here".to_string());
        let mut labels = vec![LabeledSpan::at(raw.span, primary_label)];
        if let Some(secondary) = raw.secondary {
            let (span, label) = *secondary;
            labels.push(LabeledSpan::at(span, label));
        }
        Self {
            message: raw.message,
            src: NamedSource::new(filename, source.to_string()),
            labels,
            help: raw.help,
        }
    }
}

/// Top-level error from loading a config file.
#[derive(Debug, Error, Diagnostic)]
pub enum LoadError {
    #[error("{0}")]
    Io(String),
    #[error(transparent)]
    #[diagnostic(transparent)]
    Config(#[from] Box<ConfigError>),
}
