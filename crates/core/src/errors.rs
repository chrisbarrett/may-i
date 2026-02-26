// Error types for config parsing diagnostics.
// The miette Diagnostic derive generates code that triggers unused_assignments
// false positives on struct fields.
#![allow(unused_assignments)]

use miette::{Diagnostic, LabeledSpan, NamedSource, SourceSpan};
use may_i_sexpr::RawError;
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

impl ConfigError {
    /// Build from a `RawError` plus the original source text and filename.
    pub fn from_raw(raw: RawError, source: &str, filename: &str) -> Self {
        let primary_label = raw.label.unwrap_or_else(|| "here".to_string());
        let mut labels = vec![LabeledSpan::at(
            SourceSpan::from(raw.span),
            primary_label,
        )];
        if let Some(secondary) = raw.secondary {
            let (span, label) = *secondary;
            labels.push(LabeledSpan::at(SourceSpan::from(span), label));
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
