// Span and raw error types for s-expression parsing diagnostics.

use miette::SourceSpan;

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

/// Convert a byte offset in source text to a 1-based (line, column) pair.
pub fn offset_to_line_col(source: &str, offset: usize) -> (usize, usize) {
    let before = &source[..offset.min(source.len())];
    let line = before.bytes().filter(|&b| b == b'\n').count() + 1;
    let col = before
        .rfind('\n')
        .map_or(before.len(), |p| before.len() - p - 1)
        + 1;
    (line, col)
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
