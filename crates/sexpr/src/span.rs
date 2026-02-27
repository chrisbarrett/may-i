// Span is re-exported at module level for internal crate use (e.g. sexpr.rs),
// but not from the crate root — consumers should import Span from may_i_core.
pub use may_i_core::{Span, offset_to_line_col};

/// Internal error carrying a span but no source text.
/// Used inside the sexpr and config_parse modules; converted to a diagnostic
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
