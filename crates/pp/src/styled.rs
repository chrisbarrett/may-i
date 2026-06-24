//! Styled inline text: a run of [`Span`]s, each pairing display-safe content
//! with a semantic [`Style`] role.
//!
//! This is the color-as-data content type carried by every styled layout leaf.
//! Because each span's content is a [`SafeText`] — whose constructor escapes all
//! control characters, including newlines — a [`Styled`] run can never contain a
//! raw `\x1b` or a line break: it is inherently single-line and injection-free.
//! The renderer is the only place a role becomes an actual escape sequence.

use may_i_core::SafeText;

use crate::style::{Style, atom_style};

/// One contiguous styled fragment: display-safe content plus its role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    content: SafeText,
    style: Style,
}

impl Span {
    /// Build a span, control-escaping `text` through [`SafeText`].
    #[must_use]
    pub fn new(text: impl Into<String>, style: Style) -> Self {
        Self {
            content: SafeText::new(text),
            style,
        }
    }

    /// The display-safe content.
    #[must_use]
    pub fn content(&self) -> &str {
        self.content.as_str()
    }

    /// The semantic role.
    #[must_use]
    pub fn style(&self) -> Style {
        self.style
    }

    /// Visible width of the content. Spans carry no embedded ANSI, so width is
    /// the character count (matching the pre-existing `chars().count()` metric).
    #[must_use]
    pub fn width(&self) -> usize {
        self.content.as_str().chars().count()
    }
}

/// A single-line run of styled spans.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Styled {
    spans: Vec<Span>,
}

impl Styled {
    /// An empty run.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A single unstyled span.
    #[must_use]
    pub fn plain(text: impl Into<String>) -> Self {
        Self::span(text, Style::Plain)
    }

    /// A single styled span.
    #[must_use]
    pub fn span(text: impl Into<String>, style: Style) -> Self {
        Self {
            spans: vec![Span::new(text, style)],
        }
    }

    /// A single span whose role is derived from its atom content-class.
    #[must_use]
    pub fn atom(text: impl AsRef<str>) -> Self {
        let text = text.as_ref();
        Self::span(text, atom_style(text))
    }

    /// Append a styled span, returning `self` for chaining.
    #[must_use]
    pub fn with(mut self, text: impl Into<String>, style: Style) -> Self {
        self.spans.push(Span::new(text, style));
        self
    }

    /// Append a styled span in place.
    pub fn push(&mut self, text: impl Into<String>, style: Style) {
        self.spans.push(Span::new(text, style));
    }

    /// Append another run's spans in place.
    pub fn extend(&mut self, other: Styled) {
        self.spans.extend(other.spans);
    }

    /// The spans of this run.
    #[must_use]
    pub fn spans(&self) -> &[Span] {
        &self.spans
    }

    /// Total visible width (sum of span widths).
    #[must_use]
    pub fn width(&self) -> usize {
        self.spans.iter().map(Span::width).sum()
    }

    /// Whether the run has no spans (or only empty content).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.width() == 0
    }

    /// The concatenated display-safe text, discarding styling. Useful for
    /// width-only or plain-text contexts.
    #[must_use]
    pub fn to_plain_string(&self) -> String {
        self.spans.iter().map(Span::content).collect()
    }
}

impl From<&str> for Styled {
    fn from(s: &str) -> Self {
        Styled::plain(s)
    }
}

impl From<String> for Styled {
    fn from(s: String) -> Self {
        Styled::plain(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_escapes_control_chars() {
        let s = Span::new("a\x1b[31mb", Style::Plain);
        assert!(!s.content().contains('\x1b'));
    }

    #[test]
    fn width_is_char_count_not_bytes() {
        let s = Styled::plain("ℹ Info");
        assert_eq!(s.width(), 6);
    }

    #[test]
    fn atom_classifies_keyword() {
        let s = Styled::atom(":allow");
        assert_eq!(s.spans()[0].style(), Style::Keyword);
    }

    #[test]
    fn with_chains_spans() {
        let s = Styled::span("a", Style::Dimmed).with("b", Style::Strong);
        assert_eq!(s.spans().len(), 2);
        assert_eq!(s.width(), 2);
    }
}
