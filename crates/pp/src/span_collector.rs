//! A [`PrettyOutput`] implementation that collects color-as-data styled lines.
//!
//! This is the span-producing successor to `StringBuilder`'s baked-ANSI string:
//! instead of pushing `colored` escape sequences, it records each emitted
//! fragment as a [`Span`] carrying a semantic [`Style`] role. The renderer in
//! `may-i-output` turns roles into actual SGR at one site.

use crate::output::PrettyOutput;
use crate::style::{Style, atom_style};
use crate::styled::Styled;

/// Collects pretty-printer events into one [`Styled`] run per visible line.
pub struct SpanCollector {
    lines: Vec<Styled>,
    current: Styled,
}

impl SpanCollector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            lines: Vec::new(),
            current: Styled::new(),
        }
    }

    /// Finish, returning one styled run per line (matching `String`-based
    /// rendering's `lines()` split).
    #[must_use]
    pub fn into_lines(mut self) -> Vec<Styled> {
        self.lines.push(self.current);
        self.lines
    }
}

impl Default for SpanCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl<A> PrettyOutput<A> for SpanCollector {
    fn begin_line(&mut self, indent: usize) {
        let finished = std::mem::take(&mut self.current);
        self.lines.push(finished);
        if indent > 0 {
            self.current.push(" ".repeat(indent), Style::Plain);
        }
    }

    fn emit_space(&mut self) {
        self.current.push(" ", Style::Plain);
    }

    fn emit_delim(&mut self, ch: char, _dimmed: bool) {
        // String rendering dims every delimiter when colour is on; mirror that
        // with the Dimmed role (the renderer drops it to plain when colour off).
        self.current.push(ch.to_string(), Style::Dimmed);
    }

    fn emit_atom(&mut self, text: &str, _ann: &A, dimmed: bool) {
        let style = if dimmed {
            Style::Dimmed
        } else {
            atom_style(text)
        };
        self.current.push(text, style);
    }

    fn emit_raw(&mut self, text: &str) {
        self.current.push(text, Style::Plain);
    }
}
