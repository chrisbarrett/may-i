use colored::Colorize;

use crate::color::colorize_atom;
use crate::output::{OutputEvent, PrettyOutput};

// ── StringBuilder ───────────────────────────────────────────────────

/// A `PrettyOutput` implementation that produces a colorized `String`,
/// reproducing the behavior of the original `pretty()` function.
pub struct StringBuilder {
    buf: String,
    color: bool,
}

impl StringBuilder {
    pub fn new(color: bool) -> Self {
        Self {
            buf: String::new(),
            color,
        }
    }

    pub fn into_string(self) -> String {
        self.buf
    }
}

impl<A> PrettyOutput<A> for StringBuilder {
    fn begin_line(&mut self, indent: usize) {
        self.buf.push('\n');
        for _ in 0..indent {
            self.buf.push(' ');
        }
    }

    fn emit_space(&mut self) {
        self.buf.push(' ');
    }

    fn emit_delim(&mut self, ch: char, _dimmed: bool) {
        if self.color {
            self.buf.push_str(&ch.to_string().dimmed().to_string());
        } else {
            self.buf.push(ch);
        }
    }

    fn emit_atom(&mut self, text: &str, _ann: &A, dimmed: bool) {
        if dimmed && self.color {
            self.buf.push_str(&text.dimmed().to_string());
        } else {
            self.buf.push_str(&colorize_atom(text, self.color));
        }
    }

    fn emit_raw(&mut self, text: &str) {
        self.buf.push_str(text);
    }
}

// ── EventBuffer ─────────────────────────────────────────────────────

/// Buffer that collects output events, tracks width, and can replay
/// to another `PrettyOutput`. Used for flat-vs-broken layout decisions.
pub(crate) struct EventBuffer<A> {
    events: Vec<OutputEvent<A>>,
    first_line_width: usize,
    current_line_width: usize,
    max_continuation_width: usize,
    on_first_line: bool,
}

impl<A> EventBuffer<A> {
    pub(crate) fn new() -> Self {
        Self {
            events: Vec::new(),
            first_line_width: 0,
            current_line_width: 0,
            max_continuation_width: 0,
            on_first_line: true,
        }
    }

    pub(crate) fn first_line_width(&self) -> usize {
        if self.on_first_line {
            self.current_line_width
        } else {
            self.first_line_width
        }
    }

    pub(crate) fn is_multiline(&self) -> bool {
        !self.on_first_line
    }

    /// Max line width, where the first line is offset by `base_indent`.
    pub(crate) fn max_line_width(&self, base_indent: usize) -> usize {
        let first = base_indent + self.first_line_width();
        if self.on_first_line {
            first
        } else {
            first
                .max(self.max_continuation_width)
                .max(self.current_line_width)
        }
    }

    pub(crate) fn replay(self, out: &mut impl PrettyOutput<A>) {
        for event in self.events {
            match event {
                OutputEvent::BeginLine(indent) => out.begin_line(indent),
                OutputEvent::Space => out.emit_space(),
                OutputEvent::Delim(ch, dimmed) => out.emit_delim(ch, dimmed),
                OutputEvent::Atom(text, ann, dimmed) => out.emit_atom(&text, &ann, dimmed),
                OutputEvent::NodeAnn(ann) => out.emit_node_ann(&ann),
                OutputEvent::Raw(text) => out.emit_raw(&text),
            }
        }
    }
}

impl<A: Clone> PrettyOutput<A> for EventBuffer<A> {
    fn begin_line(&mut self, indent: usize) {
        if self.on_first_line {
            self.first_line_width = self.current_line_width;
            self.on_first_line = false;
        } else {
            self.max_continuation_width = self.max_continuation_width.max(self.current_line_width);
        }
        self.current_line_width = indent;
        self.events.push(OutputEvent::BeginLine(indent));
    }

    fn emit_space(&mut self) {
        self.current_line_width += 1;
        self.events.push(OutputEvent::Space);
    }

    fn emit_delim(&mut self, ch: char, dimmed: bool) {
        self.current_line_width += 1;
        self.events.push(OutputEvent::Delim(ch, dimmed));
    }

    fn emit_atom(&mut self, text: &str, ann: &A, dimmed: bool) {
        self.current_line_width += text.chars().count();
        self.events
            .push(OutputEvent::Atom(text.to_string(), ann.clone(), dimmed));
    }

    fn emit_node_ann(&mut self, ann: &A) {
        self.events.push(OutputEvent::NodeAnn(ann.clone()));
    }

    fn emit_raw(&mut self, text: &str) {
        self.current_line_width += text.chars().count();
        self.events.push(OutputEvent::Raw(text.to_string()));
    }
}

// ── AnnotatedLineBuilder ─────────────────────────────────────────────

/// A single rendered line with its text and the annotations from atoms on that line.
#[derive(Debug, Clone)]
pub struct AnnotatedLine<A> {
    pub text: String,
    pub visible_width: usize,
    pub annotations: Vec<A>,
}

/// A `PrettyOutput` implementation that collects per-line annotations.
///
/// Each rendered line becomes an `AnnotatedLine` carrying the annotations from
/// Doc nodes that produced content on that line.
pub struct AnnotatedLineBuilder<A> {
    lines: Vec<AnnotatedLine<A>>,
    current_text: String,
    current_width: usize,
    current_annotations: Vec<A>,
}

impl<A> AnnotatedLineBuilder<A> {
    pub fn new() -> Self {
        Self {
            lines: Vec::new(),
            current_text: String::new(),
            current_width: 0,
            current_annotations: Vec::new(),
        }
    }

    pub fn into_lines(mut self) -> Vec<AnnotatedLine<A>> {
        self.flush_line();
        self.lines
    }

    fn flush_line(&mut self) {
        if !self.current_text.is_empty() || !self.current_annotations.is_empty() {
            self.lines.push(AnnotatedLine {
                text: std::mem::take(&mut self.current_text),
                visible_width: self.current_width,
                annotations: std::mem::take(&mut self.current_annotations),
            });
            self.current_width = 0;
        }
    }
}

impl<A> Default for AnnotatedLineBuilder<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Clone> PrettyOutput<A> for AnnotatedLineBuilder<A> {
    fn begin_line(&mut self, indent: usize) {
        self.flush_line();
        for _ in 0..indent {
            self.current_text.push(' ');
        }
        self.current_width = indent;
    }

    fn emit_space(&mut self) {
        self.current_text.push(' ');
        self.current_width += 1;
    }

    fn emit_delim(&mut self, ch: char, _dimmed: bool) {
        self.current_text.push(ch);
        self.current_width += 1;
    }

    fn emit_atom(&mut self, text: &str, ann: &A, dimmed: bool) {
        self.current_text.push_str(text);
        self.current_width += text.chars().count();
        if !dimmed {
            self.current_annotations.push(ann.clone());
        }
    }

    fn emit_node_ann(&mut self, ann: &A) {
        self.current_annotations.push(ann.clone());
    }

    fn emit_raw(&mut self, text: &str) {
        self.current_text.push_str(text);
        self.current_width += text.chars().count();
    }
}
