// S-expression pretty-printer with configurable width and syntax coloring.
//
// The core Doc/DocF types live in `may-i-core::doc` and are re-exported here
// for convenience. This crate provides rendering (pretty-printing, colorization)
// and s-expression string parsing.

use colored::Colorize;
use may_i_core::{Doc, DocF, LayoutHint};

// ── from_sexpr (test-only) ─────────────────────────────────────────

#[cfg(test)]
fn doc_from_sexpr(sexpr: &may_i_sexpr::Sexpr) -> Doc {
    match sexpr {
        may_i_sexpr::Sexpr::Atom(s, _) => {
            let text = if may_i_sexpr::needs_quoting(s) {
                may_i_sexpr::quote_atom(s)
            } else {
                s.clone()
            };
            Doc::atom(text)
        }
        may_i_sexpr::Sexpr::List(items, _) | may_i_sexpr::Sexpr::Vector(items, _) => {
            Doc::list(items.iter().map(doc_from_sexpr).collect())
        }
    }
}

// ── S-expression string parser (test-only) ─────────────────────────

#[cfg(test)]
fn parse_sexpr(input: &str) -> Doc {
    let tokens = tokenize(input);
    if tokens.is_empty() {
        return Doc::atom("");
    }
    let (doc, _) = parse_tokens(&tokens, 0);
    doc
}

#[cfg(test)]
fn tokenize(input: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' | b'\n' => {
                i += 1;
            }
            b'(' => {
                tokens.push(&input[i..i + 1]);
                i += 1;
            }
            b')' => {
                tokens.push(&input[i..i + 1]);
                i += 1;
            }
            b'"' => {
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
                tokens.push(&input[start..i]);
            }
            b'#' if i + 1 < bytes.len() && bytes[i + 1] == b'"' => {
                let start = i;
                i += 2;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
                tokens.push(&input[start..i]);
            }
            _ => {
                let start = i;
                while i < bytes.len() && !matches!(bytes[i], b' ' | b'\t' | b'\n' | b'(' | b')') {
                    i += 1;
                }
                tokens.push(&input[start..i]);
            }
        }
    }
    tokens
}

#[cfg(test)]
fn parse_tokens(tokens: &[&str], pos: usize) -> (Doc, usize) {
    if pos >= tokens.len() {
        return (Doc::atom(""), pos);
    }
    if tokens[pos] == "(" {
        let mut children = Vec::new();
        let mut i = pos + 1;
        while i < tokens.len() && tokens[i] != ")" {
            let (child, next) = parse_tokens(tokens, i);
            children.push(child);
            i = next;
        }
        if i < tokens.len() {
            i += 1;
        }
        (Doc::list(children), i)
    } else {
        (Doc::atom(tokens[pos]), pos + 1)
    }
}

// ── Atom classification ─────────────────────────────────────────────

const SPECIAL_FORMS: &[&str] = &[
    "rule",
    "command",
    "args",
    "effect",
    "cond",
    "if",
    "when",
    "unless",
    "else",
    "positional",
    "exact",
    "anywhere",
];

fn is_keyword(s: &str) -> bool {
    s.starts_with(':')
}
fn is_string(s: &str) -> bool {
    s.starts_with('"')
}
fn is_regex(s: &str) -> bool {
    s.starts_with("#\"")
}
fn is_special_form(s: &str) -> bool {
    SPECIAL_FORMS.contains(&s)
}

// ── Formatting settings ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Format {
    pub width: usize,
    pub color: bool,
    pub line_number: Option<usize>,
}

impl Default for Format {
    fn default() -> Self {
        Self {
            width: 72,
            color: false,
            line_number: None,
        }
    }
}

impl Format {}

/// Detect appropriate column width from existing source code.
///
/// Analyzes the source to determine the predominant line length,
/// then snaps to the nearest preset width (80, 100, 120, or 200).
///
/// This helps migrated output match the existing code style.
pub fn detect_column_width(source: &str) -> usize {
    let mut code_line_lengths: Vec<usize> = Vec::new();

    for line in source.lines() {
        let trimmed = line.trim_start();

        // Skip empty lines and comment-only lines
        if trimmed.is_empty() || trimmed.starts_with(';') {
            continue;
        }

        // Find the end of actual code (before trailing comments)
        // Be careful not to match semicolons inside strings
        let mut in_string = false;
        let mut code_end = line.len();

        for (i, c) in line.chars().enumerate() {
            match c {
                '"' => in_string = !in_string,
                ';' if !in_string => {
                    code_end = i;
                    break;
                }
                _ => {}
            }
        }

        // Measure the visible width of the code portion
        let code_line = &line[..code_end];
        let visible_width = code_line.chars().count();

        if visible_width > 0 {
            code_line_lengths.push(visible_width);
        }
    }

    if code_line_lengths.is_empty() {
        return 100; // Default
    }

    // Sort and find 95th percentile
    code_line_lengths.sort_unstable();
    let idx = ((code_line_lengths.len() as f64) * 0.95) as usize;
    let idx = idx.min(code_line_lengths.len() - 1);

    let width = code_line_lengths[idx];

    // Snap to nearest preset
    snap_to_preset(width)
}

/// Snap a width to the nearest preset (80, 100, 120, 200).
fn snap_to_preset(width: usize) -> usize {
    if width <= 90 {
        80
    } else if width <= 110 {
        100
    } else if width <= 170 {
        120
    } else {
        200
    }
}

// ── PrettyOutput trait ──────────────────────────────────────────────

/// Trait for receiving structured events from the pretty-printer.
pub trait PrettyOutput<A> {
    fn begin_line(&mut self, indent: usize);
    fn emit_space(&mut self);
    fn emit_delim(&mut self, ch: char, dimmed: bool);
    fn emit_atom(&mut self, text: &str, ann: &A, dimmed: bool);
    /// Called when entering a list/vector node that carries an annotation.
    /// Default implementation is a no-op.
    fn emit_node_ann(&mut self, _ann: &A) {}
}

/// Event emitted during flat-rendering for buffering and replay.
pub enum OutputEvent<A> {
    BeginLine(usize),
    Space,
    Delim(char, bool),
    Atom(String, A, bool),
    NodeAnn(A),
}

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
}

// ── EventBuffer ─────────────────────────────────────────────────────

/// Buffer that collects output events, tracks width, and can replay
/// to another `PrettyOutput`. Used for flat-vs-broken layout decisions.
struct EventBuffer<A> {
    events: Vec<OutputEvent<A>>,
    first_line_width: usize,
    current_line_width: usize,
    max_continuation_width: usize,
    on_first_line: bool,
}

impl<A> EventBuffer<A> {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            first_line_width: 0,
            current_line_width: 0,
            max_continuation_width: 0,
            on_first_line: true,
        }
    }

    fn first_line_width(&self) -> usize {
        if self.on_first_line {
            self.current_line_width
        } else {
            self.first_line_width
        }
    }

    fn is_multiline(&self) -> bool {
        !self.on_first_line
    }

    /// Max line width, where the first line is offset by `base_indent`.
    fn max_line_width(&self, base_indent: usize) -> usize {
        let first = base_indent + self.first_line_width();
        if self.on_first_line {
            first
        } else {
            first
                .max(self.max_continuation_width)
                .max(self.current_line_width)
        }
    }

    fn replay(self, out: &mut impl PrettyOutput<A>) {
        for event in self.events {
            match event {
                OutputEvent::BeginLine(indent) => out.begin_line(indent),
                OutputEvent::Space => out.emit_space(),
                OutputEvent::Delim(ch, dimmed) => out.emit_delim(ch, dimmed),
                OutputEvent::Atom(text, ann, dimmed) => out.emit_atom(&text, &ann, dimmed),
                OutputEvent::NodeAnn(ann) => out.emit_node_ann(&ann),
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

    fn emit_atom(&mut self, text: &str, ann: &A, _dimmed: bool) {
        self.current_text.push_str(text);
        self.current_width += text.chars().count();
        self.current_annotations.push(ann.clone());
    }

    fn emit_node_ann(&mut self, ann: &A) {
        self.current_annotations.push(ann.clone());
    }
}

// ── Rendering ───────────────────────────────────────────────────────

/// Pretty-print a Doc with the given format settings.
pub fn pretty<A: Clone>(doc: &Doc<A>, indent: usize, fmt: &Format) -> String {
    let prefix_width = fmt.line_number.map_or(0, line_prefix_width);
    let mut sb = StringBuilder::new(fmt.color);
    pretty_into(doc, indent + prefix_width, fmt.width, &mut sb);
    let content = sb.into_string();

    match fmt.line_number {
        Some(n) => prepend_line_number(&content, n, fmt.color),
        None => content,
    }
}

/// Pretty-print a Doc into any `PrettyOutput` implementation.
pub fn pretty_into<A: Clone>(
    doc: &Doc<A>,
    indent: usize,
    width: usize,
    out: &mut impl PrettyOutput<A>,
) {
    render(doc, indent, width, false, out);
}

fn line_prefix_width(n: usize) -> usize {
    format!("{n}").len() + 2
}

fn prepend_line_number(content: &str, n: usize, color: bool) -> String {
    let prefix = format!("{n}: ");
    let mut result = String::new();
    for (i, line) in content.lines().enumerate() {
        if i > 0 {
            result.push('\n');
        }
        if i == 0 {
            if color {
                result.push_str(&prefix.dimmed().to_string());
            } else {
                result.push_str(&prefix);
            }
        }
        result.push_str(line);
    }
    result
}

fn render<A: Clone>(
    doc: &Doc<A>,
    indent: usize,
    width: usize,
    dimmed: bool,
    out: &mut impl PrettyOutput<A>,
) {
    let dimmed = dimmed || doc.dimmed;
    match &doc.node {
        DocF::Atom(s) => out.emit_atom(s, &doc.ann, dimmed),
        DocF::List(children) if children.is_empty() => {
            out.emit_delim('(', dimmed);
            out.emit_delim(')', dimmed);
        }
        DocF::List(children) => {
            out.emit_node_ann(&doc.ann);
            if let Some(head) = children.first().and_then(|c| c.as_atom()) {
                match head {
                    "rule" => {
                        let mut buf = EventBuffer::new();
                        render_broken(children, indent, width, dimmed, &mut buf);
                        if buf.max_line_width(indent) <= width {
                            buf.replay(out);
                            return;
                        }
                        render_all_drop(children, indent, width, dimmed, out);
                        return;
                    }
                    "cond" => {
                        render_cond(children, indent, width, dimmed, out);
                        return;
                    }
                    "if" | "when" | "unless" => {
                        render_body_indent(children, indent, width, dimmed, out);
                        return;
                    }
                    _ => {}
                }
            }

            let must_break = doc.layout == LayoutHint::AlwaysBreak
                || children.iter().any(|c| c.layout == LayoutHint::AlwaysBreak);
            if !must_break {
                let mut buf = EventBuffer::new();
                render_flat(children, dimmed, &mut buf);
                if !buf.is_multiline() && buf.max_line_width(indent) <= width {
                    buf.replay(out);
                    return;
                }
            }
            let mut buf = EventBuffer::new();
            render_broken(children, indent, width, dimmed, &mut buf);
            if buf.max_line_width(indent) <= width {
                buf.replay(out);
                return;
            }
            render_all_drop(children, indent, width, dimmed, out);
        }
        DocF::Vector(children) if children.is_empty() => {
            out.emit_delim('[', dimmed);
            out.emit_delim(']', dimmed);
        }
        DocF::Vector(children) => {
            out.emit_node_ann(&doc.ann);
            let must_break = doc.layout == LayoutHint::AlwaysBreak
                || children.iter().any(|c| c.layout == LayoutHint::AlwaysBreak);
            if !must_break {
                let mut buf = EventBuffer::new();
                render_flat_delim(children, dimmed, '[', ']', &mut buf);
                if !buf.is_multiline() && buf.max_line_width(indent) <= width {
                    buf.replay(out);
                    return;
                }
            }
            let mut buf = EventBuffer::new();
            render_broken_delim(children, indent, width, dimmed, '[', ']', &mut buf);
            if buf.max_line_width(indent) <= width {
                buf.replay(out);
                return;
            }
            render_all_drop_delim(children, indent, width, dimmed, '[', ']', out);
        }
    }
}

fn render_flat_delim<A: Clone>(
    children: &[Doc<A>],
    dimmed: bool,
    open: char,
    close: char,
    out: &mut impl PrettyOutput<A>,
) {
    out.emit_delim(open, dimmed);
    for (i, child) in children.iter().enumerate() {
        if i > 0 {
            out.emit_space();
        }
        render(child, 0, usize::MAX, dimmed, out);
    }
    out.emit_delim(close, dimmed);
}

fn render_broken_delim<A: Clone>(
    children: &[Doc<A>],
    indent: usize,
    width: usize,
    dimmed: bool,
    open: char,
    close: char,
    out: &mut impl PrettyOutput<A>,
) {
    out.emit_delim(open, dimmed);

    let mut head_buf = EventBuffer::new();
    render(&children[0], indent + 1, width, dimmed, &mut head_buf);
    let head_width = head_buf.first_line_width();
    head_buf.replay(out);

    let align = indent + head_width + 2;

    if children.len() == 1 {
        out.emit_delim(close, dimmed);
    } else {
        out.emit_space();
        render(&children[1], align, width, dimmed, out);

        for child in &children[2..] {
            out.begin_line(align);
            render(child, align, width, dimmed, out);
        }
        out.emit_delim(close, dimmed);
    }
}

fn render_all_drop_delim<A: Clone>(
    children: &[Doc<A>],
    indent: usize,
    width: usize,
    dimmed: bool,
    open: char,
    close: char,
    out: &mut impl PrettyOutput<A>,
) {
    out.emit_delim(open, dimmed);
    render(&children[0], indent + 1, width, dimmed, out);

    if children.len() == 1 {
        out.emit_delim(close, dimmed);
        return;
    }

    let child_indent = indent + 2;
    for (i, child) in children[1..].iter().enumerate() {
        let is_last = i == children.len() - 2;
        out.begin_line(child_indent);
        render(child, child_indent, width, dimmed, out);
        if is_last {
            out.emit_delim(close, dimmed);
        }
    }
}

fn render_flat<A: Clone>(children: &[Doc<A>], dimmed: bool, out: &mut impl PrettyOutput<A>) {
    render_flat_delim(children, dimmed, '(', ')', out);
}

fn render_broken<A: Clone>(
    children: &[Doc<A>],
    indent: usize,
    width: usize,
    dimmed: bool,
    out: &mut impl PrettyOutput<A>,
) {
    render_broken_delim(children, indent, width, dimmed, '(', ')', out);
}

fn render_all_drop<A: Clone>(
    children: &[Doc<A>],
    indent: usize,
    width: usize,
    dimmed: bool,
    out: &mut impl PrettyOutput<A>,
) {
    render_all_drop_delim(children, indent, width, dimmed, '(', ')', out);
}

fn render_cond<A: Clone>(
    children: &[Doc<A>],
    indent: usize,
    width: usize,
    dimmed: bool,
    out: &mut impl PrettyOutput<A>,
) {
    out.emit_delim('(', dimmed);
    render(&children[0], indent + 1, width, dimmed, out);
    let body_indent = indent + 2;

    for (i, clause) in children[1..].iter().enumerate() {
        let is_last = i == children.len() - 2;
        let clause_dimmed = dimmed || clause.dimmed;
        match &clause.node {
            DocF::List(parts) if parts.len() >= 2 => {
                out.begin_line(body_indent);
                out.emit_delim('(', clause_dimmed);
                render(&parts[0], body_indent + 1, width, clause_dimmed, out);

                let body_col = body_indent + 1;
                for (j, body_part) in parts[1..].iter().enumerate() {
                    let is_last_part = j == parts.len() - 2;
                    out.begin_line(body_col);
                    render(body_part, body_col, width, clause_dimmed, out);
                    if is_last_part && is_last {
                        out.emit_delim(')', clause_dimmed);
                        out.emit_delim(')', dimmed);
                    } else if is_last_part {
                        out.emit_delim(')', clause_dimmed);
                    }
                }
            }
            _ => {
                out.begin_line(body_indent);
                render(clause, body_indent, width, clause_dimmed, out);
                if is_last {
                    out.emit_delim(')', dimmed);
                }
            }
        }
    }

    if children.len() == 1 {
        out.emit_delim(')', dimmed);
    }
}

fn render_body_indent<A: Clone>(
    children: &[Doc<A>],
    indent: usize,
    width: usize,
    dimmed: bool,
    out: &mut impl PrettyOutput<A>,
) {
    out.emit_delim('(', dimmed);

    // Buffer head to measure its width for alignment.
    let mut head_buf = EventBuffer::new();
    render(&children[0], indent + 1, width, dimmed, &mut head_buf);
    let head_width = head_buf.first_line_width();
    head_buf.replay(out);

    let body_indent = indent + 2;

    if children.len() == 1 {
        out.emit_delim(')', dimmed);
        return;
    }

    // Try placing the first child on the same line as the head.
    let inline_col = indent + 1 + head_width + 1;

    let mut first_buf = EventBuffer::new();
    render(&children[1], inline_col, width, dimmed, &mut first_buf);
    let first_multiline = first_buf.is_multiline();

    if first_multiline {
        // First child wraps — drop it to the next line.
        let head_atom = children[0].as_atom().unwrap_or("");
        let is_predicate_form = matches!(head_atom, "when" | "if" | "unless");
        let first_indent = if is_predicate_form {
            indent + 4
        } else {
            body_indent
        };
        out.begin_line(first_indent);
        render(&children[1], first_indent, width, dimmed, out);
    } else {
        out.emit_space();
        first_buf.replay(out);
    }

    for (i, child) in children[2..].iter().enumerate() {
        let is_last = i == children.len() - 3;
        out.begin_line(body_indent);
        render(child, body_indent, width, dimmed, out);
        if is_last {
            out.emit_delim(')', dimmed);
        }
    }

    if children.len() == 2 {
        out.emit_delim(')', dimmed);
    }
}

/// Colorize an atom value based on its content.
pub fn colorize_atom(s: &str, color: bool) -> String {
    if !color {
        return s.to_string();
    }
    if is_keyword(s) {
        s.truecolor(120, 120, 255).to_string()
    } else if is_string(s) || is_regex(s) {
        s.green().to_string()
    } else if is_special_form(s) {
        s.blue().to_string()
    } else {
        s.to_string()
    }
}

/// Visible length of a string, ignoring ANSI SGR escape sequences.
pub fn visible_len(s: &str) -> usize {
    let mut len = 0;
    let mut in_escape = false;
    for ch in s.chars() {
        if in_escape {
            if ch.is_ascii_alphabetic() {
                in_escape = false;
            }
        } else if ch == '\x1b' {
            in_escape = true;
        } else {
            len += 1;
        }
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Doc {
        Doc::atom(s)
    }

    fn l(children: Vec<Doc>) -> Doc {
        Doc::list(children)
    }

    fn v(children: Vec<Doc>) -> Doc {
        Doc::vector(children)
    }

    fn pp(doc: &Doc, width: usize) -> String {
        pretty(
            doc,
            0,
            &Format {
                width,
                ..Default::default()
            },
        )
    }

    fn pp_color(doc: &Doc, width: usize) -> String {
        pretty(
            doc,
            0,
            &Format {
                width,
                color: true,
                ..Default::default()
            },
        )
    }

    // ── Flat rendering ──────────────────────────────────────────────

    #[test]
    fn flat_empty_list() {
        assert_eq!(pp(&l(vec![]), 80), "()");
    }

    #[test]
    fn flat_simple_list() {
        assert_eq!(
            pp(&l(vec![a("command"), a("\"rm\"")]), 80),
            "(command \"rm\")"
        );
    }

    #[test]
    fn flat_vector() {
        assert_eq!(pp(&v(vec![a(":via/ssh")]), 80), "[:via/ssh]");
    }

    #[test]
    fn empty_vector() {
        assert_eq!(pp(&v(vec![]), 80), "[]");
    }

    #[test]
    fn vector_wraps_when_long() {
        let doc = v(vec![a(":ssh/host"), l(vec![a("regex"), a("\"^prod-\"")])]);
        let rendered = pp(&doc, 18);
        assert!(rendered.starts_with("[:ssh/host"));
        assert!(rendered.contains("(regex \"^prod-\")"));
        assert!(rendered.ends_with(']'));
    }

    #[test]
    fn flat_nested() {
        let doc = l(vec![a("rule"), l(vec![a("command"), a("\"rm\"")])]);
        assert_eq!(pp(&doc, 80), "(rule (command \"rm\"))");
    }

    // ── Wrapping ────────────────────────────────────────────────────

    #[test]
    fn wraps_when_exceeds_width() {
        let doc = l(vec![a("rule"), a("aaa"), a("bbb"), a("ccc")]);
        let result = pp(&doc, 15);
        assert_eq!(result, "(rule aaa\n      bbb\n      ccc)");
    }

    #[test]
    fn wraps_nested_lists() {
        let doc = l(vec![
            a("args"),
            l(vec![a("and"), a("xxxxxxxxxxxx"), a("yyyyyyyyyyyy")]),
        ]);
        let result = pp(&doc, 25);
        assert!(result.contains('\n'));
    }

    #[test]
    fn stays_flat_when_fits() {
        let doc = l(vec![a("command"), a("\"ls\"")]);
        let result = pp(&doc, 80);
        assert!(!result.contains('\n'));
    }

    #[test]
    fn single_child_wraps() {
        let doc = l(vec![a("a-very-long-form-name")]);
        let result = pp(&doc, 10);
        assert_eq!(result, "(a-very-long-form-name)");
    }

    // ── Coloring ────────────────────────────────────────────────────

    fn with_forced_color(f: impl FnOnce()) {
        // Set both the override and the environment variable to force colors
        // even in non-TTY environments (like pre-commit hooks)
        colored::control::set_override(true);
        unsafe {
            std::env::set_var("CLICOLOR_FORCE", "1");
        }
        f();
        colored::control::unset_override();
        unsafe {
            std::env::remove_var("CLICOLOR_FORCE");
        }
    }

    #[test]
    fn keywords_get_colored() {
        with_forced_color(|| {
            let result = pp_color(&a(":deny"), 80);
            assert!(
                result.contains("\x1b["),
                "expected ANSI codes in: {result:?}"
            );
            assert!(result.contains("deny"));
        });
    }

    #[test]
    fn strings_get_colored() {
        with_forced_color(|| {
            let result = pp_color(&a("\"rm\""), 80);
            assert!(
                result.contains("\x1b["),
                "expected ANSI codes in: {result:?}"
            );
            assert!(result.contains("rm"));
        });
    }

    #[test]
    fn special_forms_get_colored() {
        with_forced_color(|| {
            let result = pp_color(&a("command"), 80);
            assert!(
                result.contains("\x1b["),
                "expected ANSI codes in: {result:?}"
            );
        });
    }

    #[test]
    fn plain_atoms_not_colored() {
        with_forced_color(|| {
            let result = pp_color(&a("foo"), 80);
            assert!(
                !result.contains("\x1b["),
                "unexpected ANSI codes in: {result:?}"
            );
        });
    }

    #[test]
    fn parens_dimmed_in_color_mode() {
        with_forced_color(|| {
            let result = pp_color(&l(vec![a("x")]), 80);
            assert!(
                result.contains("\x1b["),
                "expected ANSI codes in: {result:?}"
            );
        });
    }

    // ── from_sexpr ──────────────────────────────────────────────────

    #[test]
    fn from_sexpr_atom_bare() {
        let sexpr = may_i_sexpr::Sexpr::Atom("hello".into(), may_i_core::Span::new(0, 0));
        let doc = doc_from_sexpr(&sexpr);
        assert_eq!(pp(&doc, 80), "hello");
    }

    #[test]
    fn from_sexpr_atom_needs_quoting() {
        let sexpr = may_i_sexpr::Sexpr::Atom("hello world".into(), may_i_core::Span::new(0, 0));
        let doc = doc_from_sexpr(&sexpr);
        assert_eq!(pp(&doc, 80), "\"hello world\"");
    }

    #[test]
    fn from_sexpr_list() {
        let sexpr = may_i_sexpr::Sexpr::List(
            vec![
                may_i_sexpr::Sexpr::Atom("rule".into(), may_i_core::Span::new(0, 0)),
                may_i_sexpr::Sexpr::Atom("foo".into(), may_i_core::Span::new(0, 0)),
            ],
            may_i_core::Span::new(0, 0),
        );
        let doc = doc_from_sexpr(&sexpr);
        assert_eq!(pp(&doc, 80), "(rule foo)");
    }

    // ── visible_len ─────────────────────────────────────────────────

    #[test]
    fn visible_len_plain() {
        assert_eq!(visible_len("hello"), 5);
    }

    #[test]
    fn visible_len_with_ansi() {
        let s = "hello".green().to_string();
        assert_eq!(visible_len(&s), 5);
    }

    // ── Alignment ───────────────────────────────────────────────────

    #[test]
    fn alignment_under_first_arg() {
        let doc = l(vec![a("and"), a("first-branch"), a("second-branch")]);
        let result = pp(&doc, 20);
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "(and first-branch");
        assert_eq!(lines[1], "     second-branch)");
    }

    // ── parse_sexpr ────────────────────────────────────────────────

    #[test]
    fn parse_sexpr_atom() {
        let doc = parse_sexpr("hello");
        assert_eq!(pp(&doc, 80), "hello");
    }

    #[test]
    fn parse_sexpr_simple_list() {
        let doc = parse_sexpr("(command \"curl\")");
        assert_eq!(pp(&doc, 80), "(command \"curl\")");
    }

    #[test]
    fn parse_sexpr_nested() {
        let doc = parse_sexpr("(command (or \"cat\" \"bat\"))");
        assert_eq!(pp(&doc, 80), "(command (or \"cat\" \"bat\"))");
    }

    #[test]
    fn parse_sexpr_regex() {
        let doc = parse_sexpr("(command (regex \"^git\"))");
        assert_eq!(pp(&doc, 80), "(command (regex \"^git\"))");
    }

    #[test]
    fn parse_sexpr_wraps_when_long() {
        let doc = parse_sexpr("(command (or \"cat\" \"bat\" \"head\" \"tail\" \"less\"))");
        let result = pp(&doc, 30);
        assert!(result.contains('\n'));
    }

    // ── line_number ────────────────────────────────────────────────

    #[test]
    fn line_number_single_line() {
        let doc = l(vec![a("rule"), l(vec![a("command"), a("\"curl\"")])]);
        let result = pretty(
            &doc,
            0,
            &Format {
                width: 80,
                line_number: Some(108),
                ..Default::default()
            },
        );
        assert_eq!(result, "108: (rule (command \"curl\"))");
    }

    #[test]
    fn line_number_wrapped_aligns() {
        let doc = l(vec![a("rule"), a("aaa"), a("bbb"), a("ccc")]);
        let result = pretty(
            &doc,
            0,
            &Format {
                width: 20,
                line_number: Some(5),
                ..Default::default()
            },
        );
        let lines: Vec<&str> = result.lines().collect();
        assert!(lines.len() > 1);
        assert!(lines[0].starts_with("5: "));
        assert!(lines[1].starts_with("         "));
    }

    #[test]
    fn line_number_accounts_for_width() {
        let doc = l(vec![a("rule"), l(vec![a("command"), a("\"curl\"")])]);
        let result = pretty(
            &doc,
            0,
            &Format {
                width: 30,
                line_number: Some(108),
                ..Default::default()
            },
        );
        assert!(!result.contains('\n'));
    }

    // ── map ────────────────────────────────────────────────────────

    #[test]
    fn map_tags_all_nodes() {
        let doc = l(vec![a("head"), a("child")]);
        let tagged = doc.map(&|()| 42);
        assert_eq!(tagged.ann, 42);
        if let DocF::List(children) = &tagged.node {
            assert_eq!(children[0].ann, 42);
            assert_eq!(children[1].ann, 42);
        } else {
            panic!("expected list");
        }
    }

    #[test]
    fn map_preserves_structure() {
        let doc = l(vec![a("x"), l(vec![a("y")])]);
        let tagged = doc.map(&|()| "ann");
        assert_eq!(pretty(&tagged, 0, &Format::default()), "(x (y))");
    }

    // ── fold ───────────────────────────────────────────────────────

    #[test]
    fn fold_counts_nodes() {
        let doc = l(vec![a("a"), l(vec![a("b"), a("c")])]);
        let count: usize = doc.fold(&|node, _ann| match node {
            DocF::Atom(_) => 1,
            DocF::List(children) | DocF::Vector(children) => 1 + children.iter().sum::<usize>(),
        });
        assert_eq!(count, 5); // list + a + list + b + c
    }

    #[test]
    fn fold_collects_atoms() {
        let doc = l(vec![a("rule"), a("foo"), l(vec![a("bar")])]);
        let atoms: Vec<String> = doc.fold(&|node, _ann| match node {
            DocF::Atom(s) => vec![s],
            DocF::List(children) | DocF::Vector(children) => {
                children.into_iter().flatten().collect()
            }
        });
        assert_eq!(atoms, vec!["rule", "foo", "bar"]);
    }

    #[test]
    fn fold_rebuilds_tree() {
        // Use fold to rebuild a tree with truncated atoms.
        let doc = l(vec![a("hello-world"), a("short")]);
        let truncated: Doc<()> = doc.fold(&|node, _ann| match node {
            DocF::Atom(s) => {
                let t = if s.len() > 5 { &s[..5] } else { &s };
                Doc::atom(t)
            }
            DocF::List(children) => Doc::list(children),
            DocF::Vector(children) => Doc::vector(children),
        });
        assert_eq!(pp(&truncated, 80), "(hello short)");
    }

    // ── DocF::map ──────────────────────────────────────────────────

    #[test]
    fn docf_map_transforms_children() {
        let layer: DocF<i32> = DocF::List(vec![1, 2, 3]);
        let doubled = layer.map(|x| x * 2);
        assert_eq!(doubled.children(), Some(&[2, 4, 6][..]));
    }

    #[test]
    fn docf_map_atom_is_identity() {
        let layer: DocF<i32> = DocF::Atom("hello".into());
        let mapped = layer.map(|x| x * 2);
        assert_eq!(mapped.as_atom(), Some("hello"));
    }

    // ── AlwaysBreak ────────────────────────────────────────────────

    #[test]
    fn always_break_uses_broken_layout() {
        // AlwaysBreak skips flat but still uses broken (align-under-first-arg).
        let doc = Doc::broken_list(vec![a("or"), a("\"a\""), a("\"b\""), a("\"c\"")]);
        let result = pp(&doc, 80);
        assert_eq!(result, "(or \"a\"\n    \"b\"\n    \"c\")");
    }

    #[test]
    fn always_break_single_child() {
        let doc = Doc::broken_list(vec![a("or")]);
        let result = pp(&doc, 80);
        assert_eq!(result, "(or)");
    }

    #[test]
    fn always_break_falls_back_to_all_drop_at_narrow_width() {
        // At narrow width, broken layout overflows → falls to render_all_drop.
        let doc = Doc::broken_list(vec![
            a("or"),
            a("\"long-value-one\""),
            a("\"long-value-two\""),
        ]);
        let result = pp(&doc, 20);
        assert_eq!(result, "(or\n  \"long-value-one\"\n  \"long-value-two\")");
    }

    #[test]
    fn cond_renders_clauses() {
        let doc = l(vec![
            a("cond"),
            l(vec![a("\"a\""), a(":allow")]),
            l(vec![a("\"b\""), a(":deny")]),
        ]);
        let result = pp(&doc, 40);
        assert!(result.contains("cond"));
        assert!(result.contains("\"a\""));
        assert!(result.contains(":allow"));
        assert!(result.contains("\"b\""));
        assert!(result.contains(":deny"));
    }

    #[test]
    fn cond_single_child() {
        let doc = l(vec![a("cond")]);
        let result = pp(&doc, 40);
        assert_eq!(result, "(cond)");
    }

    #[test]
    fn cond_atom_clause() {
        let doc = l(vec![a("cond"), a("else")]);
        let result = pp(&doc, 40);
        assert!(result.contains("cond"));
        assert!(result.contains("else"));
    }

    #[test]
    fn body_indent_multiline_first_child() {
        // when/if/unless use body-indent; if the predicate wraps it
        // gets extra indent (indent+4) to distinguish from body.
        let pred = l(vec![a("and"), a("xxxxxxxxxxxx"), a("yyyyyyyyyyyy")]);
        let doc = l(vec![a("when"), pred, a(":allow")]);
        let result = pp(&doc, 25);
        let lines: Vec<&str> = result.lines().collect();
        assert!(lines.len() >= 3);
        assert!(lines[0].contains("when"));
    }

    #[test]
    fn body_indent_two_children() {
        // (when pred) — only head + one child, exercises the len==2 close path.
        let pred = l(vec![a("and"), a("xxxxx"), a("yyyyy")]);
        let doc = l(vec![a("when"), pred]);
        let result = pp(&doc, 15);
        assert!(result.contains("when"));
    }

    #[test]
    fn breaking_descendant_prevents_flat() {
        // (? (and (or "a" "b") "--")) where (or ...) is AlwaysBreak.
        // Even at wide width, (? ...) must not flatten since the or
        // descendant would render at indent=0 producing wrong columns.
        let or_doc = Doc::broken_list(vec![a("or"), a("\"a\""), a("\"b\"")]);
        let and_doc = l(vec![a("and"), or_doc, a("\"--\"")]);
        let q_doc = l(vec![a("?"), and_doc]);
        let result = pp(&q_doc, 80);
        // The (or ...) children must be indented relative to their parent,
        // not at column 0.
        for line in result.lines().skip(1) {
            let leading = line.len() - line.trim_start().len();
            assert!(leading >= 2, "line has too little indent: {result:?}");
        }
    }

    // ── Dimmed rendering ─────────────────────────────────────────────

    #[test]
    fn dimmed_atom_renders_dimmed() {
        with_forced_color(|| {
            let doc = Doc {
                dimmed: true,
                ..a("command")
            };
            let result = pp_color(&doc, 80);
            // When dimmed, atoms should render without syntax coloring.
            // The dimmed styling may or may not include ANSI codes depending
            // on terminal capabilities, but the content should be present.
            assert!(result.contains("command"));
            // Verify it's not colored as a special form (blue)
            // by checking the raw output doesn't contain the blue color code
            let has_blue = result.contains("\x1b[34m") || result.contains("\x1b[38;5;");
            assert!(
                !has_blue,
                "dimmed atom should not have blue syntax color: {result:?}"
            );
        });
    }

    #[test]
    fn dimmed_inherits_to_children() {
        with_forced_color(|| {
            // Parent list is dimmed → children should also render dimmed.
            let doc = Doc {
                ann: (),
                node: DocF::List(vec![a("rule"), a(":allow")]),
                layout: LayoutHint::Auto,
                dimmed: true,
            };
            let result = pp_color(&doc, 80);
            assert!(result.contains("rule"));
            assert!(result.contains(":allow"));
        });
    }

    #[test]
    fn dimmed_only_affects_flagged_subtree() {
        with_forced_color(|| {
            // One child dimmed, sibling not — sibling retains syntax color.
            let dimmed_child = Doc {
                dimmed: true,
                ..a("\"dimmed\"")
            };
            let normal_child = a("\"bright\"");
            let doc = l(vec![a("or"), dimmed_child, normal_child]);
            let result = pp_color(&doc, 80);
            // Both should be present.
            assert!(result.contains("dimmed"));
            assert!(result.contains("bright"));
        });
    }
}

// ── Column width detection tests ────────────────────────────────────

#[cfg(test)]
mod width_tests {
    use super::*;

    #[test]
    fn test_detect_column_width_empty_source() {
        // Empty source should default to 100
        assert_eq!(detect_column_width(""), 100);
        assert_eq!(detect_column_width("   \n  \n"), 100);
    }

    #[test]
    fn test_detect_column_width_only_comments() {
        // Comment-only source should default to 100
        let source = ";; comment\n; another comment\n";
        assert_eq!(detect_column_width(source), 100);
    }

    #[test]
    fn test_detect_column_width_snap_to_80() {
        // Lines around 75-85 columns should snap to 80
        let line_75 = "(rule ".to_string() + &"x".repeat(70) + ")\n";
        assert_eq!(detect_column_width(&line_75), 80);

        let line_85 = "(rule ".to_string() + &"x".repeat(80) + ")\n";
        assert_eq!(detect_column_width(&line_85), 80);
    }

    #[test]
    fn test_detect_column_width_snap_to_100() {
        // Lines around 91-110 columns should snap to 100
        let line_91 = "(rule ".to_string() + &"x".repeat(84) + ")\n";
        assert_eq!(detect_column_width(&line_91), 100);

        // 91 chars: "(rule " (7) + 84 x's + ")" (1) = 92 chars, snap to 100
        let line_110 = "(rule ".to_string() + &"x".repeat(103) + ")\n";
        assert_eq!(detect_column_width(&line_110), 100);
    }

    #[test]
    fn test_detect_column_width_snap_to_120() {
        // Lines around 115-135 columns should snap to 120
        let line_115 = "(rule ".to_string() + &"x".repeat(110) + ")\n";
        assert_eq!(detect_column_width(&line_115), 120);

        let line_135 = "(rule ".to_string() + &"x".repeat(130) + ")\n";
        assert_eq!(detect_column_width(&line_135), 120);
    }

    #[test]
    fn test_detect_column_width_snap_to_200() {
        // Lines above 170 columns should snap to 200
        let line_170 = "(rule ".to_string() + &"x".repeat(165) + ")\n";
        assert_eq!(detect_column_width(&line_170), 200);

        let line_250 = "(rule ".to_string() + &"x".repeat(245) + ")\n";
        assert_eq!(detect_column_width(&line_250), 200);
    }

    #[test]
    fn test_detect_column_width_excludes_trailing_comments() {
        // Trailing comments should not be counted in line length
        let line = "(rule git :effect :allow)    ;; this is a comment\n";
        // Code portion is only ~27 chars, should snap to 80
        assert_eq!(detect_column_width(line), 80);
    }

    #[test]
    fn test_detect_column_width_ignores_semicolons_in_strings() {
        // Semicolons inside strings should not be treated as comments
        let line = r#"(rule "some;value" :effect :allow)"#;
        // Should measure full line, not stop at the semicolon in the string
        let width = detect_column_width(line);
        assert!(
            width > 30,
            "Should count past the semicolon in string, got {}",
            width
        );
    }

    #[test]
    fn test_detect_column_width_95th_percentile() {
        // Mix of short and long lines - should use 95th percentile
        let mut source = String::new();
        // 95 short lines (~27 chars)
        for _ in 0..95 {
            source.push_str("(rule git :effect :allow)\n");
        }
        // 5 very long lines (~202 chars: "(rule " + 195 x's + ")")
        for _ in 0..5 {
            source.push_str(&("(rule ".to_string() + &"x".repeat(195) + ")\n"));
        }
        // With 100 lines, 95th percentile is at index 95 (0-indexed)
        // Index 95 is the first long line (202 chars), which snaps to 200
        assert_eq!(detect_column_width(&source), 200);
    }
}

// ── Property-based tests ────────────────────────────────────────────

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    /// Generate an arbitrary Doc tree (atoms and nested lists).
    fn arb_doc() -> impl Strategy<Value = Doc> {
        let leaf = "[a-z_]{1,12}".prop_map(|s| Doc::atom(s));
        leaf.prop_recursive(4, 20, 5, |inner| {
            prop_oneof![
                // Plain list.
                prop::collection::vec(inner.clone(), 0..5).prop_map(Doc::list),
                // List with a head atom (common in s-expressions).
                (
                    "[a-z]{1,8}".prop_map(|s| Doc::atom(s)),
                    prop::collection::vec(inner, 0..4),
                )
                    .prop_map(|(head, mut children)| {
                        children.insert(0, head);
                        Doc::list(children)
                    }),
            ]
        })
    }

    /// Count open and close parens in visible text.
    fn count_parens(s: &str) -> (usize, usize) {
        let mut in_escape = false;
        let (mut open, mut close) = (0, 0);
        for ch in s.chars() {
            if in_escape {
                if ch.is_ascii_alphabetic() {
                    in_escape = false;
                }
            } else if ch == '\x1b' {
                in_escape = true;
            } else if ch == '(' {
                open += 1;
            } else if ch == ')' {
                close += 1;
            }
        }
        (open, close)
    }

    proptest! {
        // ── Balanced parentheses ─────────────────────────────────────

        #[test]
        fn balanced_parens(doc in arb_doc(), width in 10..120usize) {
            let result = pretty(&doc, 0, &Format { width, ..Default::default() });
            let (open, close) = count_parens(&result);
            prop_assert_eq!(open, close,
                "unbalanced parens in: {:?}", result);
        }

        #[test]
        fn balanced_parens_with_color(doc in arb_doc(), width in 10..120usize) {
            colored::control::set_override(true);
            let result = pretty(&doc, 0, &Format { width, color: true, ..Default::default() });
            colored::control::unset_override();
            let (open, close) = count_parens(&result);
            prop_assert_eq!(open, close,
                "unbalanced parens (colored) in: {:?}", result);
        }

        // ── Width constraints ────────────────────────────────────────

        #[test]
        fn no_line_exceeds_width_by_much(doc in arb_doc(), width in 20..120usize) {
            let result = pretty(&doc, 0, &Format { width, ..Default::default() });
            // Lines may exceed width for long atoms, but the overflow
            // should be bounded by the longest atom in the tree.
            let max_atom_len = doc.fold(&|node, _ann: &()| -> usize {
                match node {
                    DocF::Atom(s) => s.len(),
                    DocF::List(cs) | DocF::Vector(cs) => cs.into_iter().max().unwrap_or(0),
                }
            });
            let slack = max_atom_len + 10; // parens + spaces
            for line in result.lines() {
                let vis = visible_len(line);
                prop_assert!(vis <= width + slack,
                    "line too wide ({vis} vs width {width} + slack {slack}): {line:?}");
            }
        }

        // ── Color transparency ───────────────────────────────────────

        #[test]
        fn color_preserves_visible_text(doc in arb_doc(), width in 10..120usize) {
            let plain = pretty(&doc, 0, &Format { width, ..Default::default() });

            colored::control::set_override(true);
            let colored_output = pretty(&doc, 0, &Format { width, color: true, ..Default::default() });
            colored::control::unset_override();

            // Strip ANSI codes from colored output and compare.
            let stripped = strip_ansi(&colored_output);
            prop_assert_eq!(plain, stripped,
                "color changed visible text");
        }

        // ── Atom roundtrip ───────────────────────────────────────────

        #[test]
        fn atom_renders_as_itself(s in "[a-z_]{1,20}") {
            let doc = Doc::atom(&s);
            let result = pretty(&doc, 0, &Format::default());
            prop_assert_eq!(result, s);
        }
    }

    fn strip_ansi(s: &str) -> String {
        let mut result = String::new();
        let mut in_escape = false;
        for ch in s.chars() {
            if in_escape {
                if ch.is_ascii_alphabetic() {
                    in_escape = false;
                }
            } else if ch == '\x1b' {
                in_escape = true;
            } else {
                result.push(ch);
            }
        }
        result
    }
}

// ── AnnotatedLineBuilder tests ──────────────────────────────────────

#[cfg(test)]
mod annotated_line_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_doc() -> impl Strategy<Value = Doc> {
        let leaf = "[a-z_]{1,12}".prop_map(|s| Doc::atom(s));
        leaf.prop_recursive(4, 20, 5, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..5).prop_map(Doc::list),
                (
                    "[a-z]{1,8}".prop_map(|s| Doc::atom(s)),
                    prop::collection::vec(inner, 0..4),
                )
                    .prop_map(|(head, mut children)| {
                        children.insert(0, head);
                        Doc::list(children)
                    }),
            ]
        })
    }

    /// Reconstruct text from AnnotatedLine vec (joining with newlines).
    fn lines_to_text(lines: &[AnnotatedLine<()>]) -> String {
        let mut result = String::new();
        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                result.push('\n');
            }
            result.push_str(&line.text);
        }
        result
    }

    proptest! {
        #[test]
        fn annotated_line_text_matches_string_builder(doc in arb_doc(), width in 10..120usize) {
            let mut sb = StringBuilder::new(false);
            pretty_into(&doc, 0, width, &mut sb);
            let sb_text = sb.into_string();

            let mut alb = AnnotatedLineBuilder::new();
            pretty_into(&doc, 0, width, &mut alb);
            let lines = alb.into_lines();
            let alb_text = lines_to_text(&lines);

            prop_assert_eq!(sb_text, alb_text,
                "AnnotatedLineBuilder text should match StringBuilder");
        }

        #[test]
        fn annotated_line_visible_width_correct(doc in arb_doc(), width in 10..120usize) {
            let mut alb = AnnotatedLineBuilder::new();
            pretty_into(&doc, 0, width, &mut alb);
            let lines = alb.into_lines();

            for line in &lines {
                let actual_width = line.text.trim_start().chars().count()
                    + line.text.len() - line.text.trim_start().len();
                prop_assert_eq!(line.visible_width, actual_width,
                    "visible_width should match actual char count for line: {:?}", line.text);
            }
        }
    }

    // ── Unit tests: annotation association ───────────────────────────

    #[derive(Debug, Clone, PartialEq)]
    enum TestAnn {
        A,
        B,
        C,
    }

    fn atom_with(s: &str, ann: TestAnn) -> Doc<TestAnn> {
        Doc {
            ann,
            node: DocF::Atom(s.into()),
            layout: LayoutHint::Auto,
            dimmed: false,
        }
    }

    fn list_of(children: Vec<Doc<TestAnn>>) -> Doc<TestAnn> {
        Doc {
            ann: TestAnn::A,
            node: DocF::List(children),
            layout: LayoutHint::Auto,
            dimmed: false,
        }
    }

    #[test]
    fn single_atom_carries_annotation() {
        let doc = atom_with("hello", TestAnn::B);
        let mut alb = AnnotatedLineBuilder::new();
        pretty_into(&doc, 0, 80, &mut alb);
        let lines = alb.into_lines();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].text, "hello");
        assert_eq!(lines[0].annotations, vec![TestAnn::B]);
    }

    #[test]
    fn flat_layout_aggregates_annotations() {
        // (a b) on a wide line → single AnnotatedLine with both annotations
        let doc = list_of(vec![atom_with("a", TestAnn::A), atom_with("b", TestAnn::B)]);
        let mut alb = AnnotatedLineBuilder::new();
        pretty_into(&doc, 0, 80, &mut alb);
        let lines = alb.into_lines();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].annotations.contains(&TestAnn::A));
        assert!(lines[0].annotations.contains(&TestAnn::B));
    }

    #[test]
    fn broken_layout_separates_annotations() {
        // Force broken layout with a very narrow width
        let doc = list_of(vec![
            atom_with("alpha", TestAnn::A),
            atom_with("beta", TestAnn::B),
            atom_with("gamma", TestAnn::C),
        ]);
        let mut alb = AnnotatedLineBuilder::new();
        // Width 1 forces all-drop layout
        pretty_into(&doc, 0, 1, &mut alb);
        let lines = alb.into_lines();
        // Should have multiple lines, each with its own annotation
        assert!(
            lines.len() >= 2,
            "expected broken layout, got {} lines",
            lines.len()
        );

        // First line has "alpha" (and the list open paren), last items on separate lines
        let all_anns: Vec<_> = lines.iter().flat_map(|l| l.annotations.iter()).collect();
        assert!(all_anns.contains(&&TestAnn::A));
        assert!(all_anns.contains(&&TestAnn::B));
        assert!(all_anns.contains(&&TestAnn::C));

        // Check that annotations are distributed across lines, not all on one
        let lines_with_anns: Vec<_> = lines.iter().filter(|l| !l.annotations.is_empty()).collect();
        assert!(
            lines_with_anns.len() >= 2,
            "expected annotations on multiple lines"
        );
    }
}
