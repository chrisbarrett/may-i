// Declarative, color-as-data layout primitives for terminal output.
//
// Provides a tree of layout nodes (`Layout`) rendered to any `Write` sink. Leaf
// content is `Styled` — a run of `(SafeText, Style)` spans — so no layout value
// can carry an embedded ANSI escape: styling is *data* (a semantic `Style`
// role), and this renderer is the single site that turns a role into an actual
// SGR sequence. It is also the single site that decides colour enablement.
//
// Visible width is computed here from escape-free content; there are no
// caller-supplied width fields and no `strip_ansi`/`visible_len` helpers,
// because no value carries ANSI for them to strip.

use std::io::Write;

// Re-export the color-as-data vocabulary so consumers depend on one surface.
pub use may_i_pp::{Span, Style, Styled, atom_style};

// ── Terminal geometry ─────────────────────────────────────────────

const DIVIDER: &str = "│";

/// Terminal dimensions and colour enablement threaded through rendering.
#[derive(Debug, Clone, Copy)]
pub struct Terminal {
    pub width: usize,
    pub color: bool,
}

impl Terminal {
    /// A terminal of the given width with colour disabled.
    pub fn new(width: usize) -> Self {
        Self {
            width,
            color: false,
        }
    }

    /// Set colour enablement.
    #[must_use]
    pub fn with_color(mut self, color: bool) -> Self {
        self.color = color;
        self
    }

    /// Detect terminal width from the environment. Colour stays disabled; the
    /// sink decides colour from `NO_COLOR`/tty and sets it via `with_color`.
    pub fn detect() -> Self {
        let width = std::env::var("COLUMNS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .or_else(|| terminal_size::terminal_size().map(|(w, _)| w.0 as usize))
            .unwrap_or(80);
        Self::new(width)
    }
}

// ── Role → SGR (the single ANSI-emitting site) ────────────────────

/// SGR parameter string for a role, or `None` for `Style::Plain` (no escape).
/// This table is the only place a `\x1b` byte originates.
fn sgr_params(style: Style) -> Option<&'static str> {
    Some(match style {
        Style::Plain => return None,
        Style::Dimmed => "2",
        Style::Strong => "1",
        Style::Emphasis => "3",
        Style::Keyword => "94",
        Style::StringLit => "32",
        Style::FormHead => "34",
        Style::Allow => "1;32",
        Style::AllowSoft => "32",
        Style::Ask => "1;33",
        Style::AskSoft => "33",
        Style::AskEmphasis => "3;33",
        Style::Deny => "1;31",
        Style::DenySoft => "31",
        Style::Info => "1;34",
        Style::Accent => "36",
        Style::EchoAllow => "4;32",
        Style::EchoAsk => "4;33",
        Style::EchoDeny => "4;31",
    })
}

/// Write one styled span, emitting SGR only when colour is enabled.
fn write_span(w: &mut impl Write, span: &Span, color: bool) {
    match (color, sgr_params(span.style())) {
        (true, Some(params)) => {
            let _ = write!(w, "\x1b[{params}m{}\x1b[0m", span.content());
        }
        _ => {
            let _ = write!(w, "{}", span.content());
        }
    }
}

/// Write a styled run.
fn write_styled(w: &mut impl Write, s: &Styled, color: bool) {
    for span in s.spans() {
        write_span(w, span, color);
    }
}

/// Write chrome (dividers, fills) in the dimmed role.
fn write_dim(w: &mut impl Write, text: &str, color: bool) {
    if color {
        let _ = write!(w, "\x1b[2m{text}\x1b[0m");
    } else {
        let _ = write!(w, "{text}");
    }
}

// ── Layout types ──────────────────────────────────────────────────

/// Declarative layout tree for terminal output.
#[derive(Debug, Clone)]
pub enum Layout {
    /// Empty line.
    Blank,
    /// Horizontal rule spanning the terminal, with optional label.
    HRule(Option<HRuleLabel>),
    /// Two-column table with `│` divider.
    Columns(Vec<ColRow>),
    /// Indent child by `n` spaces.
    Indent(usize, Box<Layout>),
    /// Vertical sequence of children.
    Stack(Vec<Layout>),
    /// A single styled line.
    Text(Styled),
    /// Wrap items across lines with a separator, like a flow/inline layout.
    Wrap {
        items: Vec<ColItem>,
        separator: ColItem,
    },
    /// Advisory note with word-wrapped body text.
    Note(Note),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteLevel {
    Info,
    Warn,
    Error,
}

impl NoteLevel {
    /// The role used to colour this level's heading and icon.
    fn style(self) -> Style {
        match self {
            NoteLevel::Info => Style::Info,
            NoteLevel::Warn => Style::Ask,
            NoteLevel::Error => Style::Deny,
        }
    }

    fn icon(self) -> &'static str {
        match self {
            NoteLevel::Info => "ℹ",
            NoteLevel::Warn => "⚠",
            NoteLevel::Error => "✗",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Note {
    pub level: NoteLevel,
    pub heading: NoteHeading,
    /// Body paragraphs; each is word-wrapped by the renderer. (A `Styled` run
    /// cannot contain a newline, so paragraphs are an explicit list.)
    pub body: Vec<Styled>,
    /// Child layouts rendered inside the box, each separated by a dashed rule.
    pub children: Vec<Layout>,
}

/// Heading content for a note box. The heading appears in the top border after
/// the level icon. Carries styled content; visible width is derived.
#[derive(Debug, Clone)]
pub struct NoteHeading {
    pub content: Styled,
}

impl NoteHeading {
    fn width(&self) -> usize {
        self.content.width()
    }
}

impl From<Styled> for NoteHeading {
    fn from(content: Styled) -> Self {
        Self { content }
    }
}

impl From<String> for NoteHeading {
    fn from(s: String) -> Self {
        Self {
            content: Styled::plain(s),
        }
    }
}

impl From<&str> for NoteHeading {
    fn from(s: &str) -> Self {
        Self::from(s.to_string())
    }
}

/// High-level advisory box with structured fields.
///
/// Interpreted into a `Layout::Note` via `into_layout()`.
#[derive(Debug, Clone)]
pub struct Advisory {
    pub level: NoteLevel,
    pub heading: String,
    pub detail: String,
    pub suggestion: String,
    pub command: String,
    pub children: Vec<Layout>,
}

impl Advisory {
    /// Convert to a `Layout::Note`, colouring the heading by level (bold).
    pub fn into_layout(self) -> Layout {
        let style = self.level.style();
        let heading = NoteHeading {
            content: Styled::span(self.heading.clone(), style),
        };
        self.into_note_with_heading(heading)
    }

    /// Convert to a `Layout::Note` with a custom pre-styled heading.
    pub fn into_note_with_heading(self, heading: NoteHeading) -> Layout {
        let mut children = self.children;

        // Build suggestion + command as the last child section.
        if !self.suggestion.is_empty() || !self.command.is_empty() {
            let mut parts: Vec<Layout> = Vec::new();
            let has_suggestion = !self.suggestion.is_empty();
            if has_suggestion {
                parts.push(Layout::Text(Styled::plain(self.suggestion)));
            }
            if !self.command.is_empty() {
                if has_suggestion {
                    parts.push(Layout::Blank);
                }
                let cmd = Styled::span("$ ", Style::Dimmed).with(self.command, Style::Plain);
                parts.push(Layout::Text(cmd));
            }
            children.push(Layout::Stack(parts));
        }

        Layout::Note(Note {
            level: self.level,
            heading,
            body: paragraphs(&self.detail),
            children,
        })
    }
}

/// Split plain text into word-wrappable paragraphs on newlines.
fn paragraphs(text: &str) -> Vec<Styled> {
    if text.is_empty() {
        return Vec::new();
    }
    text.split('\n').map(Styled::plain).collect()
}

impl Layout {
    #[cfg(test)]
    fn indent(n: usize, inner: Layout) -> Layout {
        Layout::Indent(n, Box::new(inner))
    }
}

#[derive(Debug, Clone)]
pub struct HRuleLabel {
    pub content: Styled,
}

impl HRuleLabel {
    fn width(&self) -> usize {
        self.content.width()
    }
}

impl From<Styled> for HRuleLabel {
    fn from(content: Styled) -> Self {
        Self { content }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ColAlign {
    #[default]
    Left,
    Right,
}

/// Content for the right-hand side of a `ColRow`.
#[derive(Debug, Clone)]
pub enum ColContent {
    /// A single styled line.
    Text(Styled),
    /// A sequence of items that can be wrapped across multiple lines.
    Breakable {
        items: Vec<ColItem>,
        /// Separator inserted between items on the same line (e.g. ", ").
        separator: Styled,
    },
}

impl From<Styled> for ColContent {
    fn from(s: Styled) -> Self {
        ColContent::Text(s)
    }
}

impl From<&str> for ColContent {
    fn from(s: &str) -> Self {
        ColContent::Text(Styled::plain(s))
    }
}

impl From<String> for ColContent {
    fn from(s: String) -> Self {
        ColContent::Text(Styled::plain(s))
    }
}

/// One atomic item in a `Breakable` content sequence or a `Wrap`.
#[derive(Debug, Clone)]
pub struct ColItem {
    pub content: Styled,
}

impl ColItem {
    pub fn new(content: impl Into<Styled>) -> Self {
        Self {
            content: content.into(),
        }
    }

    fn width(&self) -> usize {
        self.content.width()
    }
}

#[derive(Debug, Clone)]
pub struct ColRow {
    pub left: Styled,
    pub left_align: ColAlign,
    pub right: ColContent,
}

impl ColRow {
    pub fn new(left: impl Into<Styled>, right: impl Into<ColContent>) -> Self {
        Self {
            left: left.into(),
            left_align: ColAlign::Left,
            right: right.into(),
        }
    }

    pub fn kv(label: impl Into<Styled>, value: impl Into<ColContent>) -> Self {
        Self {
            left: label.into(),
            left_align: ColAlign::Left,
            right: value.into(),
        }
    }

    #[must_use]
    pub fn right_aligned(mut self) -> Self {
        self.left_align = ColAlign::Right;
        self
    }

    fn left_width(&self) -> usize {
        self.left.width()
    }

    fn is_elision(&self) -> bool {
        self.left.width() == 1 && self.left.to_plain_string().contains('…')
    }
}

// ── Renderer ──────────────────────────────────────────────────────

pub fn write_layout(w: &mut impl Write, layout: &Layout, term: &Terminal) {
    render_layout(w, layout, 0, term);
}

/// Write a single styled line (plus newline) to `w`, honouring `term.color`.
/// The renderer remains the sole site that turns a role into an SGR sequence.
pub fn write_line(w: &mut impl Write, line: &Styled, term: &Terminal) {
    write_styled(w, line, term.color);
    let _ = writeln!(w);
}

fn render_layout(w: &mut impl Write, layout: &Layout, indent: usize, term: &Terminal) {
    match layout {
        Layout::Blank => {
            let _ = writeln!(w);
        }
        Layout::HRule(label) => {
            write_hrule(w, indent, label.as_ref(), term);
        }
        Layout::Columns(rows) => {
            write_columns(w, indent, rows, term);
        }
        Layout::Indent(n, inner) => {
            render_layout(w, inner, indent + n, term);
        }
        Layout::Stack(children) => {
            for child in children {
                render_layout(w, child, indent, term);
            }
        }
        Layout::Text(text) => {
            let _ = write!(w, "{:indent$}", "");
            write_styled(w, text, term.color);
            let _ = writeln!(w);
        }
        Layout::Wrap { items, separator } => {
            write_wrap(w, indent, items, separator, term);
        }
        Layout::Note(note) => {
            write_note(w, indent, note, term);
        }
    }
}

#[cfg(test)]
fn render_to_string(layout: &Layout, indent: usize, term: &Terminal) -> String {
    let mut buf = Vec::new();
    render_layout(&mut buf, layout, indent, term);
    let s = String::from_utf8_lossy(&buf).into_owned();
    if s.ends_with('\n') {
        s[..s.len() - 1].to_string()
    } else {
        s
    }
}

fn write_hrule(w: &mut impl Write, indent: usize, label: Option<&HRuleLabel>, term: &Terminal) {
    let usable = term.width.saturating_sub(indent);
    match label {
        Some(label) => {
            let prefix = "─── ";
            let mid = " ";
            let used = prefix.chars().count() + label.width() + mid.chars().count();
            let remaining = usable.saturating_sub(used);
            let suffix = "─".repeat(remaining);
            let _ = write!(w, "{:indent$}", "");
            write_dim(w, prefix, term.color);
            write_styled(w, &label.content, term.color);
            write_dim(w, mid, term.color);
            write_dim(w, &suffix, term.color);
            let _ = writeln!(w);
        }
        None => {
            let rule = "─".repeat(usable);
            let _ = write!(w, "{:indent$}", "");
            write_dim(w, &rule, term.color);
            let _ = writeln!(w);
        }
    }
}

fn write_columns(w: &mut impl Write, indent: usize, rows: &[ColRow], term: &Terminal) {
    let divider_col = compute_divider_col(rows);
    for row in rows {
        write_col_row(w, indent, row, divider_col, term);
    }
}

fn compute_divider_col(rows: &[ColRow]) -> usize {
    let max_left = rows
        .iter()
        .filter(|r| !r.is_elision())
        .map(ColRow::left_width)
        .max()
        .unwrap_or(0);
    max_left + 1
}

fn write_col_row(
    w: &mut impl Write,
    indent: usize,
    row: &ColRow,
    divider_col: usize,
    term: &Terminal,
) {
    match &row.right {
        ColContent::Text(text) => {
            if row.left.is_empty() && text.is_empty() {
                return;
            }
            write_col_left(w, indent, row, divider_col, term);
            write_dim(w, DIVIDER, term.color);
            if !text.is_empty() {
                let _ = write!(w, " ");
                write_styled(w, text, term.color);
            }
            let _ = writeln!(w);
        }
        ColContent::Breakable { items, separator } => {
            let right_avail = term
                .width
                .saturating_sub(indent + divider_col + 1) // divider
                .saturating_sub(2); // " │ " padding → " " after divider

            let lines = wrap_breakable(items, separator, right_avail);

            if lines.is_empty() {
                write_col_left(w, indent, row, divider_col, term);
                write_dim(w, DIVIDER, term.color);
                let _ = writeln!(w);
            } else {
                for (i, line) in lines.iter().enumerate() {
                    if i == 0 {
                        write_col_left(w, indent, row, divider_col, term);
                    } else {
                        let _ = write!(w, "{:indent$}{:divider_col$}", "", "");
                    }
                    write_dim(w, DIVIDER, term.color);
                    let _ = write!(w, " ");
                    write_styled(w, line, term.color);
                    let _ = writeln!(w);
                }
            }
        }
    }
}

/// Word-wrap breakable items into styled lines. Continued lines carry a
/// trailing separator; the final line does not.
fn wrap_breakable(items: &[ColItem], separator: &Styled, avail: usize) -> Vec<Styled> {
    let sep_width = separator.width();
    let mut lines: Vec<Styled> = Vec::new();
    let mut cur = Styled::new();
    let mut cur_width = 0;

    for (i, item) in items.iter().enumerate() {
        let need_sep = !cur.is_empty();
        let addition = if need_sep {
            sep_width + item.width()
        } else {
            item.width()
        };

        if !cur.is_empty() && cur_width + addition > avail {
            cur.extend(separator.clone());
            lines.push(std::mem::take(&mut cur));
            cur_width = 0;
        }

        if !cur.is_empty() {
            cur.extend(separator.clone());
            cur_width += sep_width;
        }
        cur.extend(item.content.clone());
        cur_width += item.width();

        if i == items.len() - 1 && !cur.is_empty() {
            lines.push(std::mem::take(&mut cur));
        }
    }

    lines
}

/// Write the left-hand side of a column row (label + alignment padding).
fn write_col_left(
    w: &mut impl Write,
    indent: usize,
    row: &ColRow,
    divider_col: usize,
    term: &Terminal,
) {
    let gap = divider_col.saturating_sub(row.left_width());
    let (lead, trail) = match row.left_align {
        ColAlign::Right => (gap.saturating_sub(1), 1),
        ColAlign::Left => (0, gap),
    };
    let _ = write!(w, "{:indent$}{:lead$}", "", "");
    write_styled(w, &row.left, term.color);
    let _ = write!(w, "{:trail$}", "");
}

fn write_wrap(
    w: &mut impl Write,
    indent: usize,
    items: &[ColItem],
    separator: &ColItem,
    term: &Terminal,
) {
    let avail = term.width.saturating_sub(indent);
    let sep_width = separator.width();
    let mut lines: Vec<Styled> = Vec::new();
    let mut cur = Styled::new();
    let mut cur_width = 0;

    for (i, item) in items.iter().enumerate() {
        let need_sep = !cur.is_empty();
        let addition = if need_sep {
            sep_width + item.width()
        } else {
            item.width()
        };

        if !cur.is_empty() && cur_width + addition > avail {
            // Break before the next item without a trailing separator — Wrap is
            // prose-style flow, not Breakable.
            lines.push(std::mem::take(&mut cur));
            cur_width = 0;
        }

        if !cur.is_empty() {
            cur.extend(separator.content.clone());
            cur_width += sep_width;
        }
        cur.extend(item.content.clone());
        cur_width += item.width();

        if i == items.len() - 1 && !cur.is_empty() {
            lines.push(std::mem::take(&mut cur));
        }
    }

    for line in &lines {
        let _ = write!(w, "{:indent$}", "");
        write_styled(w, line, term.color);
        let _ = writeln!(w);
    }
}

fn write_note(w: &mut impl Write, indent: usize, note: &Note, term: &Terminal) {
    let usable = term.width.saturating_sub(indent);
    let level_style = note.level.style();
    let icon = note.level.icon();

    // Top border: ╭─ ⚠ Heading text ───────╮
    let header_visible_width = icon.chars().count() + 1 + note.heading.width();
    let top_prefix = "╭─ ";
    let top_mid = " ";
    let top_used = top_prefix.chars().count() + header_visible_width + top_mid.chars().count() + 1; // +1 for ╮
    let top_fill = usable.saturating_sub(top_used);
    let _ = write!(w, "{:indent$}", "");
    write_dim(w, top_prefix, term.color);
    write_span(w, &Span::new(icon, level_style), term.color);
    let _ = write!(w, " ");
    write_styled(w, &note.heading.content, term.color);
    write_dim(w, top_mid, term.color);
    write_dim(w, &"─".repeat(top_fill), term.color);
    write_dim(w, "╮", term.color);
    let _ = writeln!(w);

    // "│ " prefix + " │" suffix = 4 chars of box chrome.
    let inner_width = usable.saturating_sub(4).max(10);

    // Body: each paragraph word-wrapped, blank line between paragraphs.
    for (i, para) in note.body.iter().enumerate() {
        if i > 0 {
            write_box_line(w, indent, usable, &Styled::new(), 0, term);
        }
        let plain = para.to_plain_string();
        for line in word_wrap(plain.trim(), inner_width) {
            let width = line.chars().count();
            write_box_line(w, indent, usable, &Styled::plain(line), width, term);
        }
    }

    // Child layouts rendered inside the box, each preceded by a dashed separator.
    let mid_fill = usable.saturating_sub(2);
    let child_term = Terminal::new(inner_width).with_color(term.color);
    let measure_term = Terminal::new(inner_width);
    for child in &note.children {
        let _ = write!(w, "{:indent$}", "");
        write_dim(w, "├", term.color);
        write_dim(w, &"┄".repeat(mid_fill), term.color);
        write_dim(w, "┤", term.color);
        let _ = writeln!(w);

        let mut color_buf = Vec::new();
        render_layout(&mut color_buf, child, 0, &child_term);
        let color_str = String::from_utf8_lossy(&color_buf).into_owned();

        let mut plain_buf = Vec::new();
        render_layout(&mut plain_buf, child, 0, &measure_term);
        let plain_str = String::from_utf8_lossy(&plain_buf).into_owned();

        for (display, plain) in color_str.lines().zip(plain_str.lines()) {
            let vis_width = plain.chars().count();
            write_box_line_raw(w, indent, usable, display, vis_width, term);
        }
    }

    // Bottom border: ╰──────╯
    let bottom_fill = usable.saturating_sub(2);
    let _ = write!(w, "{:indent$}", "");
    write_dim(w, "╰", term.color);
    write_dim(w, &"─".repeat(bottom_fill), term.color);
    write_dim(w, "╯", term.color);
    let _ = writeln!(w);
}

/// Write a styled line inside a box: "│ content                 │".
fn write_box_line(
    w: &mut impl Write,
    indent: usize,
    box_width: usize,
    text: &Styled,
    text_width: usize,
    term: &Terminal,
) {
    let inner_width = box_width.saturating_sub(4);
    let _ = write!(w, "{:indent$}", "");
    write_dim(w, DIVIDER, term.color);
    let _ = write!(w, " ");
    write_styled(w, text, term.color);
    if text_width > inner_width {
        let _ = writeln!(w);
    } else {
        let padding = inner_width - text_width;
        let _ = write!(w, "{:padding$} ", "");
        write_dim(w, DIVIDER, term.color);
        let _ = writeln!(w);
    }
}

/// Like `write_box_line` but the content is pre-rendered display bytes (already
/// styled) with a known visible width — used for child sub-layouts.
fn write_box_line_raw(
    w: &mut impl Write,
    indent: usize,
    box_width: usize,
    display: &str,
    text_width: usize,
    term: &Terminal,
) {
    let inner_width = box_width.saturating_sub(4);
    let _ = write!(w, "{:indent$}", "");
    write_dim(w, DIVIDER, term.color);
    let _ = write!(w, " {display}");
    if text_width > inner_width {
        let _ = writeln!(w);
    } else {
        let padding = inner_width - text_width;
        let _ = write!(w, "{:padding$} ", "");
        write_dim(w, DIVIDER, term.color);
        let _ = writeln!(w);
    }
}

/// Word-wrap plain text into lines fitting `max_width`.
fn word_wrap(text: &str, max_width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut cur = String::new();
    let mut cur_width = 0;

    for word in &words {
        let w_len = word.chars().count();
        if !cur.is_empty() && cur_width + 1 + w_len > max_width {
            lines.push(cur);
            cur = String::new();
            cur_width = 0;
        }
        if !cur.is_empty() {
            cur.push(' ');
            cur_width += 1;
        }
        cur.push_str(word);
        cur_width += w_len;
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    const TERM: Terminal = Terminal {
        width: 120,
        color: false,
    };

    fn col_row(left: &str, right: &str) -> ColRow {
        ColRow::new(Styled::plain(left), Styled::plain(right))
    }

    #[test]
    fn blank_renders_empty_line() {
        let s = render_to_string(&Layout::Blank, 0, &TERM);
        assert_eq!(s, "");
    }

    #[test]
    fn text_renders_with_indent() {
        let s = render_to_string(&Layout::Text(Styled::plain("hello")), 4, &TERM);
        assert_eq!(s, "    hello");
    }

    #[test]
    fn indent_adds_to_children() {
        let layout = Layout::indent(3, Layout::Text(Styled::plain("hi")));
        let s = render_to_string(&layout, 0, &TERM);
        assert_eq!(s, "   hi");
    }

    #[test]
    fn stack_renders_children_sequentially() {
        let layout = Layout::Stack(vec![
            Layout::Text(Styled::plain("a")),
            Layout::Text(Styled::plain("b")),
        ]);
        let s = render_to_string(&layout, 0, &TERM);
        assert_eq!(s, "a\nb");
    }

    #[test]
    fn columns_aligns_divider() {
        let rows = vec![col_row("short", "r1"), col_row("longer left", "r2")];
        let layout = Layout::Columns(rows);
        let s = render_to_string(&layout, 0, &TERM);
        let lines: Vec<&str> = s.lines().collect();
        let div_pos_0 = lines[0].find('│').unwrap();
        let div_pos_1 = lines[1].find('│').unwrap();
        assert_eq!(div_pos_0, div_pos_1);
    }

    #[test]
    fn columns_right_align() {
        let row = col_row("text", "ann").right_aligned();
        let layout = Layout::Columns(vec![col_row("longer", ""), row]);
        let s = render_to_string(&layout, 0, &TERM);
        let lines: Vec<&str> = s.lines().collect();
        assert!(lines[1].starts_with("  text"), "got: {:?}", lines[1]);
    }

    #[test]
    fn hrule_without_label() {
        let layout = Layout::HRule(None);
        let s = render_to_string(&layout, 0, &TERM);
        assert!(s.contains('─'));
    }

    #[test]
    fn hrule_with_label() {
        let layout = Layout::HRule(Some(HRuleLabel::from(Styled::plain("section"))));
        let s = render_to_string(&layout, 0, &TERM);
        assert!(s.contains("section"));
        assert!(s.contains('─'));
    }

    #[test]
    fn kv_creates_left_aligned_row() {
        let row = ColRow::kv(Styled::plain("key"), Styled::plain("value"));
        assert_eq!(row.left.to_plain_string(), "key");
        assert_eq!(row.left_width(), 3);
        assert!(matches!(row.left_align, ColAlign::Left));
    }

    #[test]
    fn note_heading_from_unicode_uses_visible_width() {
        let heading = NoteHeading::from("ℹ Info".to_string());
        assert_eq!(heading.width(), 6);
    }

    #[test]
    fn note_warn_with_body() {
        let term = Terminal::new(50);
        let layout = Layout::Note(Note {
            level: NoteLevel::Warn,
            heading: "Test heading".into(),
            body: paragraphs("This is the body text."),
            children: vec![],
        });
        let s = render_to_string(&layout, 0, &term);
        insta::assert_snapshot!(s);
    }

    #[test]
    fn note_info_level() {
        let term = Terminal::new(50);
        let layout = Layout::Note(Note {
            level: NoteLevel::Info,
            heading: "FYI".into(),
            body: paragraphs("Something to know."),
            children: vec![],
        });
        let s = render_to_string(&layout, 0, &term);
        insta::assert_snapshot!(s);
    }

    #[test]
    fn note_error_level() {
        let term = Terminal::new(50);
        let layout = Layout::Note(Note {
            level: NoteLevel::Error,
            heading: "Bad thing".into(),
            body: paragraphs("Something went wrong."),
            children: vec![],
        });
        let s = render_to_string(&layout, 0, &term);
        insta::assert_snapshot!(s);
    }

    #[test]
    fn note_wraps_body_at_terminal_width() {
        let term = Terminal::new(30);
        let layout = Layout::Note(Note {
            level: NoteLevel::Warn,
            heading: "Warn".into(),
            body: paragraphs("one two three four five six seven eight nine ten"),
            children: vec![],
        });
        let s = render_to_string(&layout, 0, &term);
        insta::assert_snapshot!(s);
    }

    #[test]
    fn note_with_empty_body() {
        let term = Terminal::new(50);
        let layout = Layout::Note(Note {
            level: NoteLevel::Warn,
            heading: "Heads up".into(),
            body: vec![],
            children: vec![],
        });
        let s = render_to_string(&layout, 0, &term);
        insta::assert_snapshot!(s);
    }

    #[test]
    fn note_with_indent() {
        let term = Terminal::new(50);
        let layout = Layout::indent(
            4,
            Layout::Note(Note {
                level: NoteLevel::Info,
                heading: "Hi".into(),
                body: paragraphs("Hello world."),
                children: vec![],
            }),
        );
        let s = render_to_string(&layout, 0, &term);
        insta::assert_snapshot!(s);
    }

    #[test]
    fn note_box_lines_are_same_visible_width() {
        let term = Terminal::new(50);
        let layout = Layout::Note(Note {
            level: NoteLevel::Warn,
            heading: "Short".into(),
            body: paragraphs("Some body text here."),
            children: vec![],
        });
        let s = render_to_string(&layout, 0, &term);
        let widths: Vec<usize> = s.lines().map(|l| l.chars().count()).collect();
        let first = widths[0];
        for (i, &w) in widths.iter().enumerate() {
            assert_eq!(w, first, "line {i} width {w} != expected {first}: {s:?}");
        }
    }

    #[test]
    fn note_overflow_line_omits_right_border() {
        let term = Terminal::new(30);
        let long_path = "/very/long/path/that/exceeds/the/box/width/entirely";
        let layout = Layout::Note(Note {
            level: NoteLevel::Warn,
            heading: "Warn".into(),
            body: paragraphs(long_path),
            children: vec![],
        });
        let s = render_to_string(&layout, 0, &term);
        let body_lines: Vec<&str> = s.lines().filter(|l| l.contains(long_path)).collect();
        assert!(!body_lines.is_empty(), "should contain the long path");
        for line in &body_lines {
            assert!(
                !line.ends_with('│'),
                "overflow line should omit right border: {line:?}"
            );
        }
    }

    #[test]
    fn note_with_paragraphs() {
        let term = Terminal::new(50);
        let layout = Layout::Note(Note {
            level: NoteLevel::Warn,
            heading: "Migration needed".into(),
            body: paragraphs("Config format is outdated.\nRun this command:\n$ may-i migrate"),
            children: vec![],
        });
        let s = render_to_string(&layout, 0, &term);
        insta::assert_snapshot!(s);
    }

    #[test]
    fn note_with_child_layout() {
        let term = Terminal::new(50);
        let child = Layout::Stack(vec![
            Layout::Text(Styled::plain("~/foo.lisp (3)")),
            Layout::Text(Styled::plain("   ls, cat, rm")),
        ]);
        let layout = Layout::Note(Note {
            level: NoteLevel::Warn,
            heading: "Test".into(),
            body: paragraphs("Body text."),
            children: vec![child],
        });
        let s = render_to_string(&layout, 0, &term);
        insta::assert_snapshot!(s);
    }

    #[test]
    fn advisory_into_layout() {
        let term = Terminal::new(60);
        let layout = Advisory {
            level: NoteLevel::Warn,
            heading: "Outdated configuration format".into(),
            detail: "Tracing output may differ from the real file.".into(),
            suggestion: "Update your config to the latest syntax:".into(),
            command: "may-i migrate".into(),
            children: vec![],
        }
        .into_layout();
        let s = render_to_string(&layout, 0, &term);
        insta::assert_snapshot!(s);
    }

    #[test]
    fn advisory_narrow_terminal() {
        let term = Terminal::new(40);
        let layout = Advisory {
            level: NoteLevel::Warn,
            heading: "Outdated config".into(),
            detail: "Tracing output may differ from the real file.".into(),
            suggestion: "Update your config:".into(),
            command: "may-i migrate".into(),
            children: vec![],
        }
        .into_layout();
        let s = render_to_string(&layout, 0, &term);
        insta::assert_snapshot!(s);
    }

    #[test]
    fn breakable_with_empty_items() {
        let rows = vec![ColRow {
            left: Styled::plain("lbl"),
            left_align: ColAlign::Left,
            right: ColContent::Breakable {
                items: vec![],
                separator: Styled::plain(", "),
            },
        }];
        let layout = Layout::Columns(rows);
        let s = render_to_string(&layout, 0, &TERM);
        assert!(s.contains('│'));
    }

    #[test]
    fn color_off_emits_no_escape() {
        let layout = Layout::Columns(vec![ColRow::new(
            Styled::span("k", Style::Keyword),
            Styled::span("v", Style::Allow),
        )]);
        let s = render_to_string(&layout, 0, &Terminal::new(40));
        assert!(!s.contains('\x1b'));
    }

    #[test]
    fn color_on_emits_palette_sgr() {
        let layout = Layout::Text(Styled::span("k", Style::Keyword));
        let s = render_to_string(&layout, 0, &Terminal::new(40).with_color(true));
        assert!(s.contains("\x1b[94m"));
        assert!(s.contains("\x1b[0m"));
    }

    #[test]
    fn breakable_wraps_items_across_lines() {
        let term = Terminal::new(30);
        let rows = vec![ColRow {
            left: Styled::plain("label"),
            left_align: ColAlign::Right,
            right: ColContent::Breakable {
                items: vec![
                    ColItem::new(Styled::plain("aaaa")),
                    ColItem::new(Styled::plain("bbbb")),
                    ColItem::new(Styled::plain("cccc")),
                    ColItem::new(Styled::plain("dddd")),
                    ColItem::new(Styled::plain("eeee")),
                ],
                separator: Styled::plain(", "),
            },
        }];
        let layout = Layout::Columns(rows);
        let s = render_to_string(&layout, 0, &term);
        let lines: Vec<&str> = s.lines().collect();
        assert!(lines.len() > 1, "expected wrapping: {s:?}");
        for line in &lines {
            assert!(
                line.contains('│'),
                "each line should have divider: {line:?}"
            );
        }
        for line in &lines[..lines.len() - 1] {
            let after_div = line.split('│').nth(1).unwrap().trim();
            assert!(
                after_div.ends_with(','),
                "continued line should end with separator: {line:?}"
            );
        }
    }

    #[test]
    fn breakable_fits_on_one_line() {
        let term = Terminal::new(80);
        let rows = vec![ColRow {
            left: Styled::plain("lbl"),
            left_align: ColAlign::Right,
            right: ColContent::Breakable {
                items: vec![
                    ColItem::new(Styled::plain("a")),
                    ColItem::new(Styled::plain("b")),
                ],
                separator: Styled::plain(", "),
            },
        }];
        let layout = Layout::Columns(rows);
        let s = render_to_string(&layout, 0, &term);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 1, "should fit on one line: {s:?}");
        assert!(s.contains("a, b"), "items joined with separator: {s:?}");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn any_note_level() -> impl Strategy<Value = NoteLevel> {
        prop_oneof![
            Just(NoteLevel::Info),
            Just(NoteLevel::Warn),
            Just(NoteLevel::Error),
        ]
    }

    fn any_layout() -> BoxedStrategy<Layout> {
        let leaf = prop_oneof![
            Just(Layout::Blank),
            Just(Layout::HRule(None)),
            "[a-z ]{0,30}".prop_map(|s| Layout::HRule(Some(HRuleLabel::from(Styled::plain(s))))),
            "[a-z ]{0,40}".prop_map(|s| Layout::Text(Styled::plain(s))),
            (any_note_level(), "[a-z ]{1,20}", "[a-z ]{0,40}").prop_map(
                |(level, heading, body)| {
                    Layout::Note(Note {
                        level,
                        heading: heading.into(),
                        body: paragraphs(&body),
                        children: vec![],
                    })
                }
            ),
            prop::collection::vec(
                ("[a-z]{1,10}", "[a-z ]{0,20}")
                    .prop_map(|(l, r)| ColRow::new(Styled::plain(l), Styled::plain(r))),
                1..=4,
            )
            .prop_map(Layout::Columns),
            prop::collection::vec(
                "[a-z]{1,10}".prop_map(|s| ColItem::new(Styled::plain(s))),
                1..=6,
            )
            .prop_map(|items| Layout::Wrap {
                items,
                separator: ColItem::new(Styled::plain(", ")),
            }),
        ];
        leaf.prop_recursive(2, 8, 3, |inner| {
            prop_oneof![
                (1..6usize, inner.clone()).prop_map(|(n, l)| Layout::Indent(n, Box::new(l))),
                prop::collection::vec(inner, 0..4).prop_map(Layout::Stack),
            ]
        })
        .boxed()
    }

    fn item_strategy() -> impl Strategy<Value = ColItem> {
        "[a-z]{1,10}".prop_map(|s| ColItem::new(Styled::plain(s)))
    }

    proptest! {
        #[test]
        fn breakable_preserves_all_items(
            items in prop::collection::vec(item_strategy(), 1..20),
            term_cols in 30..120usize,
            label_width in 1..20usize,
        ) {
            let term = Terminal::new(term_cols);
            let label = "x".repeat(label_width);
            let rows = vec![ColRow {
                left: Styled::plain(label),
                left_align: ColAlign::Right,
                right: ColContent::Breakable {
                    items: items.clone(),
                    separator: Styled::plain(", "),
                },
            }];
            let layout = Layout::Columns(rows);
            let s = render_to_string(&layout, 0, &term);

            for item in &items {
                prop_assert!(
                    s.contains(&item.content.to_plain_string()),
                    "item {:?} missing from output: {s:?}",
                    item.content.to_plain_string()
                );
            }
            for line in s.lines() {
                prop_assert!(line.contains('│'), "line missing divider: {line:?}");
            }
            let lines: Vec<&str> = s.lines().collect();
            if lines.len() > 1 {
                for line in &lines[..lines.len() - 1] {
                    let after_div = line.split('│').nth(1).unwrap().trim();
                    prop_assert!(
                        after_div.ends_with(','),
                        "continued line should end with separator: {line:?}"
                    );
                }
                let last = lines.last().unwrap();
                let after_div = last.split('│').nth(1).unwrap().trim();
                prop_assert!(
                    !after_div.ends_with(','),
                    "final line should not end with separator: {last:?}"
                );
            }
        }

        #[test]
        fn word_wrap_preserves_all_words(
            words in prop::collection::vec("[a-z]{1,15}", 1..20),
            max_width in 10usize..80,
        ) {
            let text = words.join(" ");
            let wrapped = word_wrap(&text, max_width);
            let all_output_words: Vec<&str> = wrapped.iter()
                .flat_map(|line| line.split_whitespace())
                .collect();
            prop_assert_eq!(all_output_words.len(), words.len());
            for (orig, out) in words.iter().zip(all_output_words.iter()) {
                prop_assert_eq!(orig.as_str(), *out);
            }
        }

        #[test]
        fn word_wrap_respects_width(
            words in prop::collection::vec("[a-z]{1,8}", 1..20),
            max_width in 10usize..80,
        ) {
            let text = words.join(" ");
            let wrapped = word_wrap(&text, max_width);
            for line in &wrapped {
                let line_words: Vec<&str> = line.split_whitespace().collect();
                if line_words.len() > 1 {
                    prop_assert!(line.chars().count() <= max_width,
                        "multi-word line exceeds width {}: {:?}", max_width, line);
                }
            }
        }

        /// Colour off: the renderer emits no control character for any layout.
        #[test]
        fn color_off_render_is_control_free(layout in any_layout(), width in 20..200usize) {
            let term = Terminal::new(width);
            let mut buf = Vec::new();
            write_layout(&mut buf, &layout, &term);
            let s = String::from_utf8_lossy(&buf);
            for c in s.chars() {
                prop_assert!(c == '\n' || !c.is_control(), "control char leaked: {c:?}");
            }
        }

        /// write_layout never panics on arbitrary layouts and widths.
        #[test]
        fn write_layout_never_panics(layout in any_layout(), width in 20..200usize) {
            let term = Terminal::new(width).with_color(true);
            let mut buf = Vec::new();
            write_layout(&mut buf, &layout, &term);
            let _ = String::from_utf8_lossy(&buf);
        }
    }

    #[test]
    fn word_wrap_empty_input() {
        let result = word_wrap("", 80);
        assert_eq!(result, vec![String::new()]);
    }
}
