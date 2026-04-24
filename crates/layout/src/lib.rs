// Declarative layout primitives for terminal output.
//
// Provides a tree of layout nodes (`Layout`) that can be rendered to any
// `Write` sink. The trace/check commands construct Layout trees, which are
// then rendered in one pass — separating structure from presentation.

use std::io::Write;

use colored::Colorize;
use may_i_pp::visible_len;

// ── Terminal geometry ─────────────────────────────────────────────

const DIVIDER: &str = "│";

/// Terminal dimensions threaded through layout rendering.
#[derive(Debug, Clone, Copy)]
pub struct Terminal {
    pub width: usize,
}

impl Terminal {
    pub fn new(width: usize) -> Self {
        Self { width }
    }

    /// Detect terminal width from the environment.
    pub fn detect() -> Self {
        let width = std::env::var("COLUMNS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .or_else(|| terminal_size::terminal_size().map(|(w, _)| w.0 as usize))
            .unwrap_or(80);
        Self { width }
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
    /// Pre-formatted text line(s).
    Text(String),
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

#[derive(Debug, Clone)]
pub struct Note {
    pub level: NoteLevel,
    pub heading: NoteHeading,
    pub body: String,
    /// Child layouts rendered inside the box, each separated by a dashed rule.
    pub children: Vec<Layout>,
}

/// Heading content for a note box.
///
/// The heading appears in the top border after the level icon. Use `From<String>`
/// for plain text (colored by level), or construct directly with pre-styled text
/// and its visible width.
#[derive(Debug, Clone)]
pub struct NoteHeading {
    /// Pre-rendered heading text (may contain ANSI codes).
    pub text: String,
    /// Visible width of `text` (excluding ANSI).
    pub visible_width: usize,
}

impl From<String> for NoteHeading {
    fn from(s: String) -> Self {
        let visible_width = visible_len(&s);
        Self {
            text: s,
            visible_width,
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
    /// Convert to a `Layout::Note`, coloring the heading by level.
    pub fn into_layout(self) -> Layout {
        let colorize: fn(&str) -> colored::ColoredString = match self.level {
            NoteLevel::Info => |s| s.blue(),
            NoteLevel::Warn => |s| s.yellow(),
            NoteLevel::Error => |s| s.red(),
        };
        let heading = NoteHeading {
            visible_width: visible_len(&self.heading),
            text: colorize(&self.heading).bold().to_string(),
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
                parts.push(Layout::Text(self.suggestion));
            }
            if !self.command.is_empty() {
                if has_suggestion {
                    parts.push(Layout::Blank);
                }
                let cmd_text = format!("{}{}", "$ ".dimmed(), self.command,);
                parts.push(Layout::Text(cmd_text));
            }
            children.push(Layout::Stack(parts));
        }

        Layout::Note(Note {
            level: self.level,
            heading,
            body: self.detail,
            children,
        })
    }
}

impl Layout {
    #[cfg(test)]
    fn indent(n: usize, inner: Layout) -> Layout {
        Layout::Indent(n, Box::new(inner))
    }
}

#[derive(Debug, Clone)]
pub struct HRuleLabel {
    pub text: String,
    pub visible_width: usize,
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
    /// A single pre-formatted string.
    Text(String),
    /// A sequence of items that can be wrapped across multiple lines.
    Breakable {
        items: Vec<ColItem>,
        /// Separator inserted between items on the same line (e.g. ", ").
        separator: String,
        /// Visible width of the separator.
        separator_width: usize,
    },
}

/// One atomic item in a `Breakable` content sequence.
#[derive(Debug, Clone)]
pub struct ColItem {
    /// Rendered (possibly colored) text.
    pub text: String,
    /// Visible width of `text`.
    pub width: usize,
}

impl ColItem {
    pub fn new(text: impl Into<String>, width: usize) -> Self {
        Self {
            text: text.into(),
            width,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ColRow {
    pub left: String,
    pub left_width: usize,
    pub left_align: ColAlign,
    pub right: ColContent,
}

impl ColRow {
    pub fn new(left: impl Into<String>, left_width: usize, right: impl Into<String>) -> Self {
        Self {
            left: left.into(),
            left_width,
            left_align: ColAlign::Left,
            right: ColContent::Text(right.into()),
        }
    }

    pub fn kv(label: impl Into<String>, value: impl Into<String>) -> Self {
        let label = label.into();
        let width = visible_len(&label);
        Self {
            left: label,
            left_width: width,
            left_align: ColAlign::Left,
            right: ColContent::Text(value.into()),
        }
    }

    #[cfg(test)]
    fn with_align(mut self, align: ColAlign) -> Self {
        self.left_align = align;
        self
    }

    fn is_elision(&self) -> bool {
        self.left_width == 1 && self.left.contains('…')
    }
}

// ── Renderer ──────────────────────────────────────────────────────

pub fn write_layout(w: &mut impl Write, layout: &Layout, term: &Terminal) {
    render_layout(w, layout, 0, term);
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
            let _ = writeln!(w, "{:indent$}{text}", "");
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
    // Trim trailing newline so callers get clean content.
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
            let used = visible_len(prefix) + label.visible_width + visible_len(mid);
            let remaining = usable.saturating_sub(used);
            let suffix = "─".repeat(remaining);
            let _ = writeln!(
                w,
                "{:indent$}{}{}{}{}",
                "",
                prefix.dimmed(),
                label.text,
                mid.dimmed(),
                suffix.dimmed(),
            );
        }
        None => {
            let rule = "─".repeat(usable);
            let _ = writeln!(w, "{:indent$}{}", "", rule.dimmed());
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
        .map(|r| r.left_width)
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
            let right = if text.is_empty() {
                String::new()
            } else {
                format!(" {text}")
            };
            write_col_left(w, indent, row, divider_col);
            let _ = writeln!(w, "{}{right}", DIVIDER.dimmed());
        }
        ColContent::Breakable {
            items,
            separator,
            separator_width,
        } => {
            let right_avail = term
                .width
                .saturating_sub(indent + divider_col + 1) // divider
                .saturating_sub(2); // " │ " padding → " " after divider

            // Word-wrap items into lines.
            let mut lines: Vec<String> = Vec::new();
            let mut cur = String::new();
            let mut cur_width = 0;

            for (i, item) in items.iter().enumerate() {
                let need_sep = !cur.is_empty();
                let addition = if need_sep {
                    separator_width + item.width
                } else {
                    item.width
                };

                if !cur.is_empty() && cur_width + addition > right_avail {
                    // Trailing separator on continued lines.
                    cur.push_str(separator);
                    lines.push(cur);
                    cur = String::new();
                    cur_width = 0;
                }

                if !cur.is_empty() {
                    cur.push_str(separator);
                    cur_width += separator_width;
                }
                cur.push_str(&item.text);
                cur_width += item.width;

                if i == items.len() - 1 && !cur.is_empty() {
                    lines.push(std::mem::take(&mut cur));
                }
            }

            if lines.is_empty() {
                write_col_left(w, indent, row, divider_col);
                let _ = writeln!(w, "{}", DIVIDER.dimmed());
            } else {
                for (i, line) in lines.iter().enumerate() {
                    if i == 0 {
                        write_col_left(w, indent, row, divider_col);
                    } else {
                        // Continuation lines: empty left, same divider position.
                        let _ = write!(w, "{:indent$}{:divider_col$}", "", "");
                    }
                    let _ = writeln!(w, "{} {line}", DIVIDER.dimmed());
                }
            }
        }
    }
}

/// Write the left-hand side of a column row (label + alignment padding).
fn write_col_left(w: &mut impl Write, indent: usize, row: &ColRow, divider_col: usize) {
    let gap = divider_col.saturating_sub(row.left_width);
    let (lead, trail) = match row.left_align {
        ColAlign::Right => (gap.saturating_sub(1), 1),
        ColAlign::Left => (0, gap),
    };
    let _ = write!(w, "{:indent$}{:lead$}{}{:trail$}", "", "", row.left, "",);
}

fn write_wrap(
    w: &mut impl Write,
    indent: usize,
    items: &[ColItem],
    separator: &ColItem,
    term: &Terminal,
) {
    let avail = term.width.saturating_sub(indent);
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut cur_width = 0;

    for (i, item) in items.iter().enumerate() {
        let need_sep = !cur.is_empty();
        let addition = if need_sep {
            separator.width + item.width
        } else {
            item.width
        };

        if !cur.is_empty() && cur_width + addition > avail {
            cur.push_str(&separator.text);
            lines.push(cur);
            cur = String::new();
            cur_width = 0;
        }

        if !cur.is_empty() {
            cur.push_str(&separator.text);
            cur_width += separator.width;
        }
        cur.push_str(&item.text);
        cur_width += item.width;

        if i == items.len() - 1 && !cur.is_empty() {
            lines.push(std::mem::take(&mut cur));
        }
    }

    for line in &lines {
        let _ = writeln!(w, "{:indent$}{line}", "");
    }
}

fn write_note(w: &mut impl Write, indent: usize, note: &Note, term: &Terminal) {
    let icon: &str = match note.level {
        NoteLevel::Info => "ℹ",
        NoteLevel::Warn => "⚠",
        NoteLevel::Error => "✗",
    };

    let colorize: fn(&str) -> colored::ColoredString = match note.level {
        NoteLevel::Info => |s| s.blue(),
        NoteLevel::Warn => |s| s.yellow(),
        NoteLevel::Error => |s| s.red(),
    };

    let usable = term.width.saturating_sub(indent);

    // Top border: ╭─ ⚠ Heading text ───────╮
    let header = format!("{} {}", colorize(icon).bold(), note.heading.text);
    let header_visible_width = visible_len(icon) + 1 + note.heading.visible_width;
    let top_prefix = "╭─ ";
    let top_mid = " ";
    let top_used = visible_len(top_prefix) + header_visible_width + visible_len(top_mid) + 1; // +1 for ╮
    let top_fill = usable.saturating_sub(top_used);
    let _ = writeln!(
        w,
        "{:indent$}{}{}{}{}{}",
        "",
        top_prefix.dimmed(),
        header,
        top_mid.dimmed(),
        "─".repeat(top_fill).dimmed(),
        "╮".dimmed(),
    );

    // "│ " prefix + " │" suffix = 4 chars of box chrome.
    let inner_width = usable.saturating_sub(4).max(10);

    // Body: split into paragraphs on newlines, word-wrap each, blank line between.
    if !note.body.is_empty() {
        let paragraphs: Vec<&str> = note.body.split('\n').collect();
        for (i, para) in paragraphs.iter().enumerate() {
            if i > 0 {
                write_box_line(w, indent, usable, "", 0);
            }
            let trimmed = para.trim();
            if let Some(rest) = trimmed.strip_prefix("$ ") {
                // Command lines render verbatim with dimmed sigil.
                let cmd_text = format!("{}{}", "$ ".dimmed(), rest);
                write_box_line(w, indent, usable, &cmd_text, trimmed.len());
            } else {
                for line in word_wrap(trimmed, inner_width) {
                    write_box_line(w, indent, usable, &line, line.len());
                }
            }
        }
    }

    // Child layouts rendered inside the box, each preceded by a dashed separator.
    let mid_fill = usable.saturating_sub(2);
    let child_term = Terminal::new(inner_width);
    for child in &note.children {
        let _ = writeln!(
            w,
            "{:indent$}{}{}{}",
            "",
            "├".dimmed(),
            "┄".repeat(mid_fill).dimmed(),
            "┤".dimmed(),
        );
        let mut child_buf = Vec::new();
        render_layout(&mut child_buf, child, 0, &child_term);
        let child_str = String::from_utf8_lossy(&child_buf);
        for line in child_str.lines() {
            let vis_width = visible_len(line);
            write_box_line(w, indent, usable, line, vis_width);
        }
    }

    // Bottom border: ╰──────╯
    let bottom_fill = usable.saturating_sub(2);
    let _ = writeln!(
        w,
        "{:indent$}{}{}{}",
        "",
        "╰".dimmed(),
        "─".repeat(bottom_fill).dimmed(),
        "╯".dimmed(),
    );
}

/// Write a single line inside a box: "│ content                 │"
///
/// If `text_width` exceeds the available inner width, the right border
/// character is omitted so the line doesn't wrap awkwardly.
fn write_box_line(
    w: &mut impl Write,
    indent: usize,
    box_width: usize,
    text: &str,
    text_width: usize,
) {
    let inner_width = box_width.saturating_sub(4);
    if text_width > inner_width {
        // Text overflows — omit right border to avoid wrapping.
        let _ = writeln!(w, "{:indent$}{} {text}", "", DIVIDER.dimmed(),);
    } else {
        let padding = inner_width - text_width;
        let _ = writeln!(
            w,
            "{:indent$}{} {text}{:padding$} {}",
            "",
            DIVIDER.dimmed(),
            "",
            DIVIDER.dimmed(),
        );
    }
}

/// Word-wrap plain text into lines fitting `max_width`.
fn word_wrap(text: &str, max_width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut cur = String::new();
    let mut cur_width = 0;

    for word in &words {
        let w_len = word.len();
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

// ── Helpers ───────────────────────────────────────────────────────

pub use may_i_pp::strip_ansi;

#[cfg(test)]
mod tests {
    use super::*;

    const TERM: Terminal = Terminal { width: 120 };

    #[test]
    fn blank_renders_empty_line() {
        let s = render_to_string(&Layout::Blank, 0, &TERM);
        assert_eq!(s, "");
    }

    #[test]
    fn text_renders_with_indent() {
        let s = render_to_string(&Layout::Text("hello".into()), 4, &TERM);
        assert_eq!(s, "    hello");
    }

    #[test]
    fn indent_adds_to_children() {
        let layout = Layout::indent(3, Layout::Text("hi".into()));
        let s = render_to_string(&layout, 0, &TERM);
        assert_eq!(s, "   hi");
    }

    #[test]
    fn stack_renders_children_sequentially() {
        let layout = Layout::Stack(vec![Layout::Text("a".into()), Layout::Text("b".into())]);
        let s = render_to_string(&layout, 0, &TERM);
        assert_eq!(s, "a\nb");
    }

    #[test]
    fn columns_aligns_divider() {
        let rows = vec![
            ColRow::new("short", 5, "r1"),
            ColRow::new("longer left", 11, "r2"),
        ];
        let layout = Layout::Columns(rows);
        let s = render_to_string(&layout, 0, &TERM);
        let lines: Vec<&str> = s.lines().collect();
        // Both lines should have the divider at the same column
        let div_pos_0 = strip_ansi(lines[0]).find('│').unwrap();
        let div_pos_1 = strip_ansi(lines[1]).find('│').unwrap();
        assert_eq!(div_pos_0, div_pos_1);
    }

    #[test]
    fn columns_right_align() {
        let row = ColRow::new("text", 4, "ann").with_align(ColAlign::Right);
        let layout = Layout::Columns(vec![ColRow::new("longer", 6, ""), row]);
        let s = render_to_string(&layout, 0, &TERM);
        let lines: Vec<&str> = s.lines().collect();
        let stripped = strip_ansi(lines[1]);
        // "text" should be right-aligned within the divider column
        assert!(stripped.starts_with("  text"), "got: {stripped:?}");
    }

    #[test]
    fn hrule_without_label() {
        let layout = Layout::HRule(None);
        let mut buf = Vec::new();
        write_layout(&mut buf, &layout, &TERM);
        let s = String::from_utf8(buf).unwrap();
        let stripped = strip_ansi(&s);
        assert!(stripped.contains("─"));
    }

    #[test]
    fn hrule_with_label() {
        let layout = Layout::HRule(Some(HRuleLabel {
            text: "section".into(),
            visible_width: 7,
        }));
        let mut buf = Vec::new();
        write_layout(&mut buf, &layout, &TERM);
        let s = String::from_utf8(buf).unwrap();
        let stripped = strip_ansi(&s);
        assert!(stripped.contains("section"));
        assert!(stripped.contains("─"));
    }

    #[test]
    fn kv_creates_left_aligned_row() {
        let row = ColRow::kv("key", "value");
        assert_eq!(row.left, "key");
        assert_eq!(row.left_width, 3);
        assert!(matches!(row.left_align, ColAlign::Left));
    }

    #[test]
    fn note_heading_from_unicode_uses_visible_width() {
        let heading = NoteHeading::from("ℹ Info".to_string());
        // "ℹ Info" is 6 visible chars, not 8 bytes
        assert_eq!(heading.visible_width, 6);
    }

    #[test]
    fn kv_unicode_label_uses_visible_width() {
        let row = ColRow::kv("ℹ Info", "value");
        assert_eq!(row.left_width, 6);
    }

    #[test]
    fn note_warn_with_body() {
        let term = Terminal::new(50);
        let layout = Layout::Note(Note {
            level: NoteLevel::Warn,
            heading: "Test heading".into(),
            body: "This is the body text.".into(),
            children: vec![],
        });
        let s = render_to_string(&layout, 0, &term);
        insta::assert_snapshot!(strip_ansi(&s));
    }

    #[test]
    fn note_info_level() {
        let term = Terminal::new(50);
        let layout = Layout::Note(Note {
            level: NoteLevel::Info,
            heading: "FYI".into(),
            body: "Something to know.".into(),
            children: vec![],
        });
        let s = render_to_string(&layout, 0, &term);
        insta::assert_snapshot!(strip_ansi(&s));
    }

    #[test]
    fn note_error_level() {
        let term = Terminal::new(50);
        let layout = Layout::Note(Note {
            level: NoteLevel::Error,
            heading: "Bad thing".into(),
            body: "Something went wrong.".into(),
            children: vec![],
        });
        let s = render_to_string(&layout, 0, &term);
        insta::assert_snapshot!(strip_ansi(&s));
    }

    #[test]
    fn note_wraps_body_at_terminal_width() {
        let term = Terminal::new(30);
        let layout = Layout::Note(Note {
            level: NoteLevel::Warn,
            heading: "Warn".into(),
            body: "one two three four five six seven eight nine ten".into(),
            children: vec![],
        });
        let s = render_to_string(&layout, 0, &term);
        insta::assert_snapshot!(strip_ansi(&s));
    }

    #[test]
    fn note_with_empty_body() {
        let term = Terminal::new(50);
        let layout = Layout::Note(Note {
            level: NoteLevel::Warn,
            heading: "Heads up".into(),
            body: String::new(),
            children: vec![],
        });
        let s = render_to_string(&layout, 0, &term);
        insta::assert_snapshot!(strip_ansi(&s));
    }

    #[test]
    fn note_with_indent() {
        let term = Terminal::new(50);
        let layout = Layout::indent(
            4,
            Layout::Note(Note {
                level: NoteLevel::Info,
                heading: "Hi".into(),
                body: "Hello world.".into(),
                children: vec![],
            }),
        );
        let s = render_to_string(&layout, 0, &term);
        insta::assert_snapshot!(strip_ansi(&s));
    }

    #[test]
    fn note_box_lines_are_same_visible_width() {
        let term = Terminal::new(50);
        let layout = Layout::Note(Note {
            level: NoteLevel::Warn,
            heading: "Short".into(),
            body: "Some body text here.".into(),
            children: vec![],
        });
        let s = render_to_string(&layout, 0, &term);
        let stripped = strip_ansi(&s);
        let widths: Vec<usize> = stripped.lines().map(|l| l.chars().count()).collect();
        let first = widths[0];
        for (i, &w) in widths.iter().enumerate() {
            assert_eq!(
                w, first,
                "line {} width {} != expected {}: {:?}",
                i, w, first, stripped
            );
        }
    }

    #[test]
    fn note_overflow_line_omits_right_border() {
        let term = Terminal::new(30);
        let long_path = "/very/long/path/that/exceeds/the/box/width/entirely";
        let layout = Layout::Note(Note {
            level: NoteLevel::Warn,
            heading: "Warn".into(),
            body: long_path.into(),
            children: vec![],
        });
        let s = render_to_string(&layout, 0, &term);
        let stripped = strip_ansi(&s);
        // The body line with the long path should not have a trailing │
        let body_lines: Vec<&str> = stripped.lines().filter(|l| l.contains(long_path)).collect();
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
            body: "Config format is outdated.\nRun this command:\n$ may-i migrate".into(),
            children: vec![],
        });
        let s = render_to_string(&layout, 0, &term);
        insta::assert_snapshot!(strip_ansi(&s));
    }

    #[test]
    fn note_with_child_layout() {
        let term = Terminal::new(50);
        let child = Layout::Stack(vec![
            Layout::Text("~/foo.lisp (3)".into()),
            Layout::Text("   ls, cat, rm".into()),
        ]);
        let layout = Layout::Note(Note {
            level: NoteLevel::Warn,
            heading: "Test".into(),
            body: "Body text.".into(),
            children: vec![child],
        });
        let s = render_to_string(&layout, 0, &term);
        insta::assert_snapshot!(strip_ansi(&s));
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
        insta::assert_snapshot!(strip_ansi(&s));
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
        insta::assert_snapshot!(strip_ansi(&s));
    }

    #[test]
    fn breakable_with_empty_items() {
        let rows = vec![ColRow {
            left: "lbl".into(),
            left_width: 3,
            left_align: ColAlign::Left,
            right: ColContent::Breakable {
                items: vec![],
                separator: ", ".into(),
                separator_width: 2,
            },
        }];
        let layout = Layout::Columns(rows);
        let s = render_to_string(&layout, 0, &TERM);
        let stripped = strip_ansi(&s);
        assert!(stripped.contains("│"));
    }

    #[test]
    fn strip_ansi_removes_escape_codes() {
        let colored = format!("{}hello{}", "\x1b[31m", "\x1b[0m");
        assert_eq!(strip_ansi(&colored), "hello");
    }

    #[test]
    fn strip_ansi_preserves_plain_text() {
        assert_eq!(strip_ansi("plain text"), "plain text");
    }

    #[test]
    fn breakable_wraps_items_across_lines() {
        let term = Terminal::new(30);
        let rows = vec![ColRow {
            left: "label".into(),
            left_width: 5,
            left_align: ColAlign::Right,
            right: ColContent::Breakable {
                items: vec![
                    ColItem::new("aaaa", 4),
                    ColItem::new("bbbb", 4),
                    ColItem::new("cccc", 4),
                    ColItem::new("dddd", 4),
                    ColItem::new("eeee", 4),
                ],
                separator: ", ".into(),
                separator_width: 2,
            },
        }];
        let layout = Layout::Columns(rows);
        let s = render_to_string(&layout, 0, &term);
        let stripped = strip_ansi(&s);
        let lines: Vec<&str> = stripped.lines().collect();
        // Should wrap across multiple lines
        assert!(
            lines.len() > 1,
            "expected wrapping across multiple lines, got: {stripped:?}"
        );
        // All lines should have the divider
        for line in &lines {
            assert!(
                line.contains('│'),
                "each line should have divider: {line:?}"
            );
        }
        // Non-final lines should have trailing separator (comma)
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
            left: "lbl".into(),
            left_width: 3,
            left_align: ColAlign::Right,
            right: ColContent::Breakable {
                items: vec![ColItem::new("a", 1), ColItem::new("b", 1)],
                separator: ", ".into(),
                separator_width: 2,
            },
        }];
        let layout = Layout::Columns(rows);
        let s = render_to_string(&layout, 0, &term);
        let stripped = strip_ansi(&s);
        let lines: Vec<&str> = stripped.lines().collect();
        assert_eq!(lines.len(), 1, "should fit on one line: {stripped:?}");
        assert!(
            stripped.contains("a, b"),
            "items joined with separator: {stripped:?}"
        );
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
            "[a-z ]{0,30}".prop_map(|s| Layout::HRule(Some(HRuleLabel {
                visible_width: s.len(),
                text: s,
            }))),
            "[a-z ]{0,40}".prop_map(Layout::Text),
            (any_note_level(), "[a-z ]{1,20}", "[a-z ]{0,40}").prop_map(
                |(level, heading, body)| {
                    Layout::Note(Note {
                        level,
                        heading: heading.into(),
                        body,
                        children: vec![],
                    })
                }
            ),
            prop::collection::vec(
                ("[a-z]{1,10}", "[a-z ]{0,20}").prop_map(|(l, r)| {
                    let w = l.len();
                    ColRow::new(l, w, r)
                }),
                1..=4,
            )
            .prop_map(Layout::Columns),
            prop::collection::vec(
                "[a-z]{1,10}".prop_map(|s| {
                    let w = s.len();
                    ColItem::new(s, w)
                }),
                1..=6,
            )
            .prop_map(|items| Layout::Wrap {
                items,
                separator: ColItem::new(", ", 2),
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
        "[a-z]{1,10}".prop_map(|s| {
            let w = s.len();
            ColItem::new(s, w)
        })
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
                left: label.clone(),
                left_width: label_width,
                left_align: ColAlign::Right,
                right: ColContent::Breakable {
                    items: items.clone(),
                    separator: ", ".into(),
                    separator_width: 2,
                },
            }];
            let layout = Layout::Columns(rows);
            let s = render_to_string(&layout, 0, &term);
            let stripped = strip_ansi(&s);

            // Every item text appears in the output.
            for item in &items {
                prop_assert!(
                    stripped.contains(&item.text),
                    "item {:?} missing from output: {stripped:?}",
                    item.text
                );
            }

            // Every line has a divider.
            for line in stripped.lines() {
                prop_assert!(
                    line.contains('│'),
                    "line missing divider: {line:?}"
                );
            }

            let lines: Vec<&str> = stripped.lines().collect();
            if lines.len() > 1 {
                // Non-final lines should end with trailing separator.
                for line in &lines[..lines.len() - 1] {
                    let after_div = line.split('│').nth(1).unwrap().trim();
                    prop_assert!(
                        after_div.ends_with(','),
                        "continued line should end with separator: {line:?}"
                    );
                }
                // Final line should NOT end with separator.
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

            // All original words must appear in the output
            let all_output_words: Vec<&str> = wrapped.iter()
                .flat_map(|line| line.split_whitespace())
                .collect();
            prop_assert_eq!(all_output_words.len(), words.len(),
                "word count changed: input {} words, output {} words\ninput: {:?}\nwrapped: {:?}",
                words.len(), all_output_words.len(), words, wrapped);
            for (orig, out) in words.iter().zip(all_output_words.iter()) {
                prop_assert_eq!(orig.as_str(), *out,
                    "word mismatch: original {:?} vs output {:?}", orig, out);
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
                // Lines should not exceed max_width, UNLESS they contain a single
                // word longer than max_width
                let line_words: Vec<&str> = line.split_whitespace().collect();
                if line_words.len() > 1 {
                    prop_assert!(line.len() <= max_width,
                        "multi-word line exceeds width {}: {:?} (len={})",
                        max_width, line, line.len());
                }
            }
        }
    }

    #[test]
    fn word_wrap_empty_input() {
        let result = word_wrap("", 80);
        assert_eq!(result, vec![String::new()]);
    }

    proptest! {
        /// write_layout never panics on arbitrary layouts and widths.
        #[test]
        fn write_layout_never_panics(
            layout in any_layout(),
            width in 20..200usize,
        ) {
            let term = Terminal::new(width);
            let mut buf = Vec::new();
            write_layout(&mut buf, &layout, &term);
            // Just ensuring no panic; output is valid UTF-8.
            let _ = String::from_utf8_lossy(&buf);
        }
    }
}
