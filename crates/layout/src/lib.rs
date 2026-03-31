// Declarative layout primitives for terminal output.
//
// Provides a tree of layout nodes (`Layout`) that can be rendered to any
// `Write` sink. The trace/check commands construct Layout trees, which are
// then rendered in one pass — separating structure from presentation.

use std::io::Write;

use colored::Colorize;
use may_i_pp::{colorize_atom, visible_len};

// ── Terminal geometry ─────────────────────────────────────────────

const DIVIDER: &str = "│";

pub fn term_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .or_else(|| terminal_size::terminal_size().map(|(w, _)| w.0 as usize))
        .unwrap_or(80)
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
    /// Center child in the terminal width.
    Center(Box<Layout>),
    /// Indent child by `n` spaces.
    Indent(usize, Box<Layout>),
    /// Vertical sequence of children.
    Stack(Vec<Layout>),
    /// Pre-formatted text line(s).
    Text(String),
    /// Box with optional title label and child layout.
    LabeledBox {
        title: Option<String>,
        body: Box<Layout>,
    },
}

impl Layout {
    pub fn indent(n: usize, inner: Layout) -> Layout {
        Layout::Indent(n, Box::new(inner))
    }

    pub fn center(inner: Layout) -> Layout {
        Layout::Center(Box::new(inner))
    }

    pub fn labeled_box(title: impl Into<String>, body: Layout) -> Layout {
        Layout::LabeledBox {
            title: Some(title.into()),
            body: Box::new(body),
        }
    }

    pub fn facts_box(facts: &[(String, String)]) -> Layout {
        let max_key = facts.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        let lines: Vec<String> = facts
            .iter()
            .map(|(key, value)| {
                let colored_key = colorize_atom(key, true);
                let colored_value = colorize_atom(&format!("\"{value}\""), true);
                let pad_key = max_key - key.len();
                format!("{colored_key}{:pad_key$} {colored_value}", "")
            })
            .collect();
        let body = Layout::Stack(lines.into_iter().map(Layout::Text).collect());
        Layout::Center(Box::new(Layout::labeled_box("facts", body)))
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

#[derive(Debug, Clone)]
pub struct ColRow {
    pub left: String,
    pub left_width: usize,
    pub left_align: ColAlign,
    pub right: String,
}

impl ColRow {
    pub fn new(left: impl Into<String>, left_width: usize, right: impl Into<String>) -> Self {
        Self {
            left: left.into(),
            left_width,
            left_align: ColAlign::Left,
            right: right.into(),
        }
    }

    pub fn kv(label: impl Into<String>, value: impl Into<String>) -> Self {
        let label = label.into();
        let width = label.len();
        Self {
            left: label,
            left_width: width,
            left_align: ColAlign::Right,
            right: value.into(),
        }
    }

    pub fn with_align(mut self, align: ColAlign) -> Self {
        self.left_align = align;
        self
    }

    fn is_elision(&self) -> bool {
        self.left_width == 1 && self.left.contains('…')
    }
}

// ── Renderer ──────────────────────────────────────────────────────

pub fn write_layout(w: &mut impl Write, layout: &Layout) {
    render_layout(w, layout, 0);
}

fn render_layout(w: &mut impl Write, layout: &Layout, indent: usize) {
    match layout {
        Layout::Blank => {
            let _ = writeln!(w);
        }
        Layout::HRule(label) => {
            write_hrule(w, indent, label.as_ref());
        }
        Layout::Columns(rows) => {
            write_columns(w, indent, rows);
        }
        Layout::Center(inner) => {
            let content = render_to_string(inner, 0);
            let content_width = content.lines().map(visible_len).max().unwrap_or(0);
            let tw = term_width();
            let pad = tw.saturating_sub(content_width) / 2;
            for line in content.lines() {
                let _ = writeln!(w, "{:pad$}{line}", "");
            }
        }
        Layout::Indent(n, inner) => {
            render_layout(w, inner, indent + n);
        }
        Layout::Stack(children) => {
            for child in children {
                render_layout(w, child, indent);
            }
        }
        Layout::Text(text) => {
            let _ = writeln!(w, "{:indent$}{text}", "");
        }
        Layout::LabeledBox { title, body } => {
            write_labeled_box(w, indent, title.as_deref(), body);
        }
    }
}

pub fn render_to_string(layout: &Layout, indent: usize) -> String {
    let mut buf = Vec::new();
    render_layout(&mut buf, layout, indent);
    let s = String::from_utf8_lossy(&buf).into_owned();
    // Trim trailing newline so callers get clean content.
    if s.ends_with('\n') {
        s[..s.len() - 1].to_string()
    } else {
        s
    }
}

fn write_hrule(w: &mut impl Write, indent: usize, label: Option<&HRuleLabel>) {
    let usable = term_width().saturating_sub(indent);
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

fn write_columns(w: &mut impl Write, indent: usize, rows: &[ColRow]) {
    let divider_col = compute_divider_col(rows);
    for row in rows {
        write_col_row(w, indent, row, divider_col);
    }
}

fn compute_divider_col(rows: &[ColRow]) -> usize {
    let max_left = rows
        .iter()
        .filter(|r| !r.is_elision() && matches!(r.left_align, ColAlign::Left))
        .map(|r| r.left_width)
        .max()
        .unwrap_or(0);
    max_left + 1
}

fn write_col_row(w: &mut impl Write, indent: usize, row: &ColRow, divider_col: usize) {
    if row.left.is_empty() && row.right.is_empty() {
        return;
    }

    let gap = divider_col.saturating_sub(row.left_width);
    let (lead, trail) = match row.left_align {
        ColAlign::Right => (gap.saturating_sub(1), 1),
        ColAlign::Left => (0, gap),
    };

    let right = if row.right.is_empty() {
        String::new()
    } else {
        format!(" {}", row.right)
    };

    let _ = writeln!(
        w,
        "{:indent$}{:lead$}{}{:trail$}{}{}",
        "",
        "",
        row.left,
        "",
        DIVIDER.dimmed(),
        right,
    );
}

fn write_labeled_box(w: &mut impl Write, indent: usize, title: Option<&str>, body: &Layout) {
    let body_str = render_to_string(body, 0);
    let inner_width = body_str.lines().map(visible_len).max().unwrap_or(0);

    let top = match title {
        Some(t) => {
            let remaining = (inner_width + 2).saturating_sub(t.len() + 2);
            format!(
                "{}{}{}",
                format!("┌─{t}─").dimmed(),
                "─".repeat(remaining).dimmed(),
                "┐".dimmed()
            )
        }
        None => {
            format!(
                "{}{}",
                "┌".dimmed(),
                format!("{}┐", "─".repeat(inner_width + 2)).dimmed()
            )
        }
    };
    let _ = writeln!(w, "{:indent$}{top}", "");

    for line in body_str.lines() {
        let pad_right = inner_width.saturating_sub(visible_len(line));
        let _ = writeln!(
            w,
            "{:indent$}{} {line}{:pad_right$} {}",
            "",
            "│".dimmed(),
            "",
            "│".dimmed()
        );
    }

    let _ = writeln!(
        w,
        "{:indent$}{}{}",
        "",
        "└".dimmed(),
        format!("{}┘", "─".repeat(inner_width + 2)).dimmed()
    );
}

// ── Helpers ───────────────────────────────────────────────────────

pub fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut in_escape = false;
    for ch in s.chars() {
        if in_escape {
            if ch == 'm' {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_renders_empty_line() {
        let s = render_to_string(&Layout::Blank, 0);
        assert_eq!(s, "");
    }

    #[test]
    fn text_renders_with_indent() {
        let s = render_to_string(&Layout::Text("hello".into()), 4);
        assert_eq!(s, "    hello");
    }

    #[test]
    fn indent_adds_to_children() {
        let layout = Layout::indent(3, Layout::Text("hi".into()));
        let s = render_to_string(&layout, 0);
        assert_eq!(s, "   hi");
    }

    #[test]
    fn stack_renders_children_sequentially() {
        let layout = Layout::Stack(vec![Layout::Text("a".into()), Layout::Text("b".into())]);
        let s = render_to_string(&layout, 0);
        assert_eq!(s, "a\nb");
    }

    #[test]
    fn columns_aligns_divider() {
        let rows = vec![
            ColRow::new("short", 5, "r1"),
            ColRow::new("longer left", 11, "r2"),
        ];
        let layout = Layout::Columns(rows);
        let s = render_to_string(&layout, 0);
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
        let s = render_to_string(&layout, 0);
        let lines: Vec<&str> = s.lines().collect();
        let stripped = strip_ansi(lines[1]);
        // "text" should be right-aligned within the divider column
        assert!(stripped.starts_with("  text"), "got: {stripped:?}");
    }

    #[test]
    fn labeled_box_has_title_in_border() {
        let body = Layout::Text("content".into());
        let layout = Layout::labeled_box("title", body);
        let s = render_to_string(&layout, 0);
        let stripped = strip_ansi(&s);
        assert!(stripped.contains("title"), "box should contain title");
        assert!(stripped.contains("┌"), "box should have top border");
        assert!(stripped.contains("┘"), "box should have bottom border");
        assert!(stripped.contains("content"), "box should contain body");
    }

    #[test]
    fn labeled_box_pads_content_to_width() {
        let body = Layout::Stack(vec![
            Layout::Text("short".into()),
            Layout::Text("much longer line".into()),
        ]);
        let layout = Layout::labeled_box("t", body);
        let s = render_to_string(&layout, 0);
        let stripped = strip_ansi(&s);
        // All content lines should have right border at same column
        let content_lines: Vec<&str> = stripped.lines().filter(|l| l.contains("│")).collect();
        let widths: Vec<usize> = content_lines.iter().map(|l| l.len()).collect();
        assert!(
            widths.windows(2).all(|w| w[0] == w[1]),
            "all box lines should be same width, got {widths:?}"
        );
    }

    #[test]
    fn facts_box_renders_key_value_pairs() {
        let facts = vec![
            (":key".to_string(), "val".to_string()),
            (":longer-key".to_string(), "v".to_string()),
        ];
        let layout = Layout::facts_box(&facts);
        let s = render_to_string(&layout, 0);
        let stripped = strip_ansi(&s);
        assert!(stripped.contains("facts"), "should have facts label");
        assert!(stripped.contains(":key"), "should contain first key");
        assert!(
            stripped.contains(":longer-key"),
            "should contain second key"
        );
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
}
