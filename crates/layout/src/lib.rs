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
        let width = label.len();
        Self {
            left: label,
            left_width: width,
            left_align: ColAlign::Right,
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
        .filter(|r| !r.is_elision() && matches!(r.left_align, ColAlign::Left))
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
                    lines.push(cur.clone());
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
    fn kv_creates_right_aligned_row() {
        let row = ColRow::kv("key", "value");
        assert_eq!(row.left, "key");
        assert_eq!(row.left_width, 3);
        assert!(matches!(row.left_align, ColAlign::Right));
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
    }
}
