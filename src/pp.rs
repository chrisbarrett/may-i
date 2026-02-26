// S-expression pretty-printer with configurable width and syntax coloring.

use colored::Colorize;

/// A lightweight tree for pretty-printing. Separates structure from
/// presentation so callers can build trees without dragging in Sexpr spans.
#[derive(Debug, Clone)]
pub enum Doc {
    /// Atom rendered verbatim (coloring is inferred from content).
    Atom(String),
    /// A parenthesised list of children.
    List(Vec<Doc>),
}

impl Doc {
    /// Convenience: atom from a string slice.
    pub fn atom(s: impl Into<String>) -> Self {
        Doc::Atom(s.into())
    }

    /// Convenience: wrap children in a list.
    pub fn list(children: Vec<Doc>) -> Self {
        Doc::List(children)
    }

    /// Build a Doc from an [`crate::sexpr::Sexpr`] node, re-quoting atoms
    /// that need it (contain spaces, parens, etc).
    pub fn from_sexpr(sexpr: &crate::sexpr::Sexpr) -> Self {
        match sexpr {
            crate::sexpr::Sexpr::Atom(s, _) => {
                if needs_quoting(s) {
                    Doc::Atom(format!(
                        "\"{}\"",
                        s.replace('\\', "\\\\").replace('"', "\\\"")
                    ))
                } else {
                    Doc::Atom(s.clone())
                }
            }
            crate::sexpr::Sexpr::List(items, _) => {
                Doc::List(items.iter().map(Doc::from_sexpr).collect())
            }
        }
    }
}

/// Does this raw atom value need quoting when displayed?
fn needs_quoting(s: &str) -> bool {
    s.is_empty()
        || s.contains(|c: char| {
            c.is_whitespace() || c == '(' || c == ')' || c == '"' || c == ';' || c == '\\'
        })
}

// ── Atom classification ─────────────────────────────────────────────

/// Special-form names that get highlighted.
const SPECIAL_FORMS: &[&str] = &[
    "command", "rule", "args", "cond", "when", "if", "unless",
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

/// Configuration for pretty-printing.
#[derive(Debug, Clone)]
pub struct Format {
    /// Column at which to wrap long forms.
    pub width: usize,
    /// Whether to emit ANSI color codes.
    pub color: bool,
}

impl Default for Format {
    fn default() -> Self {
        Self { width: 72, color: false }
    }
}

impl Format {
    /// Colored output at the default width.
    pub fn colored() -> Self {
        Self { color: true, ..Self::default() }
    }
}

// ── Rendering ───────────────────────────────────────────────────────

/// Pretty-print a Doc with the given format settings.
/// `indent` is the starting column (for alignment when embedded in other output).
pub fn pretty(doc: &Doc, indent: usize, fmt: &Format) -> String {
    render(doc, indent, fmt.width, fmt.color)
}

fn render(doc: &Doc, indent: usize, width: usize, color: bool) -> String {
    match doc {
        Doc::Atom(s) => colorize_atom(s, color),
        Doc::List(children) if children.is_empty() => {
            if color {
                format!("{}{}", "(".dimmed(), ")".dimmed())
            } else {
                "()".into()
            }
        }
        Doc::List(children) => {
            // Try flat first.
            let flat = render_flat(children, color);
            if indent + visible_len(&flat) <= width {
                return flat;
            }
            // Break: (head first-child\n<align>rest-children...)
            render_broken(children, indent, width, color)
        }
    }
}

/// Render all children on one line: `(a b c)`.
fn render_flat(children: &[Doc], color: bool) -> String {
    let open = if color { "(".dimmed().to_string() } else { "(".into() };
    let close = if color { ")".dimmed().to_string() } else { ")".into() };
    let parts: Vec<String> = children.iter().map(|c| render(c, 0, usize::MAX, color)).collect();
    format!("{open}{}{close}", parts.join(" "))
}

/// Break: align subsequent children under the first argument.
///
/// ```text
/// (head first-arg
///       second-arg
///       third-arg)
/// ```
fn render_broken(children: &[Doc], indent: usize, width: usize, color: bool) -> String {
    let open = if color { "(".dimmed().to_string() } else { "(".into() };
    let close = if color { ")".dimmed().to_string() } else { ")".into() };

    let head = render(&children[0], indent + 1, width, color);
    // Align column: "(" + head + " "
    let align = indent + visible_len(&head) + 2;

    let mut lines = Vec::new();

    if children.len() == 1 {
        lines.push(format!("{open}{head}{close}"));
    } else {
        let first_child = render(&children[1], align, width, color);
        lines.push(format!("{open}{head} {first_child}"));

        for child in &children[2..] {
            let child_str = render(child, align, width, color);
            lines.push(format!("{:pad$}{child_str}", "", pad = align));
        }
        // Append closing paren to last line.
        if let Some(last) = lines.last_mut() {
            last.push_str(&close);
        }
    }

    lines.join("\n")
}

/// Colorize an atom value based on its content.
fn colorize_atom(s: &str, color: bool) -> String {
    if !color {
        return s.to_string();
    }
    if is_keyword(s) {
        // Indigo: roughly (75, 0, 130)
        s.truecolor(120, 120, 255).to_string()
    } else if is_string(s) || is_regex(s) {
        s.green().to_string()
    } else if is_special_form(s) {
        s.yellow().bold().to_string()
    } else {
        s.to_string()
    }
}

/// Visible length of a string, ignoring ANSI escape sequences.
fn visible_len(s: &str) -> usize {
    let mut len = 0;
    let mut in_escape = false;
    for ch in s.chars() {
        if in_escape {
            if ch == 'm' {
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

    fn pp(doc: &Doc, width: usize) -> String {
        pretty(doc, 0, &Format { width, ..Default::default() })
    }

    fn pp_color(doc: &Doc, width: usize) -> String {
        pretty(doc, 0, &Format { width, color: true })
    }

    // ── Flat rendering ──────────────────────────────────────────────

    #[test]
    fn flat_atom() {
        assert_eq!(pp(&a("hello"), 80), "hello");
    }

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
    fn flat_nested() {
        let doc = l(vec![a("rule"), l(vec![a("command"), a("\"rm\"")])]);
        assert_eq!(pp(&doc, 80), "(rule (command \"rm\"))");
    }

    // ── Wrapping ────────────────────────────────────────────────────

    #[test]
    fn wraps_when_exceeds_width() {
        let doc = l(vec![a("rule"), a("aaa"), a("bbb"), a("ccc")]);
        // Width 15: "(rule aaa bbb ccc)" = 18 chars, won't fit.
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
    //
    // The `colored` crate suppresses ANSI when stdout is not a TTY
    // (e.g. in tests). Force it on for these tests.

    fn with_forced_color(f: impl FnOnce()) {
        colored::control::set_override(true);
        f();
        colored::control::unset_override();
    }

    #[test]
    fn keywords_get_colored() {
        with_forced_color(|| {
            let result = pp_color(&a(":deny"), 80);
            assert!(result.contains("\x1b["), "expected ANSI codes in: {result:?}");
            assert!(result.contains("deny"));
        });
    }

    #[test]
    fn strings_get_colored() {
        with_forced_color(|| {
            let result = pp_color(&a("\"rm\""), 80);
            assert!(result.contains("\x1b["), "expected ANSI codes in: {result:?}");
            assert!(result.contains("rm"));
        });
    }

    #[test]
    fn special_forms_get_colored() {
        with_forced_color(|| {
            let result = pp_color(&a("command"), 80);
            assert!(result.contains("\x1b["), "expected ANSI codes in: {result:?}");
        });
    }

    #[test]
    fn plain_atoms_not_colored() {
        with_forced_color(|| {
            let result = pp_color(&a("foo"), 80);
            assert!(!result.contains("\x1b["), "unexpected ANSI codes in: {result:?}");
        });
    }

    #[test]
    fn parens_dimmed_in_color_mode() {
        with_forced_color(|| {
            let result = pp_color(&l(vec![a("x")]), 80);
            assert!(result.contains("\x1b["), "expected ANSI codes in: {result:?}");
        });
    }

    // ── from_sexpr ──────────────────────────────────────────────────

    #[test]
    fn from_sexpr_atom_bare() {
        use crate::errors::Span;
        let sexpr = crate::sexpr::Sexpr::Atom("hello".into(), Span::new(0, 0));
        let doc = Doc::from_sexpr(&sexpr);
        assert_eq!(pp(&doc, 80), "hello");
    }

    #[test]
    fn from_sexpr_atom_needs_quoting() {
        use crate::errors::Span;
        let sexpr = crate::sexpr::Sexpr::Atom("hello world".into(), Span::new(0, 0));
        let doc = Doc::from_sexpr(&sexpr);
        assert_eq!(pp(&doc, 80), "\"hello world\"");
    }

    #[test]
    fn from_sexpr_list() {
        use crate::errors::Span;
        let sexpr = crate::sexpr::Sexpr::List(
            vec![
                crate::sexpr::Sexpr::Atom("rule".into(), Span::new(0, 0)),
                crate::sexpr::Sexpr::Atom("foo".into(), Span::new(0, 0)),
            ],
            Span::new(0, 0),
        );
        let doc = Doc::from_sexpr(&sexpr);
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
        // Second line should be indented to align under "first-branch"
        assert_eq!(lines[0], "(and first-branch");
        assert_eq!(lines[1], "     second-branch)");
    }
}
