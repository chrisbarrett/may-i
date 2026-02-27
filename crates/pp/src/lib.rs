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

    /// Build a Doc from an [`may_i_sexpr::Sexpr`] node, re-quoting atoms
    /// that need it (contain spaces, parens, etc).
    #[cfg(test)]
    pub fn from_sexpr(sexpr: &may_i_sexpr::Sexpr) -> Self {
        match sexpr {
            may_i_sexpr::Sexpr::Atom(s, _) => {
                if may_i_sexpr::needs_quoting(s) {
                    Doc::Atom(may_i_sexpr::quote_atom(s))
                } else {
                    Doc::Atom(s.clone())
                }
            }
            may_i_sexpr::Sexpr::List(items, _) => {
                Doc::List(items.iter().map(Doc::from_sexpr).collect())
            }
        }
    }
}

// ── S-expression string parser ──────────────────────────────────────

/// Parse an s-expression string (e.g. `(command "curl")`) into a Doc tree.
pub fn parse_sexpr(input: &str) -> Doc {
    let tokens = tokenize(input);
    if tokens.is_empty() {
        return Doc::Atom(String::new());
    }
    let (doc, _) = parse_tokens(&tokens, 0);
    doc
}

fn tokenize(input: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' | b'\n' => { i += 1; }
            b'(' => { tokens.push(&input[i..i + 1]); i += 1; }
            b')' => { tokens.push(&input[i..i + 1]); i += 1; }
            b'"' => {
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' { i += 1; }
                    i += 1;
                }
                if i < bytes.len() { i += 1; }
                tokens.push(&input[start..i]);
            }
            b'#' if i + 1 < bytes.len() && bytes[i + 1] == b'"' => {
                let start = i;
                i += 2;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' { i += 1; }
                    i += 1;
                }
                if i < bytes.len() { i += 1; }
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

fn parse_tokens(tokens: &[&str], pos: usize) -> (Doc, usize) {
    if pos >= tokens.len() {
        return (Doc::Atom(String::new()), pos);
    }
    if tokens[pos] == "(" {
        let mut children = Vec::new();
        let mut i = pos + 1;
        while i < tokens.len() && tokens[i] != ")" {
            let (child, next) = parse_tokens(tokens, i);
            children.push(child);
            i = next;
        }
        if i < tokens.len() { i += 1; } // skip )
        (Doc::List(children), i)
    } else {
        (Doc::Atom(tokens[pos].to_string()), pos + 1)
    }
}

// ── Doc transforms ─────────────────────────────────────────────────

/// Truncate long lists in a Doc tree, keeping the first `keep`
/// and last 1 elements with an `…` ellipsis in between.
/// Applies to any list whose head is an atom (e.g. `(or ...)`,
/// `(and ...)`, `(args ...)`, etc).
pub fn truncate_long_lists(doc: &Doc, keep: usize) -> Doc {
    match doc {
        Doc::Atom(_) => doc.clone(),
        Doc::List(children) => {
            let children: Vec<Doc> = children.iter()
                .map(|c| truncate_long_lists(c, keep))
                .collect();
            // Only truncate lists with a head atom (i.e. named forms like
            // (or ...), (and ...), etc), not bare data lists.
            let has_head = matches!(children.first(), Some(Doc::Atom(_)));
            if has_head && children.len() > keep + 2 {
                // children[0] = head, children[1..] = elements
                let mut truncated = Vec::with_capacity(keep + 3);
                truncated.push(children[0].clone());
                truncated.extend(children[1..=keep].iter().cloned());
                truncated.push(Doc::atom("…"));
                truncated.push(children.last().unwrap().clone());
                Doc::List(truncated)
            } else {
                Doc::List(children)
            }
        }
    }
}

// ── Atom classification ─────────────────────────────────────────────

/// Special-form names that get highlighted.
const SPECIAL_FORMS: &[&str] = &[
    "rule", "command", "args",
];

fn is_keyword(s: &str) -> bool {
    s.starts_with(':')
}

fn is_string(s: &str) -> bool {
    s.starts_with('"')
}

/// Convention: the engine formats regex patterns as `#"pattern"` atoms
/// so that the pretty-printer can colorize them distinctly from strings.
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
    /// Optional source line number to prefix on the first output line.
    /// Subsequent wrapped lines are indented to match.
    pub line_number: Option<usize>,
}

impl Default for Format {
    fn default() -> Self {
        Self { width: 72, color: false, line_number: None }
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
    let prefix_width = fmt.line_number.map_or(0, line_prefix_width);
    let content = render(doc, indent + prefix_width, fmt.width, fmt.color);

    match fmt.line_number {
        Some(n) => prepend_line_number(&content, n, fmt.color),
        None => content,
    }
}

/// Width of the `"N: "` prefix for a given line number.
fn line_prefix_width(n: usize) -> usize {
    // "N: " = digits + 2
    format!("{n}").len() + 2
}

/// Prepend a dimmed line number to the first line. Continuation lines
/// are left as-is — `render()` already indents them to account for
/// the prefix width passed via `indent`.
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
pub fn colorize_atom(s: &str, color: bool) -> String {
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

/// Visible length of a string, ignoring ANSI SGR escape sequences (`ESC[...m`).
///
/// Only handles SGR codes (terminated by `m`). Other CSI sequences (cursor
/// movement, etc.) are not expected here — the `colored` crate only emits SGR.
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

    fn pp(doc: &Doc, width: usize) -> String {
        pretty(doc, 0, &Format { width, ..Default::default() })
    }

    fn pp_color(doc: &Doc, width: usize) -> String {
        pretty(doc, 0, &Format { width, color: true, ..Default::default() })
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
        let sexpr = may_i_sexpr::Sexpr::Atom("hello".into(), may_i_sexpr::Span::new(0, 0));
        let doc = Doc::from_sexpr(&sexpr);
        assert_eq!(pp(&doc, 80), "hello");
    }

    #[test]
    fn from_sexpr_atom_needs_quoting() {
        let sexpr = may_i_sexpr::Sexpr::Atom("hello world".into(), may_i_sexpr::Span::new(0, 0));
        let doc = Doc::from_sexpr(&sexpr);
        assert_eq!(pp(&doc, 80), "\"hello world\"");
    }

    #[test]
    fn from_sexpr_list() {
        let sexpr = may_i_sexpr::Sexpr::List(
            vec![
                may_i_sexpr::Sexpr::Atom("rule".into(), may_i_sexpr::Span::new(0, 0)),
                may_i_sexpr::Sexpr::Atom("foo".into(), may_i_sexpr::Span::new(0, 0)),
            ],
            may_i_sexpr::Span::new(0, 0),
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
        let result = pretty(&doc, 0, &Format {
            width: 80,
            line_number: Some(108),
            ..Default::default()
        });
        assert_eq!(result, "108: (rule (command \"curl\"))");
    }

    #[test]
    fn line_number_wrapped_aligns() {
        let doc = l(vec![a("rule"), a("aaa"), a("bbb"), a("ccc")]);
        let result = pretty(&doc, 0, &Format {
            width: 20,
            line_number: Some(5),
            ..Default::default()
        });
        let lines: Vec<&str> = result.lines().collect();
        assert!(lines.len() > 1);
        assert!(lines[0].starts_with("5: "));
        // Subsequent lines are indented by render() to align under first arg.
        // "5: (rule aaa" → align column = prefix(3) + 1("(") + 4("rule") + 1(" ") = 9
        assert!(lines[1].starts_with("         "));
    }

    #[test]
    fn line_number_accounts_for_width() {
        // With line_number, the effective indent increases, affecting wrap decisions.
        let doc = l(vec![a("rule"), l(vec![a("command"), a("\"curl\"")])]);
        // Width 30: "108: (rule (command \"curl\"))" = 27 chars, fits.
        let result = pretty(&doc, 0, &Format {
            width: 30,
            line_number: Some(108),
            ..Default::default()
        });
        assert!(!result.contains('\n'));
    }
}
