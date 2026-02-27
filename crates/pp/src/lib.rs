// S-expression pretty-printer with configurable width and syntax coloring.
//
// The core Doc/DocF types live in `may-i-core::doc` and are re-exported here
// for convenience. This crate provides rendering (pretty-printing, colorization)
// and s-expression string parsing.

use colored::Colorize;

pub use may_i_core::{Doc, DocF, LayoutHint};

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
        may_i_sexpr::Sexpr::List(items, _) => {
            Doc::list(items.iter().map(doc_from_sexpr).collect())
        }
    }
}

// ── S-expression string parser ──────────────────────────────────────

/// Parse an s-expression string (e.g. `(command "curl")`) into a Doc tree.
pub fn parse_sexpr(input: &str) -> Doc {
    let tokens = tokenize(input);
    if tokens.is_empty() {
        return Doc::atom("");
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
        if i < tokens.len() { i += 1; } // skip )
        (Doc::list(children), i)
    } else {
        (Doc::atom(tokens[pos]), pos + 1)
    }
}

// ── Doc transforms ─────────────────────────────────────────────────

/// Truncate long lists in a Doc tree, keeping the first `keep`
/// and last 1 elements with an `…` ellipsis in between.
pub fn truncate_long_lists(doc: &Doc, keep: usize) -> Doc {
    match &doc.node {
        DocF::Atom(_) => doc.clone(),
        DocF::List(children) => {
            let children: Vec<Doc> = children.iter()
                .map(|c| truncate_long_lists(c, keep))
                .collect();
            let has_head = children.first().is_some_and(|c| c.as_atom().is_some());
            if has_head && children.len() > keep + 2 {
                let mut truncated = Vec::with_capacity(keep + 3);
                truncated.push(children[0].clone());
                truncated.extend(children[1..=keep].iter().cloned());
                truncated.push(Doc::atom("…"));
                truncated.push(children.last().unwrap().clone());
                Doc::list(truncated)
            } else {
                Doc { ann: (), node: DocF::List(children), layout: doc.layout, dimmed: false }
            }
        }
    }
}

// ── Atom classification ─────────────────────────────────────────────

const SPECIAL_FORMS: &[&str] = &[
    "rule", "command", "args", "effect",
    "cond", "if", "when", "unless", "else",
    "positional", "exact", "anywhere",
];

fn is_keyword(s: &str) -> bool { s.starts_with(':') }
fn is_string(s: &str) -> bool { s.starts_with('"') }
fn is_regex(s: &str) -> bool { s.starts_with("#\"") }
fn is_special_form(s: &str) -> bool { SPECIAL_FORMS.contains(&s) }

// ── Formatting settings ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Format {
    pub width: usize,
    pub color: bool,
    pub line_number: Option<usize>,
}

impl Default for Format {
    fn default() -> Self {
        Self { width: 72, color: false, line_number: None }
    }
}

impl Format {
    pub fn colored() -> Self {
        Self { color: true, ..Self::default() }
    }
}

// ── Rendering ───────────────────────────────────────────────────────

/// Pretty-print a Doc with the given format settings.
pub fn pretty<A>(doc: &Doc<A>, indent: usize, fmt: &Format) -> String {
    let prefix_width = fmt.line_number.map_or(0, line_prefix_width);
    let content = render(doc, indent + prefix_width, fmt.width, fmt.color, false);

    match fmt.line_number {
        Some(n) => prepend_line_number(&content, n, fmt.color),
        None => content,
    }
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

fn render<A>(doc: &Doc<A>, indent: usize, width: usize, color: bool, dimmed: bool) -> String {
    // Inherit dimmed from ancestors; once dimmed, stays dimmed.
    let dimmed = dimmed || doc.dimmed;
    match &doc.node {
        DocF::Atom(s) => render_atom(s, color, dimmed),
        DocF::List(children) if children.is_empty() => {
            if color {
                format!("{}{}", "(".dimmed(), ")".dimmed())
            } else {
                "()".into()
            }
        }
        DocF::List(children) => {
            if let Some(head) = children.first().and_then(|c| c.as_atom()) {
                match head {
                    "rule" => {
                        let broken = render_broken(children, indent, width, color, dimmed);
                        if max_line_width(&broken, indent) <= width {
                            return broken;
                        }
                        return render_all_drop(children, indent, width, color, dimmed);
                    }
                    "cond" => return render_cond(children, indent, width, color, dimmed),
                    "if" | "when" | "unless" => {
                        return render_body_indent(children, indent, width, color, dimmed);
                    }
                    _ => {}
                }
            }

            // Skip flat when this node or any child requires breaking.
            let must_break = doc.layout == LayoutHint::AlwaysBreak
                || children.iter().any(|c| c.layout == LayoutHint::AlwaysBreak);
            if !must_break {
                let flat = render_flat(children, color, dimmed);
                if !flat.contains('\n') && indent + visible_len(&flat) <= width {
                    return flat;
                }
            }
            let broken = render_broken(children, indent, width, color, dimmed);
            // Accept broken layout if every line fits within the width.
            if max_line_width(&broken, indent) <= width {
                return broken;
            }
            // Last resort: drop all children to separate lines at indent+2.
            // (Special forms like when/if/unless are routed to
            // render_body_indent above and never reach here.)
            render_all_drop(children, indent, width, color, dimmed)
        }
    }
}

/// Render an atom, respecting dimmed state. When dimmed, all atoms
/// render as dim text regardless of their syntactic role.
fn render_atom(s: &str, color: bool, dimmed: bool) -> String {
    if dimmed && color {
        s.dimmed().to_string()
    } else {
        colorize_atom(s, color)
    }
}

fn render_flat<A>(children: &[Doc<A>], color: bool, dimmed: bool) -> String {
    let open = if color { "(".dimmed().to_string() } else { "(".into() };
    let close = if color { ")".dimmed().to_string() } else { ")".into() };
    let parts: Vec<String> = children.iter().map(|c| render(c, 0, usize::MAX, color, dimmed)).collect();
    format!("{open}{}{close}", parts.join(" "))
}

fn render_broken<A>(children: &[Doc<A>], indent: usize, width: usize, color: bool, dimmed: bool) -> String {
    let open = if color { "(".dimmed().to_string() } else { "(".into() };
    let close = if color { ")".dimmed().to_string() } else { ")".into() };

    let head = render(&children[0], indent + 1, width, color, dimmed);
    let align = indent + visible_len(&head) + 2;

    let mut lines = Vec::new();

    if children.len() == 1 {
        lines.push(format!("{open}{head}{close}"));
    } else {
        let first_child = render(&children[1], align, width, color, dimmed);
        lines.push(format!("{open}{head} {first_child}"));

        for child in &children[2..] {
            let child_str = render(child, align, width, color, dimmed);
            lines.push(format!("{:pad$}{child_str}", "", pad = align));
        }
        if let Some(last) = lines.last_mut() {
            last.push_str(&close);
        }
    }

    lines.join("\n")
}

/// Render with all children dropped to new lines at indent+2.
/// Used for AlwaysBreak nodes where uniform child alignment is wanted.
fn render_all_drop<A>(children: &[Doc<A>], indent: usize, width: usize, color: bool, dimmed: bool) -> String {
    let open = if color { "(".dimmed().to_string() } else { "(".into() };
    let close = if color { ")".dimmed().to_string() } else { ")".into() };

    let head = render(&children[0], indent + 1, width, color, dimmed);
    let child_indent = indent + 2;

    if children.len() == 1 {
        return format!("{open}{head}{close}");
    }

    let mut lines = vec![format!("{open}{head}")];
    for (i, child) in children[1..].iter().enumerate() {
        let is_last = i == children.len() - 2;
        let rendered = render(child, child_indent, width, color, dimmed);
        if is_last {
            lines.push(format!("{:pad$}{rendered}{close}", "", pad = child_indent));
        } else {
            lines.push(format!("{:pad$}{rendered}", "", pad = child_indent));
        }
    }

    lines.join("\n")
}

fn render_cond<A>(children: &[Doc<A>], indent: usize, width: usize, color: bool, dimmed: bool) -> String {
    let open = if color { "(".dimmed().to_string() } else { "(".into() };
    let close = if color { ")".dimmed().to_string() } else { ")".into() };

    let head = render(&children[0], indent + 1, width, color, dimmed);
    let body_indent = indent + 2;

    let mut lines = vec![format!("{open}{head}")];

    for (i, clause) in children[1..].iter().enumerate() {
        let is_last = i == children.len() - 2;
        // Inherit dimmed from the clause node itself (e.g. unevaluated branches).
        let clause_dimmed = dimmed || clause.dimmed;
        match &clause.node {
            DocF::List(parts) if parts.len() >= 2 => {
                let clause_open = if color { "(".dimmed().to_string() } else { "(".into() };
                let clause_close = if color { ")".dimmed().to_string() } else { ")".into() };

                let test = render(&parts[0], body_indent + 1, width, color, clause_dimmed);
                lines.push(format!("{:pad$}{clause_open}{test}", "", pad = body_indent));

                let body_col = body_indent + 1;
                for (j, body_part) in parts[1..].iter().enumerate() {
                    let is_last_part = j == parts.len() - 2;
                    let rendered = render(body_part, body_col, width, color, clause_dimmed);
                    if is_last_part && is_last {
                        lines.push(format!("{:pad$}{rendered}{clause_close}{close}", "", pad = body_col));
                    } else if is_last_part {
                        lines.push(format!("{:pad$}{rendered}{clause_close}", "", pad = body_col));
                    } else {
                        lines.push(format!("{:pad$}{rendered}", "", pad = body_col));
                    }
                }
            }
            _ => {
                let rendered = render(clause, body_indent, width, color, clause_dimmed);
                if is_last {
                    lines.push(format!("{:pad$}{rendered}{close}", "", pad = body_indent));
                } else {
                    lines.push(format!("{:pad$}{rendered}", "", pad = body_indent));
                }
            }
        }
    }

    if children.len() == 1
        && let Some(last) = lines.last_mut()
    {
        last.push_str(&close);
    }

    lines.join("\n")
}

fn render_body_indent<A>(children: &[Doc<A>], indent: usize, width: usize, color: bool, dimmed: bool) -> String {
    let open = if color { "(".dimmed().to_string() } else { "(".into() };
    let close = if color { ")".dimmed().to_string() } else { ")".into() };

    let head = render(&children[0], indent + 1, width, color, dimmed);
    let body_indent = indent + 2;

    if children.len() == 1 {
        return format!("{open}{head}{close}");
    }

    // Try placing the first child on the same line as the head.
    let inline_col = indent + 1 + visible_len(&head) + 1;
    let first = render(&children[1], inline_col, width, color, dimmed);
    let first_multiline = first.contains('\n');

    let mut lines = if first_multiline {
        // First child wraps — drop it to the next line.
        // For predicate forms (when/if/unless), use extra indent (indent+4)
        // to visually distinguish the predicate from the body (at indent+2).
        let head_atom = children[0].as_atom().unwrap_or("");
        let is_predicate_form = matches!(head_atom, "when" | "if" | "unless");
        let first_indent = if is_predicate_form { indent + 4 } else { body_indent };
        let first = render(&children[1], first_indent, width, color, dimmed);
        vec![
            format!("{open}{head}"),
            format!("{:pad$}{first}", "", pad = first_indent),
        ]
    } else {
        vec![format!("{open}{head} {first}")]
    };

    for (i, child) in children[2..].iter().enumerate() {
        let is_last = i == children.len() - 3;
        let rendered = render(child, body_indent, width, color, dimmed);
        if is_last {
            lines.push(format!("{:pad$}{rendered}{close}", "", pad = body_indent));
        } else {
            lines.push(format!("{:pad$}{rendered}", "", pad = body_indent));
        }
    }

    if children.len() == 2
        && let Some(last) = lines.last_mut()
    {
        last.push_str(&close);
    }

    lines.join("\n")
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

/// Widest visible line in a multi-line rendered string.
/// `base_indent` is added to the first line (which lacks indentation padding
/// because indentation is added by the caller).
fn max_line_width(rendered: &str, base_indent: usize) -> usize {
    rendered.lines().enumerate()
        .map(|(i, line)| {
            let w = visible_len(line);
            if i == 0 { base_indent + w } else { w }
        })
        .max()
        .unwrap_or(0)
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

    fn pp(doc: &Doc, width: usize) -> String {
        pretty(doc, 0, &Format { width, ..Default::default() })
    }

    fn pp_color(doc: &Doc, width: usize) -> String {
        pretty(doc, 0, &Format { width, color: true, ..Default::default() })
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
        assert!(lines[1].starts_with("         "));
    }

    #[test]
    fn line_number_accounts_for_width() {
        let doc = l(vec![a("rule"), l(vec![a("command"), a("\"curl\"")])]);
        let result = pretty(&doc, 0, &Format {
            width: 30,
            line_number: Some(108),
            ..Default::default()
        });
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
            DocF::List(children) => 1 + children.iter().sum::<usize>(),
        });
        assert_eq!(count, 5); // list + a + list + b + c
    }

    #[test]
    fn fold_collects_atoms() {
        let doc = l(vec![a("rule"), a("foo"), l(vec![a("bar")])]);
        let atoms: Vec<String> = doc.fold(&|node, _ann| match node {
            DocF::Atom(s) => vec![s],
            DocF::List(children) => children.into_iter().flatten().collect(),
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
            a("or"), a("\"long-value-one\""), a("\"long-value-two\""),
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
            let doc = Doc { dimmed: true, ..a("command") };
            let result = pp_color(&doc, 80);
            // Should contain ANSI (dimmed), but not the blue syntax color.
            assert!(result.contains("\x1b["), "expected ANSI in: {result:?}");
            assert!(result.contains("command"));
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
            let dimmed_child = Doc { dimmed: true, ..a("\"dimmed\"") };
            let normal_child = a("\"bright\"");
            let doc = l(vec![a("or"), dimmed_child, normal_child]);
            let result = pp_color(&doc, 80);
            // Both should be present.
            assert!(result.contains("dimmed"));
            assert!(result.contains("bright"));
        });
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
                ).prop_map(|(head, mut children)| {
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
                if ch.is_ascii_alphabetic() { in_escape = false; }
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
                    DocF::List(cs) => cs.into_iter().max().unwrap_or(0),
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
                if ch.is_ascii_alphabetic() { in_escape = false; }
            } else if ch == '\x1b' {
                in_escape = true;
            } else {
                result.push(ch);
            }
        }
        result
    }
}
