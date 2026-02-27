// S-expression pretty-printer with configurable width and syntax coloring.
//
// The core Doc/DocF types live in `may-i-core::doc` and are re-exported here
// for convenience. This crate provides rendering (pretty-printing, colorization)
// and s-expression string parsing.

use colored::Colorize;

pub use may_i_core::{Doc, DocF};

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
            Doc { ann: (), node: DocF::Atom(text) }
        }
        may_i_sexpr::Sexpr::List(items, _) => {
            Doc { ann: (), node: DocF::List(items.iter().map(doc_from_sexpr).collect()) }
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
                Doc { ann: (), node: DocF::List(children) }
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
    let content = render(doc, indent + prefix_width, fmt.width, fmt.color);

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

fn render<A>(doc: &Doc<A>, indent: usize, width: usize, color: bool) -> String {
    match &doc.node {
        DocF::Atom(s) => colorize_atom(s, color),
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
                    "cond" => return render_cond(children, indent, width, color),
                    "if" | "when" | "unless" => {
                        return render_body_indent(children, indent, width, color);
                    }
                    _ => {}
                }
            }

            let flat = render_flat(children, color);
            if indent + visible_len(&flat) <= width {
                return flat;
            }
            render_broken(children, indent, width, color)
        }
    }
}

fn render_flat<A>(children: &[Doc<A>], color: bool) -> String {
    let open = if color { "(".dimmed().to_string() } else { "(".into() };
    let close = if color { ")".dimmed().to_string() } else { ")".into() };
    let parts: Vec<String> = children.iter().map(|c| render(c, 0, usize::MAX, color)).collect();
    format!("{open}{}{close}", parts.join(" "))
}

fn render_broken<A>(children: &[Doc<A>], indent: usize, width: usize, color: bool) -> String {
    let open = if color { "(".dimmed().to_string() } else { "(".into() };
    let close = if color { ")".dimmed().to_string() } else { ")".into() };

    let head = render(&children[0], indent + 1, width, color);
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
        if let Some(last) = lines.last_mut() {
            last.push_str(&close);
        }
    }

    lines.join("\n")
}

fn render_cond<A>(children: &[Doc<A>], indent: usize, width: usize, color: bool) -> String {
    let open = if color { "(".dimmed().to_string() } else { "(".into() };
    let close = if color { ")".dimmed().to_string() } else { ")".into() };

    let head = render(&children[0], indent + 1, width, color);
    let body_indent = indent + 2;

    let mut lines = vec![format!("{open}{head}")];

    for (i, clause) in children[1..].iter().enumerate() {
        let is_last = i == children.len() - 2;
        match &clause.node {
            DocF::List(parts) if parts.len() >= 2 => {
                let clause_open = if color { "(".dimmed().to_string() } else { "(".into() };
                let clause_close = if color { ")".dimmed().to_string() } else { ")".into() };

                let test = render(&parts[0], body_indent + 1, width, color);
                lines.push(format!("{:pad$}{clause_open}{test}", "", pad = body_indent));

                let body_col = body_indent + 1;
                for (j, body_part) in parts[1..].iter().enumerate() {
                    let is_last_part = j == parts.len() - 2;
                    let rendered = render(body_part, body_col, width, color);
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
                let rendered = render(clause, body_indent, width, color);
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

fn render_body_indent<A>(children: &[Doc<A>], indent: usize, width: usize, color: bool) -> String {
    let open = if color { "(".dimmed().to_string() } else { "(".into() };
    let close = if color { ")".dimmed().to_string() } else { ")".into() };

    let head = render(&children[0], indent + 1, width, color);
    let body_indent = indent + 2;

    if children.len() == 1 {
        return format!("{open}{head}{close}");
    }

    let first = render(&children[1], indent + 1 + visible_len(&head) + 1, width, color);
    let mut lines = vec![format!("{open}{head} {first}")];

    for (i, child) in children[2..].iter().enumerate() {
        let is_last = i == children.len() - 3;
        let rendered = render(child, body_indent, width, color);
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
        let sexpr = may_i_sexpr::Sexpr::Atom("hello".into(), may_i_sexpr::Span::new(0, 0));
        let doc = doc_from_sexpr(&sexpr);
        assert_eq!(pp(&doc, 80), "hello");
    }

    #[test]
    fn from_sexpr_atom_needs_quoting() {
        let sexpr = may_i_sexpr::Sexpr::Atom("hello world".into(), may_i_sexpr::Span::new(0, 0));
        let doc = doc_from_sexpr(&sexpr);
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
}
