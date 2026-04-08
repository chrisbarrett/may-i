// S-expression pretty-printer with configurable width and syntax coloring.
//
// The core Doc/DocF types live in `may-i-core::doc` and are re-exported here
// for convenience. This crate provides rendering (pretty-printing, colorization)
// and s-expression string parsing.

mod buffer;
pub mod color;
pub mod output;
mod render;

pub use buffer::{AnnotatedLine, AnnotatedLineBuilder, StringBuilder};
pub use color::{colorize_atom, visible_len};
pub use output::{OutputEvent, PrettyOutput};
pub use render::{line_prefix_width, pretty, pretty_into};

#[cfg(test)]
pub(crate) use colored::Colorize;
#[cfg(test)]
pub(crate) use may_i_core::{Doc, DocF, LayoutHint, Trivia, TriviaSource};

// ── from_sexpr (test-only) ─────────────────────────────────────────

#[cfg(test)]
pub(crate) fn doc_from_sexpr(sexpr: &may_i_sexpr::Sexpr) -> Doc {
    match sexpr {
        may_i_sexpr::Sexpr::Keyword(s, _) | may_i_sexpr::Sexpr::Symbol(s, _) => {
            Doc::atom(s.clone())
        }
        may_i_sexpr::Sexpr::String(s, _) => Doc::atom(may_i_sexpr::quote_atom(s)),
        may_i_sexpr::Sexpr::List(items, _) | may_i_sexpr::Sexpr::Vector(items, _) => {
            Doc::list(items.iter().map(doc_from_sexpr).collect())
        }
    }
}

// ── S-expression string parser (test-only) ─────────────────────────

#[cfg(test)]
pub(crate) fn parse_sexpr(input: &str) -> Doc {
    let tokens = tokenize(input);
    if tokens.is_empty() {
        return Doc::atom("");
    }
    let (doc, _) = parse_tokens(&tokens, 0);
    doc
}

#[cfg(test)]
pub(crate) fn tokenize(input: &str) -> Vec<&str> {
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
pub(crate) fn parse_tokens(tokens: &[&str], pos: usize) -> (Doc, usize) {
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

// ── Indent specs ────────────────────────────────────────────────────

/// Per-identifier indent specs, mapping head atoms to the number of
/// "special" arguments before the body.  Modelled after Emacs Lisp's
/// `(declare (indent N))`:
///
///   N = 0  →  all children are body (indent +2 from paren)
///   N = 1  →  first arg on head line, rest are body
///   N = 2  →  first two args special, rest are body
///   …
///
/// Identifiers not in this table use the default heuristic (align under
/// first arg when inline, indent +1 when dropped).
/// Forms with Emacs-Lisp-style `(declare (indent N))` body indentation.
/// N controls how many children after the head are "special" (stay near the
/// head) before the body, which is indented +2 from the opening paren.
///
///   N = 0  →  all children are body (indent +2)
///   N = 1  →  first arg is special (inline if fits), rest are body (+2)
///   N = 2  →  first two args special, rest are body (+2)
///
/// Forms absent from this table use function-call alignment (args align under
/// the first arg: `paren_col + 1 + head_width + 1`).
pub const INDENT_SPECS: &[(&str, u8)] = &[
    ("cond", 0),
    ("define", 1),
    ("if", 2),
    ("rule", 1),
    ("unless", 1),
    ("when", 1),
    ("with-facts", 1),
];

/// Head atoms whose all-atom argument lists use fill layout instead of
/// standard broken layout.  Fill layout packs multiple args per line,
/// wrapping at the column of the first arg.
///
/// Trigger: head is in this list AND every argument after the head is an atom.
pub const FILL_ELIGIBLE_HEADS: &[&str] = &["and", "anywhere", "forbidden", "or", "positional"];

/// Look up the indent spec for a head atom.  Returns `Some(n)` if the
/// identifier has a declared indent, `None` for the default heuristic.
pub fn indent_spec(name: &str) -> Option<u8> {
    INDENT_SPECS
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| *v)
}

#[cfg(test)]
pub(crate) fn force_color() {
    use std::sync::Once;
    // Enable colors once for all color tests. Never unset — unsetting
    // races with parallel tests that expect colors to be on.
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        colored::control::set_override(true);
    });
}

#[cfg(test)]
mod tests;
