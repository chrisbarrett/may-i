// S-expression AST node definitions.
//
// This module defines the Sexpr type and associated methods.
// Parsing is now handled by the CST parser in cst.rs; use `crate::parse()`
// which delegates to CST internally.

use crate::span::Span;

/// S-expression AST node with source spans.
#[derive(Debug, Clone, Eq)]
pub enum Sexpr {
    /// A keyword atom starting with `:` (e.g., `:allow`, `:via/ssh`).
    Keyword(String, Span),
    /// A bare symbol (e.g., `rule`, `git`, `fact?`).
    Symbol(String, Span),
    /// A string literal (e.g., `"~/.config"`).
    String(String, Span),
    List(Vec<Sexpr>, Span),
    Vector(Vec<Sexpr>, Span),
}

/// PartialEq ignores spans so existing test assertions are preserved.
impl PartialEq for Sexpr {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Sexpr::Keyword(a, _), Sexpr::Keyword(b, _)) => a == b,
            (Sexpr::Symbol(a, _), Sexpr::Symbol(b, _)) => a == b,
            (Sexpr::String(a, _), Sexpr::String(b, _)) => a == b,
            (Sexpr::List(a, _), Sexpr::List(b, _)) => a == b,
            (Sexpr::Vector(a, _), Sexpr::Vector(b, _)) => a == b,
            _ => false,
        }
    }
}

impl Sexpr {
    /// Return the atom string (keyword or symbol), or `None` if this is a
    /// list/vector/string.
    pub fn as_atom(&self) -> Option<&str> {
        match self {
            Sexpr::Keyword(s, _) | Sexpr::Symbol(s, _) => Some(s),
            _ => None,
        }
    }

    /// Return the string literal content, or `None` if not a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Sexpr::String(s, _) => Some(s),
            _ => None,
        }
    }

    /// Return the atom string for keywords, symbols, AND strings.
    /// This is a compatibility shim — prefer `as_atom()` or `as_str()`.
    pub fn as_atom_or_str(&self) -> Option<&str> {
        match self {
            Sexpr::Keyword(s, _) | Sexpr::Symbol(s, _) | Sexpr::String(s, _) => Some(s),
            _ => None,
        }
    }

    /// Return the list contents, or `None` if this is an atom.
    pub fn as_list(&self) -> Option<&[Sexpr]> {
        match self {
            Sexpr::List(v, _) | Sexpr::Vector(v, _) => Some(v),
            _ => None,
        }
    }

    pub fn is_vector(&self) -> bool {
        matches!(self, Sexpr::Vector(..))
    }

    /// Return the byte-offset span of this node.
    pub fn span(&self) -> Span {
        match self {
            Sexpr::Keyword(_, s)
            | Sexpr::Symbol(_, s)
            | Sexpr::String(_, s)
            | Sexpr::List(_, s)
            | Sexpr::Vector(_, s) => *s,
        }
    }
}

impl std::fmt::Display for Sexpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Sexpr::Keyword(s, _) | Sexpr::Symbol(s, _) => write!(f, "{s}"),
            Sexpr::String(s, _) => write!(f, "{}", quote_string(s)),
            Sexpr::List(items, _) => {
                write!(f, "(")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, ")")
            }
            Sexpr::Vector(items, _) => {
                write!(f, "[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, "]")
            }
        }
    }
}

/// Returns true if a raw atom value needs quoting when displayed as an s-expression.
pub fn needs_quoting(s: &str) -> bool {
    s.is_empty()
        || s.contains(|c: char| {
            c.is_whitespace()
                || c == '('
                || c == ')'
                || c == '['
                || c == ']'
                || c == '"'
                || c == ';'
                || c == '\\'
        })
}

/// Quote a string for s-expression display, escaping backslashes and double quotes.
pub fn quote_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sexpr_span_keyword() {
        let sexpr = Sexpr::Keyword(":allow".to_string(), Span::new(0, 6));
        assert_eq!(sexpr.span(), Span::new(0, 6));
    }

    #[test]
    fn test_sexpr_span_symbol() {
        let sexpr = Sexpr::Symbol("foo".to_string(), Span::new(0, 3));
        assert_eq!(sexpr.span(), Span::new(0, 3));
    }

    #[test]
    fn test_sexpr_span_list() {
        let sexpr = Sexpr::List(vec![], Span::new(0, 2));
        assert_eq!(sexpr.span(), Span::new(0, 2));
    }

    #[test]
    fn test_sexpr_span_vector() {
        let sexpr = Sexpr::Vector(vec![], Span::new(0, 2));
        assert_eq!(sexpr.span(), Span::new(0, 2));
    }

    #[test]
    fn test_needs_quoting_empty() {
        assert!(needs_quoting(""));
    }

    #[test]
    fn test_needs_quoting_whitespace() {
        assert!(needs_quoting("hello world"));
        assert!(needs_quoting("hello\tworld"));
        assert!(needs_quoting("hello\nworld"));
    }

    #[test]
    fn test_needs_quoting_special_chars() {
        assert!(needs_quoting("foo(bar)"));
        assert!(needs_quoting("foo[bar]"));
        assert!(needs_quoting("foo\"bar\""));
        assert!(needs_quoting("foo;bar"));
        assert!(needs_quoting("foo\\bar"));
    }

    #[test]
    fn test_needs_quoting_normal() {
        assert!(!needs_quoting("foo"));
        assert!(!needs_quoting("foo-bar"));
        assert!(!needs_quoting("foo_bar"));
        assert!(!needs_quoting("foo*bar"));
    }

    #[test]
    fn test_quote_string_simple() {
        assert_eq!(quote_string("foo"), "\"foo\"");
    }

    #[test]
    fn test_quote_string_with_quotes() {
        assert_eq!(quote_string("foo\"bar"), "\"foo\\\"bar\"");
    }

    #[test]
    fn test_quote_string_with_backslash() {
        assert_eq!(quote_string("foo\\bar"), "\"foo\\\\bar\"");
    }

    #[test]
    fn test_quote_string_complex() {
        assert_eq!(quote_string("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }

    #[test]
    fn test_display_vector_empty() {
        let sexpr = Sexpr::Vector(vec![], Span::new(0, 0));
        assert_eq!(format!("{}", sexpr), "[]");
    }

    #[test]
    fn test_display_vector_single() {
        let sexpr = Sexpr::Vector(
            vec![Sexpr::Symbol("foo".to_string(), Span::new(0, 0))],
            Span::new(0, 0),
        );
        assert_eq!(format!("{}", sexpr), "[foo]");
    }

    #[test]
    fn test_display_vector_multiple() {
        let sexpr = Sexpr::Vector(
            vec![
                Sexpr::Symbol("foo".to_string(), Span::new(0, 0)),
                Sexpr::Symbol("bar".to_string(), Span::new(0, 0)),
            ],
            Span::new(0, 0),
        );
        assert_eq!(format!("{}", sexpr), "[foo bar]");
    }

    #[test]
    fn test_display_nested() {
        let sexpr = Sexpr::List(
            vec![
                Sexpr::Symbol("outer".to_string(), Span::new(0, 0)),
                Sexpr::List(
                    vec![Sexpr::Symbol("inner".to_string(), Span::new(0, 0))],
                    Span::new(0, 0),
                ),
            ],
            Span::new(0, 0),
        );
        assert_eq!(format!("{}", sexpr), "(outer (inner))");
    }

    #[test]
    fn test_display_vector_nested() {
        let sexpr = Sexpr::Vector(
            vec![Sexpr::List(
                vec![Sexpr::Symbol("foo".to_string(), Span::new(0, 0))],
                Span::new(0, 0),
            )],
            Span::new(0, 0),
        );
        assert_eq!(format!("{}", sexpr), "[(foo)]");
    }

    #[test]
    fn test_display_string_always_quoted() {
        let sexpr = Sexpr::String("foo".to_string(), Span::new(0, 0));
        assert_eq!(format!("{}", sexpr), "\"foo\"");
    }

    #[test]
    fn test_display_string_with_path() {
        let sexpr = Sexpr::String("~/.config/foo".to_string(), Span::new(0, 0));
        assert_eq!(format!("{}", sexpr), "\"~/.config/foo\"");
    }

    #[test]
    fn test_is_vector_true() {
        let sexpr = Sexpr::Vector(vec![], Span::new(0, 0));
        assert!(sexpr.is_vector());
    }

    #[test]
    fn test_is_vector_false() {
        let sym = Sexpr::Symbol("foo".to_string(), Span::new(0, 0));
        let list = Sexpr::List(vec![], Span::new(0, 0));
        assert!(!sym.is_vector());
        assert!(!list.is_vector());
    }

    #[test]
    fn test_as_list_on_vector() {
        let sexpr = Sexpr::Vector(
            vec![Sexpr::Symbol("foo".to_string(), Span::new(0, 0))],
            Span::new(0, 0),
        );
        assert!(sexpr.as_list().is_some());
    }

    #[test]
    fn test_as_atom_returns_none_for_string() {
        let sexpr = Sexpr::String("foo".to_string(), Span::new(0, 0));
        assert!(sexpr.as_atom().is_none());
    }

    #[test]
    fn test_as_str_returns_string_content() {
        let sexpr = Sexpr::String("foo".to_string(), Span::new(0, 0));
        assert_eq!(sexpr.as_str(), Some("foo"));
    }

    #[test]
    fn test_as_atom_or_str_returns_all() {
        let kw = Sexpr::Keyword(":allow".to_string(), Span::new(0, 0));
        let sym = Sexpr::Symbol("foo".to_string(), Span::new(0, 0));
        let s = Sexpr::String("bar".to_string(), Span::new(0, 0));
        assert_eq!(kw.as_atom_or_str(), Some(":allow"));
        assert_eq!(sym.as_atom_or_str(), Some("foo"));
        assert_eq!(s.as_atom_or_str(), Some("bar"));
    }

    #[test]
    fn test_partialeq_different_variants() {
        let sym = Sexpr::Symbol("foo".to_string(), Span::new(0, 3));
        let list = Sexpr::List(vec![], Span::new(0, 2));
        assert_ne!(sym, list);
    }

    #[test]
    fn test_partialeq_keyword_vs_symbol() {
        let kw = Sexpr::Keyword(":foo".to_string(), Span::new(0, 4));
        let sym = Sexpr::Symbol(":foo".to_string(), Span::new(0, 4));
        assert_ne!(kw, sym);
    }

    #[test]
    fn test_partialeq_spans_ignored() {
        let a = Sexpr::Symbol("foo".to_string(), Span::new(0, 3));
        let b = Sexpr::Symbol("foo".to_string(), Span::new(10, 13));
        assert_eq!(a, b);
    }
}
