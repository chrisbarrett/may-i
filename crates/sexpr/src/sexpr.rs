// S-expression AST node definitions.
//
// This module defines the Sexpr type and associated methods.
// Parsing is now handled by the CST parser in cst.rs; use `crate::parse()`
// which delegates to CST internally.

use crate::span::Span;

/// S-expression AST node with source spans.
#[derive(Debug, Clone, Eq)]
pub enum Sexpr {
    Atom(String, Span),
    List(Vec<Sexpr>, Span),
    Vector(Vec<Sexpr>, Span),
}

/// PartialEq ignores spans so existing test assertions are preserved.
impl PartialEq for Sexpr {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Sexpr::Atom(a, _), Sexpr::Atom(b, _)) => a == b,
            (Sexpr::List(a, _), Sexpr::List(b, _)) => a == b,
            (Sexpr::Vector(a, _), Sexpr::Vector(b, _)) => a == b,
            _ => false,
        }
    }
}

impl Sexpr {
    /// Return the atom string, or `None` if this is a list.
    pub fn as_atom(&self) -> Option<&str> {
        match self {
            Sexpr::Atom(s, _) => Some(s),
            Sexpr::List(..) | Sexpr::Vector(..) => None,
        }
    }

    /// Return the list contents, or `None` if this is an atom.
    pub fn as_list(&self) -> Option<&[Sexpr]> {
        match self {
            Sexpr::Atom(..) => None,
            Sexpr::List(v, _) | Sexpr::Vector(v, _) => Some(v),
        }
    }

    pub fn is_vector(&self) -> bool {
        matches!(self, Sexpr::Vector(..))
    }

    /// Return the byte-offset span of this node.
    pub fn span(&self) -> Span {
        match self {
            Sexpr::Atom(_, s) | Sexpr::List(_, s) | Sexpr::Vector(_, s) => *s,
        }
    }
}

impl std::fmt::Display for Sexpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Sexpr::Atom(s, _) => {
                if needs_quoting(s) {
                    write!(f, "{}", quote_atom(s))
                } else {
                    write!(f, "{s}")
                }
            }
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

/// Quote an atom string for s-expression display, escaping backslashes and double quotes.
pub fn quote_atom(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sexpr_span_atom() {
        let sexpr = Sexpr::Atom("foo".to_string(), Span::new(0, 3));
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
    fn test_quote_atom_simple() {
        assert_eq!(quote_atom("foo"), "\"foo\"");
    }

    #[test]
    fn test_quote_atom_with_quotes() {
        assert_eq!(quote_atom("foo\"bar"), "\"foo\\\"bar\"");
    }

    #[test]
    fn test_quote_atom_with_backslash() {
        assert_eq!(quote_atom("foo\\bar"), "\"foo\\\\bar\"");
    }

    #[test]
    fn test_quote_atom_complex() {
        assert_eq!(quote_atom("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }

    #[test]
    fn test_display_vector_empty() {
        let sexpr = Sexpr::Vector(vec![], Span::new(0, 0));
        assert_eq!(format!("{}", sexpr), "[]");
    }

    #[test]
    fn test_display_vector_single() {
        let sexpr = Sexpr::Vector(
            vec![Sexpr::Atom("foo".to_string(), Span::new(0, 0))],
            Span::new(0, 0),
        );
        assert_eq!(format!("{}", sexpr), "[foo]");
    }

    #[test]
    fn test_display_vector_multiple() {
        let sexpr = Sexpr::Vector(
            vec![
                Sexpr::Atom("foo".to_string(), Span::new(0, 0)),
                Sexpr::Atom("bar".to_string(), Span::new(0, 0)),
            ],
            Span::new(0, 0),
        );
        assert_eq!(format!("{}", sexpr), "[foo bar]");
    }

    #[test]
    fn test_display_nested() {
        let sexpr = Sexpr::List(
            vec![
                Sexpr::Atom("outer".to_string(), Span::new(0, 0)),
                Sexpr::List(
                    vec![Sexpr::Atom("inner".to_string(), Span::new(0, 0))],
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
                vec![Sexpr::Atom("foo".to_string(), Span::new(0, 0))],
                Span::new(0, 0),
            )],
            Span::new(0, 0),
        );
        assert_eq!(format!("{}", sexpr), "[(foo)]");
    }

    #[test]
    fn test_is_vector_true() {
        let sexpr = Sexpr::Vector(vec![], Span::new(0, 0));
        assert!(sexpr.is_vector());
    }

    #[test]
    fn test_is_vector_false() {
        let atom = Sexpr::Atom("foo".to_string(), Span::new(0, 0));
        let list = Sexpr::List(vec![], Span::new(0, 0));
        assert!(!atom.is_vector());
        assert!(!list.is_vector());
    }

    #[test]
    fn test_as_list_on_vector() {
        let sexpr = Sexpr::Vector(
            vec![Sexpr::Atom("foo".to_string(), Span::new(0, 0))],
            Span::new(0, 0),
        );
        assert!(sexpr.as_list().is_some());
    }

    #[test]
    fn test_partialeq_different_variants() {
        let atom = Sexpr::Atom("foo".to_string(), Span::new(0, 3));
        let list = Sexpr::List(vec![], Span::new(0, 2));
        assert_ne!(atom, list);
    }

    #[test]
    fn test_partialeq_spans_ignored() {
        let a = Sexpr::Atom("foo".to_string(), Span::new(0, 3));
        let b = Sexpr::Atom("foo".to_string(), Span::new(10, 13));
        assert_eq!(a, b);
    }
}
