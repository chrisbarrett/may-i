use may_i_sexpr::cst::{CstNode, Shape, TriviaAnn};

/// Recursively strip whitespace trivia from a node and its children, preserving
/// comments.
///
/// The `pp` crate uses `has_source_trivia()` (non-zero span) to decide whether
/// to preserve a node's original source layout or reflow it fresh.  When a
/// rewrite rule *clones* a source node and places it in a new structural
/// context, call `strip_whitespace_trivia` first so the renderer treats it as a
/// constructed node and applies optimal layout (fill, broken, etc.) rather than
/// locking it to the old source formatting.
///
/// Comments are preserved so that inline comments (e.g. `;; flags-only`) survive
/// migration.  When comments remain, a sentinel span `Span::new(0, 1)` is used
/// so that `has_source_trivia()` returns true and the pretty printer emits them.
///
/// **When to call:**  any time you clone a source-parsed node and embed it in a
/// freshly-built list where its old whitespace decisions no longer apply.
/// Freshly constructed nodes (built via `CstNode::atom`/`CstNode::list` with
/// `Default::default()` annotations) already have zero spans, so
/// `strip_whitespace_trivia` is not needed for them.
pub(crate) fn strip_whitespace_trivia(node: &CstNode) -> CstNode {
    use may_i_core::Trivia;

    let mut stripped = node.clone();

    let leading: Vec<Trivia> = stripped
        .ann
        .leading
        .into_iter()
        .filter(|t| matches!(t, Trivia::Comment { .. }))
        .collect();
    let trailing: Vec<Trivia> = stripped
        .ann
        .trailing
        .into_iter()
        .filter(|t| matches!(t, Trivia::Comment { .. }))
        .collect();

    let has_comments = !leading.is_empty() || !trailing.is_empty();
    stripped.ann = TriviaAnn {
        leading,
        trailing,
        span: if has_comments {
            may_i_core::Span::new(0, 1) // sentinel: keeps has_source_trivia() true
        } else {
            may_i_core::Span::new(0, 0)
        },
    };

    // Recursively strip children
    match &mut stripped.shape {
        Shape::List(children) | Shape::Vector(children) => {
            for child in children.iter_mut() {
                **child = strip_whitespace_trivia(child);
            }
        }
        _ => {}
    }

    stripped
}

/// Returns true if the atom is a capture marker used in legacy wrapper syntax.
pub(crate) fn is_capture_marker(atom: &str) -> bool {
    atom == ":command+args" || atom == ":command" || atom == ":args"
}

/// Compute the structural complexity (nesting depth) of an expression.
///
/// Used to guide rewrite heuristics (e.g. choosing between `when` and `if`).
///
/// - Atoms (keywords, strings, wildcards, identifiers): 1
/// - `(regex "r")`: 1
/// - Any other `(tag e1 ... en)`: `1 + max(C(e1), ..., C(en))`
/// - `[e1 ... en]`: `1 + max(C(e1), ..., C(en))`
pub(crate) fn complexity(node: &CstNode) -> usize {
    match &node.shape {
        Shape::Keyword(_) | Shape::Symbol(_) | Shape::String(_) => 1,

        Shape::Vector(children) => 1 + children.iter().map(|c| complexity(c)).max().unwrap_or(0),

        Shape::List(children) => {
            let tag = children.first().and_then(|c| c.as_atom());
            if tag == Some("regex") {
                return 1;
            }
            let args = &children[1..];
            1 + args.iter().map(|c| complexity(c)).max().unwrap_or(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(input: &str) -> usize {
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        complexity(&nodes[0])
    }

    #[test]
    fn complexity_atom_keyword() {
        assert_eq!(c(":allow"), 1);
    }

    #[test]
    fn complexity_atom_string() {
        assert_eq!(c("\"hello\""), 1);
    }

    #[test]
    fn complexity_atom_wildcard() {
        assert_eq!(c("*"), 1);
    }

    #[test]
    fn complexity_regex() {
        assert_eq!(c("(regex \"^foo\")"), 1);
    }

    #[test]
    fn complexity_effect() {
        // (effect :allow "reason") -> 1 + max(1, 1) = 2
        assert_eq!(c("(effect :allow \"reason\")"), 2);
    }

    #[test]
    fn complexity_when() {
        // (when pred (effect :allow)) -> 1 + max(C(pred), C(effect))
        // = 1 + max(1, 2) = 3
        assert_eq!(c("(when pred (effect :allow \"r\"))"), 3);
    }

    #[test]
    fn complexity_if() {
        // (if pred (effect :allow "r") (effect :deny "r"))
        // = 1 + max(1, 2, 2) = 3
        assert_eq!(c("(if pred (effect :allow \"r\") (effect :deny \"r\"))"), 3);
    }

    #[test]
    fn complexity_cond() {
        // (cond (pred1 e1) (pred2 e2))
        // C((pred1 e1)) = 1 + max(1) = 2
        // C(cond ...) = 1 + max(2, 2) = 3
        assert_eq!(c("(cond (pred1 e1) (pred2 e2))"), 3);
    }

    #[test]
    fn complexity_vector() {
        // [:key "value"] -> 1 + max(1, 1) = 2
        assert_eq!(c("[:key \"value\"]"), 2);
    }

    #[test]
    fn complexity_and() {
        // (and a b c) -> 1 + max(1, 1, 1) = 2
        assert_eq!(c("(and a b c)"), 2);
    }

    #[test]
    fn complexity_or() {
        // (or a b) -> 1 + max(1, 1) = 2
        assert_eq!(c("(or a b)"), 2);
    }

    #[test]
    fn complexity_nested() {
        // (and (or a b) c) -> 1 + max(C(or a b), C(c)) = 1 + max(2, 1) = 3
        assert_eq!(c("(and (or a b) c)"), 3);
    }

    #[test]
    fn strip_whitespace_trivia_preserves_comments() {
        use may_i_core::Trivia;
        use may_i_core::span::Span;

        let ann = TriviaAnn {
            leading: vec![
                Trivia::Whitespace("\n  ".into()),
                Trivia::Comment {
                    text: ";; important".into(),
                    has_newline: true,
                },
                Trivia::Whitespace("\n  ".into()),
            ],
            trailing: vec![
                Trivia::Whitespace(" ".into()),
                Trivia::Comment {
                    text: ";; trailing".into(),
                    has_newline: true,
                },
            ],
            span: Span::new(10, 20),
        };
        let node = CstNode::atom("foo", ann);
        let stripped = strip_whitespace_trivia(&node);

        let leading_comments: Vec<_> = stripped
            .ann
            .leading
            .iter()
            .filter(|t| matches!(t, Trivia::Comment { .. }))
            .collect();
        assert_eq!(
            leading_comments.len(),
            1,
            "leading comment should be preserved"
        );

        let trailing_comments: Vec<_> = stripped
            .ann
            .trailing
            .iter()
            .filter(|t| matches!(t, Trivia::Comment { .. }))
            .collect();
        assert_eq!(
            trailing_comments.len(),
            1,
            "trailing comment should be preserved"
        );

        let leading_ws: Vec<_> = stripped
            .ann
            .leading
            .iter()
            .filter(|t| matches!(t, Trivia::Whitespace(_)))
            .collect();
        assert_eq!(leading_ws.len(), 0, "whitespace should be stripped");

        assert!(
            stripped.has_source_trivia(),
            "node with comments should have source trivia"
        );
    }

    #[test]
    fn strip_whitespace_trivia_no_comments_zeroes_span() {
        use may_i_core::Trivia;
        use may_i_core::span::Span;

        let ann = TriviaAnn {
            leading: vec![Trivia::Whitespace("\n  ".into())],
            trailing: vec![Trivia::Whitespace(" ".into())],
            span: Span::new(10, 20),
        };
        let node = CstNode::atom("foo", ann);
        let stripped = strip_whitespace_trivia(&node);

        assert!(stripped.ann.leading.is_empty());
        assert!(stripped.ann.trailing.is_empty());
        assert!(
            !stripped.has_source_trivia(),
            "node without comments should not have source trivia"
        );
    }

    #[test]
    fn migration_preserves_inline_comment() {
        let input = "(rule (command cargo) ;; flags-only, e.g. 'cargo --list'\n  (effect :allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        let serialized = result.serialize();
        assert!(
            serialized.contains("flags-only"),
            "inline comment should survive migration. Got: {}",
            serialized
        );
    }
}
