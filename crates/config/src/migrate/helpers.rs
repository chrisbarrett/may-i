use may_i_sexpr::cst::{CstNode, Shape};

/// Extract children from a node tagged with `tag`. Returns `None` if the node
/// is not a list whose first element is an atom equal to `tag`.
pub(crate) fn tagged_list<'a>(tag: &str, node: &'a CstNode) -> Option<&'a [Box<CstNode>]> {
    if !node.is_tagged(tag) {
        return None;
    }
    node.as_list()
}

/// Rebuild a list node preserving the original node's annotation.
#[allow(clippy::vec_box)] // Shape::List requires Vec<Box<CstNode>>
pub(crate) fn rebuild_list(node: &CstNode, children: Vec<Box<CstNode>>) -> Box<CstNode> {
    Box::new(CstNode {
        ann: node.ann.clone(),
        shape: Shape::List(children),
    })
}

// The "reflow a source-parsed node for construction" rule now lives in the
// rewrite-traversal seam as `may_i_sexpr::cst::reflow`, so the seam and the
// passes share one implementation. Passes call it directly.

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
        Shape::Keyword(_) | Shape::Symbol(_) | Shape::Binding(_) | Shape::String(_) => 1,

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
        // (allow "reason") -> 1 + max(1, 1) = 2
        assert_eq!(c("(allow \"reason\")"), 2);
    }

    #[test]
    fn complexity_when() {
        // (when pred (allow)) -> 1 + max(C(pred), C(effect))
        // = 1 + max(1, 2) = 3
        assert_eq!(c("(when pred (allow \"r\"))"), 3);
    }

    #[test]
    fn complexity_if() {
        // (if pred (allow "r") (deny "r"))
        // = 1 + max(1, 2, 2) = 3
        assert_eq!(c("(if pred (allow \"r\") (deny \"r\"))"), 3);
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

    // The reflow rule (whitespace stripping + comment preservation + sentinel
    // span) now lives in the seam and is covered by `may_i_sexpr::cst::reflow`
    // proptests; this test pins the end-to-end migration guarantee.
    #[test]
    fn migration_preserves_inline_comment() {
        let input = "(rule (command cargo) ;; flags-only, e.g. 'cargo --list'\n  (allow))";
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
