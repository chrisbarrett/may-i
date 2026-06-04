// `(may-i *)` → host-context-aware rewrite.
//
// `(authorise)` only appears nested in a host context that supplies the
// recursion operand:
//   - `(parameter NAME (authorise))`   — parameter value is the operand
//   - `(tail (authorise))`             — tail slice is the operand
//   - `(positional X (authorise) Y)`   — single positional element
//
// Bare `(authorise)` at any other effect position is a config-load
// error. The migration therefore picks based on context:
//   - Inside a `(parameter NAME …)` body slot → `(authorise)`
//   - Anywhere else (rule body root, `(and …)`, `(when …)`, etc.)
//     → `(tail (authorise))` so a host context wraps it.

use may_i_sexpr::cst::{CstNode, TriviaAnn};

pub(crate) fn may_i_to_authorise(node: &CstNode) -> Option<Box<CstNode>> {
    // Local rewrite. The decision is parent-relative: a `(may-i *)` in a
    // `(parameter …)` body becomes bare `(authorise)`, elsewhere it becomes
    // `(tail (authorise))`. The seam visits children before parents, so a
    // `(may-i *)` is first rewritten to `(tail (authorise))` as a bare form;
    // when its `(parameter …)` parent is then offered, the parameter handler
    // unwraps that back to bare `(authorise)`.
    let list = node.as_list()?;
    let head = list.first().and_then(|c| c.as_atom());

    // Host context: a `(parameter NAME …)` body slot supplies the recursion
    // operand. Accept both the legacy `(may-i *)` (when this pass runs ahead of
    // the seam reaching the leaf) and the `(tail (authorise))` the seam has
    // already produced for it bottom-up.
    if head == Some("parameter") {
        let mut new_children: Vec<Box<CstNode>> = Vec::with_capacity(list.len());
        let mut any_changed = false;
        for (i, child) in list.iter().enumerate() {
            if i >= 2 && (is_may_i_star(child) || is_tail_authorise(child)) {
                new_children.push(make_authorise_form(child));
                any_changed = true;
            } else {
                new_children.push(child.clone());
            }
        }
        return any_changed.then(|| Box::new(CstNode::list(new_children, TriviaAnn::default())));
    }

    // Bare `(may-i *)` anywhere else → `(tail (authorise))` so a host context
    // wraps the recursion. Bare `(authorise)` at effect position is a
    // config-load error.
    if head == Some("may-i") && list.len() == 2 && list[1].as_atom() == Some("*") {
        return Some(make_tail_authorise_form(node));
    }

    None
}

fn is_may_i_star(node: &CstNode) -> bool {
    let Some(list) = node.as_list() else {
        return false;
    };
    list.len() == 2
        && list.first().and_then(|c| c.as_atom()) == Some("may-i")
        && list[1].as_atom() == Some("*")
}

fn is_tail_authorise(node: &CstNode) -> bool {
    let Some(list) = node.as_list() else {
        return false;
    };
    list.len() == 2
        && list.first().and_then(|c| c.as_atom()) == Some("tail")
        && matches!(list[1].as_list(), Some(inner)
            if inner.len() == 1 && inner[0].as_atom() == Some("authorise"))
}

fn make_authorise_form(source: &CstNode) -> Box<CstNode> {
    let authorise_atom = Box::new(CstNode::atom(
        "authorise",
        TriviaAnn {
            leading: vec![],
            trailing: vec![],
            span: source.ann.span,
        },
    ));
    Box::new(CstNode::list(
        vec![authorise_atom],
        TriviaAnn {
            leading: source.ann.leading.clone(),
            trailing: source.ann.trailing.clone(),
            span: source.ann.span,
        },
    ))
}

fn make_tail_authorise_form(source: &CstNode) -> Box<CstNode> {
    use may_i_sexpr::cst::Trivia;
    let authorise_inner = Box::new(CstNode::list(
        vec![Box::new(CstNode::atom("authorise", TriviaAnn::default()))],
        TriviaAnn {
            leading: vec![Trivia::Whitespace(" ".to_string())],
            trailing: vec![],
            span: source.ann.span,
        },
    ));
    Box::new(CstNode::list(
        vec![
            Box::new(CstNode::atom("tail", TriviaAnn::default())),
            authorise_inner,
        ],
        TriviaAnn {
            leading: source.ann.leading.clone(),
            trailing: source.ann.trailing.clone(),
            span: source.ann.span,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The pass is parent-relative and local; nested occurrences are reached by
    // the post-order seam, so drive it through the seam in tests.
    fn migrate_first(input: &str) -> String {
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let rules: [fn(&CstNode) -> Option<Box<CstNode>>; 1] = [may_i_to_authorise];
        may_i_sexpr::cst::rewrite_post_order(node, &rules).serialize()
    }

    #[test]
    fn rewrites_bare_may_i_to_tail_authorise() {
        // No host context above — wrap with `(tail …)` so the recursion
        // operand is explicit. Bare `(authorise)` at effect position is
        // a config-load error.
        assert_eq!(migrate_first(r#"(may-i *)"#), "(tail (authorise))");
    }

    #[test]
    fn rewrites_inside_parameter() {
        // Parameter body is a host context — bare `(authorise)` is the
        // canonical form here.
        let out = migrate_first(r#"(parameter "c" (may-i *))"#);
        assert_eq!(out, r#"(parameter "c" (authorise))"#);
    }

    #[test]
    fn rewrites_may_i_at_rule_body_root_to_tail_authorise() {
        let out = migrate_first(r#"(rule "bash" (may-i *))"#);
        assert!(out.contains("(tail (authorise))"), "{out}");
        assert!(!out.contains("may-i"), "{out}");
    }

    #[test]
    fn rewrites_inside_rule_with_parameter() {
        let out = migrate_first(r#"(rule "bash" (parameter "c" (may-i *)))"#);
        assert!(out.contains(r#"(parameter "c" (authorise))"#), "{out}");
        assert!(!out.contains("may-i"), "{out}");
    }

    #[test]
    fn rewrites_may_i_inside_combinator_to_tail_authorise() {
        let out = migrate_first(r#"(rule "ssh" (and (positional "host") (may-i *)))"#);
        assert!(out.contains("(tail (authorise))"), "{out}");
        assert!(!out.contains("may-i"), "{out}");
    }

    #[test]
    fn leaves_may_i_with_non_star_pattern() {
        // (may-i (positional X)) is not a `(may-i *)` rewrite target — leave it.
        let out = migrate_first(r#"(may-i (positional "X"))"#);
        assert!(out.contains("may-i"));
    }
}
