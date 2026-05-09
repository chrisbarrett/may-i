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
    let list = node.as_list()?;
    let head = list.first().and_then(|c| c.as_atom());
    let in_parameter_body = head == Some("parameter");

    let mut new_children: Vec<Box<CstNode>> = Vec::with_capacity(list.len());
    let mut any_changed = false;
    for (i, child) in list.iter().enumerate() {
        // Parameter body slot: `(parameter NAME (may-i *) …)`. Rewrite the
        // body slot to bare `(authorise)` (the host context), without
        // recursing — the `(authorise)` form is the leaf.
        if in_parameter_body && i >= 2 && is_may_i_star(child) {
            new_children.push(make_authorise_form(child));
            any_changed = true;
            continue;
        }
        match may_i_to_authorise(child) {
            Some(new_child) => {
                new_children.push(new_child);
                any_changed = true;
            }
            None => new_children.push(child.clone()),
        }
    }

    // Bare `(may-i *)` — at this point we know it isn't sitting in a
    // parameter body slot (that path was handled above). Rewrite to
    // `(tail (authorise))` so a host context wraps the recursion.
    if head == Some("may-i") && list.len() == 2 && list[1].as_atom() == Some("*") {
        return Some(make_tail_authorise_form(node));
    }

    if any_changed {
        return Some(Box::new(CstNode::list(
            new_children,
            TriviaAnn {
                leading: node.ann.leading.clone(),
                trailing: node.ann.trailing.clone(),
                span: node.ann.span,
            },
        )));
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

    fn migrate_first(input: &str) -> String {
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        match may_i_to_authorise(&node) {
            Some(out) => out.serialize(),
            None => node.serialize(),
        }
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
