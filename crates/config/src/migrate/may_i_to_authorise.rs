// `(may-i *)` → `(authorise)`.
//
// Class A syntactic rewrite: retires the binary-named recursion verb. The
// `*` placeholder also retires (the host context — `(parameter NAME …)`,
// `(tail …)`, or a positional slot — supplies the operand).

use may_i_sexpr::cst::{CstNode, TriviaAnn};

pub(crate) fn may_i_to_authorise(node: &CstNode) -> Option<Box<CstNode>> {
    let list = node.as_list()?;

    // Recurse first.
    let rewritten: Vec<(Box<CstNode>, bool)> = list
        .iter()
        .map(|child| match may_i_to_authorise(child) {
            Some(new_child) => (new_child, true),
            None => (child.clone(), false),
        })
        .collect();
    let any_child_changed = rewritten.iter().any(|(_, c)| *c);
    let children: Vec<Box<CstNode>> = rewritten.into_iter().map(|(n, _)| n).collect();

    let head = children.first().and_then(|c| c.as_atom());
    if head == Some("may-i") && children.len() == 2 && children[1].as_atom() == Some("*") {
        let authorise_atom = Box::new(CstNode::atom(
            "authorise",
            TriviaAnn {
                leading: vec![],
                trailing: vec![],
                span: children[0].ann.span,
            },
        ));
        return Some(Box::new(CstNode::list(
            vec![authorise_atom],
            TriviaAnn {
                leading: node.ann.leading.clone(),
                trailing: node.ann.trailing.clone(),
                span: node.ann.span,
            },
        )));
    }

    if any_child_changed {
        return Some(Box::new(CstNode::list(
            children,
            TriviaAnn {
                leading: node.ann.leading.clone(),
                trailing: node.ann.trailing.clone(),
                span: node.ann.span,
            },
        )));
    }

    None
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
    fn rewrites_bare_may_i() {
        assert_eq!(migrate_first(r#"(may-i *)"#), "(authorise)");
    }

    #[test]
    fn rewrites_inside_parameter() {
        let out = migrate_first(r#"(parameter "c" (may-i *))"#);
        assert_eq!(out, r#"(parameter "c" (authorise))"#);
    }

    #[test]
    fn rewrites_inside_rule() {
        let out = migrate_first(r#"(rule "bash" (parameter "c" (may-i *)))"#);
        assert!(out.contains("(authorise)"), "{out}");
        assert!(!out.contains("may-i"));
    }

    #[test]
    fn leaves_may_i_with_non_star_pattern() {
        // (may-i (positional X)) is not a `(may-i *)` rewrite target — leave it.
        let out = migrate_first(r#"(may-i (positional "X"))"#);
        assert!(out.contains("may-i"));
    }
}
