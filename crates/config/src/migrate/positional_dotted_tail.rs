// `(positional ITEMS… . (authorise))` → sibling `(positional ITEMS…)`
// and `(tail (authorise))` composed via `(and …)`.
//
// Class A syntactic rewrite. The dotted-tail continuation form retires;
// recursion on the residual argv now expresses as a `(tail (authorise))`
// matcher that sits alongside the positional matcher.

use may_i_sexpr::cst::{CstNode, ShapeF, Trivia, TriviaAnn};

pub(crate) fn positional_dotted_tail(node: &CstNode) -> Option<Box<CstNode>> {
    let list = node.as_list()?;

    // Recurse first.
    let rewritten: Vec<(Box<CstNode>, bool)> = list
        .iter()
        .map(|child| match positional_dotted_tail(child) {
            Some(new_child) => (new_child, true),
            None => (child.clone(), false),
        })
        .collect();
    let any_child_changed = rewritten.iter().any(|(_, c)| *c);
    let children: Vec<Box<CstNode>> = rewritten.into_iter().map(|(n, _)| n).collect();

    // Match `(positional ITEM… . CONT)` where CONT is `(authorise)` or
    // `(may-i *)` (legacy — covered by may_i_to_authorise upstream too,
    // but we accept it here for robustness against ordering).
    if let Some(head) = children.first().and_then(|c| c.as_atom())
        && head == "positional"
        && let Some(dot_idx) = children.iter().position(|c| c.as_atom() == Some("."))
        && dot_idx + 1 == children.len() - 1
    {
        let cont_node = &children[dot_idx + 1];
        let cont_is_authorise = is_authorise_form(cont_node)
            || is_may_i_star(cont_node)
            || is_tail_authorise_form(cont_node);
        if cont_is_authorise {
            let positional_children: Vec<Box<CstNode>> = children[..dot_idx].to_vec();
            let positional_form = Box::new(CstNode::list(
                positional_children,
                TriviaAnn {
                    leading: node.ann.leading.clone(),
                    trailing: vec![],
                    span: node.ann.span,
                },
            ));
            let tail_form = Box::new(CstNode::list(
                vec![
                    Box::new(CstNode::atom("tail", TriviaAnn::default())),
                    Box::new(CstNode::list(
                        vec![Box::new(CstNode::atom("authorise", TriviaAnn::default()))],
                        TriviaAnn {
                            leading: vec![Trivia::Whitespace(" ".to_string())],
                            trailing: vec![],
                            span: cont_node.ann.span,
                        },
                    )),
                ],
                TriviaAnn {
                    leading: vec![Trivia::Whitespace(" ".to_string())],
                    trailing: node.ann.trailing.clone(),
                    span: node.ann.span,
                },
            ));
            // Compose into `(and POSITIONAL TAIL)`.
            let and_form = Box::new(CstNode::list(
                vec![
                    Box::new(CstNode::atom("and", TriviaAnn::default())),
                    positional_form,
                    tail_form,
                ],
                TriviaAnn {
                    leading: node.ann.leading.clone(),
                    trailing: node.ann.trailing.clone(),
                    span: node.ann.span,
                },
            ));
            return Some(and_form);
        }
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

fn is_authorise_form(node: &CstNode) -> bool {
    if let ShapeF::List(items) = &node.shape
        && items.len() == 1
        && items[0].as_atom() == Some("authorise")
    {
        return true;
    }
    false
}

fn is_tail_authorise_form(node: &CstNode) -> bool {
    if let ShapeF::List(items) = &node.shape
        && items.len() == 2
        && items[0].as_atom() == Some("tail")
        && is_authorise_form(&items[1])
    {
        return true;
    }
    false
}

fn is_may_i_star(node: &CstNode) -> bool {
    if let ShapeF::List(items) = &node.shape
        && items.len() == 2
        && items[0].as_atom() == Some("may-i")
        && items[1].as_atom() == Some("*")
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migrate_first(input: &str) -> String {
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        match positional_dotted_tail(&node) {
            Some(out) => out.serialize(),
            None => node.serialize(),
        }
    }

    #[test]
    fn rewrites_with_authorise() {
        let out = migrate_first(r#"(positional "exec" . (authorise))"#);
        assert!(out.contains(r#"(positional "exec")"#), "{out}");
        assert!(out.contains("(tail (authorise))"), "{out}");
        assert!(out.starts_with("(and"), "{out}");
    }

    #[test]
    fn rewrites_with_legacy_may_i_star() {
        let out = migrate_first(r#"(positional "x" . (may-i *))"#);
        assert!(out.contains(r#"(positional "x")"#), "{out}");
        assert!(out.contains("(tail (authorise))"), "{out}");
    }

    #[test]
    fn no_change_when_no_dot() {
        let out = migrate_first(r#"(positional "x" "y")"#);
        assert_eq!(out, r#"(positional "x" "y")"#);
    }

    #[test]
    fn rewrites_inside_rule() {
        let out = migrate_first(r#"(rule "ssh" (positional [:host *] . (authorise)))"#);
        assert!(out.contains("(and"), "{out}");
        assert!(out.contains("(tail (authorise))"), "{out}");
    }
}
