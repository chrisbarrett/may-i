// `(positional ITEMS… . (authorise))` → sibling `(positional ITEMS…)`
// and `(tail (authorise))` composed via `(and …)`.
//
// Class A syntactic rewrite. The dotted-tail continuation form retires;
// recursion on the residual argv now expresses as a `(tail (authorise))`
// matcher that sits alongside the positional matcher.

use may_i_sexpr::cst::{CstNode, ShapeF, Trivia, TriviaAnn};

pub(crate) fn positional_dotted_tail(node: &CstNode) -> Option<Box<CstNode>> {
    // Local rewrite: the seam reaches nested forms. The returned `(and …)`
    // inherits the matched node's position trivia from the seam; the inner
    // `(positional …)` / `(tail …)` children carry deliberate construction
    // trivia, kept here.
    let children = node.as_list()?;

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
                    leading: node.ann.leading.clone(),
                    trailing: node.ann.trailing.clone(),
                    span: node.ann.span,
                },
            ));
            // No prefix items → emit just `(tail (authorise))`. The empty
            // `(positional)` form is trivially truthy and adds noise.
            if dot_idx == 1 {
                return Some(tail_form);
            }
            let positional_children: Vec<Box<CstNode>> = children[..dot_idx].to_vec();
            let positional_form = Box::new(CstNode::list(
                positional_children,
                TriviaAnn {
                    leading: node.ann.leading.clone(),
                    trailing: vec![],
                    span: node.ann.span,
                },
            ));
            let tail_form_with_lead = Box::new(CstNode {
                ann: TriviaAnn {
                    leading: vec![Trivia::Whitespace(" ".to_string())],
                    trailing: tail_form.ann.trailing.clone(),
                    span: tail_form.ann.span,
                },
                shape: tail_form.shape.clone(),
            });
            // Compose into `(and POSITIONAL TAIL)`. A later `effect_to_when`
            // pass converts this to `(when POSITIONAL TAIL)` since
            // `(tail (authorise))` is a terminal effect.
            let and_form = Box::new(CstNode::list(
                vec![
                    Box::new(CstNode::atom("and", TriviaAnn::default())),
                    positional_form,
                    tail_form_with_lead,
                ],
                TriviaAnn::default(),
            ));
            return Some(and_form);
        }
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

    // The pass is a local rewrite; nested occurrences are reached by the
    // post-order seam, so drive it through the seam in tests.
    fn migrate_first(input: &str) -> String {
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let rules: [fn(&CstNode) -> Option<Box<CstNode>>; 1] = [positional_dotted_tail];
        may_i_sexpr::cst::rewrite_post_order(node, &rules).serialize()
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

    #[test]
    fn empty_positional_collapses_to_tail() {
        // No items between `positional` and `.` — the wrapping `(positional)`
        // is trivially truthy, so emit just `(tail (authorise))`.
        let out = migrate_first(r#"(positional . (authorise))"#);
        assert_eq!(out, "(tail (authorise))");
    }

    #[test]
    fn empty_positional_inside_rule_collapses() {
        let out = migrate_first(r#"(rule "env" (positional . (authorise)))"#);
        assert_eq!(out, r#"(rule "env" (tail (authorise)))"#);
    }
}
