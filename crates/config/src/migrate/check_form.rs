// `(check :decision CMD :decision CMD …)` →
// `(check (decision CMD) (decision CMD) …)`.
//
// Class A syntactic rewrite. Also lifts decision pairs nested inside
// `(with-facts FACTS …)` bodies.

use may_i_sexpr::cst::{CstNode, ShapeF, Trivia, TriviaAnn};

pub(crate) fn check_to_form(node: &CstNode) -> Option<Box<CstNode>> {
    // Local rewrite: the seam visits children first (so a nested
    // `(with-facts …)` is already lifted by the time the enclosing `(check …)`
    // is offered) and grafts the original node's position trivia onto the
    // replacement. This pass only rewrites the PLIST body of the immediate
    // `check` / `with-facts` node.
    let list = node.as_list()?;
    let head = list.first().and_then(|c| c.as_atom());
    if !matches!(head, Some("check") | Some("with-facts")) {
        return None;
    }

    let body_start = if head == Some("with-facts") { 2 } else { 1 };
    if list.len() > body_start
        && let Some(rewritten_body) = rewrite_body(&list[body_start..])
    {
        let mut new_children: Vec<Box<CstNode>> = Vec::new();
        new_children.extend(list[..body_start].iter().cloned());
        new_children.extend(rewritten_body);
        return Some(Box::new(CstNode::list(new_children, TriviaAnn::default())));
    }

    None
}

/// Walk `body` (sequence of `:decision CMD` pairs and/or `(with-facts …)`
/// wrappers and/or already-form decisions) and rewrite the PLIST pairs in
/// place. Returns `Some(new_body)` if any pair was rewritten.
fn rewrite_body(body: &[Box<CstNode>]) -> Option<Vec<Box<CstNode>>> {
    let mut out: Vec<Box<CstNode>> = Vec::new();
    let mut i = 0;
    let mut changed = false;
    while i < body.len() {
        let item = &body[i];
        // PLIST decision pair.
        if let ShapeF::Keyword(kw) = &item.shape
            && let Some(decision) = decision_from_keyword(kw)
            && i + 1 < body.len()
        {
            let cmd = &body[i + 1];
            let decision_atom = Box::new(CstNode::atom(
                decision,
                TriviaAnn {
                    leading: vec![],
                    trailing: vec![],
                    span: item.ann.span,
                },
            ));
            let cmd_node = Box::new(CstNode {
                ann: TriviaAnn {
                    leading: vec![Trivia::Whitespace(" ".to_string())],
                    trailing: vec![],
                    span: cmd.ann.span,
                },
                shape: cmd.shape.clone(),
            });
            let form = Box::new(CstNode::list(
                vec![decision_atom, cmd_node],
                TriviaAnn {
                    leading: item.ann.leading.clone(),
                    trailing: cmd.ann.trailing.clone(),
                    span: item.ann.span,
                },
            ));
            out.push(form);
            i += 2;
            changed = true;
            continue;
        }
        // Untouched (already-form decision, or with-facts already recursed).
        out.push(item.clone());
        i += 1;
    }
    if changed { Some(out) } else { None }
}

fn decision_from_keyword(kw: &str) -> Option<&'static str> {
    match kw {
        ":allow" => Some("allow"),
        ":ask" => Some("ask"),
        ":deny" => Some("deny"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The pass is a local rewrite; nested occurrences are reached by the
    // post-order seam, so drive it through the seam in tests.
    fn migrate_first(input: &str) -> String {
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let rules: [fn(&CstNode) -> Option<Box<CstNode>>; 1] = [check_to_form];
        may_i_sexpr::cst::rewrite_post_order(node, &rules).serialize()
    }

    #[test]
    fn rewrites_simple_check() {
        let out = migrate_first(r#"(check :allow "git status" :deny "rm -rf /")"#);
        assert!(out.contains(r#"(allow "git status")"#), "{out}");
        assert!(out.contains(r#"(deny "rm -rf /")"#), "{out}");
        assert!(!out.contains(":allow"), "{out}");
    }

    #[test]
    fn rewrites_three_decision_kinds() {
        let out = migrate_first(r#"(check :allow "ls" :ask "rm" :deny "sudo rm")"#);
        assert!(out.contains(r#"(allow "ls")"#));
        assert!(out.contains(r#"(ask "rm")"#));
        assert!(out.contains(r#"(deny "sudo rm")"#));
    }

    #[test]
    fn rewrites_inside_with_facts() {
        let out = migrate_first(r#"(check (with-facts [[:via/ssh]] :deny "rm" :allow "ls"))"#);
        assert!(out.contains(r#"(deny "rm")"#), "{out}");
        assert!(out.contains(r#"(allow "ls")"#), "{out}");
        assert!(!out.contains(":deny"));
    }

    #[test]
    fn no_change_when_already_form() {
        let out = migrate_first(r#"(check (allow "ls") (deny "rm"))"#);
        assert_eq!(out, r#"(check (allow "ls") (deny "rm"))"#);
    }

    #[test]
    fn ignores_non_check_forms() {
        let out = migrate_first(r#"(rule "git" :allow "x")"#);
        assert!(out.contains(":allow"), "{out}");
    }
}
