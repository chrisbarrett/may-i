// `(check :decision CMD :decision CMD …)` →
// `(check (decision CMD) (decision CMD) …)`.
//
// Class A syntactic rewrite. Also lifts decision pairs nested inside
// `(with-facts FACTS …)` bodies.

use may_i_sexpr::cst::{CstNode, ShapeF, Trivia, TriviaAnn};

pub(crate) fn check_to_form(node: &CstNode) -> Option<Box<CstNode>> {
    let list = node.as_list()?;

    // Recurse first.
    let rewritten: Vec<(Box<CstNode>, bool)> = list
        .iter()
        .map(|child| match check_to_form(child) {
            Some(new_child) => (new_child, true),
            None => (child.clone(), false),
        })
        .collect();
    let any_child_changed = rewritten.iter().any(|(_, c)| *c);
    let children: Vec<Box<CstNode>> = rewritten.into_iter().map(|(n, _)| n).collect();

    let head = children.first().and_then(|c| c.as_atom());
    if matches!(head, Some("check") | Some("with-facts")) {
        let body_start = if head == Some("with-facts") { 2 } else { 1 };
        if children.len() > body_start
            && let Some(rewritten_body) = rewrite_body(&children[body_start..])
        {
            let mut new_children: Vec<Box<CstNode>> = Vec::new();
            new_children.extend(children[..body_start].iter().cloned());
            new_children.extend(rewritten_body);
            return Some(Box::new(CstNode::list(
                new_children,
                TriviaAnn {
                    leading: node.ann.leading.clone(),
                    trailing: node.ann.trailing.clone(),
                    span: node.ann.span,
                },
            )));
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

    fn migrate_first(input: &str) -> String {
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        match check_to_form(&node) {
            Some(out) => out.serialize(),
            None => node.serialize(),
        }
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
