// `(effect :allow|:ask|:deny REASON?)` → `(allow|ask|deny REASON?)`.
//
// Class A syntactic rewrite that retires the `(effect …)` wrapper from
// surface syntax in favour of bare decision verbs. The reason string,
// when present, is preserved verbatim.

use may_i_sexpr::cst::{CstNode, ShapeF, TriviaAnn};

pub(crate) fn effect_to_decision_verb(node: &CstNode) -> Option<Box<CstNode>> {
    let list = node.as_list()?;

    // Recurse first.
    let rewritten: Vec<(Box<CstNode>, bool)> = list
        .iter()
        .map(|child| match effect_to_decision_verb(child) {
            Some(new_child) => (new_child, true),
            None => (child.clone(), false),
        })
        .collect();
    let any_child_changed = rewritten.iter().any(|(_, c)| *c);
    let children: Vec<Box<CstNode>> = rewritten.into_iter().map(|(n, _)| n).collect();

    let head = children.first().and_then(|c| c.as_atom());
    if head == Some("effect") && children.len() >= 2 {
        let kw_node = &children[1];
        if let ShapeF::Keyword(kw) = &kw_node.shape
            && let Some(verb) = decision_from_keyword(kw)
            && children.len() <= 3
        {
            // Constructed atom — no source trivia or span. Position trivia
            // for the wrapping `(allow|ask|deny ...)` list comes from the
            // original `(effect ...)` node below.
            let verb_atom = Box::new(CstNode::atom(verb, TriviaAnn::default()));
            let mut new_children: Vec<Box<CstNode>> = vec![verb_atom];
            if let Some(reason) = children.get(2) {
                new_children.push(Box::new(CstNode {
                    ann: TriviaAnn {
                        leading: vec![may_i_sexpr::cst::Trivia::Whitespace(" ".to_string())],
                        trailing: reason.ann.trailing.clone(),
                        span: reason.ann.span,
                    },
                    shape: reason.shape.clone(),
                }));
            }
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
        match effect_to_decision_verb(&node) {
            Some(out) => out.serialize(),
            None => node.serialize(),
        }
    }

    #[test]
    fn rewrites_bare_allow() {
        let out = migrate_first(r#"(effect :allow)"#);
        assert_eq!(out, "(allow)");
    }

    #[test]
    fn rewrites_with_reason() {
        let out = migrate_first(r#"(effect :deny "rm -rf is dangerous")"#);
        assert_eq!(out, r#"(deny "rm -rf is dangerous")"#);
    }

    #[test]
    fn rewrites_inside_rule() {
        let out = migrate_first(r#"(rule "git" (effect :allow))"#);
        assert!(out.contains("(allow)"), "{out}");
        assert!(!out.contains(":allow"));
    }

    #[test]
    fn rewrites_inside_when() {
        let out = migrate_first(r#"(rule "rm" (when (flag "r") (effect :ask "recursive")))"#);
        assert!(out.contains(r#"(ask "recursive")"#), "{out}");
    }

    #[test]
    fn no_change_when_already_verb() {
        let out = migrate_first(r#"(rule "ls" (allow))"#);
        assert_eq!(out, r#"(rule "ls" (allow))"#);
    }
}
