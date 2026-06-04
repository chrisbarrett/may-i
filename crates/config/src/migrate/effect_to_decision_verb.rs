// `(effect :allow|:ask|:deny REASON?)` → `(allow|ask|deny REASON?)`.
//
// Class A syntactic rewrite that retires the `(effect …)` wrapper from
// surface syntax in favour of bare decision verbs. The reason string,
// when present, is preserved verbatim.

use may_i_sexpr::cst::{CstNode, ShapeF, TriviaAnn};

pub(crate) fn effect_to_decision_verb(node: &CstNode) -> Option<Box<CstNode>> {
    // Local rewrite: the seam visits children first and grafts the original
    // node's position trivia onto the replacement, so this pass only matches
    // the immediate `(effect …)` shape.
    let list = node.as_list()?;
    let head = list.first().and_then(|c| c.as_atom());
    if head != Some("effect") || list.len() < 2 {
        return None;
    }

    let kw_node = &list[1];
    if let ShapeF::Keyword(kw) = &kw_node.shape
        && let Some(verb) = decision_from_keyword(kw)
        && list.len() <= 3
    {
        let verb_atom = Box::new(CstNode::atom(verb, TriviaAnn::default()));
        let mut new_children: Vec<Box<CstNode>> = vec![verb_atom];
        if let Some(reason) = list.get(2) {
            new_children.push(Box::new(CstNode {
                ann: TriviaAnn {
                    leading: vec![may_i_sexpr::cst::Trivia::Whitespace(" ".to_string())],
                    trailing: reason.ann.trailing.clone(),
                    span: reason.ann.span,
                },
                shape: reason.shape.clone(),
            }));
        }
        return Some(Box::new(CstNode::list(new_children, TriviaAnn::default())));
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

    // The pass is a local rewrite; nested occurrences are reached by the
    // post-order seam, so drive it through the seam in tests.
    fn migrate_first(input: &str) -> String {
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let rules: [fn(&CstNode) -> Option<Box<CstNode>>; 1] = [effect_to_decision_verb];
        may_i_sexpr::cst::rewrite_post_order(node, &rules).serialize()
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
