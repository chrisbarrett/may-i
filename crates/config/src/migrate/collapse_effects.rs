use super::helpers::{rebuild_list, tagged_list};
use may_i_sexpr::cst::{CstNode, TriviaAnn};

pub(crate) fn rule_collapse_effects(node: &CstNode) -> Option<Box<CstNode>> {
    let children = tagged_list("rule", node)?;
    if children.len() < 2 {
        return None;
    }

    // Separate the tag, command, check forms, and body effects.
    // children[0] = "rule" tag, children[1] = command
    let mut body_effects: Vec<Box<CstNode>> = Vec::new();
    let mut check_forms: Vec<Box<CstNode>> = Vec::new();

    for child in &children[2..] {
        if child.is_tagged("check") {
            check_forms.push(child.clone());
        } else {
            body_effects.push(child.clone());
        }
    }

    // If 0 or 1 body effects, no collapse needed
    if body_effects.len() <= 1 {
        return None;
    }

    // Wrap body effects in (and ...)
    let mut and_children: Vec<Box<CstNode>> = Vec::new();
    and_children.push(Box::new(CstNode::atom("and", Default::default())));
    for effect in body_effects {
        and_children.push(effect);
    }
    let and_node = CstNode::list(
        and_children,
        TriviaAnn {
            leading: vec![may_i_sexpr::cst::Trivia::Whitespace(" ".to_string())],
            ..Default::default()
        },
    );

    // Reconstruct: tag, command, (and ...), checks...
    let mut new_children = Vec::new();
    new_children.push(children[0].clone()); // "rule" tag
    new_children.push(children[1].clone()); // command
    new_children.push(Box::new(and_node));
    new_children.extend(check_forms);

    Some(rebuild_list(node, new_children))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_collapse_effects_wraps_multiple() {
        let input = r#"(rule "git" (positional "push") (ask))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_collapse_effects(&node).unwrap();
        let serialized = result.serialize();
        assert!(
            serialized.contains("(and"),
            "Expected '(and' in: {}",
            serialized
        );
    }

    #[test]
    fn test_rule_collapse_effects_single_not_modified() {
        let input = r#"(rule "git" (allow))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_collapse_effects(&node);
        assert!(result.is_none(), "Single effect should not be modified");
    }
}
