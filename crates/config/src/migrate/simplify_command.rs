use super::helpers::{rebuild_list, strip_whitespace_trivia, tagged_list};
use may_i_sexpr::cst::CstNode;

pub(crate) fn rule_simplify_command(node: &CstNode) -> Option<Box<CstNode>> {
    let children = tagged_list("rule", node)?;
    if children.len() < 2 {
        return None;
    }

    // Check if second element is (command ...)
    let second = &children[1];
    if !second.is_tagged("command") {
        return None;
    }

    // (command X) — extract the inner value
    let cmd_children = second.as_list()?;
    if cmd_children.len() != 2 {
        return None;
    }

    let cmd_value = &cmd_children[1];

    // Build new children: tag, cmd_value, rest...
    let mut new_children = Vec::new();
    new_children.push(children[0].clone()); // "rule" tag

    // Strip trivia so pretty printer can use optimal layout,
    // then restore the (command ...) node's leading/trailing trivia.
    let mut new_cmd = strip_whitespace_trivia(cmd_value);
    new_cmd.ann.leading = second.ann.leading.clone();
    new_cmd.ann.trailing = second.ann.trailing.clone();
    new_children.push(Box::new(new_cmd));

    // Rest of children
    for child in &children[2..] {
        new_children.push(child.clone());
    }

    Some(rebuild_list(node, new_children))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_simplify_command() {
        let input = "(rule (command git) (allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_simplify_command(&node).unwrap();
        assert_eq!(result.serialize(), "(rule git (allow))");
    }

    #[test]
    fn test_rule_simplify_command_not_rule() {
        let input = "(other (command git))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_simplify_command(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_rule_simplify_command_too_short() {
        let input = "(rule)";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_simplify_command(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_rule_simplify_command_not_command_tag() {
        let input = "(rule git (allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_simplify_command(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_rule_simplify_command_wrong_size() {
        let input = "(rule (command git extra) (allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_simplify_command(&node);
        assert!(result.is_none());
    }
}
