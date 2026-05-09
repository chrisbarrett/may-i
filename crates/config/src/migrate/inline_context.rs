use super::helpers::{rebuild_list, strip_whitespace_trivia, tagged_list};
use may_i_sexpr::cst::CstNode;

pub(crate) fn rule_inline_context(node: &CstNode) -> Option<Box<CstNode>> {
    let children = tagged_list("rule", node)?;
    if children.len() < 3 {
        return None;
    }

    // Find context and effect
    let mut context_expr = None;
    let mut effect_expr = None;
    let mut other_children = Vec::new();
    let mut check_forms = Vec::new();

    for child in &children[1..] {
        if child.is_tagged("context") {
            let ctx_children = child.as_list()?;
            if ctx_children.len() == 2 {
                // Strip trivia from cloned context expr so pretty printer
                // can use optimal layout (fill layout for and/or/forbidden)
                context_expr = Some(Box::new(strip_whitespace_trivia(&ctx_children[1])));
            }
        } else if child.is_tagged("effect") {
            // Strip trivia from effect node so pretty printer can use optimal layout
            effect_expr = Some(Box::new(strip_whitespace_trivia(child)));
        } else if child.is_tagged("check") {
            check_forms.push(child.clone());
        } else {
            other_children.push(child.clone());
        }
    }

    // Check if we have both context and effect, or just context
    let has_effect = effect_expr.is_some();
    let has_context = context_expr.is_some();

    // If we have both context and effect, wrap them in (when ...)
    if has_context && has_effect {
        let mut new_children = Vec::new();
        new_children.push(children[0].clone()); // "rule" tag
        new_children.extend(other_children);

        // Build (when CONTEXT EFFECT)
        let when_children = vec![
            Box::new(CstNode::atom("when", Default::default())),
            context_expr.unwrap(),
            effect_expr.unwrap(),
        ];
        let when_node = CstNode::list(when_children, Default::default());
        new_children.push(Box::new(when_node));
        new_children.extend(check_forms);

        return Some(rebuild_list(node, new_children));
    }

    // If we only have context but no effect, inline the context directly
    // (this handles cases where effect will be added later)
    if has_context {
        let mut new_children = Vec::new();
        new_children.push(children[0].clone()); // "rule" tag
        new_children.extend(other_children);
        new_children.push(context_expr.unwrap());
        new_children.extend(check_forms);

        return Some(rebuild_list(node, new_children));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_inline_context_not_rule() {
        let input = "(other (context x))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_inline_context(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_rule_inline_context_no_context() {
        let input = "(rule git (allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_inline_context(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_rule_inline_context_wrong_size() {
        let input = "(rule git (context) (allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_inline_context(&node);
        assert!(result.is_none());
    }
}
