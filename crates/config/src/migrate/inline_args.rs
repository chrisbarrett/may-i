use super::helpers::{rebuild_list, strip_whitespace_trivia, tagged_list};
use may_i_sexpr::cst::CstNode;

pub(crate) fn rule_inline_args(node: &CstNode) -> Option<Box<CstNode>> {
    let children = tagged_list("rule", node)?;
    let mut new_children = Vec::new();
    let mut changed = false;

    new_children.push(children[0].clone()); // "rule" tag

    for child in &children[1..] {
        if child.is_tagged("args") {
            // Extract the args matcher - need to handle different forms
            let args_children = child.as_list()?;
            if args_children.len() == 2 {
                let matcher = &args_children[1];

                // Skip cond forms - they're handled by hoist_cond
                if matcher.is_tagged("cond") {
                    new_children.push(child.clone());
                    continue;
                }

                // For simple matchers, inline them with stripped trivia
                // so pretty printer can use optimal layout
                let inlined = strip_whitespace_trivia(matcher);
                new_children.push(Box::new(inlined));
                changed = true;
                continue;
            }
        }
        new_children.push(child.clone());
    }

    if !changed {
        return None;
    }

    Some(rebuild_list(node, new_children))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_inline_args_not_rule() {
        let input = "(other (args x))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_inline_args(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_rule_inline_args_no_args() {
        let input = "(rule git (allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_inline_args(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_rule_inline_args_with_cond() {
        let input = "(rule git (args (cond (x :allow))) (allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rule_inline_args(&node);
        // Should return None since cond is handled by hoist_cond
        assert!(result.is_none());
    }
}
