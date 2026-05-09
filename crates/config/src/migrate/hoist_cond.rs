use super::helpers::strip_whitespace_trivia;
use may_i_sexpr::cst::CstNode;

/// Find and extract a cond/if form nested within boolean combinators.
/// Returns (remaining_predicates, cond_or_if_node) if found.
#[allow(clippy::vec_box)]
fn find_cond_or_if_in_booleans(node: &CstNode) -> Option<(Vec<Box<CstNode>>, Box<CstNode>)> {
    // Check if this is a boolean combinator
    if let Some(list) = node.as_list()
        && !list.is_empty()
        && let Some(tag) = list[0].as_atom()
    {
        match tag {
            "and" | "or" => {
                // Look through children for cond/if
                let mut remaining = Vec::new();
                let mut found = None;

                for child in &list[1..] {
                    if child.is_tagged("cond") || child.is_tagged("if") {
                        found = Some(child.clone());
                    } else if let Some((nested_remaining, nested_found)) =
                        find_cond_or_if_in_booleans(child)
                    {
                        // Found nested - merge remaining predicates
                        found = Some(nested_found);
                        remaining.extend(nested_remaining);
                    } else {
                        remaining.push(child.clone());
                    }
                }

                found.map(|f| (remaining, f))
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Convert (args ...) in rule to predicates and an effect.
/// Handles cond/if nested inside and/or combinators.
/// Also collects bare atom predicates between command and args (e.g., from inlined context).
pub(crate) fn hoist_cond(node: &CstNode) -> Option<Box<CstNode>> {
    if !node.is_tagged("rule") {
        return None;
    }

    let children = node.as_list()?;
    if children.len() < 2 {
        return None;
    }

    let mut new_children = Vec::new();
    let mut predicates_to_add = Vec::new();
    let mut rule_level_predicates = Vec::new(); // Predicates from inlined context
    let mut check_forms: Vec<Box<CstNode>> = Vec::new();
    let mut found_case_source = None;

    new_children.push(children[0].clone()); // "rule" tag
    new_children.push(children[1].clone()); // command

    // First pass: collect rule-level predicates (bare atoms after command, before args/effects)
    // and find args with cond/if
    for child in &children[2..] {
        if child.is_tagged("args") {
            let args_children = child.as_list()?;
            if args_children.len() == 2 {
                let matcher = &args_children[1];

                // Check for direct cond/if
                if matcher.is_tagged("cond") {
                    found_case_source = Some((Vec::new(), matcher.clone()));
                    continue;
                }
                if matcher.is_tagged("if") {
                    let if_children = matcher.as_list()?;
                    if if_children.len() == 4 {
                        found_case_source = Some((Vec::new(), matcher.clone()));
                        continue;
                    }
                }

                // Check for cond/if nested in and/or
                if let Some((remaining, cond_or_if)) = find_cond_or_if_in_booleans(matcher) {
                    predicates_to_add = remaining;
                    found_case_source = Some((Vec::new(), cond_or_if));
                    continue;
                }
            }
        } else if child.is_tagged("check") {
            check_forms.push(child.clone());
        } else if child.as_atom().is_some() {
            // Bare atom after command - likely a context predicate from inlined (context ...)
            rule_level_predicates.push(child.clone());
        } else {
            new_children.push(child.clone());
        }
    }

    let (extra_predicates, case_source) = found_case_source?;

    // Build cond expression based on source type
    let mut case_children = vec![Box::new(CstNode::atom("cond", Default::default()))];

    if case_source.is_tagged("cond") {
        let cond_children = case_source.as_list()?;
        for branch in &cond_children[1..] {
            case_children.push(Box::new(strip_whitespace_trivia(branch)));
        }
    } else if case_source.is_tagged("if") {
        // Convert (if PRED THEN ELSE) to case branches
        let if_children = case_source.as_list()?;
        if if_children.len() == 4 {
            // First branch: (PRED THEN)
            let pred = &if_children[1];
            let then_eff = &if_children[2];
            let branch = CstNode::list(
                vec![Box::new((**pred).clone()), Box::new((**then_eff).clone())],
                Default::default(),
            );
            case_children.push(Box::new(branch));

            // Else branch: (else ELSE)
            let else_eff = &if_children[3];
            let else_branch = CstNode::list(
                vec![
                    Box::new(CstNode::atom("else", Default::default())),
                    Box::new((**else_eff).clone()),
                ],
                Default::default(),
            );
            case_children.push(Box::new(else_branch));
        }
    }

    // Combine all predicates: from args, from cond/if, and from rule-level context references
    let all_predicates: Vec<_> = rule_level_predicates
        .iter()
        .chain(predicates_to_add.iter())
        .chain(extra_predicates.iter())
        .cloned()
        .collect();

    // Wrap the cond in a when expression if there are predicates
    let final_effect = if all_predicates.is_empty() {
        // No predicates, use cond directly
        Box::new(CstNode::list(case_children, Default::default()))
    } else if all_predicates.len() == 1 {
        // Single predicate, wrap in when
        let pred = &all_predicates[0];
        let cond_node = CstNode::list(case_children, Default::default());
        let when_children = vec![
            Box::new(CstNode::atom("when", Default::default())),
            pred.clone(),
            Box::new(cond_node),
        ];
        Box::new(CstNode::list(when_children, Default::default()))
    } else {
        // Multiple predicates, wrap in (and ...) then when
        let mut and_children = vec![Box::new(CstNode::atom("and", Default::default()))];
        for pred in &all_predicates {
            and_children.push(pred.clone());
        }
        let and_node = CstNode::list(and_children, Default::default());
        let cond_node = CstNode::list(case_children, Default::default());
        let when_children = vec![
            Box::new(CstNode::atom("when", Default::default())),
            Box::new(and_node),
            Box::new(cond_node),
        ];
        Box::new(CstNode::list(when_children, Default::default()))
    };

    // Insert the final effect, then check forms at the END
    new_children.push(final_effect);
    new_children.extend(check_forms);

    Some(Box::new(CstNode::list(new_children, node.ann.clone())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hoist_cond_not_rule() {
        let input = "(other (args (cond)))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = hoist_cond(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_hoist_cond_no_cond() {
        let input = "(rule git (args (positional)) (allow))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = hoist_cond(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_hoist_cond_with_if() {
        let input = r#"(rule "mv" (args (if (anywhere "-f") (ask) (allow))) (allow))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = hoist_cond(&node).unwrap();
        let serialized = result.serialize();
        assert!(serialized.contains("cond"));
        assert!(!serialized.contains("args"));
    }

    #[test]
    fn test_hoist_cond_with_single_predicate() {
        let input = r#"(rule git (args (cond ((regex "^push$") :allow))) prod)"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = hoist_cond(&node).unwrap();
        let serialized = result.serialize();
        assert!(
            serialized.contains("when"),
            "Expected 'when' in: {}",
            serialized
        );
    }

    #[test]
    fn test_hoist_cond_with_multiple_predicates() {
        let input = r#"(rule git (args (cond ((regex "^push$") :allow))) prod ssh)"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = hoist_cond(&node).unwrap();
        let serialized = result.serialize();
        assert!(
            serialized.contains("and"),
            "Expected 'and' in: {}",
            serialized
        );
        assert!(
            serialized.contains("when"),
            "Expected 'when' in: {}",
            serialized
        );
    }
}
