use may_i_sexpr::cst::{CstNode, TriviaAnn};

pub(crate) fn wrapper_to_rule(node: &CstNode) -> Option<Box<CstNode>> {
    if !node.is_tagged("wrapper") {
        return None;
    }

    let children = node.as_list()?;
    if children.len() < 2 {
        return None;
    }

    // Extract command
    let cmd = &children[1];

    // Build rule children
    let mut new_children = Vec::new();

    // "rule" tag
    new_children.push(Box::new(CstNode::atom(
        "rule",
        TriviaAnn {
            leading: node.ann.leading.clone(),
            ..Default::default()
        },
    )));

    // Command
    new_children.push(cmd.clone());

    // Build positional pattern from wrapper steps
    let mut patterns = Vec::new();
    let mut has_capture = false;

    for step in &children[2..] {
        if step.is_tagged("positional") {
            let pos_children = step.as_list()?;
            for pat in &pos_children[1..] {
                // Check for capture markers inside positional - don't add them to patterns
                if let Some(atom) = pat.as_atom()
                    && (atom == ":command+args" || atom == ":command" || atom == ":args")
                {
                    has_capture = true;
                } else {
                    patterns.push(pat.clone());
                }
            }
        } else if step.is_tagged("flag") {
            // (flag "--command" ...) → "--command" and patterns (excluding capture markers)
            let flag_children = step.as_list()?;
            if flag_children.len() >= 2 {
                patterns.push(flag_children[1].clone());
                for pat in &flag_children[2..] {
                    // Check for capture markers - don't add them to patterns
                    if let Some(atom) = pat.as_atom()
                        && (atom == ":command+args" || atom == ":command" || atom == ":args")
                    {
                        has_capture = true;
                    } else {
                        patterns.push(pat.clone());
                    }
                }
            }
        } else if let Some(atom) = step.as_atom() {
            // Bare atoms like :command+args
            if atom == ":command+args" || atom == ":command" || atom == ":args" {
                has_capture = true;
            }
        }
    }

    // Build positional pattern - wrappers always have arguments to match
    // Build (positional PATTERN ... [. (may-i *)]) with continuation inside
    let mut positional_children = vec![Box::new(CstNode::atom("positional", Default::default()))];

    // Add each pattern as a direct child with proper spacing
    // Note: [:key *] patterns are now preserved as-is for the parser to handle
    for (i, pat) in patterns.iter().enumerate() {
        let mut pat = pat.clone();

        // Add leading whitespace for spacing between patterns
        if i == 0 {
            pat.ann.leading = vec![may_i_sexpr::cst::Trivia::Whitespace(" ".to_string())];
        }
        positional_children.push(pat);
    }

    // Add continuation effect inside positional if capture was present
    // Syntax: (positional ... . (may-i *))
    if has_capture {
        // Add . (may-i *) as children inside the positional form
        let dot = CstNode::atom(
            ".",
            TriviaAnn {
                leading: vec![may_i_sexpr::cst::Trivia::Whitespace(" ".to_string())],
                ..Default::default()
            },
        );
        // Build * for the may-i argument (just the wildcard, not wrapped in positional)
        let may_i_arg = CstNode::atom(
            "*",
            TriviaAnn {
                leading: vec![may_i_sexpr::cst::Trivia::Whitespace(" ".to_string())],
                ..Default::default()
            },
        );
        let may_i = CstNode::list(
            vec![
                Box::new(CstNode::atom("may-i", Default::default())),
                Box::new(may_i_arg),
            ],
            TriviaAnn {
                leading: vec![may_i_sexpr::cst::Trivia::Whitespace(" ".to_string())],
                ..Default::default()
            },
        );

        positional_children.push(Box::new(dot));
        positional_children.push(Box::new(may_i));
    }

    let positional = CstNode::list(positional_children, Default::default());
    new_children.push(Box::new(positional));

    // Note: No :effect needed - the effect is determined by the nested may-i call

    Some(Box::new(CstNode::list(
        new_children,
        TriviaAnn {
            leading: node.ann.leading.clone(),
            trailing: node.ann.trailing.clone(),
            span: node.ann.span,
        },
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrapper_to_rule_not_wrapper() {
        let input = "(other cmd)";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = wrapper_to_rule(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_wrapper_to_rule_too_short() {
        let input = "(wrapper)";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = wrapper_to_rule(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_wrapper_to_rule_with_capture() {
        let input = "(wrapper docker (positional run :command))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = wrapper_to_rule(&node).unwrap();
        let serialized = result.serialize();
        assert!(serialized.contains("rule"));
        assert!(serialized.contains("may-i") || serialized.contains("effect"));
    }

    #[test]
    fn test_wrapper_to_rule_bare_capture() {
        let input = r#"(wrapper "nohup" :command+args)"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = wrapper_to_rule(&node).unwrap();
        let serialized = result.serialize();
        assert!(serialized.contains("rule"));
        assert!(serialized.contains("nohup"));
        assert!(serialized.contains("positional"));
        assert!(serialized.contains("may-i"));
        assert!(serialized.contains("*"));
        assert!(!serialized.contains("(may-i (positional"));
    }

    #[test]
    fn test_wrapper_to_rule_with_capture_pattern() {
        let input = r#"(wrapper "ssh" (positional [:host *] :command+args))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = wrapper_to_rule(&node).unwrap();
        let serialized = result.serialize();
        assert!(serialized.contains("[:host *]"));
        assert!(!serialized.contains(":command+args"));
        assert!(serialized.contains("may-i"));
    }

    #[test]
    fn test_wrapper_to_rule_preserves_fact_binding() {
        let input = r#"(wrapper "ssh" (positional [:ssh/host *] :command+args))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = wrapper_to_rule(&node).unwrap();
        let serialized = result.serialize();
        assert!(
            serialized.contains("[:ssh/host *]"),
            "Migration should preserve fact binding syntax. Got: {}",
            serialized
        );
        assert!(serialized.contains("may-i"));
    }

    #[test]
    fn test_wrapper_to_rule_with_flag() {
        let input = r#"(wrapper "docker" (flag "--rm" :command))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = wrapper_to_rule(&node).unwrap();
        let serialized = result.serialize();
        assert!(serialized.contains("positional"));
        assert!(serialized.contains("\"--rm\""));
    }

    #[test]
    fn test_wrapper_docker_run_migration() {
        let input = r#"(wrapper "docker" (positional "run" :command))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = wrapper_to_rule(&node).unwrap();
        let serialized = result.serialize();
        assert!(serialized.contains("rule"));
        assert!(serialized.contains("\"docker\""));
        assert!(serialized.contains("positional"));
        assert!(serialized.contains("\"run\""));
        assert!(serialized.contains("may-i"));
        assert!(serialized.contains("*"));
        assert!(!serialized.contains(":command"));
        assert!(!serialized.contains("(may-i (positional"));
    }

    #[test]
    fn test_wrapper_flag_with_capture() {
        let input = r#"(wrapper "cmd" (flag "-x" :command))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = wrapper_to_rule(&node).unwrap();
        let serialized = result.serialize();
        assert!(serialized.contains("\"-x\""));
        assert!(!serialized.contains(":command"));
        assert!(serialized.contains("may-i"));
    }

    #[test]
    fn test_wrapper_flag_with_multiple_patterns_and_capture() {
        let input = r#"(wrapper "cmd" (flag "-x" "-y" :command+args))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = wrapper_to_rule(&node).unwrap();
        let serialized = result.serialize();
        assert!(serialized.contains("\"-x\""));
        assert!(serialized.contains("\"-y\""));
        assert!(!serialized.contains(":command+args"));
        assert!(serialized.contains("may-i"));
    }
}
