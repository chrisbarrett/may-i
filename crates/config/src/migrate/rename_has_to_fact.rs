use may_i_sexpr::cst::{CstNode, Shape, TriviaAnn};

pub(crate) fn rename_has_to_fact(node: &CstNode) -> Option<Box<CstNode>> {
    // Local rewrite: the seam reaches nested `(has …)` occurrences and grafts
    // the matched node's position trivia onto the replacement.
    let list = node.as_list()?;
    if list.first().and_then(|c| c.as_atom()) != Some("has") {
        return None;
    }

    // Atom is constructed; trivia/span belong on the wrapping list.
    let fact_tag = Box::new(CstNode::atom("fact?", TriviaAnn::default()));

    let new_children = if list.len() == 3 {
        // (has K V) → (fact? [K V])
        let key = &list[1];
        let value = &list[2];
        let vector_node = CstNode {
            ann: TriviaAnn {
                leading: vec![],
                trailing: vec![],
                span: key.ann.span,
            },
            shape: Shape::Vector(vec![key.clone(), value.clone()]),
        };
        vec![fact_tag, Box::new(vector_node)]
    } else {
        // (has X) or (has [K V]) → (fact? X) or (fact? [K V])
        let mut children = vec![fact_tag];
        for child in &list[1..] {
            children.push(child.clone());
        }
        children
    };

    Some(Box::new(CstNode::list(new_children, TriviaAnn::default())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rename_has_to_fact_key_value() {
        let input = r#"(has :env "prod")"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rename_has_to_fact(&node).unwrap();
        let serialized = result.serialize();
        assert!(serialized.contains("fact?"));
        assert!(serialized.contains("[ :env \"prod\"]"));
    }

    #[test]
    fn test_rename_has_to_fact_presence() {
        let input = "(has :env)";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rename_has_to_fact(&node).unwrap();
        assert_eq!(result.serialize(), "(fact? :env)");
    }

    #[test]
    fn test_rename_has_to_fact_vector_arg() {
        let input = r#"(has [ :env "prod"])"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = rename_has_to_fact(&node).unwrap();
        let serialized = result.serialize();
        assert!(serialized.contains("fact?"));
        assert!(serialized.contains(":env"));
    }

    #[test]
    fn test_rename_has_to_fact_nested() {
        let input = r#"(and (has :env "prod") (has :region "us-east"))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        // Nested occurrences are reached by the post-order seam.
        let rules: [fn(&CstNode) -> Option<Box<CstNode>>; 1] = [rename_has_to_fact];
        let result = may_i_sexpr::cst::rewrite_post_order(node, &rules);
        let serialized = result.serialize();
        assert!(serialized.contains("fact?"));
        assert!(serialized.contains("[ :env \"prod\"]"));
        assert!(serialized.contains("[ :region \"us-east\"]"));
    }
}
