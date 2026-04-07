use may_i_sexpr::cst::{CstNode, Shape, TriviaAnn};

pub(crate) fn rename_has_to_fact(node: &CstNode) -> Option<Box<CstNode>> {
    if let Some(list) = node.as_list() {
        if list.is_empty() {
            return None;
        }

        // Check if this is a (has ...) expression
        if let Some(tag) = list[0].as_atom()
            && tag == "has"
        {
            let fact_tag = Box::new(CstNode::atom(
                "fact?",
                TriviaAnn {
                    leading: list[0].ann.leading.clone(),
                    trailing: list[0].ann.trailing.clone(),
                    span: list[0].ann.span,
                },
            ));

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

            return Some(Box::new(CstNode::list(
                new_children,
                TriviaAnn {
                    leading: node.ann.leading.clone(),
                    trailing: node.ann.trailing.clone(),
                    span: node.ann.span,
                },
            )));
        }

        // Recursively process children
        let mut new_children = Vec::new();
        let mut changed = false;

        for child in list {
            if let Some(transformed) = rename_has_to_fact(child) {
                new_children.push(transformed);
                changed = true;
            } else {
                new_children.push(child.clone());
            }
        }

        if changed {
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

    None
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
        let result = rename_has_to_fact(&node).unwrap();
        let serialized = result.serialize();
        assert!(serialized.contains("fact?"));
        assert!(serialized.contains("[ :env \"prod\"]"));
        assert!(serialized.contains("[ :region \"us-east\"]"));
    }
}
