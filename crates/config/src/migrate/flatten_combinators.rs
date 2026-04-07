use may_i_sexpr::cst::{CstNode, Shape};

pub(crate) fn flatten_combinators(node: &CstNode) -> Option<Box<CstNode>> {
    let children = node.as_list()?;
    if children.len() < 2 {
        return None;
    }

    let tag = children[0].as_atom()?;

    match tag {
        "and" | "or" => {
            // Check if any child is a same-tag combinator that should be flattened
            let needs_flatten = children[1..].iter().any(|c| c.is_tagged(tag));
            if !needs_flatten {
                return None;
            }
            let mut new_children: Vec<Box<CstNode>> = Vec::new();
            new_children.push(children[0].clone()); // tag
            for child in &children[1..] {
                if child.is_tagged(tag) {
                    if let Some(inner) = child.as_list() {
                        // Splice inner children (skip the tag)
                        new_children.extend(inner[1..].iter().cloned());
                    } else {
                        new_children.push(child.clone());
                    }
                } else {
                    new_children.push(child.clone());
                }
            }
            Some(Box::new(CstNode {
                ann: node.ann.clone(),
                shape: Shape::List(new_children),
            }))
        }
        "not" => {
            // (not (not e)) → e
            if children.len() != 2 {
                return None;
            }
            let inner = &children[1];
            if !inner.is_tagged("not") {
                return None;
            }
            let inner_children = inner.as_list()?;
            if inner_children.len() != 2 {
                return None;
            }
            let mut result = inner_children[1].clone();
            result.ann.leading.clear();
            Some(result)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_flatten_double_and() {
        let input = "(and (and a b))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(result.serialize(), "(and a b)");
    }

    #[test]
    fn test_flatten_and_with_nested_and_among_siblings() {
        let input = "(and (and a b) c)";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(result.serialize(), "(and a b c)");
    }

    #[test]
    fn test_flatten_double_or() {
        let input = "(or (or a b))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(result.serialize(), "(or a b)");
    }

    #[test]
    fn test_flatten_or_with_nested_or_among_siblings() {
        let input = "(or (or a b) c)";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(result.serialize(), "(or a b c)");
    }

    #[test]
    fn test_flatten_double_not() {
        let input = "(not (not a))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(result.serialize(), "a");
    }

    #[test]
    fn test_no_flatten_mixed_combinators() {
        let input = "(and (or a b))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(result.serialize(), "(and (or a b))");
    }
}
