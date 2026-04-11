use super::helpers::{rebuild_list, tagged_list};
use may_i_sexpr::cst::{CstNode, TriviaAnn};

pub(crate) fn defcontext_to_define(node: &CstNode) -> Option<Box<CstNode>> {
    let children = tagged_list("defcontext", node)?;
    if children.len() != 3 {
        return None;
    }

    // Build (define NAME BODY) preserving the original body unchanged.
    let new_children = vec![
        Box::new(CstNode::atom(
            "define",
            TriviaAnn {
                leading: node.ann.leading.clone(),
                ..Default::default()
            },
        )),
        children[1].clone(), // NAME
        children[2].clone(), // BODY
    ];

    Some(rebuild_list(node, new_children))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defcontext_to_define() {
        let input = "(defcontext ssh (has :via/ssh))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = defcontext_to_define(&node).unwrap();
        assert_eq!(result.serialize(), "(define ssh (has :via/ssh))");
    }

    #[test]
    fn test_defcontext_to_define_with_has_value() {
        let input = r#"(defcontext prod (has :env "prod"))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = defcontext_to_define(&node).unwrap();
        assert_eq!(result.serialize(), r#"(define prod (has :env "prod"))"#);
    }

    #[test]
    fn test_defcontext_to_define_not_defcontext() {
        let input = "(define x y)";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = defcontext_to_define(&node);
        assert!(result.is_none());
    }

    #[test]
    fn test_defcontext_to_define_wrong_size() {
        let input = "(defcontext x)";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        let result = defcontext_to_define(&node);
        assert!(result.is_none());
    }
}
