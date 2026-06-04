use super::helpers::tagged_list;
use may_i_sexpr::cst::{CstNode, Shape, TriviaAnn};

pub(crate) fn cond_single_clause_to_if(node: &CstNode) -> Option<Box<CstNode>> {
    let children = tagged_list("cond", node)?;
    // Expect: cond tag + exactly 2 branches
    if children.len() != 3 {
        return None;
    }
    let clause = &children[1];
    let else_clause = &children[2];

    // clause must be a list like (PRED EFFECT)
    let clause_children = clause.as_list()?;
    if clause_children.len() != 2 {
        return None;
    }

    // else_clause must be (else EFFECT)
    if !else_clause.is_tagged("else") {
        return None;
    }
    let else_children = else_clause.as_list()?;
    if else_children.len() != 2 {
        return None;
    }

    let pred = &clause_children[0];
    let then_effect = &clause_children[1];
    let else_effect = &else_children[1];

    let if_children = vec![
        Box::new(CstNode::atom("if", TriviaAnn::default())),
        pred.clone(),
        then_effect.clone(),
        else_effect.clone(),
    ];

    // Position-trivia (leading/trailing) lives on the wrapping list, not on
    // the head atom — putting it on the atom produces `( if ...)` with a
    // stray space inside the parens.
    Some(Box::new(CstNode {
        ann: TriviaAnn {
            leading: node.ann.leading.clone(),
            trailing: node.ann.trailing.clone(),
            ..Default::default()
        },
        shape: Shape::List(if_children),
    }))
}

pub(crate) fn cond_absorb_else(node: &CstNode) -> Option<Box<CstNode>> {
    let children = tagged_list("cond", node)?;
    // Need at least cond tag + one clause + else
    if children.len() < 3 {
        return None;
    }

    let last = children.last()?;
    if !last.is_tagged("else") {
        return None;
    }
    let else_children = last.as_list()?;
    if else_children.len() != 2 {
        return None;
    }

    let inner = &else_children[1];
    let inner_children = inner.as_list()?;
    let inner_tag = inner_children[0].as_atom()?;

    if inner_tag != "if" && inner_tag != "when" && inner_tag != "unless" && inner_tag != "cond" {
        return None;
    }

    // Keep existing clauses (everything except the tag and the else)
    let mut result_children: Vec<Box<CstNode>> = Vec::new();
    result_children.push(Box::new(CstNode::atom("cond", TriviaAnn::default())));
    for clause in &children[1..children.len() - 1] {
        result_children.push(Box::new(may_i_sexpr::cst::reflow(clause)));
    }

    match inner_tag {
        "if" => {
            if inner_children.len() != 4 {
                return None;
            }
            result_children.push(Box::new(CstNode::list(
                vec![
                    Box::new(may_i_sexpr::cst::reflow(&inner_children[1])),
                    Box::new(may_i_sexpr::cst::reflow(&inner_children[2])),
                ],
                Default::default(),
            )));
            result_children.push(Box::new(CstNode::list(
                vec![
                    Box::new(CstNode::atom("else", Default::default())),
                    Box::new(may_i_sexpr::cst::reflow(&inner_children[3])),
                ],
                Default::default(),
            )));
        }
        "when" => {
            if inner_children.len() != 3 {
                return None;
            }
            result_children.push(Box::new(CstNode::list(
                vec![
                    Box::new(may_i_sexpr::cst::reflow(&inner_children[1])),
                    Box::new(may_i_sexpr::cst::reflow(&inner_children[2])),
                ],
                Default::default(),
            )));
        }
        "unless" => {
            // (unless P E) → ((not P) E)
            if inner_children.len() != 3 {
                return None;
            }
            let negated_pred = CstNode::list(
                vec![
                    Box::new(CstNode::atom("not", Default::default())),
                    Box::new(may_i_sexpr::cst::reflow(&inner_children[1])),
                ],
                Default::default(),
            );
            result_children.push(Box::new(CstNode::list(
                vec![
                    Box::new(negated_pred),
                    Box::new(may_i_sexpr::cst::reflow(&inner_children[2])),
                ],
                Default::default(),
            )));
        }
        "cond" => {
            for clause in &inner_children[1..] {
                result_children.push(Box::new(may_i_sexpr::cst::reflow(clause)));
            }
        }
        _ => return None,
    }

    // Position-trivia goes on the outer wrapping list.
    Some(Box::new(CstNode::list(
        result_children,
        TriviaAnn {
            leading: node.ann.leading.clone(),
            trailing: node.ann.trailing.clone(),
            ..Default::default()
        },
    )))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_cond_single_clause_else_to_if() {
        let input = "(cond ((pred) (allow)) (else (deny)))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(result.serialize(), "(if (pred) (allow) (deny))");
    }

    #[test]
    fn test_cond_single_clause_no_else_unchanged() {
        let input = "(cond ((pred) (allow)))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(result.serialize(), "(cond ((pred) (allow)))");
    }

    #[test]
    fn test_cond_multiple_clauses_unchanged() {
        let input = "(cond ((a) x) ((b) y) (else z))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert!(
            result.serialize().starts_with("(cond"),
            "should stay as cond"
        );
    }

    #[test]
    fn test_cond_else_if_absorption() {
        let input = r#"(cond ((exact) (allow)) (else (if (positional "x") (ask) (deny))))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(cond ((exact) (allow)) ((positional "x") (ask)) (else (deny)))"#,
        );
    }

    #[test]
    fn test_cond_else_when_absorption() {
        let input = r#"(cond ((exact) (allow)) (else (when (positional "x") (ask))))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(cond ((exact) (allow)) ((positional "x") (ask)))"#,
        );
    }

    #[test]
    fn test_cond_else_cond_absorption() {
        let input =
            r#"(cond ((exact) (allow)) (else (cond ((positional "x") (ask)) (else (deny)))))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(cond ((exact) (allow)) ((positional "x") (ask)) (else (deny)))"#,
        );
    }

    #[test]
    fn test_cond_multi_clause_else_if_absorption() {
        let input = r#"(cond ((exact) (allow)) ((positional "a") (ask)) (else (if (positional "b") (deny) (allow))))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(cond ((exact) (allow)) ((positional "a") (ask)) ((positional "b") (deny)) (else (allow)))"#,
        );
    }

    #[test]
    fn test_cond_else_non_conditional_unchanged() {
        let input = r#"(cond ((exact) (allow)) (else (deny)))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(result.serialize(), r#"(if (exact) (allow) (deny))"#,);
    }

    #[test]
    fn test_cond_else_unless_absorption() {
        let input =
            r#"(cond ((exact) (allow)) ((positional "a") (ask)) (else (unless danger (deny))))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(cond ((exact) (allow)) ((positional "a") (ask)) ((not danger) (deny)))"#,
        );
    }
}
