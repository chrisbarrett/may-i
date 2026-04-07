use super::helpers::strip_whitespace_trivia;
use may_i_sexpr::cst::{CstNode, Shape, TriviaAnn};

pub(crate) fn cond_single_clause_to_if(node: &CstNode) -> Option<Box<CstNode>> {
    if !node.is_tagged("cond") {
        return None;
    }
    let children = node.as_list()?;
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
        Box::new(CstNode::atom(
            "if",
            TriviaAnn {
                leading: node.ann.leading.clone(),
                ..Default::default()
            },
        )),
        pred.clone(),
        then_effect.clone(),
        else_effect.clone(),
    ];

    Some(Box::new(CstNode {
        ann: Default::default(),
        shape: Shape::List(if_children),
    }))
}

pub(crate) fn cond_absorb_else(node: &CstNode) -> Option<Box<CstNode>> {
    if !node.is_tagged("cond") {
        return None;
    }
    let children = node.as_list()?;
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
    result_children.push(Box::new(CstNode::atom(
        "cond",
        TriviaAnn {
            leading: node.ann.leading.clone(),
            ..Default::default()
        },
    )));
    for clause in &children[1..children.len() - 1] {
        result_children.push(Box::new(strip_whitespace_trivia(clause)));
    }

    match inner_tag {
        "if" => {
            if inner_children.len() != 4 {
                return None;
            }
            result_children.push(Box::new(CstNode::list(
                vec![
                    Box::new(strip_whitespace_trivia(&inner_children[1])),
                    Box::new(strip_whitespace_trivia(&inner_children[2])),
                ],
                Default::default(),
            )));
            result_children.push(Box::new(CstNode::list(
                vec![
                    Box::new(CstNode::atom("else", Default::default())),
                    Box::new(strip_whitespace_trivia(&inner_children[3])),
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
                    Box::new(strip_whitespace_trivia(&inner_children[1])),
                    Box::new(strip_whitespace_trivia(&inner_children[2])),
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
                    Box::new(strip_whitespace_trivia(&inner_children[1])),
                ],
                Default::default(),
            );
            result_children.push(Box::new(CstNode::list(
                vec![
                    Box::new(negated_pred),
                    Box::new(strip_whitespace_trivia(&inner_children[2])),
                ],
                Default::default(),
            )));
        }
        "cond" => {
            for clause in &inner_children[1..] {
                result_children.push(Box::new(strip_whitespace_trivia(clause)));
            }
        }
        _ => return None,
    }

    Some(Box::new(CstNode::list(result_children, Default::default())))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_cond_single_clause_else_to_if() {
        let input = "(cond ((pred) (effect :allow)) (else (effect :deny)))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(result.serialize(), "(if (pred) (effect :allow) (effect :deny))");
    }

    #[test]
    fn test_cond_single_clause_no_else_unchanged() {
        let input = "(cond ((pred) (effect :allow)))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(result.serialize(), "(cond ((pred) (effect :allow)))");
    }

    #[test]
    fn test_cond_multiple_clauses_unchanged() {
        let input = "(cond ((a) x) ((b) y) (else z))";
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert!(result.serialize().starts_with("(cond"), "should stay as cond");
    }

    #[test]
    fn test_cond_else_if_absorption() {
        let input = r#"(cond ((exact) (effect :allow)) (else (if (positional "x") (effect :ask) (effect :deny))))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(cond ((exact) (effect :allow)) ((positional "x") (effect :ask)) (else (effect :deny)))"#,
        );
    }

    #[test]
    fn test_cond_else_when_absorption() {
        let input = r#"(cond ((exact) (effect :allow)) (else (when (positional "x") (effect :ask))))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(cond ((exact) (effect :allow)) ((positional "x") (effect :ask)))"#,
        );
    }

    #[test]
    fn test_cond_else_cond_absorption() {
        let input = r#"(cond ((exact) (effect :allow)) (else (cond ((positional "x") (effect :ask)) (else (effect :deny)))))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(cond ((exact) (effect :allow)) ((positional "x") (effect :ask)) (else (effect :deny)))"#,
        );
    }

    #[test]
    fn test_cond_multi_clause_else_if_absorption() {
        let input = r#"(cond ((exact) (effect :allow)) ((positional "a") (effect :ask)) (else (if (positional "b") (effect :deny) (effect :allow))))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(cond ((exact) (effect :allow)) ((positional "a") (effect :ask)) ((positional "b") (effect :deny)) (else (effect :allow)))"#,
        );
    }

    #[test]
    fn test_cond_else_non_conditional_unchanged() {
        let input = r#"(cond ((exact) (effect :allow)) (else (effect :deny)))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(if (exact) (effect :allow) (effect :deny))"#,
        );
    }

    #[test]
    fn test_cond_else_unless_absorption() {
        let input = r#"(cond ((exact) (effect :allow)) ((positional "a") (effect :ask)) (else (unless danger (effect :deny))))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(cond ((exact) (effect :allow)) ((positional "a") (effect :ask)) ((not danger) (effect :deny)))"#,
        );
    }
}
