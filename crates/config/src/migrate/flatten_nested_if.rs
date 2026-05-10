use super::helpers::{strip_whitespace_trivia, tagged_list};
use may_i_sexpr::cst::{CstNode, TriviaAnn};

pub(crate) fn flatten_nested_if(node: &CstNode) -> Option<Box<CstNode>> {
    let children = tagged_list("if", node)?;
    if children.len() != 4 {
        return None;
    }

    let pred = &children[1];
    let then_branch = &children[2];
    let else_branch = &children[3];

    let else_children = else_branch.as_list()?;
    let else_tag = else_children[0].as_atom()?;

    let mut cond_children: Vec<Box<CstNode>> = Vec::new();
    cond_children.push(Box::new(CstNode::atom("cond", TriviaAnn::default())));

    // First clause from the outer if
    cond_children.push(Box::new(CstNode::list(
        vec![
            Box::new(strip_whitespace_trivia(pred)),
            Box::new(strip_whitespace_trivia(then_branch)),
        ],
        Default::default(),
    )));

    match else_tag {
        "if" => {
            // (if P2 E2 E3) → clause (P2 E2) + (else E3)
            if else_children.len() != 4 {
                return None;
            }
            cond_children.push(Box::new(CstNode::list(
                vec![
                    Box::new(strip_whitespace_trivia(&else_children[1])),
                    Box::new(strip_whitespace_trivia(&else_children[2])),
                ],
                Default::default(),
            )));
            cond_children.push(Box::new(CstNode::list(
                vec![
                    Box::new(CstNode::atom("else", Default::default())),
                    Box::new(strip_whitespace_trivia(&else_children[3])),
                ],
                Default::default(),
            )));
        }
        "when" => {
            // (when P2 E2) → clause (P2 E2), no else
            if else_children.len() != 3 {
                return None;
            }
            cond_children.push(Box::new(CstNode::list(
                vec![
                    Box::new(strip_whitespace_trivia(&else_children[1])),
                    Box::new(strip_whitespace_trivia(&else_children[2])),
                ],
                Default::default(),
            )));
        }
        "unless" => {
            // (unless P2 E2) → clause ((not P2) E2), no else
            if else_children.len() != 3 {
                return None;
            }
            let negated_pred = CstNode::list(
                vec![
                    Box::new(CstNode::atom("not", Default::default())),
                    Box::new(strip_whitespace_trivia(&else_children[1])),
                ],
                Default::default(),
            );
            cond_children.push(Box::new(CstNode::list(
                vec![
                    Box::new(negated_pred),
                    Box::new(strip_whitespace_trivia(&else_children[2])),
                ],
                Default::default(),
            )));
        }
        "cond" => {
            // Prepend our clause to existing cond clauses
            for clause in &else_children[1..] {
                cond_children.push(Box::new(strip_whitespace_trivia(clause)));
            }
        }
        _ => return None,
    }

    Some(Box::new(CstNode::list(
        cond_children,
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
    fn test_flatten_nested_if_unless() {
        let input = r#"(if (exact) (allow) (unless danger (deny)))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(cond ((exact) (allow)) ((not danger) (deny)))"#,
        );
    }
}
