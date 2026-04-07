use super::helpers::complexity;
use may_i_sexpr::cst::{CstNode, Shape, TriviaAnn};

pub(crate) fn and_trailing_effect_to_when(node: &CstNode) -> Option<Box<CstNode>> {
    if !node.is_tagged("and") {
        return None;
    }
    let children = node.as_list()?;
    // Need at least: and + one predicate + effect
    if children.len() < 3 {
        return None;
    }

    // Find the first low-complexity effect at any position
    let effect_idx = children[1..]
        .iter()
        .position(|c| c.is_tagged("effect") && complexity(c) <= 3)?
        + 1; // adjust for skip of tag

    let effect = &children[effect_idx];

    // Build the predicate part (everything except tag and effect)
    let pred_children: Vec<&Box<CstNode>> = children[1..]
        .iter()
        .enumerate()
        .filter(|(i, _)| *i + 1 != effect_idx)
        .map(|(_, c)| c)
        .collect();

    let pred = if pred_children.len() == 1 {
        pred_children[0].clone()
    } else {
        let mut and_children: Vec<Box<CstNode>> = Vec::new();
        and_children.push(Box::new(CstNode::atom("and", Default::default())));
        and_children.extend(pred_children.into_iter().cloned());
        Box::new(CstNode::list(and_children, Default::default()))
    };

    let when_children = vec![
        Box::new(CstNode::atom(
            "when",
            TriviaAnn {
                leading: node.ann.leading.clone(),
                ..Default::default()
            },
        )),
        pred,
        effect.clone(),
    ];

    Some(Box::new(CstNode {
        ann: Default::default(),
        shape: Shape::List(when_children),
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_and_trailing_effect_to_when() {
        let input = r#"(and (anywhere "-r") (anywhere "/") (effect :deny "bad"))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(when (and (anywhere "-r") (anywhere "/")) (effect :deny "bad"))"#,
        );
    }

    #[test]
    fn test_and_trailing_effect_single_pred_to_when() {
        let input = r#"(and (anywhere "-r") (effect :allow "ok"))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(when (anywhere "-r") (effect :allow "ok"))"#,
        );
    }

    #[test]
    fn test_and_leading_effect_to_when() {
        let input = r#"(and (effect :allow) (positional "fmt"))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(when (positional "fmt") (effect :allow))"#,
        );
    }

    #[test]
    fn test_and_middle_effect_to_when() {
        let input = r#"(and (anywhere "-f") (effect :allow) (positional "x"))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(when (and (anywhere "-f") (positional "x")) (effect :allow))"#,
        );
    }

    #[test]
    fn test_and_trailing_complex_effect_unchanged() {
        let input = r#"(and pred (effect :allow (or (and a b) c)))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert!(
            result.serialize().starts_with("(and"),
            "complex effect should stay in and, got: {}",
            result.serialize(),
        );
    }

    #[test]
    fn test_and_no_trailing_effect_unchanged() {
        let input = r#"(and (anywhere "-r") (anywhere "/"))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert!(
            result.serialize().starts_with("(and"),
            "no effect → no change"
        );
    }
}
