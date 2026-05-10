use super::helpers::strip_whitespace_trivia;
use may_i_sexpr::cst::{CstNode, TriviaAnn};

pub(crate) fn or_leading_when_to_if(node: &CstNode) -> Option<Box<CstNode>> {
    let children = node.as_list()?;
    if children[0].as_atom()? != "or" {
        return None;
    }
    if children.len() < 3 {
        return None;
    }

    let first = &children[1];
    if !first.is_tagged("when") {
        return None;
    }
    let when_children = first.as_list()?;
    if when_children.len() != 3 {
        return None;
    }

    let pred = &when_children[1];
    let then_branch = &when_children[2];

    let else_branch = if children.len() == 3 {
        // (or (when P E1) E2) → (if P E1 E2)
        Box::new(strip_whitespace_trivia(&children[2]))
    } else {
        // (or (when P E1) E2 E3 ...) → (if P E1 (or E2 E3 ...))
        let mut rest = vec![Box::new(CstNode::atom("or", Default::default()))];
        for child in &children[2..] {
            rest.push(Box::new(strip_whitespace_trivia(child)));
        }
        Box::new(CstNode::list(rest, Default::default()))
    };

    let if_children = vec![
        Box::new(CstNode::atom("if", TriviaAnn::default())),
        Box::new(strip_whitespace_trivia(pred)),
        Box::new(strip_whitespace_trivia(then_branch)),
        else_branch,
    ];

    Some(Box::new(CstNode::list(
        if_children,
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
    fn test_or_all_whens_to_cond() {
        let input = r#"(or (when (exact) (allow)) (when (positional "info") (allow)))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(cond ((exact) (allow)) ((positional "info") (allow)))"#,
        );
    }

    #[test]
    fn test_or_whens_with_else_to_cond() {
        let input = r#"(or (when (exact) (allow)) (when (positional "info") (allow)) (deny))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(cond ((exact) (allow)) ((positional "info") (allow)) (else (deny)))"#,
        );
    }

    #[test]
    fn test_or_single_when_no_cond() {
        let input = r#"(or (when (exact) (allow)))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(result.serialize(), r#"(or (when (exact) (allow)))"#);
    }

    #[test]
    fn test_or_no_whens_unchanged() {
        let input = r#"(or (exact) (positional "x") (positional "y"))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert!(
            result.serialize().starts_with("(or"),
            "no when children → stays as or. Got: {}",
            result.serialize(),
        );
    }

    #[test]
    fn test_and_whens_not_converted() {
        let input = r#"(and (when (exact) (allow)) (when (positional "x") (deny)))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert!(
            !result.serialize().starts_with("(cond"),
            "and-of-whens should not become cond. Got: {}",
            result.serialize(),
        );
    }
}
