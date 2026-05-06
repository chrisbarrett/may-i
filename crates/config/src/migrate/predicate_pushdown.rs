use super::helpers::strip_whitespace_trivia;
use may_i_sexpr::cst::{CstNode, Shape, TriviaAnn};

pub(crate) fn predicate_pushdown(node: &CstNode) -> Option<Box<CstNode>> {
    let children = node.as_list()?;
    let tag = children[0].as_atom()?;
    if tag != "and" && tag != "or" {
        return None;
    }
    if children.len() < 3 {
        return None;
    }
    let last = children.last()?;
    let last_children = last.as_list()?;
    let wrapper_tag = last_children[0].as_atom()?;
    if wrapper_tag != "when" && wrapper_tag != "unless" {
        return None;
    }
    if last_children.len() != 3 {
        return None;
    }

    let inner_pred = &last_children[1];
    let body = &last_children[2];

    let mut comb_children: Vec<Box<CstNode>> = Vec::new();
    comb_children.push(Box::new(CstNode::atom(tag, Default::default())));
    for child in &children[1..children.len() - 1] {
        comb_children.push(Box::new(strip_whitespace_trivia(child)));
    }
    comb_children.push(Box::new(strip_whitespace_trivia(inner_pred)));
    let combined_pred = Box::new(CstNode::list(comb_children, Default::default()));

    let result_children = vec![
        Box::new(CstNode::atom(
            wrapper_tag,
            TriviaAnn {
                leading: node.ann.leading.clone(),
                ..Default::default()
            },
        )),
        combined_pred,
        Box::new(strip_whitespace_trivia(body)),
    ];

    Some(Box::new(CstNode {
        ann: Default::default(),
        shape: Shape::List(result_children),
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_and_trailing_when_pushdown() {
        let input = r#"(and (positional "fmt") (when build-mode (effect :allow)))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(when (and (positional "fmt") build-mode) (effect :allow))"#,
        );
    }

    #[test]
    fn test_and_trailing_when_multiple_preds() {
        let input = r#"(and (positional "x") (anywhere "-f") (when ctx (effect :ask)))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        // (anywhere "-f") collapses to the structured (flag "f") form en
        // route through the migration pipeline.
        assert_eq!(
            result.serialize(),
            r#"(when (and (positional "x") (flag "f") ctx) (effect :ask))"#,
        );
    }

    #[test]
    fn test_and_trailing_unless_pushdown() {
        let input = r#"(and (positional "x") (unless danger (effect :allow)))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(unless (and (positional "x") danger) (effect :allow))"#,
        );
    }

    #[test]
    fn test_or_trailing_when_pushdown() {
        let input = r#"(or (positional "a") (when ctx (effect :allow)))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(when (or (positional "a") ctx) (effect :allow))"#,
        );
    }

    #[test]
    fn test_or_trailing_unless_pushdown() {
        let input = r#"(or (positional "a") (unless bad (effect :deny)))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(unless (or (positional "a") bad) (effect :deny))"#,
        );
    }

    #[test]
    fn test_pushdown_no_match_when_not_last() {
        let input = r#"(and (when ctx (effect :allow)) (positional "x"))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert!(
            result.serialize().starts_with("(and"),
            "when not trailing → no pushdown. Got: {}",
            result.serialize(),
        );
    }

    #[test]
    fn test_pushdown_no_match_too_few_children() {
        let input = r#"(and (when ctx (effect :allow)))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(result.serialize(), "(and (when ctx (effect :allow)))");
    }

    #[test]
    fn test_pushdown_single_pred_unwraps_combinator() {
        let input = r#"(and (positional "x") (when ctx (effect :allow)))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(when (and (positional "x") ctx) (effect :allow))"#,
        );
    }
}
