use super::helpers::{complexity, tagged_list};
use may_i_sexpr::cst::{CstNode, Shape, TriviaAnn};

/// `(tail (authorise))` — the rule-side recursion form. Effect-flavoured
/// because `(authorise)` produces a Decision via recursion. Eligible for
/// the and→when conversion.
fn is_tail_authorise(node: &CstNode) -> bool {
    let Some(items) = tagged_list("tail", node) else {
        return false;
    };
    items.len() == 2 && items[1].is_tagged("authorise")
}

pub(crate) fn and_trailing_effect_to_when(node: &CstNode) -> Option<Box<CstNode>> {
    let children = tagged_list("and", node)?;
    // Need at least: and + one predicate + effect
    if children.len() < 3 {
        return None;
    }

    // Find the first low-complexity terminal effect at any position. The
    // legacy `(effect …)`, the bare decision verbs `(allow|ask|deny …)`,
    // and `(tail (authorise))` (recursion is effect-flavoured) all qualify.
    let effect_idx = children[1..].iter().position(|c| {
        (c.is_tagged("effect")
            || c.is_tagged("allow")
            || c.is_tagged("ask")
            || c.is_tagged("deny")
            || is_tail_authorise(c))
            && complexity(c) <= 3
    })? + 1; // adjust for skip of tag

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
        let input = r#"(and (anywhere "-r") (anywhere "/") (deny "bad"))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        // (anywhere "-r") collapses to the structured (flag "r") form en
        // route through the migration pipeline.
        assert_eq!(
            result.serialize(),
            r#"(when (and (flag "r") (anywhere "/")) (deny "bad"))"#,
        );
    }

    #[test]
    fn test_and_trailing_effect_single_pred_to_when() {
        let input = r#"(and (anywhere "-r") (allow "ok"))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(result.serialize(), r#"(when (flag "r") (allow "ok"))"#,);
    }

    #[test]
    fn test_and_leading_effect_to_when() {
        let input = r#"(and (allow) (positional "fmt"))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(result.serialize(), r#"(when (positional "fmt") (allow))"#,);
    }

    #[test]
    fn test_and_middle_effect_to_when() {
        let input = r#"(and (anywhere "-f") (allow) (positional "x"))"#;
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let result = super::super::migrate(nodes.into_iter().next().unwrap());
        assert_eq!(
            result.serialize(),
            r#"(when (and (flag "f") (positional "x")) (allow))"#,
        );
    }

    #[test]
    fn test_and_trailing_complex_effect_unchanged() {
        let input = r#"(and pred (allow (or (and a b) c)))"#;
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
