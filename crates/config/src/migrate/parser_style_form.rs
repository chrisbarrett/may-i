// `(parser PROG :style STYLE BODY…)` → `(parser PROG (style STYLE) BODY…)`.
//
// Class A syntactic rewrite: hoists the legacy `:style STYLE` PLIST pair into
// a `(style STYLE)` form so the parser body is a uniform list of declaration
// forms.

use may_i_sexpr::cst::{CstNode, ShapeF, TriviaAnn};

pub(crate) fn parser_style_to_form(node: &CstNode) -> Option<Box<CstNode>> {
    let list = node.as_list()?;

    // Recurse first so nested forms still get a chance to rewrite even when
    // the outer form is not a `(parser …)`.
    let rewritten_children: Vec<(Box<CstNode>, bool)> = list
        .iter()
        .map(|child| match parser_style_to_form(child) {
            Some(new_child) => (new_child, true),
            None => (child.clone(), false),
        })
        .collect();
    let any_child_changed = rewritten_children.iter().any(|(_, c)| *c);
    let children: Vec<Box<CstNode>> = rewritten_children.into_iter().map(|(n, _)| n).collect();

    let is_parser = matches!(children.first(), Some(c) if c.as_atom() == Some("parser"));
    let style_kw_idx = children
        .iter()
        .position(|c| matches!(&c.shape, ShapeF::Keyword(k) if k == ":style"));

    if is_parser
        && let Some(idx) = style_kw_idx
        && idx + 1 < children.len()
    {
        let style_kw = &children[idx];
        let style_value = &children[idx + 1];
        let style_form = Box::new(CstNode::list(
            vec![
                Box::new(CstNode::atom(
                    "style",
                    TriviaAnn {
                        leading: vec![],
                        trailing: vec![],
                        span: style_kw.ann.span,
                    },
                )),
                Box::new(CstNode {
                    ann: TriviaAnn {
                        leading: vec![],
                        trailing: vec![],
                        span: style_value.ann.span,
                    },
                    shape: style_value.shape.clone(),
                }),
            ],
            TriviaAnn {
                leading: style_kw.ann.leading.clone(),
                trailing: style_value.ann.trailing.clone(),
                span: style_kw.ann.span,
            },
        ));

        let mut new_children: Vec<Box<CstNode>> = Vec::with_capacity(children.len() - 1);
        new_children.extend(children[..idx].iter().cloned());
        new_children.push(style_form);
        new_children.extend(children[idx + 2..].iter().cloned());

        return Some(Box::new(CstNode::list(
            new_children,
            TriviaAnn {
                leading: node.ann.leading.clone(),
                trailing: node.ann.trailing.clone(),
                span: node.ann.span,
            },
        )));
    }

    if any_child_changed {
        return Some(Box::new(CstNode::list(
            children,
            TriviaAnn {
                leading: node.ann.leading.clone(),
                trailing: node.ann.trailing.clone(),
                span: node.ann.span,
            },
        )));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migrate_first(input: &str) -> String {
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        match parser_style_to_form(&node) {
            Some(out) => out.serialize(),
            None => node.serialize(),
        }
    }

    #[test]
    fn rewrites_simple() {
        let out = migrate_first(r#"(parser "find" :style single-dash-long)"#);
        assert!(out.contains("(style single-dash-long)"), "{out}");
        assert!(!out.contains(":style"), "{out}");
    }

    #[test]
    fn rewrites_with_body() {
        let out = migrate_first(r#"(parser "kubectl" :style gnu (flag "v") (parameter "n"))"#);
        assert!(out.contains("(style gnu)"), "{out}");
        assert!(out.contains("(flag \"v\")"), "{out}");
    }

    #[test]
    fn no_change_for_already_form() {
        let out = migrate_first(r#"(parser "find" (style single-dash-long))"#);
        assert!(!out.contains(":style"));
    }

    #[test]
    fn ignores_non_parser_forms() {
        let out = migrate_first(r#"(rule "git" (allow))"#);
        assert_eq!(out, r#"(rule "git" (allow))"#);
    }
}
