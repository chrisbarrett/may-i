// `(define-arg-style NAME (:k1 v1 :k2 v2 …))` →
// `(define-arg-style NAME (k1 v1) (k2 v2) …)`.
//
// Class A syntactic rewrite: hoists the PLIST body into a sequence of
// attribute forms. The `:separators` key, whose value is a list of
// strings, becomes a variadic `(separators s1 s2 …)` form.

use may_i_sexpr::cst::{CstNode, ShapeF, TriviaAnn};

pub(crate) fn define_arg_style_to_form(node: &CstNode) -> Option<Box<CstNode>> {
    // Local rewrite: the seam reaches nested forms and grafts the matched
    // node's position trivia onto the replacement.
    let list = node.as_list()?;

    let is_define = matches!(list.first(), Some(c) if c.as_atom() == Some("define-arg-style"));
    if is_define && list.len() == 3 {
        let children = list;
        // Body must be a list whose first element is a `:keyword`. If the body
        // is already form-list (first element is `(k v)`), skip.
        if let ShapeF::List(plist) = &children[2].shape
            && plist
                .first()
                .map(|n| matches!(&n.shape, ShapeF::Keyword(_)))
                .unwrap_or(false)
        {
            let body_span = children[2].ann.span;
            let mut attr_forms: Vec<Box<CstNode>> = Vec::new();
            let mut i = 0;
            while i < plist.len() {
                let key_node = &plist[i];
                let ShapeF::Keyword(keyword) = &key_node.shape else {
                    return None;
                };
                if i + 1 >= plist.len() {
                    return None;
                }
                let value_node = &plist[i + 1];
                let bare_name = keyword.trim_start_matches(':').to_string();
                let name_node = Box::new(CstNode::atom(
                    bare_name.clone(),
                    TriviaAnn {
                        leading: vec![],
                        trailing: vec![],
                        span: key_node.ann.span,
                    },
                ));

                let mut attr_children: Vec<Box<CstNode>> = vec![name_node];

                // `:separators (s1 s2 …)` → variadic `(separators s1 s2 …)`.
                if bare_name == "separators"
                    && let ShapeF::List(items) = &value_node.shape
                {
                    for item in items {
                        attr_children.push(Box::new(CstNode {
                            ann: TriviaAnn {
                                leading: vec![Trivia_space()],
                                trailing: vec![],
                                span: item.ann.span,
                            },
                            shape: item.shape.clone(),
                        }));
                    }
                } else {
                    attr_children.push(Box::new(CstNode {
                        ann: TriviaAnn {
                            leading: vec![Trivia_space()],
                            trailing: vec![],
                            span: value_node.ann.span,
                        },
                        shape: value_node.shape.clone(),
                    }));
                }

                attr_forms.push(Box::new(CstNode::list(
                    attr_children,
                    TriviaAnn {
                        leading: if attr_forms.is_empty() {
                            children[2].ann.leading.clone()
                        } else {
                            vec![Trivia_space()]
                        },
                        trailing: vec![],
                        span: key_node.ann.span,
                    },
                )));

                i += 2;
            }

            // Attach trailing trivia of original body to the last attr form.
            if let Some(last) = attr_forms.last_mut() {
                last.ann.trailing = children[2].ann.trailing.clone();
            }

            let mut new_children: Vec<Box<CstNode>> = Vec::new();
            new_children.push(children[0].clone());
            new_children.push(children[1].clone());
            new_children.extend(attr_forms);

            // If body was empty PLIST, keep the original (nothing to do).
            if new_children.len() == 2 {
                new_children.push(children[2].clone());
            }
            let _ = body_span;

            return Some(Box::new(CstNode::list(new_children, TriviaAnn::default())));
        }
    }

    None
}

#[allow(non_snake_case)]
fn Trivia_space() -> may_i_sexpr::cst::Trivia {
    may_i_sexpr::cst::Trivia::Whitespace(" ".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migrate_first(input: &str) -> String {
        let (nodes, _) = may_i_sexpr::parse_cst(input);
        let node = nodes.into_iter().next().unwrap();
        match define_arg_style_to_form(&node) {
            Some(out) => out.serialize(),
            None => node.serialize(),
        }
    }

    #[test]
    fn rewrites_basic_plist() {
        let out = migrate_first(r#"(define-arg-style gnu (:long-prefix "--" :short-prefix "-"))"#);
        assert!(out.contains(r#"(long-prefix "--")"#), "{out}");
        assert!(out.contains(r#"(short-prefix "-")"#), "{out}");
        assert!(!out.contains(":long-prefix"), "{out}");
    }

    #[test]
    fn rewrites_separators_to_variadic() {
        let out =
            migrate_first(r#"(define-arg-style java (:overrides gnu :separators (" " "=" ":")))"#);
        assert!(out.contains(r#"(overrides gnu)"#), "{out}");
        assert!(out.contains(r#"(separators " " "=" ":")"#), "{out}");
    }

    #[test]
    fn rewrites_pun_keyword_value() {
        let out = migrate_first(r#"(define-arg-style x (:pun :allow))"#);
        assert!(out.contains(r#"(pun :allow)"#), "{out}");
    }

    #[test]
    fn rewrites_bool_value() {
        let out = migrate_first(r#"(define-arg-style x (:combined-shorts t))"#);
        assert!(out.contains(r#"(combined-shorts t)"#), "{out}");
    }

    #[test]
    fn no_change_when_already_form_list() {
        let out = migrate_first(r#"(define-arg-style x (long-prefix "--"))"#);
        assert!(!out.contains(":long-prefix"));
    }

    #[test]
    fn ignores_non_define_arg_style_forms() {
        let out = migrate_first(r#"(rule "git" (allow))"#);
        assert_eq!(out, r#"(rule "git" (allow))"#);
    }
}
