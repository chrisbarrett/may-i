use may_i_core::doc::{Doc, DocF, LayoutHint};

use super::annotate::is_forbidden_pattern;
use crate::annotation::Ann;

pub(super) fn truncate_matched_anywhere(doc: &Doc<Option<Ann>>) -> Doc<Option<Ann>> {
    if let Some(Ann::ArgMatch {
        matched: true,
        search_tokens,
        ..
    }) = &doc.ann
        && !search_tokens.is_empty()
        && !is_forbidden_pattern(doc)
        && let DocF::List(children) = &doc.node
    {
        let head = children.first().and_then(|c| c.as_atom());
        if matches!(head, Some("anywhere")) && children.len() > 2 {
            let truncated = vec![children[0].clone(), children[1].clone()];
            return Doc {
                ann: doc.ann.clone(),
                node: DocF::List(truncated),
                layout: doc.layout,
                dimmed: doc.dimmed,
            };
        }
    }
    match &doc.node {
        DocF::List(children) => Doc {
            ann: doc.ann.clone(),
            node: DocF::List(children.iter().map(truncate_matched_anywhere).collect()),
            layout: doc.layout,
            dimmed: doc.dimmed,
        },
        DocF::Vector(children) => Doc {
            ann: doc.ann.clone(),
            node: DocF::Vector(children.iter().map(truncate_matched_anywhere).collect()),
            layout: doc.layout,
            dimmed: doc.dimmed,
        },
        DocF::Atom(_) => doc.clone(),
    }
}

pub(super) fn truncate_unevaluated(doc: &Doc<Option<Ann>>, keep: usize) -> Doc<Option<Ann>> {
    if let Some(Ann::ArgMatch { search_tokens, .. }) = &doc.ann
        && !search_tokens.is_empty()
    {
        return doc.clone();
    }
    match &doc.node {
        DocF::Atom(_) => doc.clone(),
        DocF::List(children) => {
            let children: Vec<Doc<Option<Ann>>> = children
                .iter()
                .map(|c| truncate_unevaluated(c, keep))
                .collect();
            let head = children.first().and_then(|c| c.as_atom());
            let has_head = head.is_some();
            let args_unevaluated =
                has_head && children[1..].iter().all(|c| !has_any_visible_annotation(c));
            if args_unevaluated && children.len() > keep + 2 {
                let mut truncated = Vec::with_capacity(keep + 3);
                truncated.push(children[0].clone());
                truncated.extend(children[1..=keep].iter().cloned());
                truncated.push(Doc {
                    ann: None,
                    node: DocF::Atom("…".into()),
                    layout: LayoutHint::Auto,
                    dimmed: true,
                });
                truncated.push(children.last().unwrap().clone());
                Doc {
                    ann: doc.ann.clone(),
                    node: DocF::List(truncated),
                    layout: doc.layout,
                    dimmed: doc.dimmed,
                }
            } else {
                Doc {
                    ann: doc.ann.clone(),
                    node: DocF::List(children),
                    layout: doc.layout,
                    dimmed: doc.dimmed,
                }
            }
        }
        DocF::Vector(children) => Doc {
            ann: doc.ann.clone(),
            node: DocF::Vector(
                children
                    .iter()
                    .map(|c| truncate_unevaluated(c, keep))
                    .collect(),
            ),
            layout: doc.layout,
            dimmed: doc.dimmed,
        },
    }
}

pub(super) fn dim_unevaluated(doc: Doc<Option<Ann>>) -> Doc<Option<Ann>> {
    dim_unevaluated_inner(doc, false).0
}

fn dim_unevaluated_inner(
    doc: Doc<Option<Ann>>,
    ancestor_annotated: bool,
) -> (Doc<Option<Ann>>, usize) {
    let self_score = usize::from(doc.ann.is_some());
    let children_inherit = ancestor_annotated || self_score > 0;
    match doc.node {
        DocF::Atom(_) => (doc, self_score),
        DocF::List(children) => {
            let mut total = self_score;
            let children: Vec<_> = children
                .into_iter()
                .map(|c| {
                    let (c, n) = dim_unevaluated_inner(c, children_inherit);
                    total += n;
                    c
                })
                .collect();
            let dimmed = doc.dimmed || (!ancestor_annotated && total == 0);
            (
                Doc {
                    ann: doc.ann,
                    node: DocF::List(children),
                    layout: doc.layout,
                    dimmed,
                },
                total,
            )
        }
        DocF::Vector(children) => {
            let mut total = self_score;
            let children: Vec<_> = children
                .into_iter()
                .map(|c| {
                    let (c, n) = dim_unevaluated_inner(c, children_inherit);
                    total += n;
                    c
                })
                .collect();
            let dimmed = doc.dimmed || (!ancestor_annotated && total == 0);
            (
                Doc {
                    ann: doc.ann,
                    node: DocF::Vector(children),
                    layout: doc.layout,
                    dimmed,
                },
                total,
            )
        }
    }
}

/// Distribute parent `ArgMatch` annotations to individual child atoms.
///
/// For `(anywhere "t1" "t2")` with a parent `ArgMatch`, each token atom gets
/// its own `ArgMatch` with `search_tokens: [that_token]`. This enables
/// `AnnotatedLineBuilder` to collect per-atom annotations structurally.
///
/// Handles forbidden patterns `(not (anywhere ...))` by distributing into the
/// inner anywhere's children.
pub(super) fn distribute_arg_annotations(doc: &Doc<Option<Ann>>) -> Doc<Option<Ann>> {
    if let Some(Ann::ArgMatch {
        search_tokens,
        arg_set,
        matched,
    }) = &doc.ann
        && let DocF::List(children) = &doc.node
    {
        let head = children.first().and_then(|c| c.as_atom());

        // Anywhere/forbidden patterns: distribute per-token ArgMatch.
        if !search_tokens.is_empty() && matches!(head, Some("anywhere" | "forbidden")) {
            let new_children =
                distribute_to_token_children(children, search_tokens, arg_set, *matched);
            return Doc {
                ann: None,
                node: DocF::List(new_children),
                layout: doc.layout,
                dimmed: doc.dimmed,
            };
        }

        // Forbidden via (not (anywhere ...))
        // The inner (anywhere ...) has inverted matched status.
        if !search_tokens.is_empty()
            && matches!(head, Some("not"))
            && let Some(inner) = children.get(1)
            && let DocF::List(inner_children) = &inner.node
            && let Some(inner_head) = inner_children.first().and_then(|c| c.as_atom())
            && inner_head == "anywhere"
        {
            // Use the inner's matched status (inverted from parent).
            let inner_matched = if let Some(Ann::ArgMatch { matched: m, .. }) = &inner.ann {
                *m
            } else {
                !*matched
            };
            let new_inner_children =
                distribute_to_token_children(inner_children, search_tokens, arg_set, inner_matched);
            let new_inner = Doc {
                ann: None, // cleared — annotation distributed to children
                node: DocF::List(new_inner_children),
                layout: inner.layout,
                dimmed: inner.dimmed,
            };
            let mut new_children = vec![children[0].clone(), new_inner];
            new_children.extend(children[2..].iter().cloned());
            return Doc {
                ann: None,
                node: DocF::List(new_children),
                layout: doc.layout,
                dimmed: doc.dimmed,
            };
        }

        // Positional/exact patterns: distribute PositionalMatch to literal atoms.
        if search_tokens.is_empty()
            && !arg_set.is_empty()
            && matches!(head, Some("positional" | "exact"))
        {
            let positional_args = extract_positional_args(arg_set);
            if let Some(first_arg) = positional_args.first() {
                let new_children: Vec<_> = std::iter::once(children[0].clone())
                    .chain(
                        children[1..]
                            .iter()
                            .map(|c| distribute_positional_comparisons(c, first_arg)),
                    )
                    .collect();
                return Doc {
                    ann: None,
                    node: DocF::List(new_children),
                    layout: doc.layout,
                    dimmed: doc.dimmed,
                };
            }
        }
    }

    // Recurse into children
    match &doc.node {
        DocF::List(children) => Doc {
            ann: doc.ann.clone(),
            node: DocF::List(children.iter().map(distribute_arg_annotations).collect()),
            layout: doc.layout,
            dimmed: doc.dimmed,
        },
        DocF::Vector(children) => Doc {
            ann: doc.ann.clone(),
            node: DocF::Vector(children.iter().map(distribute_arg_annotations).collect()),
            layout: doc.layout,
            dimmed: doc.dimmed,
        },
        DocF::Atom(_) => doc.clone(),
    }
}

fn extract_positional_args(args: &[String]) -> Vec<&str> {
    let mut result = Vec::new();
    let mut iter = args.iter().peekable();
    let mut past_terminator = false;

    while let Some(arg) = iter.next() {
        if past_terminator {
            result.push(arg.as_str());
        } else if arg == "--" {
            result.push(arg.as_str());
            past_terminator = true;
        } else if arg.starts_with("--") {
            if !arg.contains('=') {
                iter.next();
            }
        } else if arg.starts_with('-') {
            // Short flag — skip
        } else {
            result.push(arg.as_str());
        }
    }
    result
}

/// Recursively distribute PositionalMatch annotations to string literal atoms
/// within a positional pattern.
fn distribute_positional_comparisons(doc: &Doc<Option<Ann>>, actual_arg: &str) -> Doc<Option<Ann>> {
    match &doc.node {
        DocF::Atom(s) => {
            if s.starts_with('"') && s.ends_with('"') && s.len() > 2 {
                let inner_text = &s[1..s.len() - 1];
                let matched = actual_arg == inner_text;
                Doc {
                    ann: Some(Ann::PositionalMatch {
                        actual_arg: actual_arg.to_string(),
                        pattern_text: s.clone(),
                        matched,
                    }),
                    node: doc.node.clone(),
                    layout: doc.layout,
                    dimmed: doc.dimmed,
                }
            } else {
                doc.clone()
            }
        }
        DocF::List(children) => {
            let head = children.first().and_then(|c| c.as_atom());
            match head {
                Some("or") => {
                    let new_children: Vec<_> = std::iter::once(children[0].clone())
                        .chain(
                            children[1..]
                                .iter()
                                .map(|c| distribute_positional_comparisons(c, actual_arg)),
                        )
                        .collect();
                    Doc {
                        ann: doc.ann.clone(),
                        node: DocF::List(new_children),
                        layout: doc.layout,
                        dimmed: doc.dimmed,
                    }
                }
                Some("?" | "+" | "*") => {
                    let mut new_children = vec![children[0].clone()];
                    if let Some(inner) = children.get(1) {
                        new_children.push(distribute_positional_comparisons(inner, actual_arg));
                    }
                    new_children.extend(children[2..].iter().cloned());
                    Doc {
                        ann: doc.ann.clone(),
                        node: DocF::List(new_children),
                        layout: doc.layout,
                        dimmed: doc.dimmed,
                    }
                }
                _ => doc.clone(),
            }
        }
        _ => doc.clone(),
    }
}

fn distribute_to_token_children(
    children: &[Doc<Option<Ann>>],
    search_tokens: &[String],
    arg_set: &[String],
    matched: bool,
) -> Vec<Doc<Option<Ann>>> {
    let mut new_children = Vec::with_capacity(children.len());
    // Keep the head keyword as-is
    new_children.push(children[0].clone());

    for child in &children[1..] {
        if let DocF::Atom(text) = &child.node {
            // Find this atom's token in search_tokens
            if search_tokens.iter().any(|t| t == text) {
                new_children.push(Doc {
                    ann: Some(Ann::ArgMatch {
                        search_tokens: vec![text.clone()],
                        arg_set: arg_set.to_vec(),
                        matched,
                    }),
                    node: child.node.clone(),
                    layout: child.layout,
                    dimmed: child.dimmed,
                });
            } else {
                new_children.push(child.clone());
            }
        } else {
            new_children.push(distribute_arg_annotations(child));
        }
    }
    new_children
}

fn has_any_visible_annotation(doc: &Doc<Option<Ann>>) -> bool {
    if let Some(ann) = &doc.ann
        && !matches!(ann, Ann::RuleMatch { .. })
    {
        return true;
    }
    if let DocF::List(children) | DocF::Vector(children) = &doc.node {
        children.iter().any(has_any_visible_annotation)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::test_helpers::*;
    use may_i_core::doc::LayoutHint;

    #[test]
    fn dim_unevaluated_dims_unannotated() {
        let doc = list(vec![atom("rule"), atom("body")]);
        let dimmed = dim_unevaluated(doc);
        assert!(dimmed.dimmed);
    }

    #[test]
    fn dim_unevaluated_preserves_annotated() {
        let child = atom_ann(
            "x",
            Ann::EffectDecision {
                decision: may_i_core::Decision::Allow,
                reason: None,
            },
        );
        let doc = list(vec![atom("rule"), child]);
        let dimmed = dim_unevaluated(doc);
        assert!(!dimmed.dimmed);
    }

    #[test]
    fn truncate_anywhere_keeps_first_match() {
        let doc = list_ann(
            Ann::ArgMatch {
                search_tokens: vec!["a".into(), "b".into(), "c".into()],
                arg_set: vec!["a".into()],
                matched: true,
            },
            vec![atom("anywhere"), atom("a"), atom("b"), atom("c")],
        );
        let truncated = truncate_matched_anywhere(&doc);
        if let DocF::List(children) = &truncated.node {
            assert_eq!(children.len(), 2);
        } else {
            panic!("expected list");
        }
    }

    #[test]
    fn truncate_anywhere_preserves_unmatched() {
        let doc = list_ann(
            Ann::ArgMatch {
                search_tokens: vec!["a".into()],
                arg_set: vec![],
                matched: false,
            },
            vec![atom("anywhere"), atom("a"), atom("b")],
        );
        let truncated = truncate_matched_anywhere(&doc);
        if let DocF::List(children) = &truncated.node {
            assert_eq!(children.len(), 3);
        } else {
            panic!("expected list");
        }
    }

    #[test]
    fn visible_annotation_ignores_rule_match() {
        let doc = list_ann(
            Ann::RuleMatch {
                matched: true,
                line: None,
            },
            vec![atom("x")],
        );
        assert!(!has_any_visible_annotation(&doc));
    }

    #[test]
    fn visible_annotation_detects_effect_decision() {
        let doc = atom_ann(
            "x",
            Ann::EffectDecision {
                decision: may_i_core::Decision::Allow,
                reason: None,
            },
        );
        assert!(has_any_visible_annotation(&doc));
    }

    #[test]
    fn truncate_unevaluated_passes_through_vector() {
        let doc = vec_doc(vec![atom("a"), atom("b")]);
        let result = truncate_unevaluated(&doc, 2);
        match &result.node {
            DocF::Vector(cs) => assert_eq!(cs.len(), 2),
            _ => panic!("expected vector"),
        }
    }

    #[test]
    fn truncate_unevaluated_skips_anywhere_pattern() {
        let doc = Doc {
            ann: Some(Ann::ArgMatch {
                search_tokens: vec!["tok".into()],
                arg_set: vec![],
                matched: true,
            }),
            node: DocF::List(vec![
                atom("anywhere"),
                atom("a"),
                atom("b"),
                atom("c"),
                atom("d"),
                atom("e"),
            ]),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        let result = truncate_unevaluated(&doc, 1);
        match &result.node {
            DocF::List(cs) => assert_eq!(cs.len(), 6),
            _ => panic!("expected list"),
        }
    }

    #[test]
    fn dim_unevaluated_dims_vector_without_annotations() {
        let doc = vec_doc(vec![atom("a"), atom("b")]);
        let (result, _) = dim_unevaluated_inner(doc, false);
        assert!(result.dimmed, "vector with no annotations should be dimmed");
    }

    #[test]
    fn dim_unevaluated_preserves_annotated_vector() {
        let inner = atom_ann("x", Ann::CommandMatch { matched: true });
        let doc = vec_doc(vec![inner]);
        let (result, score) = dim_unevaluated_inner(doc, false);
        assert!(!result.dimmed);
        assert!(score > 0);
    }

    // ── distribute_arg_annotations tests ─────────────────────────────

    #[test]
    fn distribute_anywhere_gives_per_token_annotations() {
        let doc = list_ann(
            Ann::ArgMatch {
                search_tokens: vec!["\"t1\"".into(), "\"t2\"".into()],
                arg_set: vec!["a".into(), "b".into()],
                matched: true,
            },
            vec![atom("anywhere"), atom("\"t1\""), atom("\"t2\"")],
        );
        let result = distribute_arg_annotations(&doc);
        if let DocF::List(children) = &result.node {
            // Head "anywhere" unchanged
            assert!(children[0].ann.is_none());
            // Token children each have their own ArgMatch
            match &children[1].ann {
                Some(Ann::ArgMatch { search_tokens, .. }) => {
                    assert_eq!(search_tokens, &["\"t1\""]);
                }
                other => panic!("expected ArgMatch, got {other:?}"),
            }
            match &children[2].ann {
                Some(Ann::ArgMatch { search_tokens, .. }) => {
                    assert_eq!(search_tokens, &["\"t2\""]);
                }
                other => panic!("expected ArgMatch, got {other:?}"),
            }
        } else {
            panic!("expected list");
        }
    }

    #[test]
    fn distribute_forbidden_not_anywhere() {
        // (not (anywhere "t1" "t2")) with parent ArgMatch
        let inner = list(vec![atom("anywhere"), atom("\"t1\""), atom("\"t2\"")]);
        let doc = Doc {
            ann: Some(Ann::ArgMatch {
                search_tokens: vec!["\"t1\"".into(), "\"t2\"".into()],
                arg_set: vec!["x".into()],
                matched: false,
            }),
            node: DocF::List(vec![atom("not"), inner]),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        let result = distribute_arg_annotations(&doc);
        if let DocF::List(children) = &result.node {
            // "not" head unchanged
            assert_eq!(children[0].as_atom(), Some("not"));
            // Inner (anywhere ...) has distributed children
            if let DocF::List(inner_children) = &children[1].node {
                assert_eq!(inner_children[0].as_atom(), Some("anywhere"));
                assert!(matches!(
                    &inner_children[1].ann,
                    Some(Ann::ArgMatch { search_tokens, .. }) if search_tokens == &["\"t1\""]
                ));
                assert!(matches!(
                    &inner_children[2].ann,
                    Some(Ann::ArgMatch { search_tokens, .. }) if search_tokens == &["\"t2\""]
                ));
            } else {
                panic!("expected inner list");
            }
        } else {
            panic!("expected list");
        }
    }

    #[test]
    fn distribute_preserves_non_argmatch_nodes() {
        let doc = list(vec![
            atom_ann("cmd", Ann::CommandMatch { matched: true }),
            atom("arg"),
        ]);
        let result = distribute_arg_annotations(&doc);
        // Structure unchanged
        if let DocF::List(children) = &result.node {
            assert!(matches!(
                &children[0].ann,
                Some(Ann::CommandMatch { matched: true })
            ));
            assert!(children[1].ann.is_none());
        } else {
            panic!("expected list");
        }
    }

    #[test]
    fn distribute_positional_adds_positional_match() {
        // Positional patterns have empty search_tokens — distributes PositionalMatch
        let doc = list_ann(
            Ann::ArgMatch {
                search_tokens: vec![],
                arg_set: vec!["a".into()],
                matched: true,
            },
            vec![atom("positional"), atom("\"a\"")],
        );
        let result = distribute_arg_annotations(&doc);
        // Parent annotation cleared
        assert!(result.ann.is_none());
        if let DocF::List(children) = &result.node {
            assert!(matches!(
                &children[1].ann,
                Some(Ann::PositionalMatch { actual_arg, pattern_text, matched: true })
                    if actual_arg == "a" && pattern_text == "\"a\""
            ));
        } else {
            panic!("expected list");
        }
    }
}
