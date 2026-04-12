use may_i_core::{Span, Trivia, TriviaAnn};
use proptest::prelude::*;

use crate::cst::{CstNode, ShapeF};
use crate::sexpr::Sexpr;

// ── Primitive constructors ────────────────────────────────────────────
//
// Zero-trivia helpers for building CST nodes in tests. These are
// intentionally simple — trivia generators compose on top.

pub fn cst_atom(s: impl Into<String>) -> Box<CstNode> {
    Box::new(CstNode::atom(s, TriviaAnn::default()))
}

pub fn cst_str(s: impl Into<String>) -> Box<CstNode> {
    Box::new(CstNode {
        ann: TriviaAnn::default(),
        shape: ShapeF::String(s.into()),
    })
}

pub fn cst_list(children: Vec<Box<CstNode>>) -> Box<CstNode> {
    Box::new(CstNode::list(children, TriviaAnn::default()))
}

pub fn cst_vector(children: Vec<Box<CstNode>>) -> Box<CstNode> {
    Box::new(CstNode::vector(children, TriviaAnn::default()))
}

// ── Leaf strategies ───────────────────────────────────────────────────

/// Bare atom strings: identifiers, keywords, operators.
pub fn any_atom_string() -> BoxedStrategy<String> {
    prop_oneof![
        "[a-z][a-z0-9_-]{0,12}",
        ":[a-z][a-z0-9_/-]{0,12}",
        Just("*".to_string()),
        Just("?".to_string()),
    ]
    .boxed()
}

/// String literal content (no quotes — the Str shape adds them on serialize).
///
/// Restricted to characters that are valid atom chars, so that roundtripping
/// through `to_sexpr → Sexpr::Display → parse` preserves structure.
pub fn any_str_content() -> BoxedStrategy<String> {
    prop_oneof!["[a-zA-Z0-9 _./-]{0,20}", Just(String::new()),].boxed()
}

/// An atom CstNode.
pub fn any_atom_node() -> BoxedStrategy<Box<CstNode>> {
    any_atom_string().prop_map(cst_atom).boxed()
}

/// A string literal CstNode.
pub fn any_str_node() -> BoxedStrategy<Box<CstNode>> {
    any_str_content().prop_map(cst_str).boxed()
}

/// A leaf CstNode (atom or string).
pub fn any_leaf_node() -> BoxedStrategy<Box<CstNode>> {
    prop_oneof![any_atom_node(), any_str_node(),].boxed()
}

// ── Trivia strategies ─────────────────────────────────────────────────

/// Whitespace trivia (spaces, newlines, indentation).
pub fn any_whitespace_trivia() -> BoxedStrategy<Trivia> {
    prop_oneof![
        Just(Trivia::Whitespace(" ".to_string())),
        Just(Trivia::Whitespace("  ".to_string())),
        Just(Trivia::Whitespace("\n".to_string())),
        Just(Trivia::Whitespace("\n  ".to_string())),
        Just(Trivia::Whitespace("\n    ".to_string())),
    ]
    .boxed()
}

/// Comment trivia.
pub fn any_comment_trivia() -> BoxedStrategy<Trivia> {
    "[a-zA-Z0-9 _-]{0,30}"
        .prop_map(|text| Trivia::Comment {
            text: format!(";; {}", text.trim()),
            has_newline: true,
        })
        .boxed()
}

/// Any trivia item.
pub fn any_trivia() -> BoxedStrategy<Trivia> {
    prop_oneof![
        3 => any_whitespace_trivia(),
        1 => any_comment_trivia(),
    ]
    .boxed()
}

/// A trivia annotation with optional leading/trailing trivia.
pub fn any_trivia_ann() -> BoxedStrategy<TriviaAnn> {
    (
        prop::collection::vec(any_trivia(), 0..=2),
        prop::collection::vec(any_trivia(), 0..=1),
    )
        .prop_map(|(leading, trailing)| TriviaAnn {
            leading,
            trailing,
            span: Span::new(0, 0),
        })
        .boxed()
}

/// Empty trivia annotation (for freshly-constructed nodes).
pub fn empty_trivia_ann() -> BoxedStrategy<TriviaAnn> {
    Just(TriviaAnn::default()).boxed()
}

// ── Recursive tree strategies ─────────────────────────────────────────

/// A CstNode tree with no trivia (bare structure).
pub fn any_cst_node(depth: u32) -> BoxedStrategy<Box<CstNode>> {
    if depth == 0 {
        any_leaf_node()
    } else {
        prop_oneof![
            any_leaf_node(),
            // list with children
            prop::collection::vec(any_cst_node(depth - 1), 0..=5).prop_map(cst_list),
            // vector with children
            prop::collection::vec(any_cst_node(depth - 1), 0..=4).prop_map(cst_vector),
        ]
        .boxed()
    }
}

/// A CstNode tree with trivia attached to nodes.
pub fn any_cst_node_with_trivia(depth: u32) -> BoxedStrategy<Box<CstNode>> {
    if depth == 0 {
        (any_leaf_node(), any_trivia_ann())
            .prop_map(|(mut node, ann)| {
                node.ann = ann;
                node
            })
            .boxed()
    } else {
        prop_oneof![
            (any_leaf_node(), any_trivia_ann()).prop_map(|(mut node, ann)| {
                node.ann = ann;
                node
            }),
            (
                prop::collection::vec(any_cst_node_with_trivia(depth - 1), 0..=5),
                any_trivia_ann()
            )
                .prop_map(|(children, ann)| {
                    Box::new(CstNode {
                        ann,
                        shape: ShapeF::List(children),
                    })
                }),
            (
                prop::collection::vec(any_cst_node_with_trivia(depth - 1), 0..=4),
                any_trivia_ann()
            )
                .prop_map(|(children, ann)| {
                    Box::new(CstNode {
                        ann,
                        shape: ShapeF::Vector(children),
                    })
                }),
        ]
        .boxed()
    }
}

/// A "tagged list" — `(tag child...)`, the most common CST pattern.
pub fn any_tagged_list(
    tag: &'static str,
    children: BoxedStrategy<Vec<Box<CstNode>>>,
) -> BoxedStrategy<Box<CstNode>> {
    children
        .prop_map(move |mut kids| {
            kids.insert(0, cst_atom(tag));
            cst_list(kids)
        })
        .boxed()
}

/// Multi-form document (like a config file with multiple top-level forms).
pub fn any_cst_document(depth: u32) -> BoxedStrategy<Vec<Box<CstNode>>> {
    prop::collection::vec(any_cst_node(depth), 1..=6).boxed()
}

/// Multi-form document with trivia.
pub fn any_cst_document_with_trivia(depth: u32) -> BoxedStrategy<Vec<Box<CstNode>>> {
    prop::collection::vec(any_cst_node_with_trivia(depth), 1..=6).boxed()
}

// ── Sexpr strategies ──────────────────────────────────────────────────

/// An arbitrary Sexpr (no trivia, just structure).
pub fn any_sexpr(depth: u32) -> BoxedStrategy<Sexpr> {
    let span = Span::new(0, 0);
    if depth == 0 {
        prop_oneof![
            any_atom_string()
                .prop_filter("not a keyword", |s| !s.starts_with(':'))
                .prop_map(move |s| Sexpr::Symbol(s, span)),
            ":[a-z][a-z0-9_/-]{0,12}".prop_map(move |s| Sexpr::Keyword(s, span)),
            any_str_content().prop_map(move |s| Sexpr::String(s, span)),
        ]
        .boxed()
    } else {
        prop_oneof![
            any_atom_string()
                .prop_filter("not a keyword", |s| !s.starts_with(':'))
                .prop_map(move |s| Sexpr::Symbol(s, span)),
            ":[a-z][a-z0-9_/-]{0,12}".prop_map(move |s| Sexpr::Keyword(s, span)),
            any_str_content().prop_map(move |s| Sexpr::String(s, span)),
            prop::collection::vec(any_sexpr(depth - 1), 0..=5)
                .prop_map(move |items| Sexpr::List(items, span)),
            prop::collection::vec(any_sexpr(depth - 1), 0..=4)
                .prop_map(move |items| Sexpr::Vector(items, span)),
        ]
        .boxed()
    }
}

// ── Domain-specific config generators ─────────────────────────────────
//
// These generate CSTs representing valid may-i config syntax.
// They are useful across the config, engine, and migration crates.

/// A command pattern: literal string, `(or ...)`, or `(regex ...)`.
pub fn any_command_pattern_cst() -> BoxedStrategy<Box<CstNode>> {
    prop_oneof![
        "[a-z][a-z0-9_-]{0,10}".prop_map(|s| cst_str(&s)),
        prop::collection::vec("[a-z][a-z0-9_-]{0,10}".prop_map(|s| cst_str(&s)), 2..=4).prop_map(
            |cmds| {
                let mut children = vec![cst_atom("or")];
                children.extend(cmds);
                cst_list(children)
            }
        ),
    ]
    .boxed()
}

/// A keyword atom like `:via/ssh`, `:in/ci`.
pub fn any_keyword_cst() -> BoxedStrategy<Box<CstNode>> {
    prop_oneof![
        Just(cst_atom(":via/ssh")),
        Just(cst_atom(":in/ci")),
        Just(cst_atom(":tool/docker")),
        "[a-z]{1,8}".prop_map(|s| cst_atom(format!(":{}", s))),
    ]
    .boxed()
}

/// A terminal effect: `(effect :allow/:ask/:deny ["reason"])`.
pub fn any_terminal_effect_cst() -> BoxedStrategy<Box<CstNode>> {
    prop_oneof![
        Just(cst_list(vec![cst_atom("effect"), cst_atom(":allow")])),
        Just(cst_list(vec![cst_atom("effect"), cst_atom(":deny")])),
        Just(cst_list(vec![cst_atom("effect"), cst_atom(":ask")])),
        "[a-z ]{1,20}".prop_map(|r| cst_list(vec![
            cst_atom("effect"),
            cst_atom(":allow"),
            cst_str(r.trim())
        ])),
        "[a-z ]{1,20}".prop_map(|r| cst_list(vec![
            cst_atom("effect"),
            cst_atom(":ask"),
            cst_str(r.trim())
        ])),
        "[a-z ]{1,20}".prop_map(|r| cst_list(vec![
            cst_atom("effect"),
            cst_atom(":deny"),
            cst_str(r.trim())
        ])),
    ]
    .boxed()
}

/// A predicate CST: `(fact? :key)`, `(and P P)`, `(or P P)`, `(not P)`.
pub fn any_predicate_cst(depth: u32) -> BoxedStrategy<Box<CstNode>> {
    if depth == 0 {
        any_keyword_cst()
            .prop_map(|k| cst_list(vec![cst_atom("fact?"), k]))
            .boxed()
    } else {
        prop_oneof![
            any_predicate_cst(0),
            (any_predicate_cst(depth - 1), any_predicate_cst(depth - 1))
                .prop_map(|(a, b)| cst_list(vec![cst_atom("and"), a, b])),
            (any_predicate_cst(depth - 1), any_predicate_cst(depth - 1))
                .prop_map(|(a, b)| cst_list(vec![cst_atom("or"), a, b])),
            any_predicate_cst(depth - 1).prop_map(|p| cst_list(vec![cst_atom("not"), p])),
        ]
        .boxed()
    }
}

/// A canonical effect CST (fixed point of migration).
///
/// Constraints to avoid triggering rewrite rules:
/// - `if` else branch must be terminal (not if/when/unless/cond)
/// - `cond` needs 2+ regular clauses (1 clause + else becomes `if`)
/// - `cond` else body must be terminal (not conditional)
pub fn any_canonical_effect_cst(depth: u32) -> BoxedStrategy<Box<CstNode>> {
    if depth == 0 {
        any_terminal_effect_cst()
    } else {
        prop_oneof![
            any_terminal_effect_cst(),
            // (when P E)
            (any_predicate_cst(1), any_canonical_effect_cst(depth - 1))
                .prop_map(|(p, e)| cst_list(vec![cst_atom("when"), p, e])),
            // (if P E1 E2) — else must be terminal
            (
                any_predicate_cst(1),
                any_canonical_effect_cst(depth - 1),
                any_terminal_effect_cst()
            )
                .prop_map(|(p, e1, e2)| cst_list(vec![cst_atom("if"), p, e1, e2])),
            // (cond (P1 E1) (P2 E2) ...) — 2+ clauses, no else
            prop::collection::vec((any_predicate_cst(1), any_terminal_effect_cst()), 2..=4)
                .prop_map(|clauses| {
                    let mut children = vec![cst_atom("cond")];
                    children.extend(clauses.into_iter().map(|(p, e)| cst_list(vec![p, e])));
                    cst_list(children)
                }),
            // (cond (P1 E1) (P2 E2) ... (else TERMINAL))
            (
                prop::collection::vec((any_predicate_cst(1), any_terminal_effect_cst()), 2..=4),
                any_terminal_effect_cst()
            )
                .prop_map(|(clauses, else_eff)| {
                    let mut children = vec![cst_atom("cond")];
                    children.extend(clauses.into_iter().map(|(p, e)| cst_list(vec![p, e])));
                    children.push(cst_list(vec![cst_atom("else"), else_eff]));
                    cst_list(children)
                }),
        ]
        .boxed()
    }
}

/// A canonical rule: `(rule CMD EFFECT)`.
pub fn any_canonical_rule_cst() -> BoxedStrategy<Box<CstNode>> {
    (any_command_pattern_cst(), any_canonical_effect_cst(2))
        .prop_map(|(cmd, eff)| cst_list(vec![cst_atom("rule"), cmd, eff]))
        .boxed()
}

/// A canonical config (multiple rules).
pub fn any_canonical_config_cst() -> BoxedStrategy<Vec<Box<CstNode>>> {
    prop::collection::vec(any_canonical_rule_cst(), 1..=4).boxed()
}

// ── Property test helpers ─────────────────────────────────────────────

/// Check structural equality of two CstNodes ignoring trivia.
pub fn cst_nodes_structurally_equal(a: &CstNode, b: &CstNode) -> bool {
    match (&a.shape, &b.shape) {
        (ShapeF::Keyword(a_str), ShapeF::Keyword(b_str)) => a_str == b_str,
        (ShapeF::Symbol(a_str), ShapeF::Symbol(b_str)) => a_str == b_str,
        (ShapeF::String(a_str), ShapeF::String(b_str)) => a_str == b_str,
        (ShapeF::List(a_kids), ShapeF::List(b_kids))
        | (ShapeF::Vector(a_kids), ShapeF::Vector(b_kids)) => {
            a_kids.len() == b_kids.len()
                && a_kids
                    .iter()
                    .zip(b_kids.iter())
                    .all(|(a, b)| cst_nodes_structurally_equal(a, b))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cst;

    // ── Generator sanity tests ────────────────────────────────────────
    //
    // Verify that generated CSTs serialize to parseable text and roundtrip
    // through parse → to_sexpr → structural comparison.

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn generated_atoms_roundtrip(node in any_atom_node()) {
            let text = node.serialize();
            let (parsed, errors) = cst::parse(&text);
            prop_assert!(errors.is_empty(), "parse errors: {:?}", errors);
            prop_assert_eq!(parsed.len(), 1);
            prop_assert!(
                cst_nodes_structurally_equal(&node, &parsed[0]),
                "roundtrip failed:\n  original: {:?}\n  reparsed: {:?}",
                node, parsed[0]
            );
        }

        #[test]
        fn generated_strs_roundtrip(node in any_str_node()) {
            let text = node.serialize();
            let (parsed, errors) = cst::parse(&text);
            prop_assert!(errors.is_empty(), "parse errors for {:?}: {:?}", text, errors);
            prop_assert_eq!(parsed.len(), 1);
            // String nodes parse back as ShapeF::String in the CST parser
            prop_assert!(
                matches!(&parsed[0].shape, ShapeF::String(s) if s == node.as_str().unwrap_or("")),
                "string content mismatch:\n  serialized: {}\n  reparsed shape: {:?}",
                text, parsed[0].shape
            );
        }

        #[test]
        fn generated_trees_serialize_and_reparse(node in any_cst_node(3)) {
            let text = node.serialize();
            let (parsed, errors) = cst::parse(&text);
            prop_assert!(
                errors.is_empty(),
                "parse errors for generated tree:\n  text: {}\n  errors: {:?}",
                text, errors
            );
            // Must produce at least one node (the tree is non-empty)
            prop_assert!(!parsed.is_empty(), "parsed no nodes from: {}", text);
        }

        #[test]
        fn generated_trees_with_trivia_reparse(node in any_cst_node_with_trivia(2)) {
            let text = node.serialize();
            let (parsed, errors) = cst::parse(&text);
            prop_assert!(
                errors.is_empty(),
                "parse errors for trivia tree:\n  text: {:?}\n  errors: {:?}",
                text, errors
            );
            prop_assert!(!parsed.is_empty(), "parsed no nodes from: {:?}", text);
        }

        // ── to_sexpr roundtrip ────────────────────────────────────────

        #[test]
        fn to_sexpr_preserves_structure(node in any_cst_node(3)) {
            let sexpr = node.to_sexpr();
            // Sexpr Display → reparse as Sexpr and compare
            let text = format!("{}", sexpr);
            let (reparsed, errors) = crate::parse(&text);
            prop_assert!(
                errors.is_empty(),
                "Sexpr display didn't reparse:\n  text: {}\n  errors: {:?}",
                text, errors
            );
            prop_assert_eq!(reparsed.len(), 1);
            prop_assert_eq!(
                &sexpr, &reparsed[0],
                "Sexpr roundtrip mismatch:\n  original: {}\n  reparsed: {}",
                sexpr, reparsed[0]
            );
        }

        // ── Serialize roundtrip (structural equality) ─────────────────

        #[test]
        fn serialize_roundtrip_preserves_structure(node in any_cst_node(3)) {
            let text = node.serialize();
            let (parsed, errors) = cst::parse(&text);
            prop_assert!(errors.is_empty());
            prop_assert!(!parsed.is_empty());

            // CST → serialize → parse should produce structurally identical tree
            prop_assert!(
                cst_nodes_structurally_equal(&node, &parsed[0]),
                "structural mismatch after roundtrip:\n  text: {}\n  original: {:?}\n  reparsed: {:?}",
                text, node.shape, parsed[0].shape
            );
        }

        // ── Document roundtrip ────────────────────────────────────────

        #[test]
        fn document_serialize_roundtrip(forms in any_cst_document(2)) {
            let text: String = forms.iter().map(|f| f.serialize()).collect::<Vec<_>>().join("\n");
            let (parsed, errors) = cst::parse(&text);
            prop_assert!(
                errors.is_empty(),
                "document parse errors:\n  text: {}\n  errors: {:?}",
                text, errors
            );
            prop_assert_eq!(
                forms.len(), parsed.len(),
                "form count changed:\n  text: {}",
                text
            );
            for (orig, re) in forms.iter().zip(parsed.iter()) {
                prop_assert!(
                    cst_nodes_structurally_equal(orig, re),
                    "document form mismatch:\n  original: {:?}\n  reparsed: {:?}",
                    orig.shape, re.shape
                );
            }
        }

        // ── Sexpr strategies ──────────────────────────────────────────

        #[test]
        fn generated_sexprs_display_and_reparse(sexpr in any_sexpr(3)) {
            let text = format!("{}", sexpr);
            let (reparsed, errors) = crate::parse(&text);
            prop_assert!(
                errors.is_empty(),
                "Sexpr display failed to reparse:\n  text: {}\n  errors: {:?}",
                text, errors
            );
            prop_assert_eq!(reparsed.len(), 1);
            prop_assert_eq!(
                &sexpr, &reparsed[0],
                "Sexpr display roundtrip mismatch"
            );
        }

        // ── Domain-specific generators ────────────────────────────────

        #[test]
        fn canonical_rules_serialize_and_parse(rule in any_canonical_rule_cst()) {
            let text = rule.serialize();
            let result = may_i_config_parse_roundtrip(&text);
            prop_assert!(
                result,
                "canonical rule failed to parse:\n  text: {}",
                text
            );
        }

        #[test]
        fn canonical_configs_serialize_and_parse(forms in any_canonical_config_cst()) {
            let text: String = forms.iter().map(|f| f.serialize()).collect::<Vec<_>>().join("\n");
            let (parsed, errors) = cst::parse(&text);
            prop_assert!(
                errors.is_empty(),
                "canonical config parse errors:\n  text: {}\n  errors: {:?}",
                text, errors
            );
            prop_assert_eq!(forms.len(), parsed.len());
        }
    }

    /// Check that a config string parses as a valid CST document.
    fn may_i_config_parse_roundtrip(text: &str) -> bool {
        let (forms, errors) = cst::parse(text);
        errors.is_empty() && !forms.is_empty()
    }
}
