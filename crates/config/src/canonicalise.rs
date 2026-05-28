//! Canonical body-form ordering for the DSL.
//!
//! A pre-render pass that applies deterministic ordering to multi-declaration
//! bodies. A body is sorted only when **both** conditions hold; otherwise
//! authored order is preserved:
//!
//! 1. **Engine-order-independent**: reordering is a semantic no-op (no
//!    short-circuit evaluation, no positional binding).
//! 2. **Not human-curated**: the body has no convention of embedded
//!    organisation (section-header comments, mnemonic grouping).
//!
//! Ordered bodies:
//! - `(parser PROG …)`: `(style)` first, then `(flags)`, then `(flag …)`
//!   block alphabetised by canonical name, then `(parameter …)` block
//!   alphabetised by canonical name, then `(positional …)` in source
//!   order (positional order is semantic), then `(rest)`. Legacy
//!   `(tail …)` if present is emitted last during the migration window.
//! - `(define-arg-style NAME …)`: attribute forms alphabetised by head atom.
//!
//! Preserved-order bodies:
//! - `(check …)`: cases are engine-order-independent but human-curated
//!   (users group cases under section-header comments). Source order is
//!   preserved verbatim.
//! - Rule bodies: evaluated short-circuit, order is semantic.
//!
//! Vectors in the name position of `(flag VEC)` and `(parameter VEC …)` are
//! set-typed and are sorted lexicographically. Vectors elsewhere
//! (separators, prefixes, rule bodies) are sequence-typed and untouched.

use may_i_sexpr::cst::{CstNode, ShapeF};

/// Apply canonical ordering to a list of top-level CST forms.
pub fn canonicalise_forms(forms: Vec<Box<CstNode>>) -> Vec<Box<CstNode>> {
    forms.into_iter().map(canonicalise_node).collect()
}

/// Apply canonical ordering recursively to a single CST node.
///
/// Takes `Box<CstNode>` because callers iterate over `Vec<Box<CstNode>>`
/// from `ShapeF<Box<CstNode>>`'s children — accepting `Box` directly avoids
/// an unbox/rebox at every call site.
#[allow(clippy::boxed_local)]
pub(crate) fn canonicalise_node(node: Box<CstNode>) -> Box<CstNode> {
    let CstNode { ann, shape } = *node;
    let new_shape = match shape {
        ShapeF::List(children) => {
            let recursed: Vec<Box<CstNode>> = children.into_iter().map(canonicalise_node).collect();
            let head = recursed
                .first()
                .and_then(|c| c.as_atom())
                .map(str::to_owned);
            let reordered = match head.as_deref() {
                Some("parser") => sort_parser_body(recursed),
                Some("define-arg-style") => sort_define_arg_style_body(recursed),
                Some("flag") => sort_flag_or_parameter_vec(recursed, 1),
                Some("parameter") => sort_flag_or_parameter_vec(recursed, 1),
                Some("after") => collapse_singleton_after(recursed),
                _ => recursed,
            };
            ShapeF::List(reordered)
        }
        ShapeF::Vector(children) => {
            let recursed: Vec<Box<CstNode>> = children.into_iter().map(canonicalise_node).collect();
            ShapeF::Vector(recursed)
        }
        atom
        @ (ShapeF::Keyword(_) | ShapeF::Symbol(_) | ShapeF::Binding(_) | ShapeF::String(_)) => atom,
    };
    Box::new(CstNode {
        ann,
        shape: new_shape,
    })
}

fn sort_parser_body(children: Vec<Box<CstNode>>) -> Vec<Box<CstNode>> {
    if children.len() < 3 {
        return children;
    }
    let mut iter = children.into_iter();
    let head = iter.next().expect("parser head");
    let program = iter.next().expect("parser program");
    let body: Vec<Box<CstNode>> = iter.collect();

    // Bucket ordering (parser-named-bindings):
    //   (style) (flags) (flag …) (parameter …) (positional …) (rest) (tail)
    //
    // `tail` stays at the end during the migration window — it is the
    // legacy form and gets emitted by `may-i migrate` for old configs.
    // Once removed (section 5), the `Tail` arm goes too.
    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
    enum Bucket {
        Style,
        Flags,
        Flag,
        Parameter,
        Positional,
        Rest,
        Tail,
        Other,
    }

    fn classify(n: &CstNode) -> Bucket {
        match n
            .as_list()
            .and_then(|c| c.first())
            .and_then(|c| c.as_atom())
        {
            Some("style") => Bucket::Style,
            Some("flags") => Bucket::Flags,
            Some("flag") => Bucket::Flag,
            Some("parameter") => Bucket::Parameter,
            Some("positional") => Bucket::Positional,
            Some("rest") => Bucket::Rest,
            Some("tail") => Bucket::Tail,
            _ => Bucket::Other,
        }
    }

    let mut indexed: Vec<(usize, Box<CstNode>)> = body.into_iter().enumerate().collect();
    indexed.sort_by(|(ai, a), (bi, b)| {
        let ba = classify(a);
        let bb = classify(b);
        ba.cmp(&bb).then_with(|| {
            if matches!(ba, Bucket::Flag | Bucket::Parameter) {
                let ka = flag_or_parameter_sort_key(a);
                let kb = flag_or_parameter_sort_key(b);
                ka.cmp(&kb).then_with(|| ai.cmp(bi))
            } else {
                ai.cmp(bi)
            }
        })
    });

    let mut out = Vec::with_capacity(indexed.len() + 2);
    out.push(head);
    out.push(program);
    out.extend(indexed.into_iter().map(|(_, n)| n));
    out
}

fn sort_define_arg_style_body(children: Vec<Box<CstNode>>) -> Vec<Box<CstNode>> {
    if children.len() < 3 {
        return children;
    }
    let mut iter = children.into_iter();
    let head = iter.next().expect("define-arg-style head");
    let name = iter.next().expect("define-arg-style name");
    let body: Vec<Box<CstNode>> = iter.collect();

    let mut indexed: Vec<(usize, Box<CstNode>)> = body.into_iter().enumerate().collect();
    indexed.sort_by(|(ai, a), (bi, b)| {
        let ka = head_atom_or_empty(a);
        let kb = head_atom_or_empty(b);
        ka.cmp(&kb).then_with(|| ai.cmp(bi))
    });

    let mut out = Vec::with_capacity(indexed.len() + 2);
    out.push(head);
    out.push(name);
    out.extend(indexed.into_iter().map(|(_, n)| n));
    out
}

/// If `children[vec_index]` is a vector (i.e. the name set of a `(flag …)` /
/// `(parameter …)` declaration), sort its string children lexicographically.
/// Other shapes are left untouched. Children outside the name slot are
/// unchanged.
fn sort_flag_or_parameter_vec(
    mut children: Vec<Box<CstNode>>,
    vec_index: usize,
) -> Vec<Box<CstNode>> {
    if let Some(slot) = children.get_mut(vec_index)
        && matches!(slot.shape, ShapeF::Vector(_))
    {
        let CstNode { ann, shape } = std::mem::replace(
            slot.as_mut(),
            CstNode {
                ann: Default::default(),
                shape: ShapeF::Symbol(String::new()),
            },
        );
        let ShapeF::Vector(items) = shape else {
            unreachable!()
        };
        let sorted = sort_string_vector(items);
        **slot = CstNode {
            ann,
            shape: ShapeF::Vector(sorted),
        };
    }
    children
}

/// Collapse `(after [STR])` → `(after "STR")`. The single-element bracket
/// form is semantically identical to the bare-string form; pretty-print
/// the compact spelling so canonical output matches the prelude/REFERENCE
/// idiom. Multi-element vectors and non-string vectors are left alone.
fn collapse_singleton_after(mut children: Vec<Box<CstNode>>) -> Vec<Box<CstNode>> {
    let Some(slot) = children.get_mut(1) else {
        return children;
    };
    let ShapeF::Vector(items) = &slot.shape else {
        return children;
    };
    if items.len() != 1 {
        return children;
    }
    let only = &items[0];
    let ShapeF::String(s) = &only.shape else {
        return children;
    };
    let s = s.clone();
    let ann = slot.ann.clone();
    **slot = CstNode {
        ann,
        shape: ShapeF::String(s),
    };
    children
}

fn sort_string_vector(items: Vec<Box<CstNode>>) -> Vec<Box<CstNode>> {
    let all_strings = items.iter().all(|n| matches!(n.shape, ShapeF::String(_)));
    if !all_strings {
        return items;
    }
    let mut indexed: Vec<(usize, Box<CstNode>)> = items.into_iter().enumerate().collect();
    indexed.sort_by(|(ai, a), (bi, b)| {
        let ka = a.as_str().unwrap_or("");
        let kb = b.as_str().unwrap_or("");
        ka.cmp(kb).then_with(|| ai.cmp(bi))
    });
    indexed.into_iter().map(|(_, n)| n).collect()
}

fn flag_or_parameter_sort_key(node: &CstNode) -> String {
    let Some(children) = node.as_list() else {
        return String::new();
    };
    let Some(name) = children.get(1) else {
        return String::new();
    };
    match &name.shape {
        ShapeF::String(s) => s.clone(),
        ShapeF::Vector(items) => items
            .iter()
            .filter_map(|n| n.as_str())
            .min()
            .map(|s| s.to_string())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

fn head_atom_or_empty(node: &CstNode) -> String {
    node.as_list()
        .and_then(|c| c.first())
        .and_then(|c| c.as_atom())
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_sexpr::parse_cst;

    fn render(forms: &[Box<CstNode>]) -> String {
        forms
            .iter()
            .map(|f| f.pretty_serialize(100))
            .collect::<Vec<_>>()
            .join("")
    }

    /// Render and collapse whitespace so structural assertions don't depend
    /// on the pretty-printer's line-wrapping heuristics.
    fn render_flat(forms: &[Box<CstNode>]) -> String {
        let raw = render(forms);
        raw.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn parser_body_canonical_order() {
        let src = r#"(parser "git" (parameter "C") (flag "v") (flag "version") (parameter "config") (style gnu) (tail (after :flags)))"#;
        let (forms, errs) = parse_cst(src);
        assert!(errs.is_empty(), "{errs:?}");
        let canon = canonicalise_forms(forms);
        let out = render_flat(&canon);
        let want = r#"(parser "git" (style gnu) (flag "v") (flag "version") (parameter "C") (parameter "config") (tail (after :flags)))"#;
        assert_eq!(out.trim(), want);
    }

    #[test]
    fn define_arg_style_attributes_alphabetised() {
        let src =
            r#"(define-arg-style mystyle (separators "=") (long-prefix "--") (overrides gnu))"#;
        let (forms, errs) = parse_cst(src);
        assert!(errs.is_empty(), "{errs:?}");
        let canon = canonicalise_forms(forms);
        let out = render_flat(&canon);
        let want =
            r#"(define-arg-style mystyle (long-prefix "--") (overrides gnu) (separators "="))"#;
        assert_eq!(out.trim(), want);
    }

    #[test]
    fn check_cases_preserve_source_order() {
        let src = r#"(check (deny "rm -rf /") (allow "ls"))"#;
        let (forms, errs) = parse_cst(src);
        assert!(errs.is_empty(), "{errs:?}");
        let canon = canonicalise_forms(forms);
        let out = render_flat(&canon);
        let want = r#"(check (deny "rm -rf /") (allow "ls"))"#;
        assert_eq!(out.trim(), want);
    }

    #[test]
    fn check_section_header_comments_stay_with_their_cases() {
        let src = "(check\n  ;; State manipulation\n  (deny \"rm -rf /\")\n  ;; Inspection\n  (allow \"ls\"))";
        let (forms, errs) = parse_cst(src);
        assert!(errs.is_empty(), "{errs:?}");
        let canon = canonicalise_forms(forms);
        let out = render(&canon);
        let pos_state = out.find(";; State manipulation").expect(&out);
        let pos_deny = out.find(r#"(deny "rm -rf /")"#).expect(&out);
        let pos_inspect = out.find(";; Inspection").expect(&out);
        let pos_allow = out.find(r#"(allow "ls")"#).expect(&out);
        assert!(
            pos_state < pos_deny,
            "section header should precede its case: {out}"
        );
        assert!(
            pos_deny < pos_inspect,
            "deny case should precede next section header: {out}"
        );
        assert!(
            pos_inspect < pos_allow,
            "section header should precede its case: {out}"
        );
    }

    #[test]
    fn flag_name_vector_sorted() {
        let src = r#"(parser "x" (style gnu) (flag ["r" "0"]))"#;
        let (forms, errs) = parse_cst(src);
        assert!(errs.is_empty(), "{errs:?}");
        let canon = canonicalise_forms(forms);
        let out = render(&canon);
        assert!(out.contains(r#"(flag ["0" "r"])"#), "got: {out}");
    }

    #[test]
    fn parameter_name_vector_sorted() {
        let src = r#"(parser "x" (style gnu) (parameter ["n" "interval"]))"#;
        let (forms, errs) = parse_cst(src);
        assert!(errs.is_empty(), "{errs:?}");
        let canon = canonicalise_forms(forms);
        let out = render(&canon);
        assert!(
            out.contains(r#"(parameter ["interval" "n"])"#),
            "got: {out}"
        );
    }

    #[test]
    fn after_singleton_vector_collapses_to_string() {
        let src = r#"(parser "x" (style gnu) (tail (after ["--"])))"#;
        let (forms, errs) = parse_cst(src);
        assert!(errs.is_empty(), "{errs:?}");
        let canon = canonicalise_forms(forms);
        let out = render(&canon);
        assert!(
            out.contains(r#"(after "--")"#),
            "expected single-element bracket form to collapse to bare string; got: {out}"
        );
        assert!(
            !out.contains(r#"(after [""#),
            "single-element bracket form should not survive canonicalisation; got: {out}"
        );
    }

    #[test]
    fn after_multi_token_vector_preserved() {
        let src = r#"(parser "nix" (style gnu) (tail (after ["--command" "-c"])))"#;
        let (forms, errs) = parse_cst(src);
        assert!(errs.is_empty(), "{errs:?}");
        let canon = canonicalise_forms(forms);
        let out = render(&canon);
        assert!(
            out.contains(r#"(after ["--command" "-c"])"#),
            "multi-element bracket form must be preserved verbatim; got: {out}"
        );
    }

    #[test]
    fn separator_vector_preserved() {
        let src = r#"(define-arg-style mystyle (separators "=" " "))"#;
        let (forms, errs) = parse_cst(src);
        assert!(errs.is_empty(), "{errs:?}");
        let canon = canonicalise_forms(forms);
        let out = render(&canon);
        assert!(out.contains(r#"(separators "=" " ")"#), "got: {out}");
    }

    #[test]
    fn rule_body_order_preserved() {
        let src = r#"(rule "git" (positional "diff") (allow))"#;
        let (forms, errs) = parse_cst(src);
        assert!(errs.is_empty(), "{errs:?}");
        let canon = canonicalise_forms(forms);
        let out = render_flat(&canon);
        let want = r#"(rule "git" (positional "diff") (allow))"#;
        assert_eq!(out.trim(), want);
    }

    #[test]
    fn vector_name_sort_key_uses_min_after_sort() {
        // Sort key for a vector-named flag is the min element. Both before
        // and after the vector itself is sorted, the key is "0".
        let src = r#"(parser "x" (style gnu) (flag "z") (flag ["r" "0"]) (flag "a"))"#;
        let (forms, errs) = parse_cst(src);
        assert!(errs.is_empty(), "{errs:?}");
        let canon = canonicalise_forms(forms);
        let out = render(&canon);
        // Order after canonicalisation should be: ["0" "r"], "a", "z".
        let pos_vec = out.find(r#"(flag ["0" "r"])"#).expect(&out);
        let pos_a = out.find(r#"(flag "a")"#).expect(&out);
        let pos_z = out.find(r#"(flag "z")"#).expect(&out);
        assert!(pos_vec < pos_a, "vec should come before a in: {out}");
        assert!(pos_a < pos_z, "a should come before z in: {out}");
    }

    use proptest::prelude::*;

    // Generate arbitrary parser/define-arg-style/check bodies and assert that
    // canonicalisation is idempotent — running it twice produces the same
    // tree as running it once.
    fn parser_body_strategy() -> impl Strategy<Value = String> {
        let flag = prop::collection::vec("[a-z]{1,4}", 0..5).prop_map(|names| {
            names
                .into_iter()
                .map(|n| format!(r#"(flag "{n}")"#))
                .collect::<Vec<_>>()
                .join(" ")
        });
        let param = prop::collection::vec("[a-z]{1,4}", 0..5).prop_map(|names| {
            names
                .into_iter()
                .map(|n| format!(r#"(parameter "{n}")"#))
                .collect::<Vec<_>>()
                .join(" ")
        });
        (flag, param, prop::bool::ANY).prop_map(|(flags, params, with_tail)| {
            let tail = if with_tail {
                "(tail (after :flags))"
            } else {
                ""
            };
            format!(r#"(parser "p" (style gnu) {flags} {params} {tail})"#)
        })
    }

    fn check_body_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(
            (
                prop_oneof![Just("allow"), Just("deny"), Just("ask")],
                "[a-z]{1,8}",
            ),
            0..6,
        )
        .prop_map(|cases| {
            let body = cases
                .into_iter()
                .map(|(d, c)| format!(r#"({d} "{c}")"#))
                .collect::<Vec<_>>()
                .join(" ");
            format!(r#"(check {body})"#)
        })
    }

    /// Generate a `(parser …)` form, parse it, canonicalise it, render it,
    /// then re-parse the canonical text and confirm the AST matches the
    /// canonical AST. Closes dsl-coherence §1.4.
    fn parser_body_full_strategy() -> impl Strategy<Value = String> {
        (
            "[a-z]{1,4}",
            prop::collection::vec("[a-z]{1,4}", 0..4),
            prop::collection::vec("[a-z]{1,4}", 0..4),
        )
            .prop_map(|(prog, flags, params)| {
                let f = flags
                    .iter()
                    .map(|n| format!(r#"(flag "{n}")"#))
                    .collect::<Vec<_>>()
                    .join(" ");
                let p = params
                    .iter()
                    .map(|n| format!(r#"(parameter "{n}")"#))
                    .collect::<Vec<_>>()
                    .join(" ");
                format!(r#"(parser "{prog}" (style gnu) {f} {p})"#)
            })
    }

    proptest! {
        // Closes dsl-coherence §1.4: every parser body roundtrips through
        // parse → canonicalise → render → parse → canonicalise unchanged.
        #[test]
        fn parser_body_canonical_roundtrips(src in parser_body_full_strategy()) {
            let (forms, errs) = parse_cst(&src);
            prop_assert!(errs.is_empty(), "parse errors: {:?}", errs);
            let canon1 = render(&canonicalise_forms(forms));
            let (forms2, errs2) = parse_cst(&canon1);
            prop_assert!(errs2.is_empty(), "canonical re-parse errors: {:?}", errs2);
            let canon2 = render(&canonicalise_forms(forms2));
            prop_assert_eq!(canon1, canon2);
        }

        // Closes dsl-coherence §4.4: decision verbs (allow/ask/deny) embedded
        // in rule bodies survive the canonical-form round-trip.
        #[test]
        fn decision_verbs_roundtrip_through_canonical(
            cmd in "[a-z]{1,6}",
            verb in prop_oneof![Just("allow"), Just("ask"), Just("deny")],
            with_reason in any::<bool>(),
        ) {
            let body = if with_reason {
                format!(r#"({verb} "because")"#)
            } else {
                format!("({verb})")
            };
            let src = format!(r#"(rule "{cmd}" {body})"#);
            let (forms, errs) = parse_cst(&src);
            prop_assert!(errs.is_empty());
            let canon1 = render(&canonicalise_forms(forms));
            // The decision verb head and shape must appear unchanged in
            // the rendered output.
            prop_assert!(canon1.contains(&format!("({verb}")), "verb head missing: {}", canon1);
            // Round-trip stability.
            let (forms2, errs2) = parse_cst(&canon1);
            prop_assert!(errs2.is_empty());
            let canon2 = render(&canonicalise_forms(forms2));
            prop_assert_eq!(canon1, canon2);
        }

        #[test]
        fn canonicalise_is_idempotent_on_parser(src in parser_body_strategy()) {
            let (forms, errs) = parse_cst(&src);
            prop_assert!(errs.is_empty(), "parse errors: {:?}", errs);
            let pass1 = render(&canonicalise_forms(forms));
            let (forms2, _) = parse_cst(&pass1);
            let pass2 = render(&canonicalise_forms(forms2));
            prop_assert_eq!(pass1, pass2);
        }

        #[test]
        fn canonicalise_is_idempotent_on_check(src in check_body_strategy()) {
            let (forms, errs) = parse_cst(&src);
            prop_assert!(errs.is_empty(), "parse errors: {:?}", errs);
            let pass1 = render(&canonicalise_forms(forms));
            let (forms2, _) = parse_cst(&pass1);
            let pass2 = render(&canonicalise_forms(forms2));
            prop_assert_eq!(pass1, pass2);
        }

        // Permuting body declarations must not change canonical form.
        #[test]
        fn parser_permutations_render_identically(
            mut flags in prop::collection::vec("[a-z]{1,5}", 1..5),
            mut params in prop::collection::vec("[a-z]{1,5}", 1..5),
            seed in any::<u64>(),
        ) {
            // Deterministic shuffle from the seed.
            let mut rng = seed;
            fn shuffle<T>(v: &mut [T], rng: &mut u64) {
                for i in (1..v.len()).rev() {
                    *rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let j = (*rng as usize) % (i + 1);
                    v.swap(i, j);
                }
            }
            let original_flags = flags.clone();
            let original_params = params.clone();
            shuffle(&mut flags, &mut rng);
            shuffle(&mut params, &mut rng);

            let make = |fs: &[String], ps: &[String]| -> String {
                let f = fs.iter().map(|n| format!(r#"(flag "{n}")"#)).collect::<Vec<_>>().join(" ");
                let p = ps.iter().map(|n| format!(r#"(parameter "{n}")"#)).collect::<Vec<_>>().join(" ");
                format!(r#"(parser "p" (style gnu) {f} {p})"#)
            };
            let a = make(&original_flags, &original_params);
            let b = make(&flags, &params);
            let (fa, _) = parse_cst(&a);
            let (fb, _) = parse_cst(&b);
            prop_assert_eq!(render(&canonicalise_forms(fa)), render(&canonicalise_forms(fb)));
        }
    }

    // ── Trivia attachment under sort ─────────────────────────────────

    #[test]
    fn comment_between_forms_travels_with_next_form_on_sort() {
        let src = "(parser \"x\" (style gnu)\n  (flag \"z\")\n  ;; about a\n  (flag \"a\"))";
        let (forms, errs) = parse_cst(src);
        assert!(errs.is_empty(), "{errs:?}");
        let canon = canonicalise_forms(forms);
        let out = render(&canon);
        // The comment is attached as leading trivia on (flag "a"). After
        // sort, (flag "a") moves before (flag "z"), and the comment goes
        // with it.
        let pos_comment = out.find(";; about a").expect(&out);
        let pos_a = out.find(r#"(flag "a")"#).expect(&out);
        let pos_z = out.find(r#"(flag "z")"#).expect(&out);
        assert!(
            pos_comment < pos_a,
            "comment should precede (flag \"a\"): {out}"
        );
        assert!(
            pos_a < pos_z,
            "(flag \"a\") should precede (flag \"z\"): {out}"
        );
    }

    #[test]
    fn trailing_comment_on_last_child_moves_with_child() {
        // When a comment is attached as trailing trivia of the last child,
        // sort moves the child elsewhere and the comment rides along.
        let src = "(parser \"x\" (style gnu)\n  (flag \"z\")\n  (flag \"a\") ;; trailing-a\n)";
        let (forms, errs) = parse_cst(src);
        assert!(errs.is_empty(), "{errs:?}");
        let canon = canonicalise_forms(forms);
        let out = render(&canon);
        let pos_a = out.find(r#"(flag "a")"#).expect(&out);
        let pos_comment = out.find(";; trailing-a").expect(&out);
        let pos_z = out.find(r#"(flag "z")"#).expect(&out);
        assert!(
            pos_a < pos_comment,
            "(flag \"a\") should precede its trailing comment: {out}"
        );
        assert!(
            pos_comment < pos_z,
            "comment should remain attached to (flag \"a\") and precede (flag \"z\"): {out}"
        );
    }

    #[test]
    fn section_header_comment_travels_with_following_form() {
        // Documents the spec: a section-header comment migrates with whichever
        // form follows it. Here the comment sits before (parameter "C") and
        // (parameter "C") sorts after (flag "v"). Comment goes with the param.
        let src =
            "(parser \"x\" (style gnu)\n  (flag \"v\")\n  ;; --- params ---\n  (parameter \"C\"))";
        let (forms, errs) = parse_cst(src);
        assert!(errs.is_empty(), "{errs:?}");
        let canon = canonicalise_forms(forms);
        let out = render(&canon);
        let pos_v = out.find(r#"(flag "v")"#).expect(&out);
        let pos_comment = out.find(";; --- params ---").expect(&out);
        let pos_param = out.find(r#"(parameter "C")"#).expect(&out);
        assert!(pos_v < pos_comment, "flag block before comment: {out}");
        assert!(
            pos_comment < pos_param,
            "comment travels with (parameter \"C\"): {out}"
        );
    }

    // ── Coverage for degenerate inputs ───────────────────────────────

    #[test]
    fn parser_with_only_head_left_alone() {
        // Degenerate parser (no program, no body) bypasses the sort fast
        // path. The canonicaliser must not panic.
        let src = "(parser)";
        let (forms, _) = parse_cst(src);
        let canon = canonicalise_forms(forms);
        assert_eq!(canon[0].serialize(), "(parser)");
    }

    #[test]
    fn define_arg_style_without_attributes_left_alone() {
        let src = "(define-arg-style mystyle)";
        let (forms, _) = parse_cst(src);
        let canon = canonicalise_forms(forms);
        assert_eq!(canon[0].serialize(), "(define-arg-style mystyle)");
    }

    #[test]
    fn unknown_parser_body_form_kept_in_source_order_at_tail() {
        // An unrecognised parser body item falls into the `Other` bucket and
        // sorts after `(tail …)`. Two such items keep source order.
        let src = r#"(parser "x" (style gnu) (custom1) (custom2))"#;
        let (forms, _) = parse_cst(src);
        let canon = canonicalise_forms(forms);
        let out = render_flat(&canon);
        let p1 = out.find("(custom1)").expect(&out);
        let p2 = out.find("(custom2)").expect(&out);
        assert!(p1 < p2, "source order preserved among Other items: {out}");
    }

    #[test]
    fn vector_with_non_string_items_left_alone() {
        // Mixed-type vectors are not sortable as set-vectors.
        let src = r#"(flag [a "b"])"#;
        let (forms, _) = parse_cst(src);
        let canon = canonicalise_forms(forms);
        // Original order preserved because the vector contains a non-string.
        let out = canon[0].serialize();
        assert!(
            out.contains(r#"[a "b"]"#),
            "non-string vec preserved: {out}"
        );
    }

    #[test]
    fn flag_form_without_name_yields_empty_sort_key() {
        // (flag) — degenerate. Sort key is the empty string. Sorts first
        // among flags. Coverage path for `children.get(1) == None`.
        let src = r#"(parser "x" (style gnu) (flag "z") (flag))"#;
        let (forms, _) = parse_cst(src);
        let canon = canonicalise_forms(forms);
        let out = render_flat(&canon);
        let p_empty = out.find("(flag)").expect(&out);
        let p_z = out.find(r#"(flag "z")"#).expect(&out);
        assert!(p_empty < p_z, "empty-name flag sorts first: {out}");
    }

    #[test]
    fn flag_with_atom_name_yields_empty_sort_key() {
        // (flag SYMBOL) — name slot is an atom rather than string or
        // vector. Sort key falls through to empty. Coverage path for the
        // `_ => String::new()` arm in `flag_or_parameter_sort_key`.
        let src = r#"(parser "x" (style gnu) (flag "z") (flag bare))"#;
        let (forms, _) = parse_cst(src);
        let canon = canonicalise_forms(forms);
        let out = render_flat(&canon);
        // Empty key sorts first, so the bare-atom flag precedes "z".
        let p_bare = out.find("(flag bare)").expect(&out);
        let p_z = out.find(r#"(flag "z")"#).expect(&out);
        assert!(p_bare < p_z, "bare-name flag sorts before string: {out}");
    }

    #[test]
    fn idempotent_on_canonical_input() {
        let src = r#"(parser "git" (parameter "C") (flag "v") (style gnu))"#;
        let (forms, errs) = parse_cst(src);
        assert!(errs.is_empty());
        let pass1 = canonicalise_forms(forms);
        let pass1_text = render(&pass1);
        let (forms2, _) = parse_cst(&pass1_text);
        let pass2 = canonicalise_forms(forms2);
        let pass2_text = render(&pass2);
        assert_eq!(pass1_text, pass2_text);
    }
}
