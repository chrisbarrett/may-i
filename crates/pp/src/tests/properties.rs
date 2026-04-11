use crate::*;
use proptest::prelude::*;

/// Generate an arbitrary Doc tree (atoms and nested lists).
fn arb_doc() -> impl Strategy<Value = Doc> {
    let leaf = "[a-z_]{1,12}".prop_map(Doc::atom);
    leaf.prop_recursive(4, 20, 5, |inner| {
        prop_oneof![
            // Plain list.
            prop::collection::vec(inner.clone(), 0..5).prop_map(Doc::list),
            // List with a head atom (common in s-expressions).
            (
                "[a-z]{1,8}".prop_map(Doc::atom),
                prop::collection::vec(inner, 0..4),
            )
                .prop_map(|(head, mut children)| {
                    children.insert(0, head);
                    Doc::list(children)
                }),
        ]
    })
}

/// Count open and close parens in visible text.
fn count_parens(s: &str) -> (usize, usize) {
    let mut in_escape = false;
    let (mut open, mut close) = (0, 0);
    for ch in s.chars() {
        if in_escape {
            if ch.is_ascii_alphabetic() {
                in_escape = false;
            }
        } else if ch == '\x1b' {
            in_escape = true;
        } else if ch == '(' {
            open += 1;
        } else if ch == ')' {
            close += 1;
        }
    }
    (open, close)
}

proptest! {
    // ── Balanced parentheses ─────────────────────────────────────

    #[test]
    fn balanced_parens(doc in arb_doc(), width in 10..120usize) {
        let result = pretty(&doc, 0, &Format { width, ..Default::default() });
        let (open, close) = count_parens(&result);
        prop_assert_eq!(open, close,
            "unbalanced parens in: {:?}", result);
    }

    #[test]
    fn balanced_parens_with_color(doc in arb_doc(), width in 10..120usize) {
        force_color();
        let result = pretty(&doc, 0, &Format { width, color: true, ..Default::default() });
        let (open, close) = count_parens(&result);
        prop_assert_eq!(open, close,
            "unbalanced parens (colored) in: {:?}", result);
    }

    // ── Width constraints ────────────────────────────────────────

    #[test]
    fn no_line_exceeds_width_by_much(doc in arb_doc(), width in 20..120usize) {
        let result = pretty(&doc, 0, &Format { width, ..Default::default() });
        // Lines may exceed width for long atoms, but the overflow
        // should be bounded by the longest atom in the tree.
        let max_atom_len = doc.fold(&|node, _ann: &()| -> usize {
            match node {
                DocF::Atom(s) => s.len(),
                DocF::List(cs) | DocF::Vector(cs) => cs.into_iter().max().unwrap_or(0),
            }
        });
        let slack = max_atom_len + 10; // parens + spaces
        for line in result.lines() {
            let vis = visible_len(line);
            prop_assert!(vis <= width + slack,
                "line too wide ({vis} vs width {width} + slack {slack}): {line:?}");
        }
    }

    // ── Color transparency ───────────────────────────────────────

    #[test]
    fn color_preserves_visible_text(doc in arb_doc(), width in 10..120usize) {
        let plain = pretty(&doc, 0, &Format { width, ..Default::default() });

        force_color();
        let colored_output = pretty(&doc, 0, &Format { width, color: true, ..Default::default() });

        // Strip ANSI codes from colored output and compare.
        let stripped = strip_ansi(&colored_output);
        prop_assert_eq!(plain, stripped,
            "color changed visible text");
    }

    // ── Atom roundtrip ───────────────────────────────────────────

    #[test]
    fn atom_renders_as_itself(s in "[a-z_]{1,20}") {
        let doc = Doc::atom(&s);
        let result = pretty(&doc, 0, &Format::default());
        prop_assert_eq!(result, s);
    }
}

fn strip_ansi(s: &str) -> String {
    crate::strip_ansi(s)
}

// ── Pretty-print idempotency (task 10.1) ─────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

    #[test]
    fn pretty_print_is_idempotent(doc in arb_doc(), width in 20..120usize) {
        let fmt = Format { width, ..Default::default() };
        let output1 = pretty(&doc, 0, &fmt);
        let reparsed = parse_sexpr(&output1);
        let output2 = pretty(&reparsed, 0, &fmt);
        prop_assert_eq!(output1, output2,
            "pretty-print not idempotent at width {}", width);
    }

    // ── Pretty-print width monotonicity (task 10.2) ──────────────

    #[test]
    fn narrower_width_produces_at_least_as_many_lines(
        doc in arb_doc(),
        w1 in 20..60usize,
        w2 in 60..120usize,
    ) {
        let fmt_narrow = Format { width: w1, ..Default::default() };
        let fmt_wide = Format { width: w2, ..Default::default() };
        let narrow = pretty(&doc, 0, &fmt_narrow);
        let wide = pretty(&doc, 0, &fmt_wide);
        prop_assert!(narrow.lines().count() >= wide.lines().count(),
            "narrow ({}) has fewer lines than wide ({}):\nnarrow:\n{}\nwide:\n{}", w1, w2, narrow, wide);
    }
}
