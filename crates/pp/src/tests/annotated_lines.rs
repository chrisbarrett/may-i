use crate::*;
use proptest::prelude::*;

fn arb_doc() -> impl Strategy<Value = Doc> {
    let leaf = "[a-z_]{1,12}".prop_map(|s| Doc::atom(s));
    leaf.prop_recursive(4, 20, 5, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(Doc::list),
            (
                "[a-z]{1,8}".prop_map(|s| Doc::atom(s)),
                prop::collection::vec(inner, 0..4),
            )
                .prop_map(|(head, mut children)| {
                    children.insert(0, head);
                    Doc::list(children)
                }),
        ]
    })
}

/// Reconstruct text from AnnotatedLine vec (joining with newlines).
fn lines_to_text(lines: &[AnnotatedLine<()>]) -> String {
    let mut result = String::new();
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            result.push('\n');
        }
        result.push_str(&line.text);
    }
    result
}

proptest! {
    #[test]
    fn annotated_line_text_matches_string_builder(doc in arb_doc(), width in 10..120usize) {
        let mut sb = StringBuilder::new(false);
        pretty_into(&doc, 0, width, &mut sb);
        let sb_text = sb.into_string();

        let mut alb = AnnotatedLineBuilder::new();
        pretty_into(&doc, 0, width, &mut alb);
        let lines = alb.into_lines();
        let alb_text = lines_to_text(&lines);

        prop_assert_eq!(sb_text, alb_text,
            "AnnotatedLineBuilder text should match StringBuilder");
    }

    #[test]
    fn visible_len_ignores_ansi_escapes(s in "[a-zA-Z0-9 ()]{0,30}", codes in prop::collection::vec("\\x1b\\[[0-9;]{1,5}m", 0..5)) {
        // Build a string with ANSI SGR sequences interleaved
        let plain_len = s.chars().count();
        let mut decorated = String::new();
        for (i, ch) in s.chars().enumerate() {
            if let Some(code) = codes.get(i % codes.len().max(1)) {
                decorated.push_str(code);
            }
            decorated.push(ch);
        }
        let vis = visible_len(&decorated);
        prop_assert_eq!(vis, plain_len);
        // Also: visible_len of plain string equals char count
        prop_assert_eq!(visible_len(&s), plain_len);
    }

    #[test]
    fn annotated_line_visible_width_correct(doc in arb_doc(), width in 10..120usize) {
        let mut alb = AnnotatedLineBuilder::new();
        pretty_into(&doc, 0, width, &mut alb);
        let lines = alb.into_lines();

        for line in &lines {
            let actual_width = line.text.trim_start().chars().count()
                + line.text.len() - line.text.trim_start().len();
            prop_assert_eq!(line.visible_width, actual_width,
                "visible_width should match actual char count for line: {:?}", line.text);
        }
    }
}

// ── Unit tests: annotation association ───────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum TestAnn {
    A,
    B,
    C,
}

impl TriviaSource for TestAnn {
    fn forced_break(&self) -> bool {
        false
    }
    fn leading_trivia(&self) -> &[Trivia] {
        &[]
    }
    fn trailing_trivia(&self) -> &[Trivia] {
        &[]
    }
}

fn atom_with(s: &str, ann: TestAnn) -> Doc<TestAnn> {
    Doc {
        ann,
        node: DocF::Atom(s.into()),
        layout: LayoutHint::Auto,
        dimmed: false,
    }
}

fn list_of(children: Vec<Doc<TestAnn>>) -> Doc<TestAnn> {
    Doc {
        ann: TestAnn::A,
        node: DocF::List(children),
        layout: LayoutHint::Auto,
        dimmed: false,
    }
}

#[test]
fn single_atom_carries_annotation() {
    let doc = atom_with("hello", TestAnn::B);
    let mut alb = AnnotatedLineBuilder::new();
    pretty_into(&doc, 0, 80, &mut alb);
    let lines = alb.into_lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].text, "hello");
    assert_eq!(lines[0].annotations, vec![TestAnn::B]);
}

#[test]
fn flat_layout_aggregates_annotations() {
    // (a b) on a wide line → single AnnotatedLine with both annotations
    let doc = list_of(vec![atom_with("a", TestAnn::A), atom_with("b", TestAnn::B)]);
    let mut alb = AnnotatedLineBuilder::new();
    pretty_into(&doc, 0, 80, &mut alb);
    let lines = alb.into_lines();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].annotations.contains(&TestAnn::A));
    assert!(lines[0].annotations.contains(&TestAnn::B));
}

#[test]
fn broken_layout_separates_annotations() {
    // Force broken layout with a very narrow width
    let doc = list_of(vec![
        atom_with("alpha", TestAnn::A),
        atom_with("beta", TestAnn::B),
        atom_with("gamma", TestAnn::C),
    ]);
    let mut alb = AnnotatedLineBuilder::new();
    // Width 1 forces all-drop layout
    pretty_into(&doc, 0, 1, &mut alb);
    let lines = alb.into_lines();
    // Should have multiple lines, each with its own annotation
    assert!(
        lines.len() >= 2,
        "expected broken layout, got {} lines",
        lines.len()
    );

    // First line has "alpha" (and the list open paren), last items on separate lines
    let all_anns: Vec<_> = lines.iter().flat_map(|l| l.annotations.iter()).collect();
    assert!(all_anns.contains(&&TestAnn::A));
    assert!(all_anns.contains(&&TestAnn::B));
    assert!(all_anns.contains(&&TestAnn::C));

    // Check that annotations are distributed across lines, not all on one
    let lines_with_anns: Vec<_> = lines.iter().filter(|l| !l.annotations.is_empty()).collect();
    assert!(
        lines_with_anns.len() >= 2,
        "expected annotations on multiple lines"
    );
}

#[test]
fn fully_dimmed_doc_suppresses_atom_annotations() {
    let doc = Doc {
        ann: TestAnn::A,
        node: DocF::List(vec![
            atom_with("head", TestAnn::B),
            atom_with("body", TestAnn::C),
        ]),
        layout: LayoutHint::Auto,
        dimmed: true,
    };
    let mut alb = AnnotatedLineBuilder::new();
    pretty_into(&doc, 0, 80, &mut alb);
    let lines = alb.into_lines();
    let all_anns: Vec<_> = lines.iter().flat_map(|l| &l.annotations).collect();
    // Node-level annotation (TestAnn::A on the list) IS emitted even when dimmed,
    // but atom annotations (TestAnn::B, TestAnn::C) are suppressed.
    assert!(
        all_anns.contains(&&TestAnn::A),
        "list node annotation should be emitted even when dimmed"
    );
    assert!(
        !all_anns.contains(&&TestAnn::B),
        "dimmed atom annotation B should be suppressed"
    );
    assert!(
        !all_anns.contains(&&TestAnn::C),
        "dimmed atom annotation C should be suppressed"
    );
}

#[test]
fn mixed_dimmed_only_collects_non_dimmed_atom_annotations() {
    // List with one normal child and one dimmed child
    let normal = atom_with("visible", TestAnn::A);
    let dimmed_child = Doc {
        ann: TestAnn::B,
        node: DocF::Atom("hidden".into()),
        layout: LayoutHint::Auto,
        dimmed: true,
    };
    let doc = Doc {
        ann: TestAnn::C,
        node: DocF::List(vec![normal, dimmed_child]),
        layout: LayoutHint::Auto,
        dimmed: false,
    };
    let mut alb = AnnotatedLineBuilder::new();
    pretty_into(&doc, 0, 80, &mut alb);
    let lines = alb.into_lines();
    let all_anns: Vec<_> = lines.iter().flat_map(|l| &l.annotations).collect();
    // Should have TestAnn::C (list node_ann) and TestAnn::A (normal atom)
    // but NOT TestAnn::B (dimmed atom)
    assert!(
        all_anns.contains(&&TestAnn::A),
        "should contain non-dimmed atom annotation"
    );
    assert!(
        all_anns.contains(&&TestAnn::C),
        "should contain non-dimmed list node annotation"
    );
    assert!(
        !all_anns.contains(&&TestAnn::B),
        "should NOT contain dimmed atom annotation"
    );
}
