use crate::*;
use may_i_core::{Trivia as CoreTrivia, TriviaAnn};

fn trivia_ann(leading: Vec<CoreTrivia>, trailing: Vec<CoreTrivia>) -> Option<TriviaAnn> {
    Some(TriviaAnn {
        leading,
        trailing,
        span: may_i_core::Span::new(1, 2), // non-zero = source-parsed
    })
}

fn trivia_atom(s: &str, ann: Option<TriviaAnn>) -> Doc<Option<TriviaAnn>> {
    Doc {
        ann,
        node: DocF::Atom(s.into()),
        layout: LayoutHint::Auto,
        dimmed: false,
    }
}

fn trivia_list(
    children: Vec<Doc<Option<TriviaAnn>>>,
    ann: Option<TriviaAnn>,
) -> Doc<Option<TriviaAnn>> {
    Doc {
        ann,
        node: DocF::List(children),
        layout: LayoutHint::Auto,
        dimmed: false,
    }
}

fn pp_trivia(doc: &Doc<Option<TriviaAnn>>, width: usize) -> String {
    pretty(
        doc,
        0,
        &Format {
            width,
            ..Default::default()
        },
    )
}

#[test]
fn trivia_forced_break_prevents_flat() {
    // A child with newline in trivia forces multi-line layout
    let child_with_newline = trivia_atom(
        "b",
        trivia_ann(vec![CoreTrivia::Whitespace("\n  ".to_string())], vec![]),
    );
    let doc = trivia_list(vec![trivia_atom("a", None), child_with_newline], None);
    let result = pp_trivia(&doc, 80);
    assert!(
        result.contains('\n'),
        "should break to multi-line: {result:?}"
    );
}

#[test]
fn trivia_no_forced_break_stays_flat() {
    // Children without trivia stay flat when they fit
    let doc = trivia_list(vec![trivia_atom("a", None), trivia_atom("b", None)], None);
    let result = pp_trivia(&doc, 80);
    assert_eq!(result, "(a b)");
}

#[test]
fn trivia_comment_emitted_before_child() {
    let child_with_comment = trivia_atom(
        "b",
        trivia_ann(
            vec![CoreTrivia::Comment {
                text: "; a comment".to_string(),
                has_newline: true,
            }],
            vec![],
        ),
    );
    let doc = trivia_list(vec![trivia_atom("a", None), child_with_comment], None);
    let result = pp_trivia(&doc, 80);
    assert!(
        result.contains("; a comment"),
        "comment should be present: {result:?}"
    );
    // The comment should appear before "b"
    let comment_pos = result.find("; a comment").unwrap();
    let b_pos = result.find('b').unwrap();
    assert!(
        comment_pos < b_pos,
        "comment should appear before b: {result:?}"
    );
}

#[test]
fn trivia_trailing_comment_emitted_after_node() {
    let child_with_trailing = trivia_atom(
        "a",
        trivia_ann(
            vec![],
            vec![
                CoreTrivia::Whitespace(" ".to_string()),
                CoreTrivia::Comment {
                    text: "; trailing".to_string(),
                    has_newline: true,
                },
            ],
        ),
    );
    let doc = trivia_list(vec![child_with_trailing, trivia_atom("b", None)], None);
    let result = pp_trivia(&doc, 80);
    assert!(
        result.contains("; trailing"),
        "trailing comment should be present: {result:?}"
    );
}

#[test]
fn trivia_blank_line_between_leading_comment_groups() {
    // A blank line between comment groups in leading trivia should be preserved
    let doc = trivia_atom(
        "foo",
        trivia_ann(
            vec![
                CoreTrivia::Comment {
                    text: ";; group A".to_string(),
                    has_newline: true,
                },
                CoreTrivia::Whitespace("\n".to_string()),
                CoreTrivia::Comment {
                    text: ";; group B".to_string(),
                    has_newline: true,
                },
                CoreTrivia::Whitespace("\n".to_string()),
            ],
            vec![],
        ),
    );
    let result = pp_trivia(&doc, 80);
    assert!(
        result.contains(";; group A\n\n;; group B"),
        "blank line between comment groups should be preserved: {result:?}"
    );
}

#[test]
fn trivia_cascade_after_forced_break() {
    // After a forced break, subsequent children should also break
    let child_with_break = trivia_atom(
        "b",
        trivia_ann(vec![CoreTrivia::Whitespace("\n  ".to_string())], vec![]),
    );
    let doc = trivia_list(
        vec![
            trivia_atom("a", None),
            child_with_break,
            trivia_atom("c", None),
        ],
        None,
    );
    let result = pp_trivia(&doc, 80);
    // All children after the forced break should be on separate lines
    let lines: Vec<&str> = result.lines().collect();
    assert!(
        lines.len() >= 3,
        "should have at least 3 lines (a, b, c): {result:?}"
    );
}

// ── Blank line preservation tests ─────────────────────────────────

#[test]
fn blank_line_single_preserved_between_forms() {
    // Single blank line between forms should be preserved
    // In a simple list (a b) with width 80, the cascade is 1 (under head)
    // Blank lines should NOT have trailing whitespace
    let child_with_blank = trivia_atom(
        "b",
        trivia_ann(
            vec![CoreTrivia::Whitespace("\n\n ".to_string())], // two newlines = one blank line
            vec![],
        ),
    );
    let doc = trivia_list(vec![trivia_atom("a", None), child_with_blank], None);
    let result = pp_trivia(&doc, 80);
    // Should have blank line between a and b, blank lines have no indentation
    assert_eq!(result, "(a\n\n b)");
}

#[test]
fn blank_line_multiple_preserved_between_forms() {
    // Multiple blank lines between forms should be preserved
    let child_with_blanks = trivia_atom(
        "b",
        trivia_ann(
            vec![CoreTrivia::Whitespace("\n\n\n\n ".to_string())], // four newlines = three blank lines
            vec![],
        ),
    );
    let doc = trivia_list(vec![trivia_atom("a", None), child_with_blanks], None);
    let result = pp_trivia(&doc, 80);
    // Should have three blank lines between a and b, blank lines have no indentation
    assert_eq!(result, "(a\n\n\n\n b)");
}

#[test]
fn blank_line_no_extra_single_newline() {
    // Single newline should not produce blank lines
    let child_single_newline = trivia_atom(
        "b",
        trivia_ann(
            vec![CoreTrivia::Whitespace("\n ".to_string())], // one newline = no blank line
            vec![],
        ),
    );
    let doc = trivia_list(vec![trivia_atom("a", None), child_single_newline], None);
    let result = pp_trivia(&doc, 80);
    // Should have single newline, no blank line, with cascade indent of 1
    assert_eq!(result, "(a\n b)");
}

#[test]
fn blank_line_preserved_in_check_form_between_cases() {
    // Blank lines between test cases in a check form should be preserved
    // check has indent spec 0, so body is at indent+2
    let case1 = trivia_list(
        vec![trivia_atom("command", None), trivia_atom("\"test1\"", None)],
        None,
    );
    let case2 = trivia_list(
        vec![trivia_atom("command", None), trivia_atom("\"test2\"", None)],
        trivia_ann(
            vec![CoreTrivia::Whitespace("\n\n  ".to_string())], // blank line before case2
            vec![],
        ),
    );
    let case3 = trivia_list(
        vec![trivia_atom("command", None), trivia_atom("\"test3\"", None)],
        trivia_ann(
            vec![CoreTrivia::Whitespace("\n\n  ".to_string())], // blank line before case3
            vec![],
        ),
    );
    let doc = trivia_list(vec![trivia_atom("check", None), case1, case2, case3], None);
    let result = pp_trivia(&doc, 80);
    // Check form with indent spec 0 means body is at indent+2 = 2 spaces
    // The blank lines should be preserved with proper indentation
    assert!(
        result.contains("check"),
        "result should contain 'check': {result:?}"
    );
    assert!(
        result.contains("test1"),
        "result should contain 'test1': {result:?}"
    );
    assert!(
        result.contains("test2"),
        "result should contain 'test2': {result:?}"
    );
    assert!(
        result.contains("test3"),
        "result should contain 'test3': {result:?}"
    );
    // Verify blank line preservation - check for double newlines in output
    let newline_count = result.matches('\n').count();
    assert!(
        newline_count >= 4,
        "should have at least 4 newlines (one between each test case + form breaks): {result:?}"
    );
}

#[test]
fn blank_line_preserved_at_top_level() {
    // Blank lines at top level should be preserved (without trailing whitespace)
    let form2 = trivia_list(
        vec![trivia_atom("rule2", None)],
        trivia_ann(
            vec![CoreTrivia::Whitespace("\n\n".to_string())], // blank line before
            vec![],
        ),
    );
    let doc = trivia_list(
        vec![trivia_list(vec![trivia_atom("rule1", None)], None), form2],
        None,
    );
    let result = pp_trivia(&doc, 80);
    // Both forms should be present with blank line between (no trailing whitespace on blank line)
    assert!(
        result.contains("(rule1)"),
        "result should contain '(rule1)': {result:?}"
    );
    assert!(
        result.contains("(rule2)"),
        "result should contain '(rule2)': {result:?}"
    );
    // Check for blank line between without trailing whitespace
    assert!(
        result.contains("(rule1)\n\n (rule2)"),
        "blank line should be preserved between top-level forms: {result:?}"
    );
}

