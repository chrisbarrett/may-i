use crate::*;

fn a(s: &str) -> Doc {
    Doc::atom(s)
}

fn l(children: Vec<Doc>) -> Doc {
    Doc::list(children)
}

fn v(children: Vec<Doc>) -> Doc {
    Doc::vector(children)
}

fn pp(doc: &Doc, width: usize) -> String {
    pretty(
        doc,
        0,
        &Format {
            width,
            ..Default::default()
        },
    )
}

fn pp_color(doc: &Doc, width: usize) -> String {
    pretty(
        doc,
        0,
        &Format {
            width,
            color: true,
            ..Default::default()
        },
    )
}

// ── Flat rendering ──────────────────────────────────────────────

#[test]
fn flat_empty_list() {
    assert_eq!(pp(&l(vec![]), 80), "()");
}

#[test]
fn flat_simple_list() {
    assert_eq!(
        pp(&l(vec![a("command"), a("\"rm\"")]), 80),
        "(command \"rm\")"
    );
}

#[test]
fn flat_vector() {
    assert_eq!(pp(&v(vec![a(":via/ssh")]), 80), "[:via/ssh]");
}

#[test]
fn empty_vector() {
    assert_eq!(pp(&v(vec![]), 80), "[]");
}

#[test]
fn vector_wraps_when_long() {
    let doc = v(vec![a(":ssh/host"), l(vec![a("regex"), a("\"^prod-\"")])]);
    let rendered = pp(&doc, 18);
    assert!(rendered.starts_with("[:ssh/host"));
    assert!(rendered.contains("(regex \"^prod-\")"));
    assert!(rendered.ends_with(']'));
}

#[test]
fn flat_nested() {
    let doc = l(vec![a("rule"), l(vec![a("command"), a("\"rm\"")])]);
    assert_eq!(pp(&doc, 80), "(rule (command \"rm\"))");
}

// ── Wrapping ────────────────────────────────────────────────────

#[test]
fn wraps_when_exceeds_width() {
    let doc = l(vec![a("rule"), a("aaa"), a("bbb"), a("ccc")]);
    let result = pp(&doc, 15);
    assert_eq!(result, "(rule aaa\n  bbb\n  ccc)");
}

#[test]
fn wraps_nested_lists() {
    let doc = l(vec![
        a("args"),
        l(vec![a("and"), a("xxxxxxxxxxxx"), a("yyyyyyyyyyyy")]),
    ]);
    let result = pp(&doc, 25);
    assert!(result.contains('\n'));
}

#[test]
fn stays_flat_when_fits() {
    let doc = l(vec![a("command"), a("\"ls\"")]);
    let result = pp(&doc, 80);
    assert!(!result.contains('\n'));
}

#[test]
fn single_child_wraps() {
    let doc = l(vec![a("a-very-long-form-name")]);
    let result = pp(&doc, 10);
    assert_eq!(result, "(a-very-long-form-name)");
}

// ── Coloring ────────────────────────────────────────────────────

fn with_forced_color(f: impl FnOnce()) {
    force_color();
    f();
}

#[test]
fn keywords_get_colored() {
    with_forced_color(|| {
        let result = pp_color(&a(":deny"), 80);
        assert!(
            result.contains("\x1b["),
            "expected ANSI codes in: {result:?}"
        );
        assert!(result.contains("deny"));
    });
}

#[test]
fn strings_get_colored() {
    with_forced_color(|| {
        let result = pp_color(&a("\"rm\""), 80);
        assert!(
            result.contains("\x1b["),
            "expected ANSI codes in: {result:?}"
        );
        assert!(result.contains("rm"));
    });
}

#[test]
fn special_forms_get_colored() {
    with_forced_color(|| {
        let result = pp_color(&a("command"), 80);
        assert!(
            result.contains("\x1b["),
            "expected ANSI codes in: {result:?}"
        );
    });
}

#[test]
fn plain_atoms_not_colored() {
    with_forced_color(|| {
        let result = pp_color(&a("foo"), 80);
        assert!(
            !result.contains("\x1b["),
            "unexpected ANSI codes in: {result:?}"
        );
    });
}

#[test]
fn parens_dimmed_in_color_mode() {
    with_forced_color(|| {
        let result = pp_color(&l(vec![a("x")]), 80);
        assert!(
            result.contains("\x1b["),
            "expected ANSI codes in: {result:?}"
        );
    });
}

// ── from_sexpr ──────────────────────────────────────────────────

#[test]
fn from_sexpr_atom_bare() {
    let sexpr = may_i_sexpr::Sexpr::Symbol("hello".into(), may_i_core::Span::new(0, 0));
    let doc = doc_from_sexpr(&sexpr);
    assert_eq!(pp(&doc, 80), "hello");
}

#[test]
fn from_sexpr_string_is_quoted() {
    let sexpr = may_i_sexpr::Sexpr::String("hello world".into(), may_i_core::Span::new(0, 0));
    let doc = doc_from_sexpr(&sexpr);
    assert_eq!(pp(&doc, 80), "\"hello world\"");
}

#[test]
fn from_sexpr_list() {
    let sexpr = may_i_sexpr::Sexpr::List(
        vec![
            may_i_sexpr::Sexpr::Symbol("rule".into(), may_i_core::Span::new(0, 0)),
            may_i_sexpr::Sexpr::Symbol("foo".into(), may_i_core::Span::new(0, 0)),
        ],
        may_i_core::Span::new(0, 0),
    );
    let doc = doc_from_sexpr(&sexpr);
    assert_eq!(pp(&doc, 80), "(rule foo)");
}

// ── visible_len ─────────────────────────────────────────────────

#[test]
fn visible_len_plain() {
    assert_eq!(visible_len("hello"), 5);
}

#[test]
fn visible_len_with_ansi() {
    let s = "hello".green().to_string();
    assert_eq!(visible_len(&s), 5);
}

// ── Default layout heuristic (non-indent-spec forms) ──────────
//
// Forms not in INDENT_SPECS use a default layout with four tiers:
//   1. Flat:      (foo x y z w)
//   2. Broken:    (foo x
//                      y
//                      z)
//   3. Partial:   (foo x y
//                        z
//                        w)
//   4. All-drop:  (foo
//                  x
//                  y
//                  z)

#[test]
fn default_layout_flat() {
    // All args fit on one line.
    let doc = l(vec![a("foo"), a("x"), a("y"), a("z"), a("w")]);
    assert_eq!(pp(&doc, 80), "(foo x y z w)");
}

#[test]
fn default_layout_broken_one_inline() {
    // Width 8: greedy packs x,y on head line (cascade 5, under first arg).
    // Continuation "     z\n     w)" max 6 ≤ 8.
    let doc = l(vec![a("foo"), a("x"), a("y"), a("z"), a("w")]);
    assert_eq!(pp(&doc, 8), "(foo x y\n     z\n     w)");
}

#[test]
fn default_layout_broken_greedy() {
    // Two args fit on first line with continuation under first arg.
    // Width 12: x,y inline (cascade 5), cont "     wwww)" = 10 <= 12.
    let doc = l(vec![a("foo"), a("x"), a("y"), a("zzzz"), a("wwww")]);
    assert_eq!(pp(&doc, 12), "(foo x y\n     zzzz\n     wwww)");
}

#[test]
fn default_layout_all_drop() {
    // Even one inline arg's continuation exceeds width.
    // Width 5: conservative "(foo x\n     w)" max 7 > 5. All-drop.
    let doc = l(vec![a("foo"), a("x"), a("y"), a("z"), a("w")]);
    assert_eq!(pp(&doc, 5), "(foo\n x\n y\n z\n w)");
}

#[test]
fn default_layout_long_head_forces_drop() {
    // Head so long that even 1 inline arg's cascade (col 10)
    // makes continuation "          c)" = 12 > 11. All-drop.
    let doc = l(vec![a("longname"), a("a"), a("b"), a("c")]);
    assert_eq!(pp(&doc, 11), "(longname\n a\n b\n c)");
}

#[test]
fn alignment_under_first_arg() {
    let doc = l(vec![a("and"), a("first-branch"), a("second-branch")]);
    let result = pp(&doc, 20);
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], "(and first-branch");
    assert_eq!(lines[1], "     second-branch)");
}

#[test]
fn or_atoms_fill_layout() {
    // (or "activate" "config" "doctor" "fmt") flat = 39 > 25
    // Fill packs items onto lines, wrapping at col 4 (under first arg).
    let doc = l(vec![
        a("or"),
        a(r#""activate""#),
        a(r#""config""#),
        a(r#""doctor""#),
        a(r#""fmt""#),
    ]);
    let result = pp(&doc, 25);
    // (or "activate" "config"   [22 chars]
    //     "doctor" "fmt")       [18 chars]
    assert_eq!(
        result,
        "(or \"activate\" \"config\"\n    \"doctor\" \"fmt\")"
    );
}

#[test]
fn and_atoms_fill_layout() {
    // and also uses fill when all args are atoms
    let doc = l(vec![
        a("and"),
        a(r#""a""#),
        a(r#""bb""#),
        a(r#""ccc""#),
        a(r#""dddd""#),
    ]);
    let result = pp(&doc, 17);
    // (and "a" "bb"      [13 chars]
    //      "ccc" "dddd") [14 chars]
    assert_eq!(result, "(and \"a\" \"bb\"\n     \"ccc\" \"dddd\")");
}

#[test]
fn forbidden_fill_layout() {
    // forbidden also uses fill when all args are atoms
    let doc = l(vec![
        a("forbidden"),
        a(r#""-d""#),
        a(r#""--data""#),
        a(r#""--data-raw""#),
    ]);
    let result = pp(&doc, 30);
    // (forbidden "-d" "--data"
    //            "--data-raw")
    assert!(result.contains("forbidden"));
    assert!(result.contains("--data-raw"));
}

#[test]
fn forbidden_in_when_fill_layout() {
    // Test forbidden nested inside when - with many args like real config
    let when_doc = l(vec![
        a("when"),
        l(vec![
            a("forbidden"),
            a(r#""-d""#),
            a(r#""--data""#),
            a(r#""--data-raw""#),
            a(r#""--data-binary""#),
            a(r#""--data-urlencode""#),
            a(r#""-F""#),
            a(r#""--form""#),
            a(r#""-T""#),
            a(r#""--upload-file""#),
            a(r#""-X""#),
            a(r#""--request""#),
        ]),
        a("body"),
    ]);
    let result = pp(&when_doc, 80);
    println!("forbidden_in_when (full):\n{}", result);
    // Should not have excessive rightward drift
    for line in result.lines() {
        let leading = line.len() - line.trim_start().len();
        assert!(
            leading < 40,
            "Line has excessive indent ({} chars): {}",
            leading,
            line
        );
    }
}

#[test]
fn forbidden_via_trivia_doc() {
    // Test using Option<()> annotation like to_doc_with_trivia produces
    use may_i_core::doc::{DocF, LayoutHint};

    fn atom_with_ann(s: &str) -> Doc<Option<()>> {
        Doc {
            ann: None,
            node: DocF::Atom(s.to_string()),
            layout: LayoutHint::Auto,
            dimmed: false,
        }
    }

    fn list_with_ann(children: Vec<Doc<Option<()>>>) -> Doc<Option<()>> {
        Doc {
            ann: None,
            node: DocF::List(children),
            layout: LayoutHint::Auto,
            dimmed: false,
        }
    }

    let forbidden_doc = list_with_ann(vec![
        atom_with_ann("forbidden"),
        atom_with_ann(r#""-d""#),
        atom_with_ann(r#""--data""#),
        atom_with_ann(r#""--data-raw""#),
        atom_with_ann(r#""--data-binary""#),
        atom_with_ann(r#""--data-urlencode""#),
        atom_with_ann(r#""-F""#),
        atom_with_ann(r#""--form""#),
        atom_with_ann(r#""-T""#),
        atom_with_ann(r#""--upload-file""#),
        atom_with_ann(r#""-X""#),
        atom_with_ann(r#""--request""#),
    ]);

    let when_doc = list_with_ann(vec![
        atom_with_ann("when"),
        forbidden_doc,
        atom_with_ann("body"),
    ]);

    let result = pretty(
        &when_doc,
        0,
        &Format {
            width: 80,
            ..Default::default()
        },
    );
    println!("forbidden_via_trivia_doc:\n{}", result);

    // Should not have excessive rightward drift
    for line in result.lines() {
        let leading = line.len() - line.trim_start().len();
        assert!(
            leading < 40,
            "Line has excessive indent ({} chars): {}",
            leading,
            line
        );
    }
}

#[test]
fn forbidden_fill_aligns_under_first_arg() {
    // Continuation lines in fill layout should align under the first arg
    let doc = l(vec![
        a("forbidden"),
        a(r#""-d""#),
        a(r#""--data""#),
        a(r#""--data-raw""#),
        a(r#""--data-binary""#),
        a(r#""--data-urlencode""#),
        a(r#""-F""#),
        a(r#""--form""#),
    ]);
    let result = pp(&doc, 60);
    let lines: Vec<&str> = result.lines().collect();
    if lines.len() > 1 {
        // First arg "-d" position
        let first_arg_col = lines[0].find(r#""-d""#).unwrap();
        // Continuation should start at the same column
        let cont_col = lines[1].len() - lines[1].trim_start().len();
        assert_eq!(
            cont_col, first_arg_col,
            "continuation should align under first arg. Output:\n{result}"
        );
    }
}

#[test]
fn anywhere_fill_layout() {
    // anywhere uses fill layout when all args are atoms
    let doc = l(vec![
        a("anywhere"),
        a(r#""-r""#),
        a(r#""--recursive""#),
        a(r#""-f""#),
        a(r#""--force""#),
    ]);
    let result = pp(&doc, 35);
    // (anywhere "-r" "--recursive"
    //          "-f" "--force")
    assert!(result.contains("anywhere"));
    assert!(result.contains("--recursive"));
    assert!(result.contains("--force"));
}

#[test]
fn positional_fill_layout() {
    // positional uses fill layout when all args are atoms
    let doc = l(vec![
        a("positional"),
        a(r#""exec""#),
        a(r#""--""#),
        a(r#""run""#),
        a(r#""start""#),
    ]);
    let result = pp(&doc, 40);
    // (positional "exec" "--"
    //             "run" "start")
    assert!(result.contains("positional"));
    assert!(result.contains("exec"));
    assert!(result.contains("start"));
}

#[test]
fn all_fill_eligible_forms_in_and_use_fill_layout() {
    // Test that all fill-eligible forms inside an and use fill layout
    let and_doc = l(vec![
        a("and"),
        l(vec![a("forbidden"), a(r#""-d""#), a(r#""--data""#)]),
        l(vec![a("anywhere"), a(r#""-r""#), a(r#""--recursive""#)]),
        l(vec![a("positional"), a(r#""exec""#), a(r#""--""#)]),
    ]);
    let result = pp(&and_doc, 80);
    println!("all_fill_eligible_forms:\n{}", result);
    // All should be on their own lines but with reasonable indentation
    for line in result.lines() {
        let leading = line.len() - line.trim_start().len();
        assert!(
            leading < 20,
            "Line has excessive indent ({} chars): {}",
            leading,
            line
        );
    }
}

// ── Broken layout with zero inline children ──────────────────

#[test]
fn broken_zero_inline_uses_drop_indent() {
    // When all children are multiline, broken layout should cascade at
    // indent+1 (like all-drop), not indent+head_width+2 (under first arg).
    let doc = l(vec![
        a("or"),
        l(vec![
            a("when"),
            a("(exact)"),
            l(vec![a("effect"), a(":allow")]),
        ]),
        l(vec![a("when"), a("pred"), l(vec![a("effect"), a(":ask")])]),
    ]);
    let result = pp(&doc, 40);
    let lines: Vec<&str> = result.lines().collect();
    // Children should be at indent 1 (all-drop style), not indent 4
    if lines.len() > 1 {
        let second_line_indent = lines[1].len() - lines[1].trim_start().len();
        assert_eq!(
            second_line_indent, 1,
            "children should be at indent 1 when nothing inlined. Output:\n{result}"
        );
    }
}

// ── Multiline last-child breaks to own line ──────────────────

#[test]
fn two_line_multiline_last_child_not_inlined() {
    // (and (positional "fmt") (when build-mode (effect :allow)))
    // The (when ...) is 2 lines and should NOT inline after (positional "fmt")
    let doc = l(vec![
        a("and"),
        l(vec![a("positional"), a("\"fmt\"")]),
        l(vec![
            a("when"),
            a("build-mode"),
            l(vec![a("effect"), a(":allow")]),
        ]),
    ]);
    let result = pp(&doc, 80);
    let lines: Vec<&str> = result.lines().collect();
    let fmt_line = lines.iter().find(|l| l.contains("\"fmt\"")).unwrap();
    assert!(
        !fmt_line.contains("when"),
        "when should not be on same line as positional: {result:?}"
    );
}

#[test]
fn large_multiline_last_child_not_inlined() {
    // (positional "foo" "bar" (cond ...)) where the cond has 3+ lines
    // should put (cond ...) on its own line, not inline after "bar"
    let doc = l(vec![
        a("positional"),
        a("\"foo\""),
        a("\"bar\""),
        l(vec![
            a("cond"),
            l(vec![a("\"x\""), l(vec![a("exact")])]),
            l(vec![a("\"y\""), l(vec![a("exact")])]),
            l(vec![a("\"z\""), l(vec![a("exact")])]),
        ]),
    ]);
    let result = pp(&doc, 40);
    // The cond should start on its own line, not on the same line as "bar"
    let lines: Vec<&str> = result.lines().collect();
    // Find the line containing "bar" — cond should NOT be on the same line
    let bar_line = lines.iter().find(|l| l.contains("\"bar\"")).unwrap();
    assert!(
        !bar_line.contains("cond"),
        "cond should not be on same line as bar: {result:?}"
    );
}

// ── parse_sexpr ────────────────────────────────────────────────

#[test]
fn parse_sexpr_atom() {
    let doc = parse_sexpr("hello");
    assert_eq!(pp(&doc, 80), "hello");
}

#[test]
fn parse_sexpr_simple_list() {
    let doc = parse_sexpr("(command \"curl\")");
    assert_eq!(pp(&doc, 80), "(command \"curl\")");
}

#[test]
fn parse_sexpr_nested() {
    let doc = parse_sexpr("(command (or \"cat\" \"bat\"))");
    assert_eq!(pp(&doc, 80), "(command (or \"cat\" \"bat\"))");
}

#[test]
fn parse_sexpr_regex() {
    let doc = parse_sexpr("(command (regex \"^git\"))");
    assert_eq!(pp(&doc, 80), "(command (regex \"^git\"))");
}

#[test]
fn parse_sexpr_wraps_when_long() {
    let doc = parse_sexpr("(command (or \"cat\" \"bat\" \"head\" \"tail\" \"less\"))");
    let result = pp(&doc, 30);
    assert!(result.contains('\n'));
}

// ── line_number ────────────────────────────────────────────────

#[test]
fn line_number_single_line() {
    let doc = l(vec![a("rule"), l(vec![a("command"), a("\"curl\"")])]);
    let result = pretty(
        &doc,
        0,
        &Format {
            width: 80,
            line_number: Some(108),
            ..Default::default()
        },
    );
    assert_eq!(result, "108: (rule (command \"curl\"))");
}

#[test]
fn line_number_wrapped_aligns() {
    let doc = l(vec![a("rule"), a("aaa"), a("bbb"), a("ccc")]);
    let result = pretty(
        &doc,
        0,
        &Format {
            width: 20,
            line_number: Some(5),
            ..Default::default()
        },
    );
    let lines: Vec<&str> = result.lines().collect();
    assert!(lines.len() > 1);
    assert!(lines[0].starts_with("5: "));
    assert!(lines[1].starts_with("     "));
}

#[test]
fn line_number_accounts_for_width() {
    let doc = l(vec![a("rule"), l(vec![a("command"), a("\"curl\"")])]);
    let result = pretty(
        &doc,
        0,
        &Format {
            width: 30,
            line_number: Some(108),
            ..Default::default()
        },
    );
    assert!(!result.contains('\n'));
}

// ── map ────────────────────────────────────────────────────────

#[test]
fn map_tags_all_nodes() {
    let doc = l(vec![a("head"), a("child")]);
    let tagged = doc.map(&|()| 42);
    assert_eq!(tagged.ann, 42);
    if let DocF::List(children) = &tagged.node {
        assert_eq!(children[0].ann, 42);
        assert_eq!(children[1].ann, 42);
    } else {
        panic!("expected list");
    }
}

#[test]
fn map_preserves_structure() {
    let doc = l(vec![a("x"), l(vec![a("y")])]);
    let tagged = doc.map(&|()| "ann");
    assert_eq!(pretty(&tagged, 0, &Format::default()), "(x (y))");
}

// ── fold ───────────────────────────────────────────────────────

#[test]
fn fold_counts_nodes() {
    let doc = l(vec![a("a"), l(vec![a("b"), a("c")])]);
    let count: usize = doc.fold(&|node, _ann| match node {
        DocF::Atom(_) => 1,
        DocF::List(children) | DocF::Vector(children) => 1 + children.iter().sum::<usize>(),
    });
    assert_eq!(count, 5); // list + a + list + b + c
}

#[test]
fn fold_collects_atoms() {
    let doc = l(vec![a("rule"), a("foo"), l(vec![a("bar")])]);
    let atoms: Vec<String> = doc.fold(&|node, _ann| match node {
        DocF::Atom(s) => vec![s],
        DocF::List(children) | DocF::Vector(children) => {
            children.into_iter().flatten().collect()
        }
    });
    assert_eq!(atoms, vec!["rule", "foo", "bar"]);
}

#[test]
fn fold_rebuilds_tree() {
    // Use fold to rebuild a tree with truncated atoms.
    let doc = l(vec![a("hello-world"), a("short")]);
    let truncated: Doc<()> = doc.fold(&|node, _ann| match node {
        DocF::Atom(s) => {
            let t = if s.len() > 5 { &s[..5] } else { &s };
            Doc::atom(t)
        }
        DocF::List(children) => Doc::list(children),
        DocF::Vector(children) => Doc::vector(children),
    });
    assert_eq!(pp(&truncated, 80), "(hello short)");
}

// ── DocF::map ──────────────────────────────────────────────────

#[test]
fn docf_map_transforms_children() {
    let layer: DocF<i32> = DocF::List(vec![1, 2, 3]);
    let doubled = layer.map(|x| x * 2);
    assert_eq!(doubled.children(), Some(&[2, 4, 6][..]));
}

#[test]
fn docf_map_atom_is_identity() {
    let layer: DocF<i32> = DocF::Atom("hello".into());
    let mapped = layer.map(|x| x * 2);
    assert_eq!(mapped.as_atom(), Some("hello"));
}

// ── AlwaysBreak ────────────────────────────────────────────────

#[test]
fn always_break_uses_broken_layout() {
    // AlwaysBreak skips flat but still uses broken (align-under-first-arg).
    let doc = Doc::broken_list(vec![a("or"), a("\"a\""), a("\"b\""), a("\"c\"")]);
    let result = pp(&doc, 80);
    assert_eq!(result, "(or \"a\"\n    \"b\"\n    \"c\")");
}

#[test]
fn always_break_single_child() {
    let doc = Doc::broken_list(vec![a("or")]);
    let result = pp(&doc, 80);
    assert_eq!(result, "(or)");
}

#[test]
fn always_break_falls_back_to_all_drop_at_narrow_width() {
    // At narrow width, broken layout overflows → falls to render_all_drop.
    let doc = Doc::broken_list(vec![
        a("or"),
        a("\"long-value-one\""),
        a("\"long-value-two\""),
    ]);
    let result = pp(&doc, 20);
    assert_eq!(result, "(or\n \"long-value-one\"\n \"long-value-two\")");
}

#[test]
fn cond_renders_clauses() {
    let doc = l(vec![
        a("cond"),
        l(vec![a("\"a\""), a(":allow")]),
        l(vec![a("\"b\""), a(":deny")]),
    ]);
    let result = pp(&doc, 40);
    assert!(result.contains("cond"));
    assert!(result.contains("\"a\""));
    assert!(result.contains(":allow"));
    assert!(result.contains("\"b\""));
    assert!(result.contains(":deny"));
}

#[test]
fn cond_single_child() {
    let doc = l(vec![a("cond")]);
    let result = pp(&doc, 40);
    assert_eq!(result, "(cond)");
}

#[test]
fn cond_atom_clause() {
    let doc = l(vec![a("cond"), a("else")]);
    let result = pp(&doc, 40);
    assert!(result.contains("cond"));
    assert!(result.contains("else"));
}

#[test]
fn body_indent_multiline_first_child() {
    // when/if/unless use body-indent; if the predicate wraps it
    // gets extra indent (indent+4) to distinguish from body.
    let pred = l(vec![a("and"), a("xxxxxxxxxxxx"), a("yyyyyyyyyyyy")]);
    let doc = l(vec![a("when"), pred, a(":allow")]);
    let result = pp(&doc, 25);
    let lines: Vec<&str> = result.lines().collect();
    assert!(lines.len() >= 3);
    assert!(lines[0].contains("when"));
}

#[test]
fn body_indent_two_children() {
    // (when pred) — only head + one child, exercises the len==2 close path.
    let pred = l(vec![a("and"), a("xxxxx"), a("yyyyy")]);
    let doc = l(vec![a("when"), pred]);
    let result = pp(&doc, 15);
    assert!(result.contains("when"));
}

#[test]
fn if_keeps_multiline_condition_inline() {
    // (if (or "a" "b") (effect :allow "yes") (effect :deny "no"))
    // The condition is multiline but should stay on the if line.
    // With (indent 2): condition and then-branch are special args.
    let cond = l(vec![
        a("or"),
        a("\"~/.config/tmux/custom.conf\""),
        a("\"~/.config/tmux/tmux.conf\""),
    ]);
    let then_br = l(vec![a("effect"), a(":allow"), a("\"yes\"")]);
    let else_br = l(vec![a("effect"), a(":deny"), a("\"no\"")]);
    let doc = l(vec![a("if"), cond, then_br, else_br]);
    let result = pp(&doc, 50);
    // First line should have "if" and "(or" together
    let first_line = result.lines().next().unwrap();
    assert!(
        first_line.contains("if") && first_line.contains("(or"),
        "Expected 'if' and '(or' on same line, got:\n{}",
        result,
    );
}

#[test]
fn if_indent_spec_is_2() {
    // With (indent 2), condition + then-branch are special args.
    // else-branch is body (at indent+2).
    // At width 10, then-branch overflows so it drops to align
    // under the condition.
    let cond = a("pred");
    let then_br = a("yes");
    let else_br = a("no");
    let doc = l(vec![a("if"), cond, then_br, else_br]);
    let result = pp(&doc, 10);
    // (if pred
    //     yes
    //   no)
    assert_eq!(result, "(if pred\n    yes\n  no)");
}

#[test]
fn breaking_descendant_prevents_flat() {
    // (? (and (or "a" "b") "--")) where (or ...) is AlwaysBreak.
    // Even at wide width, (? ...) must not flatten since the or
    // descendant would render at indent=0 producing wrong columns.
    let or_doc = Doc::broken_list(vec![a("or"), a("\"a\""), a("\"b\"")]);
    let and_doc = l(vec![a("and"), or_doc, a("\"--\"")]);
    let q_doc = l(vec![a("?"), and_doc]);
    let result = pp(&q_doc, 80);
    // The (or ...) children must be indented relative to their parent,
    // not at column 0.
    for line in result.lines().skip(1) {
        let leading = line.len() - line.trim_start().len();
        assert!(leading >= 2, "line has too little indent: {result:?}");
    }
}

// ── Dimmed rendering ─────────────────────────────────────────────

#[test]
fn dimmed_atom_renders_dimmed() {
    with_forced_color(|| {
        let doc = Doc {
            dimmed: true,
            ..a("command")
        };
        let result = pp_color(&doc, 80);
        // When dimmed, atoms should render without syntax coloring.
        // The dimmed styling may or may not include ANSI codes depending
        // on terminal capabilities, but the content should be present.
        assert!(result.contains("command"));
        // Verify it's not colored as a special form (blue)
        // by checking the raw output doesn't contain the blue color code
        let has_blue = result.contains("\x1b[34m") || result.contains("\x1b[38;5;");
        assert!(
            !has_blue,
            "dimmed atom should not have blue syntax color: {result:?}"
        );
    });
}

#[test]
fn dimmed_inherits_to_children() {
    with_forced_color(|| {
        // Parent list is dimmed → children should also render dimmed.
        let doc = Doc {
            ann: (),
            node: DocF::List(vec![a("rule"), a(":allow")]),
            layout: LayoutHint::Auto,
            dimmed: true,
        };
        let result = pp_color(&doc, 80);
        assert!(result.contains("rule"));
        assert!(result.contains(":allow"));
    });
}

#[test]
fn dimmed_only_affects_flagged_subtree() {
    with_forced_color(|| {
        // One child dimmed, sibling not — sibling retains syntax color.
        let dimmed_child = Doc {
            dimmed: true,
            ..a("\"dimmed\"")
        };
        let normal_child = a("\"bright\"");
        let doc = l(vec![a("or"), dimmed_child, normal_child]);
        let result = pp_color(&doc, 80);
        // Both should be present.
        assert!(result.contains("dimmed"));
        assert!(result.contains("bright"));
    });
}

