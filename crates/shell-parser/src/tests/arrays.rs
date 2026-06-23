//! Tests for bash array modelling: array-literal assignments and
//! subscripted parameter expansions. See the `model-bash-arrays` change.

use crate::*;

/// Task 1.1: an array literal must not error or discard the following command.
#[test]
fn array_literal_preserves_following_command() {
    let result = parse("arr=(a b c); echo done");
    assert!(
        !result.has_errors(),
        "array literal should emit no Error diagnostic, got: {:?}",
        result.diagnostics
    );
    // The sequence must contain `echo done`.
    let names: Vec<Option<&str>> = extract_simple_commands(&result.command)
        .iter()
        .map(|sc| sc.command_name())
        .collect();
    assert!(
        names.contains(&Some("echo")),
        "expected `echo` to survive, got commands: {names:?}"
    );
}

/// Task 1.4: kind is recorded — `declare -a` indexed, `declare -A` associative.
#[test]
fn declare_records_array_kind() {
    fn array_kind_of(input: &str, name: &str) -> ArrayKind {
        let cmd = parse(input).into_command();
        let sc = match &cmd {
            Command::Simple(sc) => sc,
            other => panic!("expected simple command, got {other:?}"),
        };
        let a = sc
            .assignments
            .iter()
            .find(|a| a.name == name)
            .unwrap_or_else(|| panic!("no assignment named {name} in {sc:?}"));
        match &a.value {
            AssignmentValue::Array { array_kind, .. } => *array_kind,
            other => panic!("expected array value, got {other:?}"),
        }
    }

    assert_eq!(
        array_kind_of("declare -a idx=(a b c)", "idx"),
        ArrayKind::Indexed
    );
    assert_eq!(
        array_kind_of("declare -A assoc=([k]=v)", "assoc"),
        ArrayKind::Associative
    );
}

/// Task 1.4: a bare `arr=(a b c)` is indexed.
#[test]
fn bare_array_is_indexed() {
    let cmd = parse("arr=(a b c)").into_command();
    match &cmd {
        Command::Assignment(a) => match &a.value {
            AssignmentValue::Array { array_kind, .. } => {
                assert_eq!(*array_kind, ArrayKind::Indexed);
            }
            other => panic!("expected array, got {other:?}"),
        },
        other => panic!("expected assignment, got {other:?}"),
    }
}

/// Spec scenario: array element words are preserved, with quoting respected.
#[test]
fn array_elements_preserved() {
    let cmd = parse(r#"arr=(one "two three" four)"#).into_command();
    match &cmd {
        Command::Assignment(a) => match &a.value {
            AssignmentValue::Array { elements, .. } => {
                let strs: Vec<String> = elements.iter().map(|w| w.to_str()).collect();
                assert_eq!(strs, vec!["one", "two three", "four"]);
            }
            other => panic!("expected array, got {other:?}"),
        },
        other => panic!("expected assignment, got {other:?}"),
    }
}

/// Task 2.2: a subscript inside `${…}` is separated from the name.
#[test]
fn subscript_separated_from_name() {
    // Pull the single word-part out of `${…}` in an echo argument.
    fn array_part(input: &str) -> WordPart {
        let cmd = parse(input).into_command();
        let sc = match &cmd {
            Command::Simple(sc) => sc,
            other => panic!("expected simple, got {other:?}"),
        };
        // The first argument word's first part.
        let arg = &sc.args()[0];
        arg.parts[0].clone()
    }

    match array_part("echo ${arr[@]}") {
        WordPart::ArrayExpansion {
            name,
            subscript,
            length,
        } => {
            assert_eq!(name, "arr");
            assert_eq!(subscript, Subscript::All);
            assert!(!length);
        }
        other => panic!("expected ArrayExpansion, got {other:?}"),
    }

    match array_part("echo ${arr[*]}") {
        WordPart::ArrayExpansion {
            subscript, name, ..
        } => {
            assert_eq!(name, "arr");
            assert_eq!(subscript, Subscript::Star);
        }
        other => panic!("expected ArrayExpansion, got {other:?}"),
    }

    match array_part("echo ${arr[0]}") {
        WordPart::ArrayExpansion {
            name, subscript, ..
        } => {
            assert_eq!(name, "arr");
            assert_eq!(subscript, Subscript::Index(Word::literal("0")));
        }
        other => panic!("expected ArrayExpansion, got {other:?}"),
    }
}

/// Spec scenario: append and indexed element assignment do not truncate.
/// `arr=(a); arr+=(b); arr[5]=c; echo end` must keep `echo end` in the parse
/// and emit no Error diagnostic (invariant (a): no silent discard).
#[test]
fn append_and_indexed_assignment_do_not_truncate() {
    let input = "arr=(a); arr+=(b); arr[5]=c; echo end";
    let result = parse(input);
    assert!(
        !result.has_errors(),
        "no Error diagnostic expected, got: {:?}",
        result.diagnostics
    );
    let names: Vec<Option<&str>> = extract_simple_commands(&result.command)
        .iter()
        .map(|sc| sc.command_name())
        .collect();
    assert!(
        names.contains(&Some("echo")),
        "expected trailing `echo end` to survive, got commands: {names:?}"
    );
    // The trailing argument word `end` must be present too.
    let echo = extract_simple_commands(&result.command)
        .into_iter()
        .find(|sc| sc.command_name() == Some("echo"))
        .expect("echo command present");
    assert_eq!(
        echo.args().iter().map(|w| w.to_str()).collect::<Vec<_>>(),
        vec!["end"],
        "echo's argument `end` was dropped"
    );
}

/// Task 2.2: the length form `${#arr[@]}` records `length: true`.
#[test]
fn subscript_length_form() {
    let cmd = parse("echo ${#arr[@]}").into_command();
    let sc = match &cmd {
        Command::Simple(sc) => sc,
        other => panic!("expected simple, got {other:?}"),
    };
    match &sc.args()[0].parts[0] {
        WordPart::ArrayExpansion {
            name,
            subscript,
            length,
        } => {
            assert_eq!(name, "arr");
            assert_eq!(*subscript, Subscript::All);
            assert!(*length);
        }
        other => panic!("expected ArrayExpansion, got {other:?}"),
    }
}

// ── Lexer/parser edge cases a proptest can't reliably reach (task 4.3) ──

/// Pull the first argument word's first part out of a simple command.
fn first_arg_part(input: &str) -> WordPart {
    let cmd = parse(input).into_command();
    let sc = match &cmd {
        Command::Simple(sc) => sc,
        other => panic!("expected simple, got {other:?}"),
    };
    sc.args()[0].parts[0].clone()
}

/// A subscript followed by an operator (`${arr[0]:-x}`) is not an array
/// reference: the lexer restores and reads it as a flat parameter expansion,
/// never dropping the subscript or the operator (`read_subscript` restore path).
#[test]
fn subscript_then_operator_is_flat_expansion() {
    assert!(
        matches!(
            first_arg_part("echo ${arr[0]:-x}"),
            WordPart::ParameterExpansion(_)
        ),
        "subscript-then-operator should fall back to a flat expansion"
    );
    assert!(!parse("echo ${arr[0]:-x}").has_errors());
}

/// A length form whose subscript does not close before `}` (`${#arr[0]x}`)
/// restores and reads flat — exercising the `${#…[…]}` restore path — without
/// an Error diagnostic or a dropped token.
#[test]
fn malformed_length_subscript_falls_back_flat() {
    assert!(matches!(
        first_arg_part("echo ${#arr[0]x}"),
        WordPart::ParameterExpansion(_)
    ));
    assert!(!parse("echo ${#arr[0]x}").has_errors());
}

/// A subscript with a nested bracket (`${arr[a[0]]}`) is captured whole as an
/// `Index` word — the `read_subscript` depth counter pairs the inner `[`/`]`.
#[test]
fn nested_bracket_subscript_is_indexed() {
    match first_arg_part("echo ${arr[a[0]]}") {
        WordPart::ArrayExpansion {
            name, subscript, ..
        } => {
            assert_eq!(name, "arr");
            // The whole `a[0]` is captured (depth counter pairs the inner
            // bracket); its inner text is re-lexed, so `[0]` becomes a Glob
            // part — what matters is the subscript is not truncated at `a`.
            match subscript {
                Subscript::Index(w) => assert_eq!(w.to_str(), "a[0]"),
                other => panic!("expected Index, got {other:?}"),
            }
        }
        other => panic!("expected ArrayExpansion, got {other:?}"),
    }
}

/// An empty subscript (`${arr[]}`) yields an `Index` holding an empty word
/// rather than panicking or dropping the reference.
#[test]
fn empty_subscript_is_empty_index() {
    match first_arg_part("echo ${arr[]}") {
        WordPart::ArrayExpansion { subscript, .. } => {
            assert_eq!(subscript, Subscript::Index(Word::literal("")));
        }
        other => panic!("expected ArrayExpansion, got {other:?}"),
    }
}

/// An indexed-element assignment `arr[2]=x` is never silently discarded: the
/// trailing command survives whether the element form parses as an assignment
/// or (after glob-splitting of `[2]`) as a command word.
#[test]
fn indexed_element_assignment_does_not_truncate() {
    let result = parse("arr[2]=x; echo end");
    assert!(!result.has_errors(), "got: {:?}", result.diagnostics);
    let names: Vec<Option<&str>> = extract_simple_commands(&result.command)
        .iter()
        .map(|sc| sc.command_name())
        .collect();
    assert!(
        names.contains(&Some("echo")),
        "trailing echo dropped: {names:?}"
    );
}

// ── Invariant proptests (model-bash-arrays tasks 4.2 / 3.3) ─────────────

use proptest::prelude::*;

/// Count every `AssignmentValue::Array` and `WordPart::ArrayExpansion` node in
/// a parsed command tree. Used by the behaviour-preserving guard: an input with
/// no array syntax must produce zero of either.
fn array_node_count(cmd: &Command) -> usize {
    fn count_word(w: &Word, n: &mut usize) {
        fn count_parts(parts: &[WordPart], n: &mut usize) {
            for p in parts {
                match p {
                    WordPart::ArrayExpansion { .. } => *n += 1,
                    WordPart::DoubleQuoted(inner) => count_parts(inner, n),
                    _ => {}
                }
            }
        }
        count_parts(&w.parts, n);
    }
    let mut n = 0;
    for sc in extract_simple_commands(cmd) {
        for a in &sc.assignments {
            if matches!(a.value, AssignmentValue::Array { .. }) {
                n += 1;
            }
            for w in a.value.words() {
                count_word(w, &mut n);
            }
        }
        for w in &sc.words {
            count_word(w, &mut n);
        }
    }
    // Bare `Command::Assignment` values are not reached via
    // `extract_simple_commands`; walk them too.
    fn walk_assignments(cmd: &Command, n: &mut usize) {
        if let Command::Assignment(a) = cmd
            && matches!(a.value, AssignmentValue::Array { .. })
        {
            *n += 1;
        }
        for child in cmd.children() {
            walk_assignments(child, n);
        }
    }
    walk_assignments(cmd, &mut n);
    n
}

/// Array-ish fragments: the syntactic shapes this change must model or coarsely
/// diagnose without panicking or silently dropping tokens — array literals,
/// appends, indexed-element assignments, declarations, subscripted expansions,
/// and the malformed/unterminated/nested variants of each.
const ARRAY_ISH: &[&str] = &[
    "arr=(",
    ")",
    "arr=(a b c)",
    "arr+=(x)",
    "arr[5]=c",
    "arr[$i]=c",
    "declare -a",
    "declare -A",
    "declare -A m=([k]=v)",
    "local -a x=(1 2)",
    "export -a y=(p q)",
    "${arr[@]}",
    "${arr[*]}",
    "${arr[0]}",
    "${#arr[@]}",
    "${arr[$i]}",
    "${arr[",
    "]}",
    "[",
    "]",
    "@",
    "*",
    "((",
    "unset 'arr[1]'",
    "=(",
    "+=",
    "; echo end",
    "| cat",
    "&&",
    "$(date)",
    "\"${a[@]}\"",
];

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, max_shrink_iters: 64, .. ProptestConfig::default() })]

    /// Invariant (b), parser side: arbitrary array-ish input never panics the
    /// parser, whatever combination of `(`, `)`, `[`, `]`, `@`, `*`, `+=`,
    /// `declare -A`, and unterminated/nested fragments it assembles.
    #[test]
    fn prop_parse_never_panics_on_array_ish(
        frags in proptest::collection::vec(proptest::sample::select(ARRAY_ISH), 0..10),
    ) {
        let input = frags.join(" ");
        let _ = crate::parse(&input);
    }

    /// Invariant (c), refactor-safety: an input containing **no** array syntax
    /// (no `(`/`)` array literal, no `[`/`]` subscript) parses to zero
    /// `AssignmentValue::Array` and zero `WordPart::ArrayExpansion` nodes — so
    /// every assignment value stays a `Scalar` exactly as the pre-refactor
    /// `value: Word` field was, and every downstream consumer sees identical
    /// data. The `Assignment.value` enum refactor is therefore transparent for
    /// non-array input; the per-decision byte-for-byte guarantee is pinned by
    /// the unchanged decision/segment golden fixtures.
    #[test]
    fn prop_no_array_syntax_yields_no_array_nodes(
        // Excludes `(` `)` `[` `]` entirely: an array literal needs `(` and a
        // subscript needs `[`, so neither shape can be generated.
        input in r#"[a-zA-Z0-9 ;|&"'$<>/\\=._@*?:{}#+-]{0,80}"#,
    ) {
        let result = crate::parse(&input);
        prop_assert_eq!(
            array_node_count(&result.command),
            0,
            "non-array input produced array node(s): {:?}",
            input
        );
    }
}
