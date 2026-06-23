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
