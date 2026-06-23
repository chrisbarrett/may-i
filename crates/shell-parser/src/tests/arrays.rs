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
