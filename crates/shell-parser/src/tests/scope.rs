//! Tests for assignment scope tagging — the syntactic part of whether an
//! environment write reaches a child process. See the `harden-env-write-scope`
//! change.

use crate::*;

/// Find the assignment named `name` anywhere in a parsed command, returning its
/// scope. Looks in both `Command::Simple` assignment lists and the bare
/// `Command::Assignment` form.
fn scope_of(input: &str, name: &str) -> AssignmentScope {
    fn find(cmd: &Command, name: &str) -> Option<AssignmentScope> {
        match cmd {
            Command::Assignment(a) if a.name == name => Some(a.scope),
            Command::Simple(sc) => sc
                .assignments
                .iter()
                .find(|a| a.name == name)
                .map(|a| a.scope),
            _ => cmd.children().iter().find_map(|c| find(c, name)),
        }
    }
    let cmd = parse(input).into_command();
    find(&cmd, name).unwrap_or_else(|| panic!("no assignment named {name} in {cmd:?}"))
}

#[test]
fn command_prefix_is_prefix_scope() {
    assert_eq!(scope_of("FOO=bar cmd arg", "FOO"), AssignmentScope::Prefix);
}

#[test]
fn bare_assignment_is_bare_scope() {
    assert_eq!(scope_of("FOO=bar", "FOO"), AssignmentScope::Bare);
}

#[test]
fn multiple_bare_assignments_are_bare_scope() {
    // Two assignments and no command word: both are bare.
    assert_eq!(scope_of("A=1 B=2", "A"), AssignmentScope::Bare);
    assert_eq!(scope_of("A=1 B=2", "B"), AssignmentScope::Bare);
}

#[test]
fn export_scalar_is_exported_declaration() {
    assert_eq!(
        scope_of("export FOO=bar", "FOO"),
        AssignmentScope::Declaration { exported: true }
    );
}

#[test]
fn declare_x_scalar_is_exported_declaration() {
    assert_eq!(
        scope_of("declare -x LD_PRELOAD=/evil.so", "LD_PRELOAD"),
        AssignmentScope::Declaration { exported: true }
    );
}

#[test]
fn plain_declare_scalar_is_shell_local_declaration() {
    assert_eq!(
        scope_of("declare FOO=bar", "FOO"),
        AssignmentScope::Declaration { exported: false }
    );
}

#[test]
fn declare_associative_array_is_shell_local_declaration() {
    assert_eq!(
        scope_of("declare -A m=([k]=v)", "m"),
        AssignmentScope::Declaration { exported: false }
    );
}

#[test]
fn declare_xa_combined_flag_is_exported() {
    // A combined `-Ax` flag carries the export attribute.
    assert_eq!(
        scope_of("declare -Ax m=([k]=v)", "m"),
        AssignmentScope::Declaration { exported: true }
    );
}

#[test]
fn local_x_is_exported_declaration() {
    assert_eq!(
        scope_of("local -x FOO=bar", "FOO"),
        AssignmentScope::Declaration { exported: true }
    );
}

#[test]
fn declared_scalar_value_is_preserved() {
    // Lifting the scalar declaration arg must preserve its value.
    let cmd = parse("export FOO=bar baz").into_command();
    match &cmd {
        Command::Simple(sc) => {
            let a = sc.assignments.iter().find(|a| a.name == "FOO").unwrap();
            assert_eq!(a.value.as_scalar().unwrap().to_str(), "bar");
            // `export` and the trailing non-assignment word `baz` stay as words.
            assert_eq!(sc.command_name(), Some("export"));
            assert!(sc.args().iter().any(|w| w.to_str() == "baz"));
        }
        other => panic!("expected simple command, got {other:?}"),
    }
}

#[test]
fn set_allexport_is_a_recoverable_simple_command() {
    // The parser need not track allexport state itself; it must leave `set -a`
    // recoverable as a simple command so the engine can detect it.
    let cmd = parse("set -a").into_command();
    match &cmd {
        Command::Simple(sc) => {
            assert_eq!(sc.command_name(), Some("set"));
            assert_eq!(
                sc.args().first().map(|w| w.to_str()),
                Some("-a".to_string())
            );
        }
        other => panic!("expected `set -a` simple command, got {other:?}"),
    }
}
