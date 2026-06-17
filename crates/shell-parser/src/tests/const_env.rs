use crate::*;
use std::collections::HashMap;

fn env_of(input: &str) -> HashMap<String, String> {
    constant_env(&parse(input).command)
}

#[test]
fn single_static_assignment_qualifies() {
    let env = env_of("BIN=./x; $BIN run");
    assert_eq!(env, [("BIN".to_string(), "./x".to_string())].into());
}

#[test]
fn substitution_rhs_does_not_qualify() {
    assert_eq!(env_of("BIN=$(which x)"), HashMap::new());
}

#[test]
fn reassignment_does_not_qualify() {
    assert_eq!(env_of("B=a; B=b"), HashMap::new());
}

#[test]
fn assignment_inside_if_does_not_qualify() {
    assert_eq!(env_of("if true; then BIN=./x; fi"), HashMap::new());
}

#[test]
fn assignment_inside_loop_does_not_qualify() {
    assert_eq!(env_of("for i in 1 2; do BIN=./x; done"), HashMap::new());
}

#[test]
fn assignment_inside_function_does_not_qualify() {
    assert_eq!(env_of("f() { BIN=./x; }"), HashMap::new());
}

#[test]
fn loop_variable_does_not_qualify() {
    assert_eq!(env_of("for c in rm cp; do $c x; done"), HashMap::new());
}

// -- Task 1.3: export and prefix assignments --

#[test]
fn export_assignment_qualifies() {
    let env = env_of("export VAR=./x; $VAR run");
    assert_eq!(env, [("VAR".to_string(), "./x".to_string())].into());
}

#[test]
fn prefix_assignment_does_not_feed() {
    // `VAR=lit cmd` binds only cmd's environment; it must not feed
    // command-name resolution for a later use.
    assert_eq!(env_of("BIN=./x foo; $BIN run"), HashMap::new());
}

#[test]
fn unset_disqualifies() {
    assert_eq!(env_of("BIN=./x; unset BIN; $BIN run"), HashMap::new());
}

#[test]
fn export_dynamic_name_does_not_bind() {
    // `export $FOO` — the argument is a parameter expansion, not a
    // `NAME=VALUE` literal, so nothing is bound.
    assert_eq!(env_of("export $FOO"), HashMap::new());
}

#[test]
fn export_invalid_name_does_not_bind() {
    // A name that is not a valid identifier (leading digit) is rejected.
    assert_eq!(env_of("export 1BAD=x"), HashMap::new());
}

#[test]
fn unset_dynamic_name_is_ignored() {
    // `unset $X` names no statically-known variable; it neither binds nor
    // disqualifies a provably-constant assignment.
    let env = env_of("BIN=./x; unset $X; $BIN run");
    assert_eq!(env, [("BIN".to_string(), "./x".to_string())].into());
}
