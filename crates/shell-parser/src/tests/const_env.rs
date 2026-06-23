use crate::*;
use proptest::prelude::*;
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

// -- Task 1: use-order-awareness (D2) --

#[test]
fn use_before_sole_assignment_does_not_qualify() {
    // At the use site `$B`, the assignment `B=rm` has not yet executed, so the
    // value there is the inherited environment, not `rm`. `B` must not resolve.
    assert_eq!(env_of("$B x; B=rm"), HashMap::new());
}

#[test]
fn unset_dynamic_name_is_ignored() {
    // `unset $X` names no statically-known variable; it neither binds nor
    // disqualifies a provably-constant assignment.
    let env = env_of("BIN=./x; unset $X; $BIN run");
    assert_eq!(env, [("BIN".to_string(), "./x".to_string())].into());
}

// -- Task 1: statically-enumerable `for` loops --

/// The enumerable value set of the first `for` loop in `input`, resolved
/// against the command's constant env, or `None` when the loop is not
/// statically enumerable.
fn for_values(input: &str) -> Option<Vec<String>> {
    let cmd = parse(input).command;
    let env = constant_env(&cmd);
    let mut found = None;
    fn walk(cmd: &Command, env: &HashMap<String, String>, found: &mut Option<Option<Vec<String>>>) {
        if found.is_some() {
            return;
        }
        if let Command::For { var, words, body } = cmd {
            *found = Some(enumerable_for_values(var, words, body, env));
            return;
        }
        for child in cmd.children() {
            walk(child, env, found);
        }
    }
    walk(&cmd, &env, &mut found);
    found.flatten()
}

#[test]
fn literal_list_is_enumerable() {
    assert_eq!(
        for_values("for k in a b c; do echo $k; done"),
        Some(vec!["a".to_string(), "b".to_string(), "c".to_string()])
    );
}

#[test]
fn command_substitution_list_is_not_enumerable() {
    assert_eq!(for_values("for k in $(ls); do rm $k; done"), None);
}

#[test]
fn glob_list_is_not_enumerable() {
    assert_eq!(for_values("for k in *.txt; do rm $k; done"), None);
}

#[test]
fn splat_list_is_not_enumerable() {
    assert_eq!(for_values("for k in \"$@\"; do rm $k; done"), None);
}

#[test]
fn nonconstant_variable_list_is_not_enumerable() {
    assert_eq!(for_values("for k in $X; do rm $k; done"), None);
}

#[test]
fn constant_variable_list_is_enumerable() {
    // A list word that is itself a provably-constant scalar resolves.
    assert_eq!(
        for_values("D=lit; for k in $D x; do echo $k; done"),
        Some(vec!["lit".to_string(), "x".to_string()])
    );
}

#[test]
fn reassigned_loop_var_is_not_enumerable() {
    assert_eq!(for_values("for k in a b; do k=$(date); rm $k; done"), None);
}

#[test]
fn unset_loop_var_is_not_enumerable() {
    assert_eq!(for_values("for k in a b; do unset k; rm $k; done"), None);
}

// Distinct unrelated identifiers that never collide with the variable under
// test (which is uppercase) or name a special builtin we model (export/unset).
fn arb_filler() -> impl Strategy<Value = Vec<String>> {
    let cmd = "[a-z][a-z0-9]{0,4}";
    proptest::collection::vec(cmd, 0..3)
}

proptest! {
    /// Enumerability of a literal `for` list is invariant to reordering
    /// unrelated commands in the body, and flips off when a list word is made
    /// dynamic (`$(…)`) or the loop variable is reassigned before use.
    #[test]
    fn prop_enumerability_invariants(
        vals in proptest::collection::vec("[a-z][a-z0-9]{0,4}", 1..4),
        filler in arb_filler(),
    ) {
        let list = vals.join(" ");
        // Reordering unrelated body commands does not change enumerability.
        let body_a = {
            let mut b = filler.clone();
            b.push("echo $k".to_string());
            b.join("; ")
        };
        let body_b = {
            let mut b = vec!["echo $k".to_string()];
            b.extend(filler.clone());
            b.join("; ")
        };
        let va = for_values(&format!("for k in {list}; do {body_a}; done"));
        let vb = for_values(&format!("for k in {list}; do {body_b}; done"));
        prop_assert_eq!(&va, &vb);
        prop_assert_eq!(va.as_deref(), Some(vals.as_slice()));

        // A dynamic list word disqualifies.
        let dyn_list = format!("{list} $(date)");
        prop_assert_eq!(
            for_values(&format!("for k in {dyn_list}; do echo $k; done")),
            None
        );

        // Reassigning the loop variable before the use disqualifies.
        prop_assert_eq!(
            for_values(&format!("for k in {list}; do k=$(date); echo $k; done")),
            None
        );
    }

    /// Straight-line `NAME=lit; <filler…>; <use>` qualifies regardless of how
    /// many unrelated commands sit between the assignment and the use; moving
    /// the use before the assignment flips it to disqualified (D2).
    #[test]
    fn prop_use_order_qualification(
        name in "[A-Z][A-Z_]{0,5}",
        value in "[a-z][a-z0-9]{0,6}",
        filler in arb_filler(),
    ) {
        let mid = filler.join("; ");
        let sep = if mid.is_empty() { String::new() } else { format!("{mid}; ") };

        // assign then (filler) then use
        let assign_first = format!("{name}={value}; {sep}foo ${name}");
        let env = constant_env(&parse(&assign_first).command);
        prop_assert_eq!(env.get(&name).map(String::as_str), Some(value.as_str()));

        // use then assign — disqualified
        let use_first = format!("foo ${name}; {sep}{name}={value}");
        let env = constant_env(&parse(&use_first).command);
        prop_assert_eq!(env.get(&name), None);
    }
}
