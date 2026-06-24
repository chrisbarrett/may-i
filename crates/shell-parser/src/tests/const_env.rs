use crate::*;
use proptest::prelude::*;
use std::collections::HashMap;

fn env_of(input: &str) -> HashMap<String, ConstValue> {
    constant_env(&parse(input).command)
}

/// Build an expected constant env of scalar bindings.
fn scalars(pairs: &[(&str, &str)]) -> HashMap<String, ConstValue> {
    pairs
        .iter()
        .map(|(n, v)| (n.to_string(), ConstValue::Scalar(v.to_string())))
        .collect()
}

#[test]
fn single_static_assignment_qualifies() {
    let env = env_of("BIN=./x; $BIN run");
    assert_eq!(env, scalars(&[("BIN", "./x")]));
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
    assert_eq!(env, scalars(&[("VAR", "./x")]));
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
    assert_eq!(env, scalars(&[("BIN", "./x")]));
}

// -- Task 1: statically-enumerable `for` loops --

/// The enumerable value set of the first `for` loop in `input`, resolved
/// against the command's constant env, or `None` when the loop is not
/// statically enumerable.
fn for_values(input: &str) -> Option<Vec<String>> {
    let cmd = parse(input).command;
    let env = constant_env(&cmd);
    let mut found = None;
    fn walk(
        cmd: &Command,
        env: &HashMap<String, ConstValue>,
        found: &mut Option<Option<Vec<String>>>,
    ) {
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

#[test]
fn prefix_assignment_of_loop_var_in_body_is_not_enumerable() {
    // `k=x cmd` inside the body rebinds the loop variable for that command's
    // environment — conservatively disqualifies the loop.
    assert_eq!(for_values("for k in a b; do k=x rm $k; done"), None);
}

#[test]
fn export_of_loop_var_in_body_is_not_enumerable() {
    // `export k=x` inside the body reassigns the loop variable.
    assert_eq!(for_values("for k in a b; do export k=x; rm $k; done"), None);
}

#[test]
fn unrelated_export_in_body_stays_enumerable() {
    // An `export` of a *different* variable does not disqualify the loop.
    assert_eq!(
        for_values("for k in a b; do export OTHER=x; rm $k; done"),
        Some(vec!["a".to_string(), "b".to_string()])
    );
}

// -- Security C2: rebinding builtins in the body disqualify the loop --

#[test]
fn read_into_loop_var_is_not_enumerable() {
    // `read k` rewrites the loop variable from stdin — unprovable.
    assert_eq!(
        for_values("for k in a b; do read k; rm /data/$k; done"),
        None
    );
    assert_eq!(
        for_values("for k in a b; do read a k c; rm /data/$k; done"),
        None
    );
}

#[test]
fn read_array_flag_into_loop_var_is_not_enumerable() {
    assert_eq!(
        for_values("for k in a b; do read -a k; rm /data/$k; done"),
        None
    );
}

#[test]
fn mapfile_and_readarray_into_loop_var_are_not_enumerable() {
    assert_eq!(
        for_values("for k in a b; do mapfile k; rm /data/$k; done"),
        None
    );
    assert_eq!(
        for_values("for k in a b; do readarray k < f; rm /data/$k; done"),
        None
    );
}

#[test]
fn printf_v_into_loop_var_is_not_enumerable() {
    assert_eq!(
        for_values("for k in a b; do printf -v k pwned; rm /data/$k; done"),
        None
    );
    assert_eq!(
        for_values("for k in a b; do printf -vk pwned; rm /data/$k; done"),
        None
    );
}

#[test]
fn declaration_builtins_into_loop_var_are_not_enumerable() {
    for kw in ["declare", "typeset", "local", "readonly"] {
        assert_eq!(
            for_values(&format!("for k in a b; do {kw} k=pwned; rm /data/$k; done")),
            None,
            "{kw} k=pwned must disqualify"
        );
    }
}

#[test]
fn getopts_into_loop_var_is_not_enumerable() {
    assert_eq!(
        for_values("for k in a b; do getopts xy k; rm /data/$k; done"),
        None
    );
}

#[test]
fn let_assignment_to_loop_var_is_not_enumerable() {
    assert_eq!(
        for_values("for k in a b; do let k=5; rm /data/$k; done"),
        None
    );
    assert_eq!(
        for_values("for k in a b; do let \"k += 1\"; rm /data/$k; done"),
        None
    );
}

#[test]
fn unrelated_rebinding_builtins_stay_enumerable() {
    // The same builtins targeting a *different* variable must not disqualify —
    // guard against over-rejection collapsing the feature.
    assert_eq!(
        for_values("for k in a b; do read other; rm /data/$k; done"),
        Some(vec!["a".to_string(), "b".to_string()])
    );
    assert_eq!(
        for_values("for k in a b; do printf -v other x; rm /data/$k; done"),
        Some(vec!["a".to_string(), "b".to_string()])
    );
    assert_eq!(
        for_values("for k in a b; do declare other=x; rm /data/$k; done"),
        Some(vec!["a".to_string(), "b".to_string()])
    );
    assert_eq!(
        for_values("for k in a b; do let other=5; rm /data/$k; done"),
        Some(vec!["a".to_string(), "b".to_string()])
    );
    // A flagless `read` with no operands writes REPLY, not the loop var.
    assert_eq!(
        for_values("for k in a b; do read; rm /data/$k; done"),
        Some(vec!["a".to_string(), "b".to_string()])
    );
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
        prop_assert_eq!(env.get(&name), Some(&ConstValue::Scalar(value.clone())));

        // use then assign — disqualified
        let use_first = format!("foo ${name}; {sep}{name}={value}");
        let env = constant_env(&parse(&use_first).command);
        prop_assert_eq!(env.get(&name), None);
    }
}

// -- Constant-array analysis (D1) --

/// The constant value bound to `name` in `input`'s constant env, or `None`.
fn value_of(input: &str, name: &str) -> Option<ConstValue> {
    env_of(input).get(name).cloned()
}

#[test]
fn literal_array_qualifies_as_constant() {
    assert_eq!(
        value_of("arr=(a b c); cmd \"${arr[@]}\"", "arr"),
        Some(ConstValue::Array(vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string()
        ]))
    );
}

#[test]
fn empty_array_qualifies() {
    assert_eq!(
        value_of("arr=(); cmd", "arr"),
        Some(ConstValue::Array(vec![]))
    );
}

#[test]
fn append_disqualifies_array() {
    // `arr+=(d)` parses as a second array assignment to `arr` — a second
    // occurrence disqualifies it.
    assert_eq!(
        value_of("arr=(a b); arr+=(d); cmd \"${arr[@]}\"", "arr"),
        None
    );
}

#[test]
fn scalar_append_disqualifies() {
    // `arr+=foo` (scalar append) is detected as a mutating command word.
    assert_eq!(value_of("arr=(a b); arr+=foo; cmd", "arr"), None);
}

#[test]
fn element_assignment_disqualifies_array() {
    assert_eq!(
        value_of("arr=(a b); arr[1]=x; cmd \"${arr[@]}\"", "arr"),
        None
    );
}

#[test]
fn element_append_disqualifies_array() {
    assert_eq!(
        value_of("arr=(a b); arr[1]+=x; cmd \"${arr[@]}\"", "arr"),
        None
    );
}

#[test]
fn unset_element_disqualifies_array() {
    assert_eq!(
        value_of("arr=(a b); unset 'arr[0]'; cmd \"${arr[@]}\"", "arr"),
        None
    );
}

#[test]
fn unset_whole_array_disqualifies() {
    assert_eq!(
        value_of("arr=(a b); unset arr; cmd \"${arr[@]}\"", "arr"),
        None
    );
}

#[test]
fn nonliteral_element_disqualifies_array() {
    assert_eq!(
        value_of("arr=(a $(hostname) c); cmd \"${arr[@]}\"", "arr"),
        None
    );
}

#[test]
fn glob_element_disqualifies_array() {
    // An unquoted glob element is glob-expanded by bash at runtime — not a
    // provable literal.
    assert_eq!(value_of("arr=(a *.txt c); cmd \"${arr[@]}\"", "arr"), None);
}

#[test]
fn variable_element_disqualifies_array() {
    assert_eq!(value_of("arr=(a $x c); cmd \"${arr[@]}\"", "arr"), None);
}

#[test]
fn associative_array_is_disqualified() {
    // `declare -A` records an associative array (unspecified element order);
    // it must never become a constant the resolver could order.
    assert_eq!(
        value_of("declare -A m=([a]=1 [b]=2); cmd \"${m[@]}\"", "m"),
        None
    );
}

#[test]
fn array_inside_conditional_does_not_qualify() {
    assert_eq!(value_of("if true; then arr=(a b); fi", "arr"), None);
}

#[test]
fn use_before_array_assignment_disqualifies() {
    // `"${arr[@]}"` reads `arr` before its sole assignment — the value there is
    // the inherited environment, not `(a b)` (D2).
    assert_eq!(value_of("cmd \"${arr[@]}\"; arr=(a b)", "arr"), None);
}
