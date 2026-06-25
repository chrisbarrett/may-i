//! Scenarios for the expansion-bearing-word requirement: a non-wildcard
//! matcher tested against a word whose runtime value is not provable from
//! its source bytes must not contribute to `:allow`; the segment floors
//! to at least `:ask` with a reason naming the unresolved word.

use may_i_config::parse_config;
use may_i_core::{ContextFacts, Decision};

use crate::eval::evaluate_command;

fn facts() -> ContextFacts {
    ContextFacts::default()
}

fn decide(config_src: &str, input: &str) -> crate::EvalResult {
    let config = parse_config(config_src).expect("config parses");
    evaluate_command(input, &config, &facts()).expect("evaluation succeeds")
}

const TMP_GUARD: &str = r#"
(parser "rm" (style gnu) (flags posix) (positional #paths (regex "^/tmp/") *))
(rule "rm" (when (every? #paths (regex "^/tmp/")) (allow "tmp only")))
"#;

#[test]
fn literal_tmp_path_still_allows() {
    let result = decide(TMP_GUARD, "rm /tmp/x");
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reason);
}

#[test]
fn parameter_expansion_defeats_tmp_guard() {
    let result = decide(TMP_GUARD, "rm /tmp/$HOME");
    assert!(
        result.decision >= Decision::Ask,
        "expected at least ask, got {:?} ({:?})",
        result.decision,
        result.reason
    );
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("/tmp/$HOME"),
        "reason should name the unresolved word: {reason}"
    );
    assert!(!reason.contains('\n'), "single-line reason: {reason:?}");
}

#[test]
fn glob_floors_tmp_guard() {
    let result = decide(TMP_GUARD, "rm /tmp/*");
    assert!(
        result.decision >= Decision::Ask,
        "expected at least ask, got {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn brace_expansion_floors_tmp_guard() {
    let result = decide(TMP_GUARD, "rm /tmp/{a,../etc}");
    assert!(
        result.decision >= Decision::Ask,
        "expected at least ask, got {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn wildcard_matcher_is_unaffected_by_expansion() {
    let config = r#"(rule "rm" (when (positional *) (allow "any single arg")))"#;
    let result = decide(config, "rm $HOME");
    assert_eq!(
        result.decision,
        Decision::Allow,
        "wildcard matches any value soundly: {:?}",
        result.reason
    );
}

#[test]
fn pure_literal_positional_matches_as_written() {
    let config = r#"(rule "rm" (when (positional "/tmp/x") (allow)))"#;
    let result = decide(config, "rm /tmp/x");
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reason);
}

#[test]
fn deny_matcher_still_fires_on_expansion() {
    let config = r#"(rule "rm" (when (anywhere (regex "secret")) (deny "no secrets")))"#;
    let result = decide(config, "rm secret$X");
    assert_eq!(
        result.decision,
        Decision::Deny,
        "deny under expansion errs toward caution: {:?}",
        result.reason
    );
}

#[test]
fn parameter_value_expansion_floors_allow() {
    let config = r#"(rule "kubectl" (when (parameter ["n" "namespace"] (regex "^dev-")) (allow "dev namespaces")))"#;
    let result = decide(config, "kubectl -n dev-$ENV get pods");
    assert!(
        result.decision >= Decision::Ask,
        "expected at least ask, got {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn parameter_value_literal_still_allows() {
    let config = r#"(rule "kubectl" (when (parameter ["n" "namespace"] (regex "^dev-")) (allow "dev namespaces")))"#;
    let result = decide(config, "kubectl -n dev-staging get pods");
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reason);
}

#[test]
fn anywhere_allow_guard_floors_on_expansion() {
    let config = r#"(rule "git" (when (anywhere "status") (allow "status only")))"#;
    // `status$X` flattens to text containing `status`… it does not — the
    // literal expr `status` must equal the whole token. Use a regex guard
    // so the textual match fires on the expansion-bearing token.
    let config_re = r#"(rule "git" (when (anywhere (regex "status")) (allow "status-ish")))"#;
    let _ = config;
    let result = decide(config_re, "git status$X");
    assert!(
        result.decision >= Decision::Ask,
        "expected at least ask, got {:?} ({:?})",
        result.decision,
        result.reason
    );
}

#[test]
fn forbidden_still_fires_on_expansion() {
    // `(forbidden …)` firing on an expansion-bearing word tightens the
    // decision (the guarded allow does not apply) — that direction is
    // allowed and must keep working.
    let config = r#"(rule "rm" (when (forbidden (regex "secret")) (allow "no secrets present")))"#;
    let result = decide(config, "rm secret$X");
    assert!(
        result.decision >= Decision::Ask,
        "forbidden must still fire on the expansion-bearing token: {:?}",
        result.reason
    );
    // And a non-firing forbidden over literal args keeps its allow.
    let result = decide(config, "rm /tmp/x");
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reason);
}

#[test]
fn matches_binding_floors_on_expansion_bearing_capture() {
    let config = r#"
(parser "ssh" (style gnu) (flags posix) (positional #host * ?))
(rule "ssh" (when (matches? #host (regex "^prod-")) (allow "prod hosts")))
"#;
    let literal = decide(config, "ssh prod-web1");
    assert_eq!(literal.decision, Decision::Allow, "{:?}", literal.reason);

    let expanded = decide(config, "ssh prod-$REGION");
    assert!(
        expanded.decision >= Decision::Ask,
        "expansion-bearing capture cannot satisfy matches? toward allow: {:?} ({:?})",
        expanded.decision,
        expanded.reason
    );
}

#[test]
fn bound_predicate_unaffected_by_expansion() {
    let config = r#"
(parser "ssh" (style gnu) (flags posix) (positional #host * ?))
(rule "ssh" (when (bound? #host) (allow "host given")))
"#;
    let result = decide(config, "ssh $HOST");
    assert_eq!(
        result.decision,
        Decision::Allow,
        "bound? tests presence, not value: {:?}",
        result.reason
    );
}

#[test]
fn deny_is_not_relaxed_by_unresolved_matches() {
    // Both a deny matcher and an allow-ward unresolved match are present;
    // uncertainty never relaxes the deny.
    let config = r#"
(rule "rm" (when (anywhere (regex "secret")) (deny "no secrets")))
(rule "rm" (when (positional (regex "^/tmp/")) (allow "tmp")))
"#;
    let result = decide(config, "rm /tmp/secret$X");
    assert_eq!(result.decision, Decision::Deny, "{:?}", result.reason);
}

// ── Asymmetric-soundness properties (tasks 4.1, 4.2) ────────────────

#[cfg(test)]
mod properties {
    use super::*;
    use proptest::prelude::*;

    /// An expansion-bearing rewrite of a literal /tmp path: each variant
    /// still *textually* satisfies a `^/tmp/` guard but its runtime value
    /// is unprovable.
    fn expansion_variants(path: &str) -> Vec<String> {
        vec![
            format!("{path}$X"),
            format!("{path}*"),
            format!("{path}{{a,b}}"),
            format!("{path}$(cmd)"),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, max_shrink_iters: 50, .. ProptestConfig::default() })]

        /// 4.1 — replacing any matched literal token with an
        /// expansion-bearing variant never moves the decision toward
        /// `:allow`.
        #[test]
        fn expansion_never_widens_toward_allow(
            stems in prop::collection::vec("[a-z0-9]{1,8}", 1..4),
            victim in 0usize..4,
        ) {
            let paths: Vec<String> =
                stems.iter().map(|s| format!("/tmp/{s}")).collect();
            let literal_cmd = format!("rm {}", paths.join(" "));
            let baseline = decide(TMP_GUARD, &literal_cmd);
            prop_assert_eq!(baseline.decision, Decision::Allow,
                "literal baseline should allow: {:?}", baseline.reason);

            let victim = victim % paths.len();
            for variant in expansion_variants(&paths[victim]) {
                let mut mutated = paths.clone();
                mutated[victim] = variant.clone();
                let cmd = format!("rm {}", mutated.join(" "));
                let result = decide(TMP_GUARD, &cmd);
                prop_assert!(
                    result.decision >= Decision::Ask,
                    "expansion variant {variant:?} widened to {:?} for {cmd:?}",
                    result.decision
                );
            }
        }

        /// 4.2 — the floor only raises strictness: a deny is unchanged
        /// by the suppression.
        #[test]
        fn deny_unchanged_by_expansion(stem in "[a-z0-9]{1,8}") {
            let config = r#"(rule "rm" (when (anywhere (regex "^/tmp/")) (deny "no tmp")))"#;
            let literal = decide(config, &format!("rm /tmp/{stem}"));
            prop_assert_eq!(literal.decision, Decision::Deny);
            for variant in expansion_variants(&format!("/tmp/{stem}")) {
                let result = decide(config, &format!("rm {variant}"));
                prop_assert_eq!(
                    result.decision,
                    Decision::Deny,
                    "deny relaxed for {}: {:?}",
                    variant,
                    result.reason
                );
            }
        }
    }
}

#[test]
fn some_binding_floors_when_only_expansion_bearing_elements_match() {
    let config = r#"
(parser "rm" (style gnu) (flags posix) (positional #paths * *))
(rule "rm" (when (some? #paths (regex "^/tmp/")) (allow "a tmp path present")))
"#;
    // A literal element matches → provable → allow stands.
    let literal = decide(config, "rm /tmp/x /etc/y");
    assert_eq!(literal.decision, Decision::Allow, "{:?}", literal.reason);

    // Only an expansion-bearing element matches → unprovable → floors.
    let expanded = decide(config, "rm /tmp/$HOME /etc/y");
    assert!(
        expanded.decision >= Decision::Ask,
        "some? satisfied only by an expansion-bearing element floors: {:?} ({:?})",
        expanded.decision,
        expanded.reason
    );
}

#[test]
fn authorised_token_list_with_expansion_bearing_command_name_asks() {
    // `ssh host $CMD` — the rest binding's first token is expansion-
    // bearing; its flattened text (`CMD`) is not the runtime command.
    let config = r#"
(parser "ssh" (style gnu) (flags posix) (positional #host * ?) (rest #cmd))
(rule "ssh" (when (bound? #cmd) (authorise #cmd)))
(rule "CMD" (allow))
(rule "echo" (allow))
"#;
    let literal = decide(config, "ssh host echo hi");
    assert_eq!(literal.decision, Decision::Allow, "{:?}", literal.reason);

    let expanded = decide(config, "ssh host $CMD hi");
    assert!(
        expanded.decision >= Decision::Ask,
        "expansion-bearing inner command name must not resolve to a literal rule: {:?} ({:?})",
        expanded.decision,
        expanded.reason
    );
}

#[test]
fn authorised_single_token_expansion_cannot_allow() {
    let config = r#"
(parser "ssh" (style gnu) (flags posix) (positional #host * ?) (rest #cmd))
(rule "ssh" (when (bound? #cmd) (authorise #cmd)))
(rule "true" (allow))
"#;
    // Single rest token, expansion-bearing: flattened text re-parses as
    // `true` (allowed) but the runtime command is unknown.
    let result = decide(config, "ssh host true$X");
    assert!(
        result.decision >= Decision::Ask,
        "single-token expansion-bearing recursion cannot allow: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

// ── Bash-array modelling (model-bash-arrays) ────────────────────────────

/// Spec scenario: an unresolved subscripted expansion floors an allow.
/// `aws s3 cp "${parts[@]}" /tmp/x` with a rule that would allow `aws` only
/// for a constrained source: the subscripted `${parts[@]}` is
/// expansion-bearing and unresolved, so it cannot satisfy the constraint and
/// the `:allow` floors to `:ask` (no value resolution in this change).
#[test]
fn unresolved_subscript_floors_an_allow() {
    // The regex matches the flattened `parts[@]` prefix, so the matcher
    // *attempts* the word and then floors on its unresolved expansion — the
    // same path a plain unknown scalar takes.
    let config = r#"(rule "aws" (when (anywhere (regex "parts")) (allow "constrained")))"#;
    let result = decide(config, r#"aws s3 cp "${parts[@]}" /tmp/x"#);
    assert!(
        result.decision >= Decision::Ask,
        "subscripted expansion must floor the allow: {:?} ({:?})",
        result.decision,
        result.reason
    );
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("unresolved shell expansion"),
        "expected an unresolved-expansion floor naming the array reference: {reason:?}"
    );
}

/// The trailing command after an array literal is evaluated (no silent
/// discard): `arr=(a b c); rm -rf /` must surface the `rm` segment, here
/// gated by a deny rule, rather than dropping it as the pre-change parser did.
#[test]
fn command_after_array_literal_is_evaluated() {
    let config = r#"(rule "rm" (deny "no rm"))"#;
    let result = decide(config, "arr=(a b c); rm -rf /");
    assert_eq!(
        result.decision,
        Decision::Deny,
        "trailing rm after an array literal must be evaluated: {:?}",
        result.reason
    );
}

/// An array element that is a command substitution is gated exactly as a
/// scalar `x=$(cmd)` is (design D4): `arr=($(rm -rf /))` extracts the
/// embedded command as its own evaluation unit.
#[test]
fn array_element_substitution_is_gated() {
    let config = r#"(rule "rm" (deny "no rm")) (rule "echo" (allow))"#;
    let result = decide(config, "arr=($(rm -rf /)); echo done");
    assert_eq!(
        result.decision,
        Decision::Deny,
        "embedded command in an array element must be gated: {:?}",
        result.reason
    );
}

/// A command substitution inside an array subscript must be gated, exactly as
/// one in any other word position (design D4): `echo ${arr[$(rm -rf /)]}` runs
/// the `rm` (bash arithmetic-evaluates the subscript), so the substitution must
/// surface as its own evaluation unit and the deny rule must fire. Covers the
/// `$(…)` and backtick spellings.
#[test]
fn command_substitution_in_subscript_is_gated() {
    let config = r#"(rule "rm" (deny "no rm")) (rule "echo" (allow))"#;
    for cmd in [
        "echo ${arr[$(rm -rf /)]}",
        "echo ${arr[`rm -rf /`]}",
        "echo ${#arr[$(rm -rf /)]}",
    ] {
        let result = decide(config, cmd);
        assert_eq!(
            result.decision,
            Decision::Deny,
            "embedded command in a subscript must be gated for {cmd:?}: {:?}",
            result.reason
        );
    }
}

/// A mixed subscript combining literal text, a command substitution, and a
/// parameter (`${arr[foo-$(rm -rf /)-$BAR]}`) gates the embedded command — the
/// subscript Word has several parts, so the fix must recurse into all of them,
/// not just a lone substitution.
#[test]
fn mixed_subscript_gates_embedded_command() {
    let config = r#"(rule "rm" (deny "no rm")) (rule "echo" (allow))"#;
    let result = decide(config, "echo ${arr[foo-$(rm -rf /)-$BAR]}");
    assert_eq!(
        result.decision,
        Decision::Deny,
        "embedded command in a mixed subscript must be gated: {:?}",
        result.reason
    );
}

/// The parameter read in a mixed subscript (`${arr[foo-$BAR]}`) is taint-scanned
/// like any other argv read.
#[test]
fn mixed_subscript_taints_parameter_read() {
    let config = r#"(rule "echo" (allow)) (env "AWS_TOKEN" (deny))"#;
    let result = decide(config, "echo ${arr[foo-$AWS_TOKEN]}");
    assert_eq!(
        result.decision,
        Decision::Deny,
        "secret read in a mixed subscript must taint: {:?}",
        result.reason
    );
}

/// A command substitution in an operator operand of a *subscripted* expansion
/// (`${arr[@]:-$(rm -rf /)}`) must be gated. The non-subscripted
/// `${VAR:-$(rm)}` is gated; the subscripted form must not fall to an
/// unstructured flat expansion that buries the substitution.
#[test]
fn substitution_in_subscripted_operator_operand_is_gated() {
    let config = r#"(rule "rm" (deny "no rm")) (rule "echo" (allow))"#;
    for cmd in [
        "echo ${arr[@]:-$(rm -rf /)}",
        "echo ${arr[0]:-$(rm -rf /)}",
        "echo ${arr[*]#$(rm -rf /)}",
    ] {
        let result = decide(config, cmd);
        assert_eq!(
            result.decision,
            Decision::Deny,
            "embedded command in a subscripted operator operand must be gated for {cmd:?}: {:?}",
            result.reason
        );
    }
}

/// A command substitution inside a subscript that *also* carries an operator
/// whose operand is read structurally (`${arr[$(rm -rf /)]:-x}`, `#`, …) must
/// still be gated: bash arithmetic-evaluates the subscript regardless of the
/// operator. The subscript-fold carries the subscript's embedded substitutions
/// into the operator op so they are gated.
#[test]
fn substitution_in_subscript_with_operator_is_gated() {
    let config = r#"(rule "rm" (deny "no rm")) (rule "echo" (allow))"#;
    for cmd in [
        "echo ${arr[$(rm -rf /)]:-x}",
        "echo ${arr[$(rm -rf /)]#foo}",
        "echo ${arr[`rm -rf /`]:-x}",
        "echo ${arr[$(rm -rf /)]:-$(rm -rf /)}",
    ] {
        let result = decide(config, cmd);
        assert_eq!(
            result.decision,
            Decision::Deny,
            "embedded command in a subscript-with-operator must be gated for {cmd:?}: {:?}",
            result.reason
        );
    }
}

/// A command substitution buried in a flat parameter-expansion form — patterned
/// case-conversion (`${x^$(cmd)}`, `${x,,$(cmd)}`), transform/unknown operator
/// (`${x@Q$(cmd)}`), or indirect/nameref (`${!$(cmd)}`) — runs in bash, so it
/// must be gated. These forms stay unresolved (they floor `:allow`); the fix
/// makes the buried substitution visible, not the value resolvable.
#[test]
fn substitution_in_flat_parameter_expansion_is_gated() {
    let config = r#"(rule "rm" (deny "no rm")) (rule "echo" (allow))"#;
    for cmd in [
        "echo ${x^$(rm -rf /)}",
        "echo ${x^^$(rm -rf /)}",
        "echo ${x,$(rm -rf /)}",
        "echo ${x,,$(rm -rf /)}",
        "echo ${x@Q$(rm -rf /)}",
        "echo ${x@a$(rm -rf /)}",
        "echo ${!$(rm -rf /)}",
    ] {
        let result = decide(config, cmd);
        assert_eq!(
            result.decision,
            Decision::Deny,
            "embedded command in a flat parameter expansion must be gated for {cmd:?}: {:?}",
            result.reason
        );
    }
}

/// A command substitution inside a glob bracket (`echo [$(rm -rf /)]`) runs:
/// bash performs command substitution before pathname globbing, so the command
/// must be gated rather than swallowed into the glob pattern text. Covers the
/// `$(…)` and backtick spellings.
#[test]
fn substitution_in_glob_bracket_is_gated() {
    let config = r#"(rule "rm" (deny "no rm")) (rule "echo" (allow))"#;
    for cmd in ["echo [$(rm -rf /)]", "echo [`rm -rf /`]"] {
        let result = decide(config, cmd);
        assert_eq!(
            result.decision,
            Decision::Deny,
            "embedded command in a glob bracket must be gated for {cmd:?}: {:?}",
            result.reason
        );
    }
}

/// An indirect expansion floors an `:allow`: its runtime value is unknown, so
/// the word is expansion-bearing and a non-wildcard matcher tested against it
/// must not be satisfied on the strength of the literal text (ADDED spec
/// scenario "Indirect expansion floors an allow").
#[test]
fn indirect_expansion_floors_allow() {
    let config = r#"(rule "echo" (when (anywhere "ref") (allow "matched literal")))"#;
    let result = decide(config, "echo ${!ref}");
    assert!(
        result.decision >= Decision::Ask,
        "indirect expansion must not satisfy a non-wildcard allow on its literal text: {:?} ({:?})",
        result.decision,
        result.reason
    );
}

/// An indirect expansion does not taint its literal name: `${!AWS_TOKEN}` reads
/// the variable *named by* `$AWS_TOKEN`, not `AWS_TOKEN` itself, so a secret-read
/// capability on `AWS_TOKEN` must not fire. (The form still floors an `:allow` as
/// expansion-bearing — asserted by the parser tests — but it is not a read of the
/// literal name.)
#[test]
fn indirect_expansion_does_not_taint_literal_name() {
    let config = r#"(rule "echo" (allow)) (env "AWS_TOKEN" (deny))"#;
    let result = decide(config, "echo ${!AWS_TOKEN}");
    assert_ne!(
        result.decision,
        Decision::Deny,
        "indirect ${{!AWS_TOKEN}} must not taint the literal name: {:?}",
        result.reason
    );
}

/// Secret-read taint reaches the operand of a transform / unknown operator:
/// bash parameter-expands such operand text, so a `$AWS_TOKEN` smuggled there
/// is a read and must deny. Locks the `Transform`/`Unknown` operand scan in
/// `operator_operands` against regression — these forms keep a bare `$NAME` as
/// verbatim operand text (not in `embedded`), so this scan is the only thing
/// that gates it. Conservative: the scan over-approximates toward tainting.
#[test]
fn taint_fires_in_transform_and_unknown_operands() {
    let config = r#"(rule "echo" (allow)) (env "AWS_TOKEN" (deny))"#;
    for cmd in ["echo ${x@Q$AWS_TOKEN}", "echo ${x.$AWS_TOKEN}"] {
        let result = decide(config, cmd);
        assert_eq!(
            result.decision,
            Decision::Deny,
            "secret read in a transform/unknown operand must taint for {cmd:?}: {:?}",
            result.reason
        );
    }
}

/// An indirect array-key expansion taints a secret read in its *subscript*:
/// `${!arr[$AWS_TOKEN]}` reads the variable named indirectly (not `arr`), but
/// bash arithmetic-evaluates the subscript, so `$AWS_TOKEN` there is a genuine
/// read and must deny. (The literal indirect name itself is still not tainted —
/// see `indirect_expansion_does_not_taint_literal_name`.)
#[test]
fn indirect_array_key_subscript_taints_secret_read() {
    let config = r#"(rule "echo" (allow)) (env "AWS_TOKEN" (deny))"#;
    for cmd in ["echo ${!arr[$AWS_TOKEN]}", "echo ${!arr[$AWS_TOKEN-x]}"] {
        let result = decide(config, cmd);
        assert_eq!(
            result.decision,
            Decision::Deny,
            "secret read in an indirect array-key subscript must taint for {cmd:?}: {:?}",
            result.reason
        );
    }
}

/// Secret-read taint reaches the *pattern* of a patterned case-conversion:
/// bash parameter-expands the pattern, so `${x^$AWS_TOKEN}` reads the tainted
/// variable and must deny under an `(env … (deny))` capability.
#[test]
fn taint_fires_in_case_conversion_pattern() {
    let config = r#"(rule "echo" (allow)) (env "AWS_TOKEN" (deny))"#;
    let result = decide(config, "echo ${x^$AWS_TOKEN}");
    assert_eq!(
        result.decision,
        Decision::Deny,
        "secret read in a case-conversion pattern must taint: {:?}",
        result.reason
    );
}

/// Secret-read taint reaches an operator operand of a subscripted expansion:
/// `${arr[@]:-$AWS_TOKEN}` reads the tainted variable just as `${VAR:-$AWS_TOKEN}`
/// does, so it must deny under an `(env … (deny))` capability.
#[test]
fn taint_fires_on_subscripted_operator_operand() {
    let config = r#"(rule "echo" (allow)) (env "AWS_TOKEN" (deny))"#;
    let result = decide(config, "echo ${arr[@]:-$AWS_TOKEN}");
    assert_eq!(
        result.decision,
        Decision::Deny,
        "secret read in a subscripted operator operand must taint: {:?}",
        result.reason
    );
}

use proptest::prelude::*;

/// Array-ish fragments mirroring the parser fuzz corpus — the shapes the
/// evaluator must accept (model or coarsely diagnose) without panicking.
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
    "${arr[@]}",
    "${arr[*]}",
    "${arr[0]}",
    "${#arr[@]}",
    "${arr[$i]}",
    "${arr[$(date)]}",
    "${arr[foo-$(date)-$BAR]}",
    "${arr[@]:-$(date)}",
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
    "rm -rf /",
];

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, max_shrink_iters: 64, .. ProptestConfig::default() })]

    /// Invariant (b), evaluator side: `evaluate_command` never panics on
    /// arbitrary array-ish input (design "parser/eval must not panic on
    /// arbitrary input"). A representative config exercises rule matching,
    /// taint, and recursion against the new AST nodes.
    #[test]
    fn prop_evaluate_never_panics_on_array_ish(
        frags in proptest::collection::vec(proptest::sample::select(ARRAY_ISH), 0..10),
    ) {
        let input = frags.join(" ");
        let config = parse_config(
            r#"(rule "echo" (allow)) (rule "rm" (deny)) (env "AWS_TOKEN" (deny))"#,
        )
        .expect("config parses");
        // Must return Ok (or a graceful Err) — never panic/unwind.
        let _ = evaluate_command(&input, &config, &facts());
    }
}
