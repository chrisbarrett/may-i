//! Scenarios for policy-sees-redirects-and-env-prefixes: a redirect to a
//! non-standard file target floors to at least `:ask`, and a `NAME=VALUE`
//! prefix floors unless `NAME` is in the effective safe-env-vars set.

use may_i_config::parse_config;
use may_i_core::{ContextFacts, Decision};

use crate::eval::evaluate_command;

fn decide(config_src: &str, input: &str) -> crate::EvalResult {
    let config = parse_config(config_src).expect("config parses");
    evaluate_command(input, &config, &ContextFacts::default()).expect("evaluation succeeds")
}

const ECHO_GIT: &str = r#"
(rule "echo" (allow))
(rule "git" (allow))
"#;

// ── Redirect targets ────────────────────────────────────────────────

#[test]
fn write_redirect_to_file_floors_an_allow() {
    let result = decide(ECHO_GIT, "echo x > /home/u/.ssh/authorized_keys");
    assert!(
        result.decision >= Decision::Ask,
        "redirect target must not be silently ignored: {:?}",
        result.reason
    );
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("/home/u/.ssh/authorized_keys"),
        "reason must name the target: {reason}"
    );
    assert!(!reason.contains('\n'), "single-line reason: {reason:?}");
}

#[test]
fn append_clobber_and_input_redirects_floor() {
    for input in [
        "echo x >> /var/log/app.log",
        "echo x >| /tmp/out",
        "git status < /etc/shadow",
    ] {
        let result = decide(ECHO_GIT, input);
        assert!(
            result.decision >= Decision::Ask,
            "expected floor for {input:?}, got {:?} ({:?})",
            result.decision,
            result.reason
        );
    }
}

#[test]
fn standard_plumbing_does_not_floor() {
    for input in [
        "echo x 2>&1",
        "echo x > /dev/null",
        "echo x 2> /dev/null",
        "echo x > /dev/null 2>&1",
    ] {
        let result = decide(ECHO_GIT, input);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "standard plumbing must not floor for {input:?}: {:?}",
            result.reason
        );
    }
}

#[test]
fn expansion_bearing_redirect_target_floors() {
    let result = decide(ECHO_GIT, "echo x > /tmp/$NAME");
    assert!(
        result.decision >= Decision::Ask,
        "expansion-bearing target floors: {:?}",
        result.reason
    );
}

#[test]
fn quoted_dev_null_is_still_plumbing() {
    let result = decide(ECHO_GIT, "echo x > '/dev/null'");
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reason);
}

#[test]
fn heredoc_and_herestring_do_not_floor_as_redirects() {
    let config = r#"(rule "cat" (allow))"#;
    for input in ["cat <<'EOF'\nhello\nEOF\n", "cat <<< hello"] {
        let result = decide(config, input);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "stdin data feeds are not file targets for {input:?}: {:?}",
            result.reason
        );
    }
}

#[test]
fn redirect_floor_does_not_relax_deny() {
    let config = r#"(rule "rm" (deny "never"))"#;
    let result = decide(config, "rm -rf / > /tmp/log");
    assert_eq!(result.decision, Decision::Deny, "{:?}", result.reason);
}

#[test]
fn compound_redirect_on_wrapper_floors() {
    let config = r#"
(rule "true" (allow))
(rule "echo" (allow))
"#;
    let result = decide(config, "while true; do echo x; done > /tmp/out");
    assert!(
        result.decision >= Decision::Ask,
        "a compound's redirect floors too: {:?}",
        result.reason
    );
}

// ── Environment-assignment prefixes ─────────────────────────────────

#[test]
fn dangerous_env_prefix_floors_an_allow() {
    let result = decide(ECHO_GIT, "LD_PRELOAD=/evil.so git status");
    assert!(
        result.decision >= Decision::Ask,
        "non-allowlisted env prefix floors: {:?}",
        result.reason
    );
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("LD_PRELOAD"),
        "reason must name the variable: {reason}"
    );
}

#[test]
fn allowlisted_env_prefix_passes_through() {
    let config = r#"
(rule "git" (allow))
(safe-env-vars "GIT_PAGER")
"#;
    let result = decide(config, "GIT_PAGER=cat git status");
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reason);
}

#[test]
fn mixed_prefixes_floor_if_any_not_allowlisted() {
    let config = r#"
(rule "git" (allow))
(safe-env-vars "GIT_PAGER")
"#;
    let result = decide(config, "GIT_PAGER=cat LD_PRELOAD=/evil.so git status");
    assert!(
        result.decision >= Decision::Ask,
        "any non-allowlisted prefix floors: {:?}",
        result.reason
    );
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(reason.contains("LD_PRELOAD"), "reason: {reason}");
}

#[test]
fn empty_set_floors_every_prefix() {
    let result = decide(ECHO_GIT, "FOO=bar git status");
    assert!(
        result.decision >= Decision::Ask,
        "with no (safe-env-vars …) every prefix floors: {:?}",
        result.reason
    );
    let reason = result.reason.as_deref().unwrap_or("");
    assert!(reason.contains("FOO"), "reason: {reason}");
}

#[test]
fn env_prefix_value_embedded_command_still_evaluated() {
    let config = r#"
(rule "git" (allow))
(rule "rm" (deny "never"))
(safe-env-vars "GIT_PAGER")
"#;
    let result = decide(config, "GIT_PAGER=$(rm -rf /) git status");
    assert_eq!(
        result.decision,
        Decision::Deny,
        "embedded command in a prefix value is evaluated: {:?}",
        result.reason
    );
}

#[test]
fn loaded_safe_env_vars_are_inert_in_effective_set() {
    // Engine-level contract: only the primary + trusted-loaded sets count.
    // The binary's trust layer clears the loaded set when unapproved; here
    // we exercise the engine consuming a config whose loaded set is
    // populated (i.e. trusted) vs cleared.
    let mut config = parse_config(r#"(rule "git" (allow))"#).unwrap();
    config
        .security
        .loaded_safe_env_vars
        .insert("FOO".to_string());
    let result = evaluate_command("FOO=bar git status", &config, &ContextFacts::default()).unwrap();
    assert_eq!(
        result.decision,
        Decision::Allow,
        "trusted loaded entry passes through: {:?}",
        result.reason
    );

    let config = parse_config(r#"(rule "git" (allow))"#).unwrap();
    let result = evaluate_command("FOO=bar git status", &config, &ContextFacts::default()).unwrap();
    assert!(
        result.decision >= Decision::Ask,
        "absent from the effective set, the prefix floors: {:?}",
        result.reason
    );
}

// ── Properties (tasks 3.1, 3.2) ─────────────────────────────────────

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 128, max_shrink_iters: 50, .. ProptestConfig::default() })]

        /// A command with a file-target redirect (target ≠ /dev/null,
        /// not an fd dup) never evaluates to `:allow`.
        #[test]
        fn redirect_never_allows(
            target in "/[a-z][a-z0-9/._-]{0,12}",
            op in prop::sample::select(vec![">", ">>", "<", ">|"]),
        ) {
            prop_assume!(target != "/dev/null");
            let result = decide(ECHO_GIT, &format!("echo x {op} {target}"));
            prop_assert!(
                result.decision >= Decision::Ask,
                "redirect {op} {target} evaluated to {:?}",
                result.decision
            );
        }

        /// An env prefix whose name is outside the effective set never
        /// evaluates to `:allow`; the floor only raises strictness.
        #[test]
        fn unlisted_env_prefix_never_allows(
            name in "[A-Z][A-Z0-9_]{0,10}",
            value in "[a-z0-9/._-]{0,8}",
        ) {
            prop_assume!(name != "GIT_PAGER");
            let allow = decide(
                r#"(rule "git" (allow)) (safe-env-vars "GIT_PAGER")"#,
                &format!("{name}={value} git status"),
            );
            prop_assert!(
                allow.decision >= Decision::Ask,
                "prefix {name}= evaluated to {:?}",
                allow.decision
            );

            // Floors never relax a deny.
            let deny = decide(
                r#"(rule "git" (deny "no git"))"#,
                &format!("{name}={value} git status"),
            );
            prop_assert_eq!(deny.decision, Decision::Deny);
        }
    }
}

#[test]
fn structural_floors_raise_overlapping_segments() {
    let result = decide(ECHO_GIT, "echo x > /tmp/out");
    assert!(result.decision >= Decision::Ask);
    assert!(
        !result.segment_decisions.is_empty(),
        "expected a segment for the echo command"
    );
    assert!(
        result
            .segment_decisions
            .iter()
            .all(|s| s.decision >= Decision::Ask),
        "the floored command's segment must not display as allow: {:?}",
        result.segment_decisions
    );
}
