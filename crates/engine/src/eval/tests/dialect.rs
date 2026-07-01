//! Dialect threading through the engine: the resolved dialect reaches the
//! recursive re-parse of an embedded command substitution's source, so a
//! zsh-only construct inside `$(…)` is judged under zsh, not bash.

use may_i_config::parse_config;
use may_i_core::{ContextFacts, Decision, EntryEnv};
use may_i_shell_parser::Dialect;

use crate::eval::evaluate_command_with_fold_env;
use crate::fold::PureFold;

fn decide_with_dialect(config_src: &str, input: &str, dialect: Dialect) -> crate::EvalResult {
    let config = parse_config(config_src).expect("config parses");
    let mut fold = PureFold;
    evaluate_command_with_fold_env(
        input,
        &config,
        &ContextFacts::default(),
        &EntryEnv::empty(),
        dialect,
        &mut fold,
    )
    .expect("evaluation succeeds")
}

/// A glob qualifier inside `$(…)` is an `Error` under bash — which floors the
/// embedded command to at least `:ask` — but is clean under zsh. The decision
/// differing across dialects proves the dialect reaches the embedded re-parse.
#[test]
fn glob_qualifier_in_command_substitution_threads_dialect() {
    let config = r#"(rule "true" (allow)) (rule "ls" (allow))"#;
    let input = "true $(ls *(.))";

    let bash = decide_with_dialect(config, input, Dialect::Bash);
    assert_eq!(
        bash.decision,
        Decision::Ask,
        "bash embedded glob qualifier should floor to ask: {:?}",
        bash.reason
    );

    let zsh = decide_with_dialect(config, input, Dialect::Zsh);
    assert_eq!(
        zsh.decision,
        Decision::Allow,
        "zsh embedded glob qualifier should not floor: {:?}",
        zsh.reason
    );
}

/// A no-semicolon brace inside `$(…)` is not diagnosed under zsh, so the
/// embedded body evaluates by its rules rather than being floored by a parse
/// error. The body's `rm` is still surfaced (strictness preserved).
#[test]
fn no_semi_brace_in_command_substitution_evaluated_under_zsh() {
    let config = r#"(rule "true" (allow)) (rule "rm" (deny))"#;
    // The embedded body defines and does not call the function, but its `rm`
    // is still extracted and evaluated — a denied `rm` denies the aggregate.
    let input = r#"true $(cleanup() { rm -rf /tmp/x })"#;

    let zsh = decide_with_dialect(config, input, Dialect::Zsh);
    assert_eq!(
        zsh.decision,
        Decision::Deny,
        "zsh embedded body's rm should be evaluated (and denied): {:?}",
        zsh.reason
    );
}

/// The dialect is observed ground truth, never a Fact: running under
/// `Dialect::Zsh` must not inject a `:zsh` or `:dialect` fact, so a rule
/// guarded on such a fact cannot branch on the dialect. A `(fact? :zsh)`
/// guard takes its else branch under zsh exactly as under bash.
#[test]
fn dialect_is_not_reachable_as_a_fact() {
    for key in [":zsh", ":dialect"] {
        let config = format!(r#"(rule "echo" (if (fact? {key}) (allow) (deny)))"#);
        let zsh = decide_with_dialect(&config, "echo hi", Dialect::Zsh);
        assert_eq!(
            zsh.decision,
            Decision::Deny,
            "{key} must not be a fact under zsh, but the guard matched: {:?}",
            zsh.reason
        );
        // Same outcome under bash — the dialect never enters the fact set.
        let bash = decide_with_dialect(&config, "echo hi", Dialect::Bash);
        assert_eq!(
            zsh.decision, bash.decision,
            "{key}: dialect leaked into facts"
        );
    }
}

use proptest::{prop_assert_eq, proptest};

proptest! {
    /// For any allowed inner command, a glob qualifier applied to it inside
    /// `$(…)` never floors the outer decision to `:ask` under zsh — the
    /// dialect reaches the embedded re-parse and suppresses the bash error.
    #[test]
    fn prop_zsh_glob_qualifier_in_cmdsub_not_floored(
        inner in proptest::sample::select(vec!["ls", "print", "cat", "stat"]),
    ) {
        let config = format!(
            r#"(rule "true" (allow)) (rule "{inner}" (allow))"#
        );
        let input = format!("true $({inner} *(.))");
        let zsh = decide_with_dialect(&config, &input, Dialect::Zsh);
        prop_assert_eq!(
            zsh.decision,
            Decision::Allow,
            "zsh embedded qualifier floored: {:?}",
            zsh.reason
        );
    }
}
