// Config validation — run embedded checks against the engine.

use crate::{DisplaySafe, EvalResult};
use may_i_core::ast::{Check, Config};
use may_i_core::{ContextFacts, Decision};
use may_i_shell_parser::{self as parser, Command};

/// Result of evaluating a single embedded check.
#[derive(Debug)]
pub struct CheckResult<T = ()> {
    pub command: String,
    pub expected: Decision,
    pub actual: Decision,
    pub passed: bool,
    pub context: ContextFacts,
    /// Stringified from the evaluation's escaped [`crate::DisplaySafe`] (or a
    /// fixed check-status literal); never raw, attacker-derived input.
    pub reason: Option<String>,
    pub extra: T,
}

/// Result of parsing a check command string.
pub(crate) enum ParsedCheck {
    /// A simple command with name and arguments.
    Simple(String, Vec<String>),
    /// An empty or assignment-only command.
    Empty,
    /// A compound command (not yet supported).
    Compound,
}

/// Parse a check command string into its components.
pub(crate) fn parse_check_command(input: &str) -> ParsedCheck {
    if let Some((cmd_name, args)) = parser::parse_simple_command(input) {
        ParsedCheck::Simple(cmd_name, args)
    } else {
        match parser::parse(input).command {
            Command::Simple(_) | Command::Assignment(_) => ParsedCheck::Empty,
            Command::Pipeline(_)
            | Command::And(_, _)
            | Command::Or(_, _)
            | Command::Sequence(_)
            | Command::Background(_)
            | Command::Subshell(_)
            | Command::BraceGroup(_)
            | Command::If { .. }
            | Command::For { .. }
            | Command::Loop { .. }
            | Command::Case { .. }
            | Command::FunctionDef { .. }
            | Command::Redirected { .. } => ParsedCheck::Compound,
        }
    }
}

/// Evaluate a simple shell command string using the default evaluator.
fn evaluate_simple(input: &str, config: &Config, context: &ContextFacts) -> EvalResult {
    match parse_check_command(input) {
        ParsedCheck::Simple(cmd_name, args) => {
            match crate::eval::evaluate(&cmd_name, &args, config, context) {
                Ok(result) => result,
                Err(e) => EvalResult::new(Decision::Deny, Some(DisplaySafe::new(e.to_string()))),
            }
        }
        ParsedCheck::Empty => EvalResult::new(Decision::Allow, None),
        ParsedCheck::Compound => EvalResult::new(
            Decision::Ask,
            Some(DisplaySafe::new(
                "Compound commands not yet supported in checks",
            )),
        ),
    }
}

/// Run all embedded checks from config, using a caller-provided evaluation
/// function. The function receives the full `Check` and returns
/// `(EvalResult, T)` where `T` is any extra data the caller wants to attach
/// (e.g. trace output, location info). Returns `Err` if the evaluation function fails.
pub fn run_checks_with<T, E>(
    config: &Config,
    mut eval_fn: impl FnMut(&Check) -> Result<(EvalResult, T), E>,
) -> Result<Vec<CheckResult<T>>, E> {
    let mut results = Vec::new();

    let checks = config
        .rules
        .iter()
        .flat_map(|rule| rule.checks.iter())
        .chain(config.checks.iter());

    for check in checks {
        let (eval, extra) = eval_fn(check)?;
        results.push(CheckResult {
            command: check.command.clone(),
            expected: check.expected,
            actual: eval.decision,
            passed: eval.decision == check.expected,
            context: check.context.clone(),
            reason: eval.reason.map(|r| r.to_string()),
            extra,
        });
    }

    Ok(results)
}

/// Names of `(env NAME …)` capabilities whose decision is **scope-dependent**
/// (it consults a `(scope …)` predicate) but for which no `(check …)` case
/// declares `NAME` in a `(with-env …)`. The hermetic default entry environment
/// is empty, so such a rule's reaching-write branch is never exercised — most
/// of the always-exported dangerous names (`PATH`, `LD_*`, …) the rule guards.
/// Used to emit a non-failing `warn`-level advisory from `may-i check`.
///
/// Coverage is measured as "the name appears in some check's `(with-env …)`".
/// This is a deliberate heuristic: a check that exercises the reaching-write
/// branch via a prefix or `export` (which reach unconditionally, needing no
/// `(with-env …)`) is not counted, so such a rule may still be advised. The
/// advisory is non-failing, and `(with-env …)` is the intended way to test the
/// entry-environment-dependent branch, so this errs toward a reminder.
pub fn untested_scope_env_rules(config: &Config) -> Vec<String> {
    use std::collections::BTreeSet;

    let entry_envs: Vec<&may_i_core::EntryEnv> = config
        .rules
        .iter()
        .flat_map(|rule| rule.checks.iter())
        .chain(config.checks.iter())
        .map(|c| &c.entry_env)
        .collect();
    let covered = |name: &str| entry_envs.iter().any(|env| env.contains(name));

    // A `(scope …)` can be reached through a `(define …)`, so resolve named
    // references against the define table when scanning capability decisions.
    let defines: std::collections::HashMap<&str, &may_i_core::ast::Predicate> = config
        .defines
        .iter()
        .map(|d| (d.name.as_str(), &d.predicate.value))
        .collect();

    let mut untested = BTreeSet::new();
    for cap in config
        .security
        .env_caps
        .iter()
        .chain(config.security.loaded_env_caps.iter())
    {
        if effect_uses_scope(&cap.decision.value, &defines) && !covered(&cap.name) {
            untested.insert(cap.name.clone());
        }
    }
    untested.into_iter().collect()
}

/// Whether a capability decision consults a `(scope …)` predicate anywhere
/// (resolving `(define …)` references).
fn effect_uses_scope(
    effect: &may_i_core::ast::Effect,
    defines: &std::collections::HashMap<&str, &may_i_core::ast::Predicate>,
) -> bool {
    use may_i_core::ast::Effect;
    match effect {
        Effect::When { predicate, effect } | Effect::Unless { predicate, effect } => {
            predicate_uses_scope(&predicate.value, defines, &mut Vec::new())
                || effect_uses_scope(&effect.value, defines)
        }
        Effect::If {
            predicate,
            then_effect,
            else_effect,
        } => {
            predicate_uses_scope(&predicate.value, defines, &mut Vec::new())
                || effect_uses_scope(&then_effect.value, defines)
                || effect_uses_scope(&else_effect.value, defines)
        }
        Effect::Cond { branches, fallback } => {
            branches.iter().any(|(p, b)| {
                predicate_uses_scope(&p.value, defines, &mut Vec::new())
                    || effect_uses_scope(&b.value, defines)
            }) || fallback
                .as_ref()
                .is_some_and(|fb| effect_uses_scope(&fb.value, defines))
        }
        Effect::And { effects } | Effect::Or { effects } => {
            effects.iter().any(|e| effect_uses_scope(&e.value, defines))
        }
        Effect::Not { effect } => effect_uses_scope(&effect.value, defines),
        Effect::Terminal { .. }
        | Effect::CommandPattern(_)
        | Effect::ArgPattern(_)
        | Effect::Authorise { .. } => false,
    }
}

fn predicate_uses_scope<'a>(
    pred: &'a may_i_core::ast::Predicate,
    defines: &std::collections::HashMap<&'a str, &'a may_i_core::ast::Predicate>,
    seen: &mut Vec<&'a str>,
) -> bool {
    use may_i_core::ast::Predicate;
    #[allow(clippy::wildcard_enum_match_arm)]
    match pred {
        Predicate::Scope(_) => true,
        Predicate::And(preds) | Predicate::Or(preds) => {
            preds.iter().any(|p| predicate_uses_scope(p, defines, seen))
        }
        Predicate::Not(inner) => predicate_uses_scope(inner, defines, seen),
        Predicate::Named(name) => {
            if seen.contains(&name.as_str()) {
                return false; // cycle guard
            }
            defines.get(name.as_str()).is_some_and(|resolved| {
                seen.push(name.as_str());
                let uses = predicate_uses_scope(resolved, defines, seen);
                seen.pop();
                uses
            })
        }
        _ => false,
    }
}

/// Run all embedded checks using the default evaluator (no extra data).
pub fn run_checks(config: &Config) -> Vec<CheckResult> {
    run_checks_with(config, |check| {
        Ok::<_, std::convert::Infallible>((
            evaluate_simple(&check.command, config, &check.context),
            (),
        ))
    })
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::ast::{Check, Config, Effect, Rule};
    use may_i_core::pattern::CommandPattern;
    use may_i_core::{Decision, Span};

    #[test]
    fn untested_scope_rule_is_reported() {
        let config =
            may_i_config::parse_config(r#"(env "PATH" (when (scope reaches-child) (ask)))"#)
                .expect("parses");
        assert_eq!(untested_scope_env_rules(&config), vec!["PATH".to_string()]);
    }

    #[test]
    fn scope_rule_with_with_env_coverage_is_not_reported() {
        let config = may_i_config::parse_config(
            r#"
            (env "PATH" (when (scope reaches-child) (ask)))
            (check (with-env ["PATH"] (ask "PATH=/evil:$PATH")))
            "#,
        )
        .expect("parses");
        assert!(untested_scope_env_rules(&config).is_empty());
    }

    #[test]
    fn scope_in_if_branch_is_detected() {
        let config =
            may_i_config::parse_config(r#"(env "PATH" (if (scope reaches-child) (ask) (allow)))"#)
                .expect("parses");
        assert_eq!(untested_scope_env_rules(&config), vec!["PATH".to_string()]);
    }

    #[test]
    fn scope_nested_in_and_is_detected() {
        let config = may_i_config::parse_config(
            r#"(env "PATH" (when (and (scope bare) (not (fact? :ci))) (deny)))"#,
        )
        .expect("parses");
        assert_eq!(untested_scope_env_rules(&config), vec!["PATH".to_string()]);
    }

    #[test]
    fn scope_via_define_is_detected() {
        // A (scope …) reached through a (define …) must still be flagged as
        // untested when no (with-env …) covers the name.
        let config = may_i_config::parse_config(
            r#"(define reaches (scope reaches-child)) (env "PATH" (when reaches (ask)))"#,
        )
        .expect("parses");
        assert_eq!(untested_scope_env_rules(&config), vec!["PATH".to_string()]);
    }

    #[test]
    fn non_scope_env_rule_is_not_reported() {
        // A plain (env NAME (deny)) does not depend on (scope …), so it is not
        // a scope-dependent rule and needs no with-env coverage.
        let config = may_i_config::parse_config(r#"(env "AWS_TOKEN" (deny))"#).expect("parses");
        assert!(untested_scope_env_rules(&config).is_empty());
    }

    fn create_test_rule(name: &str, effect: Effect) -> Rule {
        use may_i_core::ast::Spanned;
        Rule {
            command_effect: Spanned::new(
                Effect::CommandPattern(CommandPattern::Literal(name.into())),
                Span::new(0, 0),
            ),
            effect: Spanned::new(effect, Span::new(0, 0)),
            checks: vec![],
            span: Span::new(0, 0),
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        }
    }

    #[test]
    fn run_checks_passing() {
        let config = Config {
            rules: vec![create_test_rule(
                "ls",
                Effect::Terminal {
                    decision: Decision::Allow,
                    reason: Some("listed".into()),
                },
            )],
            ..Config::default()
        };

        let check = Check {
            command: "ls -la".into(),
            expected: Decision::Allow,
            context: ContextFacts::default(),
            entry_env: may_i_core::EntryEnv::empty(),
            span: Span::new(0, 0),
        };

        let eval = evaluate_simple(&check.command, &config, &check.context);
        assert_eq!(eval.decision, Decision::Allow);
    }

    #[test]
    fn run_checks_failing() {
        let config = Config {
            rules: vec![create_test_rule(
                "ls",
                Effect::Terminal {
                    decision: Decision::Deny,
                    reason: Some("denied".into()),
                },
            )],
            ..Config::default()
        };

        let check = Check {
            command: "ls".into(),
            expected: Decision::Allow,
            context: ContextFacts::default(),
            entry_env: may_i_core::EntryEnv::empty(),
            span: Span::new(0, 0),
        };

        let eval = evaluate_simple(&check.command, &config, &check.context);
        assert_eq!(eval.decision, Decision::Deny);
    }

    #[test]
    fn compound_command_returns_ask() {
        let config = Config::default();
        let facts = ContextFacts::default();
        let eval = evaluate_simple("ls && rm -rf /", &config, &facts);
        assert_eq!(eval.decision, Decision::Ask);
        assert!(eval.reason.unwrap().contains("Compound"));
    }

    #[test]
    fn empty_command_returns_allow() {
        let config = Config::default();
        let facts = ContextFacts::default();
        let eval = evaluate_simple("", &config, &facts);
        assert_eq!(eval.decision, Decision::Allow);
    }

    #[test]
    fn run_checks_collects_rule_and_config_checks() {
        let s = Span::new(0, 0);
        let rule = Rule {
            command_effect: may_i_core::ast::Spanned::new(
                Effect::CommandPattern(CommandPattern::Literal("echo".into())),
                s,
            ),
            effect: may_i_core::ast::Spanned::new(
                Effect::Terminal {
                    decision: Decision::Allow,
                    reason: Some("ok".into()),
                },
                s,
            ),
            checks: vec![Check {
                command: "echo hi".into(),
                expected: Decision::Allow,
                context: ContextFacts::default(),
                entry_env: may_i_core::EntryEnv::empty(),
                span: s,
            }],
            span: s,
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        };

        let config = Config {
            rules: vec![rule],
            checks: vec![Check {
                command: "echo bye".into(),
                expected: Decision::Allow,
                context: ContextFacts::default(),
                entry_env: may_i_core::EntryEnv::empty(),
                span: s,
            }],
            ..Config::default()
        };

        let results = run_checks(&config);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.passed));
    }

    #[test]
    fn unresolved_predicate_returns_error_not_panic() {
        use may_i_core::ast::{Predicate, Spanned};

        let s = Span::new(0, 0);
        let rule = Rule {
            command_effect: Spanned::new(
                Effect::CommandPattern(CommandPattern::Literal("echo".into())),
                s,
            ),
            effect: Spanned::new(
                Effect::When {
                    predicate: Spanned::new(Predicate::Named("undefined".into()), s),
                    effect: Box::new(Spanned::new(
                        Effect::Terminal {
                            decision: Decision::Allow,
                            reason: Some("ok".into()),
                        },
                        s,
                    )),
                },
                s,
            ),
            checks: vec![Check {
                command: "echo hi".into(),
                expected: Decision::Allow,
                context: ContextFacts::default(),
                entry_env: may_i_core::EntryEnv::empty(),
                span: s,
            }],
            span: s,
            provenance: may_i_core::ast::Provenance::PrimaryConfig,
        };

        let config = Config {
            rules: vec![rule],
            ..Config::default()
        };

        // Should not panic — should return a result with an error diagnostic
        let results = run_checks(&config);
        assert_eq!(results.len(), 1);
        // The check should fail since the predicate can't be resolved
        assert!(!results[0].passed);
    }

    #[test]
    fn word_to_str_with_double_quoted() {
        use may_i_shell_parser::{Word, WordPart};
        let word = Word {
            parts: vec![WordPart::DoubleQuoted(vec![WordPart::Literal(
                "hello world".into(),
            )])],
        };
        assert_eq!(word.to_str(), "hello world");
    }
}
