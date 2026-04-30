use may_i_core::ast::{Convention, EffectResult, Profile, Rule};
use may_i_core::{ContextFacts, Decision};

use crate::fold::{EvalFold, PureFold};
use crate::{EvalError, EvalResult};

use super::context::EvalContext;
use super::effects::evaluate_effect_fold;

/// Evaluate a command against config and context using PureFold.
/// This is the main entry point for evaluation.
#[must_use = "evaluation result contains the access decision"]
pub fn evaluate(
    command: &str,
    args: &[String],
    config: &may_i_core::ast::Config,
    facts: &ContextFacts,
) -> Result<EvalResult, EvalError> {
    let mut fold = PureFold;
    evaluate_with_fold(command, args, config, facts, &mut fold)
}

/// Evaluate a command against config and context using a custom fold.
#[must_use = "evaluation result contains the access decision"]
pub fn evaluate_with_fold<F: EvalFold>(
    command: &str,
    args: &[String],
    config: &may_i_core::ast::Config,
    facts: &ContextFacts,
    fold: &mut F,
) -> Result<EvalResult, EvalError> {
    let convention = config.convention_for(command);
    fold.record_convention(command, &convention);
    let expanded = expand_combined_flags(args, &convention);
    let bindings = EvalContext::build_bindings(&config.defines);
    let evaluator = Evaluator::new(&config.rules);
    let ctx = EvalContext::with_convention(
        command,
        &expanded,
        facts,
        bindings,
        convention,
        &config.args_styles,
    );
    evaluator.evaluate(fold, &ctx)
}

/// Expand combined short flags subject to the resolved tokenisation
/// convention.
///
/// - `:gnu` — `-rf` → `-r -f` (the legacy default).
/// - `:single-dash-long` — never split; every `-foo` is a single long flag.
/// - `:legacy-bundle` — first non-dashed alphanumeric cluster of letters
///   becomes a flag bundle (`tar xvzf` → `-x -v -z -f`); subsequent tokens
///   then follow `:gnu` rules.
/// - `:key-value` — never split; tokens are classified at positional time.
pub(crate) fn expand_combined_flags(args: &[String], convention: &Convention) -> Vec<String> {
    match convention.profile {
        Profile::Gnu => expand_gnu(args),
        Profile::SingleDashLong | Profile::KeyValue => args.to_vec(),
        Profile::LegacyBundle => expand_legacy_bundle(args),
    }
}

fn expand_gnu(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        if is_gnu_combined_short_flag(arg) {
            for ch in arg[1..].chars() {
                out.push(format!("-{ch}"));
            }
        } else {
            out.push(arg.clone());
        }
    }
    out
}

fn is_gnu_combined_short_flag(arg: &str) -> bool {
    arg.starts_with('-')
        && !arg.starts_with("--")
        && arg.len() > 2
        && arg[1..].chars().all(|c| c.is_ascii_alphabetic())
}

fn expand_legacy_bundle(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut bundle_consumed = false;
    for arg in args {
        if !bundle_consumed
            && !arg.is_empty()
            && !arg.starts_with('-')
            && arg.chars().all(|c| c.is_ascii_alphabetic())
        {
            for ch in arg.chars() {
                out.push(format!("-{ch}"));
            }
            bundle_consumed = true;
        } else if is_gnu_combined_short_flag(arg) {
            for ch in arg[1..].chars() {
                out.push(format!("-{ch}"));
            }
            bundle_consumed = true;
        } else {
            out.push(arg.clone());
            // Any non-bundle token after the start blocks further bundle
            // consumption (the bundle, if it exists, must be first).
            bundle_consumed = true;
        }
    }
    out
}

/// Extract positional (non-flag) arguments under the resolved convention.
///
/// `--` always terminates option processing (and is itself emitted as a
/// positional arg) under every profile. Beyond that, each profile decides
/// what counts as a flag vs. a positional and which flags consume the next
/// argument as a value.
pub(crate) fn positional_args<'a>(args: &'a [String], convention: &Convention) -> Vec<&'a str> {
    match convention.profile {
        Profile::Gnu | Profile::LegacyBundle => positional_gnu(args, convention),
        Profile::SingleDashLong => positional_single_dash_long(args, convention),
        Profile::KeyValue => positional_key_value(args, convention),
    }
}

fn positional_gnu<'a>(args: &'a [String], convention: &Convention) -> Vec<&'a str> {
    let mut result = Vec::new();
    let mut iter = args.iter().peekable();
    let mut past_terminator = false;

    while let Some(arg) = iter.next() {
        if past_terminator {
            result.push(arg.as_str());
        } else if arg == "--" {
            result.push(arg.as_str());
            past_terminator = true;
        } else if arg.starts_with("--") {
            if !arg.contains('=') {
                iter.next();
            }
        } else if arg.starts_with('-') {
            if convention.flag_takes_value(arg) {
                iter.next();
            }
        } else {
            result.push(arg.as_str());
        }
    }
    result
}

fn positional_single_dash_long<'a>(args: &'a [String], convention: &Convention) -> Vec<&'a str> {
    let mut result = Vec::new();
    let mut iter = args.iter().peekable();
    let mut past_terminator = false;

    while let Some(arg) = iter.next() {
        if past_terminator {
            result.push(arg.as_str());
        } else if arg == "--" {
            result.push(arg.as_str());
            past_terminator = true;
        } else if arg.starts_with('-') {
            // Every `-foo` is a single long flag. Consume the next arg as a
            // value when the flag is in `:flags-with-values` and the form
            // is not `-foo=val`.
            if convention.flag_takes_value(arg) && !arg.contains('=') {
                iter.next();
            }
        } else {
            result.push(arg.as_str());
        }
    }
    result
}

fn positional_key_value<'a>(args: &'a [String], _convention: &Convention) -> Vec<&'a str> {
    let mut result = Vec::new();
    let mut past_terminator = false;
    for arg in args {
        if past_terminator {
            result.push(arg.as_str());
        } else if arg == "--" {
            result.push(arg.as_str());
            past_terminator = true;
        } else if is_key_value_token(arg) {
            // flag-equivalent under :key-value
        } else {
            result.push(arg.as_str());
        }
    }
    result
}

fn is_key_value_token(arg: &str) -> bool {
    if arg.is_empty() {
        return false;
    }
    if arg.starts_with('=') {
        return false;
    }
    let Some(eq) = arg.find('=') else {
        return false;
    };
    // Require the key portion to be a non-empty identifier-like token: at
    // least one char before `=`, and no whitespace.
    let key = &arg[..eq];
    !key.is_empty() && !key.chars().any(char::is_whitespace)
}

/// Evaluator for rules with unified effect model.
pub struct Evaluator<'a> {
    rules: &'a [Rule],
}

impl<'a> Evaluator<'a> {
    /// Create a new evaluator with the given rules.
    pub fn new(rules: &'a [Rule]) -> Self {
        Self { rules }
    }

    /// Evaluate a command against all rules.
    /// Returns the first matching rule's effect, or ask if none match.
    pub fn evaluate<F: EvalFold>(
        &self,
        fold: &mut F,
        ctx: &EvalContext,
    ) -> Result<EvalResult, EvalError> {
        // If depth exceeded, return ask
        if ctx.is_depth_exceeded() {
            return Ok(EvalResult::new(
                Decision::Ask,
                Some(format!(
                    "recursion depth limit ({}) exceeded",
                    ctx.recursion_limit
                )),
            ));
        }

        // Evaluate rules in order, return first non-Nil result
        let mut any_command_matched = false;
        for rule in self.rules {
            let out = self.evaluate_rule(fold, rule, ctx)?;
            let result = F::effect_result(&out);

            match result {
                EffectResult::Decision(decision, reason) => {
                    return Ok(EvalResult::new(*decision, reason.clone()));
                }
                EffectResult::Nil => {
                    // Track whether any rule's command pattern matched.
                    if rule.command_effect.value.matches_command(ctx.command) {
                        any_command_matched = true;
                    }
                    continue;
                }
            }
        }

        // No rules matched - return ask with a descriptive reason
        let reason = if any_command_matched {
            format!(
                "Rules for `{}` exist but context or arguments did not match any patterns",
                ctx.command
            )
        } else {
            format!("No rule for command `{}`", ctx.command)
        };
        let _out = fold.default_ask(&reason);
        Ok(EvalResult::new(Decision::Ask, Some(reason)))
    }

    /// Evaluate a single rule. Returns the fold output.
    fn evaluate_rule<F: EvalFold>(
        &self,
        fold: &mut F,
        rule: &Rule,
        ctx: &EvalContext,
    ) -> Result<F::EffectOut, EvalError> {
        // Step 1: Evaluate command effect - must return non-Nil for rule to apply
        let command_out = evaluate_effect_fold(fold, &rule.command_effect.value, ctx, self.rules)?;
        let command_result = F::effect_result(&command_out);

        if command_result.is_nil() {
            return Ok(fold.rule_skipped(rule));
        }

        // Step 2: Evaluate the single body effect.
        let out = evaluate_effect_fold(fold, &rule.effect.value, ctx, self.rules)?;
        let result = F::effect_result(&out);

        Ok(match result {
            EffectResult::Nil => fold.rule_not_matched(rule, ctx.facts, command_out, out),
            EffectResult::Decision(_, _) => {
                let line = None;
                fold.rule_matched(rule, line, ctx.facts, command_out, out)
            }
        })
    }
}

#[cfg(test)]
mod tokenisation_unit {
    use super::*;

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn gnu_flags_with_values_consumes_next_arg() {
        let conv = Convention {
            profile: Profile::Gnu,
            flags_with_values: vec!["-n".into()],
        };
        let args = s(&["-n", "ns", "get", "pods"]);
        assert_eq!(positional_args(&args, &conv), vec!["get", "pods"]);
    }

    #[test]
    fn single_dash_long_flags_with_values_consumes_next_arg() {
        let conv = Convention {
            profile: Profile::SingleDashLong,
            flags_with_values: vec!["-name".into()],
        };
        let args = s(&["-name", "foo", "leftover"]);
        assert_eq!(positional_args(&args, &conv), vec!["leftover"]);
    }

    #[test]
    fn single_dash_long_eq_value_does_not_consume_next() {
        let conv = Convention {
            profile: Profile::SingleDashLong,
            flags_with_values: vec!["-name".into()],
        };
        let args = s(&["-name=foo", "leftover"]);
        assert_eq!(positional_args(&args, &conv), vec!["leftover"]);
    }

    #[test]
    fn key_value_token_recognises_simple_keys() {
        assert!(is_key_value_token("if=foo"));
        assert!(is_key_value_token("a=b"));
    }

    #[test]
    fn key_value_token_rejects_edge_cases() {
        assert!(!is_key_value_token(""));
        assert!(!is_key_value_token("=foo"));
        assert!(!is_key_value_token("nopkg"));
        assert!(!is_key_value_token(" =foo"));
    }

    #[test]
    fn key_value_double_dash_terminates() {
        let conv = Convention {
            profile: Profile::KeyValue,
            flags_with_values: vec![],
        };
        let args = s(&["if=foo", "--", "k=v"]);
        assert_eq!(positional_args(&args, &conv), vec!["--", "k=v"]);
    }

    #[test]
    fn legacy_bundle_blocked_when_first_token_is_dashed() {
        let conv = Convention {
            profile: Profile::LegacyBundle,
            flags_with_values: vec![],
        };
        let args = s(&["-x", "abc", "file"]);
        // First token already starts with `-` → no bundle consumed; `abc` is positional.
        assert_eq!(
            expand_combined_flags(&args, &conv),
            s(&["-x", "abc", "file"])
        );
    }

    #[test]
    fn legacy_bundle_with_combined_short_flag_first() {
        let conv = Convention {
            profile: Profile::LegacyBundle,
            flags_with_values: vec![],
        };
        let args = s(&["-rf", "file"]);
        assert_eq!(
            expand_combined_flags(&args, &conv),
            s(&["-r", "-f", "file"])
        );
    }
}

#[cfg(test)]
mod tokenisation_properties {
    use super::*;
    use proptest::prelude::*;

    fn arg_token() -> impl Strategy<Value = String> {
        prop_oneof![
            // Plain positional words
            "[a-z]{1,5}".prop_map(String::from),
            // Combined short flags
            "-[a-z]{1,4}".prop_map(String::from),
            // Long options
            "--[a-z]{1,5}".prop_map(String::from),
            // Long with value
            "--[a-z]{1,5}=[a-z]{1,5}".prop_map(String::from),
            // Key=value
            "[a-z]{1,4}=[a-z]{1,4}".prop_map(String::from),
            // Just `--` terminator
            Just(String::from("--")),
            // A short numeric flag like -1
            "-[0-9]{1}".prop_map(String::from),
        ]
    }

    fn argv() -> impl Strategy<Value = Vec<String>> {
        proptest::collection::vec(arg_token(), 0..8)
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        // 5.1 — `:gnu` profile + empty `flags_with_values` matches the
        // pre-refactor tokenisation byte-for-byte.
        #[test]
        fn gnu_profile_matches_legacy_behaviour(args in argv()) {
            let conv = Convention::gnu();
            let expanded = expand_combined_flags(&args, &conv);
            let legacy = expand_gnu_legacy(&args);
            prop_assert_eq!(&expanded, &legacy);

            let pos_args = positional_args(&expanded, &conv);
            let legacy_pos = positional_args_legacy(&expanded);
            prop_assert_eq!(pos_args, legacy_pos);
        }

        // 5.2 — Tokenisation is deterministic for a fixed argv + convention.
        #[test]
        fn tokenisation_is_deterministic(args in argv(), profile_idx in 0usize..4) {
            let profile = match profile_idx {
                0 => Profile::Gnu,
                1 => Profile::SingleDashLong,
                2 => Profile::LegacyBundle,
                _ => Profile::KeyValue,
            };
            let conv = Convention { profile, flags_with_values: vec![] };
            let a = expand_combined_flags(&args, &conv);
            let b = expand_combined_flags(&args, &conv);
            prop_assert_eq!(&a, &b);
            let pa = positional_args(&a, &conv);
            let pb = positional_args(&a, &conv);
            prop_assert_eq!(pa, pb);
        }

        // 5.3 — Under `:single-dash-long`, `expand_combined_flags` never
        // increases the token count (no splitting at all).
        #[test]
        fn single_dash_long_never_splits(args in argv()) {
            let conv = Convention { profile: Profile::SingleDashLong, flags_with_values: vec![] };
            let expanded = expand_combined_flags(&args, &conv);
            prop_assert_eq!(expanded.len(), args.len());
            prop_assert_eq!(&expanded, &args);
        }
    }

    /// Mirror of the pre-refactor `expand_combined_flags` behaviour.
    fn expand_gnu_legacy(args: &[String]) -> Vec<String> {
        let mut out = Vec::with_capacity(args.len());
        for arg in args {
            if arg.starts_with('-')
                && !arg.starts_with("--")
                && arg.len() > 2
                && arg[1..].chars().all(|c| c.is_ascii_alphabetic())
            {
                for ch in arg[1..].chars() {
                    out.push(format!("-{ch}"));
                }
            } else {
                out.push(arg.clone());
            }
        }
        out
    }

    /// Mirror of the pre-refactor `positional_args` behaviour.
    fn positional_args_legacy(args: &[String]) -> Vec<&str> {
        let mut result = Vec::new();
        let mut iter = args.iter().peekable();
        let mut past_terminator = false;
        while let Some(arg) = iter.next() {
            if past_terminator {
                result.push(arg.as_str());
            } else if arg == "--" {
                result.push(arg.as_str());
                past_terminator = true;
            } else if arg.starts_with("--") {
                if !arg.contains('=') {
                    iter.next();
                }
            } else if arg.starts_with('-') {
                // short flag — does not consume value
            } else {
                result.push(arg.as_str());
            }
        }
        result
    }
}
