use may_i_core::ast::{EffectResult, Rule};
use may_i_core::{ContextFacts, Decision};

use crate::fold::{EvalFold, PureFold};
use crate::{EvalError, EvalResult};

use super::context::EvalContext;
use super::effects::evaluate_effect_fold;

/// Evaluate a command against config and context using PureFold.
/// This is the main entry point for evaluation.
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
pub fn evaluate_with_fold<F: EvalFold>(
    command: &str,
    args: &[String],
    config: &may_i_core::ast::Config,
    facts: &ContextFacts,
    fold: &mut F,
) -> Result<EvalResult, EvalError> {
    let expanded = expand_combined_flags(args);
    let evaluator = Evaluator::new(&config.rules);
    let ctx = EvalContext::new(command, &expanded, facts);
    evaluator.evaluate(fold, &ctx)
}

/// Expand combined short flags (e.g. `-rf` → `-r`, `-f`).
///
/// Only expands args that start with a single `-` followed by multiple
/// ASCII letters. Long options (`--foo`) and args with non-letter characters
/// (e.g. `-1`, `-p8080`) are left unchanged.
pub(crate) fn expand_combined_flags(args: &[String]) -> Vec<String> {
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

/// Extract positional (non-flag) arguments from the argument list.
///
/// Handles `--` as an option terminator: `--` itself is included as a
/// positional arg, and all subsequent args are positional regardless of
/// prefix. Long options (`--foo`) consume the following arg as their value.
pub(crate) fn positional_args(args: &[String]) -> Vec<&String> {
    let mut result = Vec::new();
    let mut iter = args.iter().peekable();
    let mut past_terminator = false;

    while let Some(arg) = iter.next() {
        if past_terminator {
            result.push(arg);
        } else if arg == "--" {
            result.push(arg);
            past_terminator = true;
        } else if arg.starts_with("--") {
            // Long option — skip its value (next arg) if present.
            // We assume long options that look like --opt=val are a single
            // arg, so only skip the next arg if it doesn't contain '='.
            if !arg.contains('=') {
                iter.next(); // skip value
            }
        } else if arg.starts_with('-') {
            // Short flag(s) — already expanded by expand_combined_flags.
            // Don't skip the next arg; short flags that take values (like
            // `-o file`) are ambiguous without command-specific knowledge,
            // but this matches the oracle's behaviour for most commands.
        } else {
            result.push(arg);
        }
    }
    result
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
