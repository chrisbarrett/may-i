use may_i_core::ast::{Effect, EffectResult, Rule};
use may_i_core::pattern::{ArgPattern, MatchMode};
use may_i_core::{ContextFacts, Decision, Keyword};

use crate::EvalError;
#[cfg(test)]
use crate::fold::PureFold;
use crate::fold::{ArgMatchDetail, ChildResult, EvalFold};

use super::context::{EvalContext, PredicateResult};
use super::entry::{Evaluator, expand_combined_flags, positional_args};
use super::positional::{
    build_positional_element_details, match_positional_patterns, resolve_trailing_cond_effect,
};
use super::predicates::evaluate_predicate_fold;

/// Evaluate an effect to produce an EffectResult (convenience, uses PureFold).
#[cfg(test)]
pub(crate) fn evaluate_effect(
    effect: &Effect,
    ctx: &EvalContext,
    rules: &[Rule],
) -> Result<EffectResult, EvalError> {
    evaluate_effect_fold(&mut PureFold, effect, ctx, rules)
}

/// Evaluate an effect with a fold, producing `F::EffectOut`.
pub(crate) fn evaluate_effect_fold<F: EvalFold>(
    fold: &mut F,
    effect: &Effect,
    ctx: &EvalContext,
    rules: &[Rule],
) -> Result<F::EffectOut, EvalError> {
    Ok(match effect {
        // Terminal effects
        Effect::Terminal { decision, reason } => {
            fold.effect_terminal(effect, EffectResult::Decision(*decision, reason.clone()))
        }

        // Command pattern
        Effect::CommandPattern(pattern) => {
            let matched = pattern.is_match(ctx.command);
            fold.effect_command_match(pattern, ctx.command, matched)
        }

        // Arg pattern
        Effect::ArgPattern(pattern) => evaluate_arg_pattern_effect_fold(fold, pattern, ctx, rules)?,

        // Combinators
        Effect::And { effects } => {
            let mut children = Vec::new();
            let mut last_result = EffectResult::Decision(Decision::Allow, None);
            let mut short_circuited = false;

            for child in effects {
                if short_circuited {
                    children.push(ChildResult::Skipped);
                } else {
                    let out = evaluate_effect_fold(fold, &child.value, ctx, rules)?;
                    let result = F::effect_result(&out).clone();
                    if result.is_nil() {
                        short_circuited = true;
                        last_result = EffectResult::Nil;
                    } else {
                        last_result = result;
                    }
                    children.push(ChildResult::Evaluated(out));
                }
            }

            let final_result = if short_circuited {
                EffectResult::Nil
            } else {
                last_result
            };
            fold.effect_and(children, final_result)
        }

        Effect::Or { effects } => {
            let mut children = Vec::new();
            let mut final_result = EffectResult::Nil;
            let mut short_circuited = false;

            for child in effects {
                if short_circuited {
                    children.push(ChildResult::Skipped);
                } else {
                    let out = evaluate_effect_fold(fold, &child.value, ctx, rules)?;
                    let result = F::effect_result(&out).clone();
                    if !result.is_nil() {
                        final_result = result;
                        short_circuited = true;
                    }
                    children.push(ChildResult::Evaluated(out));
                }
            }

            fold.effect_or(children, final_result)
        }

        Effect::Not { effect: inner } => {
            let out = evaluate_effect_fold(fold, &inner.value, ctx, rules)?;
            let result = F::effect_result(&out).clone();
            let inverted = match result {
                EffectResult::Nil => EffectResult::Decision(Decision::Allow, None),
                EffectResult::Decision(Decision::Allow, _) => EffectResult::Nil,
                EffectResult::Decision(ask_or_deny, reason) => {
                    EffectResult::Decision(ask_or_deny, reason)
                }
            };
            fold.effect_not(out, inverted)
        }

        // Conditionals
        Effect::When {
            predicate,
            effect: body,
        } => {
            let pred_out = evaluate_predicate_fold(fold, &predicate.value, ctx)?;
            let pred_result = F::predicate_result(&pred_out);
            let (body_child, result) = if pred_result == PredicateResult::Match {
                let body_out = evaluate_effect_fold(fold, &body.value, ctx, rules)?;
                let body_result = F::effect_result(&body_out).clone();
                (ChildResult::Evaluated(body_out), body_result)
            } else {
                (ChildResult::Skipped, EffectResult::Nil)
            };
            fold.effect_when(pred_out, body_child, &body.value, result)
        }

        Effect::Unless {
            predicate,
            effect: body,
        } => {
            let pred_out = evaluate_predicate_fold(fold, &predicate.value, ctx)?;
            let pred_result = F::predicate_result(&pred_out);
            let (body_child, result) = if pred_result == PredicateResult::NoMatch {
                let body_out = evaluate_effect_fold(fold, &body.value, ctx, rules)?;
                let body_result = F::effect_result(&body_out).clone();
                (ChildResult::Evaluated(body_out), body_result)
            } else {
                (ChildResult::Skipped, EffectResult::Nil)
            };
            fold.effect_unless(pred_out, body_child, &body.value, result)
        }

        Effect::If {
            predicate,
            then_effect,
            else_effect,
        } => {
            let pred_out = evaluate_predicate_fold(fold, &predicate.value, ctx)?;
            let pred_result = F::predicate_result(&pred_out);
            let (then_child, else_child, result) = if pred_result == PredicateResult::Match {
                let then_out = evaluate_effect_fold(fold, &then_effect.value, ctx, rules)?;
                let then_result = F::effect_result(&then_out).clone();
                (
                    ChildResult::Evaluated(then_out),
                    ChildResult::Skipped,
                    then_result,
                )
            } else {
                let else_out = evaluate_effect_fold(fold, &else_effect.value, ctx, rules)?;
                let else_result = F::effect_result(&else_out).clone();
                (
                    ChildResult::Skipped,
                    ChildResult::Evaluated(else_out),
                    else_result,
                )
            };
            fold.effect_if(pred_out, then_child, else_child, result)
        }

        Effect::Cond { branches, fallback } => {
            let mut fold_branches = Vec::new();
            let mut found = false;
            let mut result = EffectResult::Nil;

            for (predicate, branch_effect) in branches {
                if found {
                    fold_branches.push((ChildResult::Skipped, ChildResult::Skipped));
                } else {
                    let pred_out = evaluate_predicate_fold(fold, &predicate.value, ctx)?;
                    let pred_result = F::predicate_result(&pred_out);
                    if pred_result == PredicateResult::Match {
                        let body_out =
                            evaluate_effect_fold(fold, &branch_effect.value, ctx, rules)?;
                        result = F::effect_result(&body_out).clone();
                        fold_branches.push((
                            ChildResult::Evaluated(pred_out),
                            ChildResult::Evaluated(body_out),
                        ));
                        found = true;
                    } else {
                        fold_branches
                            .push((ChildResult::Evaluated(pred_out), ChildResult::Skipped));
                    }
                }
            }

            let fb = if found {
                fallback.as_ref().map(|_| ChildResult::Skipped)
            } else if let Some(fb) = fallback {
                let fb_out = evaluate_effect_fold(fold, &fb.value, ctx, rules)?;
                result = F::effect_result(&fb_out).clone();
                Some(ChildResult::Evaluated(fb_out))
            } else {
                None
            };

            fold.effect_cond(fold_branches, fb, result)
        }

        // Recursion
        Effect::MayI { pattern } => match extract_inner_command(ctx.args) {
            Some((inner_cmd, inner_args)) => {
                let evaluator = Evaluator::new(rules);
                let mut inner_facts = ctx.facts.clone();
                inner_facts.insert_scalar(Keyword::new(":via").unwrap(), ctx.command);
                let inner_convention = ctx.convention_for(&inner_cmd);
                fold.record_convention(&inner_cmd, &inner_convention);
                let expanded_inner = expand_combined_flags(&inner_args, &inner_convention);
                let inner_ctx = EvalContext {
                    command: &inner_cmd,
                    args: &expanded_inner,
                    facts: &inner_facts,
                    bindings: ctx.bindings.clone(),
                    recursion_depth: ctx.recursion_depth + 1,
                    recursion_limit: ctx.recursion_limit,
                    convention: inner_convention,
                    args_styles: ctx.args_styles,
                };
                fold.begin_recursive_eval();
                let eval_result = evaluator.evaluate(fold, &inner_ctx)?;
                let inner_result = EffectResult::Decision(eval_result.decision, eval_result.reason);
                let inner_out = fold.effect_terminal(
                    &Effect::Terminal {
                        decision: Decision::Allow,
                        reason: None,
                    },
                    inner_result.clone(),
                );
                fold.effect_may_i(pattern, &inner_cmd, &inner_args, inner_result, inner_out)
            }
            None => fold.effect_may_i_no_match(pattern),
        },
        _ => unreachable!("unknown Effect variant"),
    })
}

/// Evaluate an arg pattern as an effect with a fold.
fn evaluate_arg_pattern_effect_fold<F: EvalFold>(
    fold: &mut F,
    pattern: &ArgPattern,
    ctx: &EvalContext,
    rules: &[Rule],
) -> Result<F::EffectOut, EvalError> {
    Ok(match pattern {
        ArgPattern::Ordered {
            mode,
            patterns,
            continuation,
        } => {
            let pos_args: Vec<&str> = positional_args(ctx.args, &ctx.convention);

            let (pat_matched, consumed, bound_facts) =
                match_positional_patterns(&pos_args, patterns);
            let matched =
                pat_matched && (*mode == MatchMode::Positional || consumed == pos_args.len());
            let elements = build_positional_element_details(&pos_args, patterns, matched, consumed);
            if matched {
                let effective_continuation = continuation
                    .as_deref()
                    .or_else(|| resolve_trailing_cond_effect(patterns, &pos_args, consumed));
                if let Some(cont) = effective_continuation {
                    let remaining_args: Vec<String> = match mode {
                        MatchMode::Positional => self::positional_args(ctx.args, &ctx.convention)
                            .into_iter()
                            .skip(consumed)
                            .map(|s| s.to_string())
                            .collect(),
                        MatchMode::Exact => ctx
                            .args
                            .iter()
                            .filter(|arg| arg.starts_with('-'))
                            .map(|s| s.to_string())
                            .collect(),
                    };
                    let cont_out = evaluate_effect_with_owned_args_fold(
                        fold,
                        cont,
                        ctx,
                        rules,
                        remaining_args,
                        bound_facts,
                    )?;
                    let detail = ArgMatchDetail::new(ctx.args.to_vec(), true, elements);
                    fold.effect_arg_continuation(pattern, ctx.args, detail, cont_out)
                } else {
                    let detail = ArgMatchDetail::new(ctx.args.to_vec(), true, elements);
                    fold.effect_arg_match(pattern, ctx.args, true, detail)
                }
            } else {
                let detail = ArgMatchDetail::new(ctx.args.to_vec(), false, elements);
                fold.effect_arg_match(pattern, ctx.args, false, detail)
            }
        }
        ArgPattern::Anywhere(exprs) => {
            let mut matched = false;
            let search_tokens: Vec<String> = exprs.iter().map(|e| format!("{e}")).collect();
            for expr in exprs {
                if ctx.args.iter().any(|arg| expr.is_match(arg)) {
                    matched = true;
                    break;
                }
            }
            let detail = ArgMatchDetail {
                search_tokens,
                arg_set: ctx.args.to_vec(),
                matched,
                positional_elements: vec![],
            };
            fold.effect_arg_match(pattern, ctx.args, matched, detail)
        }
        ArgPattern::Forbidden(exprs) => {
            let mut found_forbidden = false;
            let search_tokens: Vec<String> = exprs.iter().map(|e| format!("{e}")).collect();
            for expr in exprs {
                if ctx.args.iter().any(|arg| expr.is_match(arg)) {
                    found_forbidden = true;
                    break;
                }
            }
            let detail = ArgMatchDetail {
                search_tokens,
                arg_set: ctx.args.to_vec(),
                matched: !found_forbidden,
                positional_elements: vec![],
            };
            fold.effect_arg_match(pattern, ctx.args, !found_forbidden, detail)
        }
        _ => unreachable!("unknown ArgPattern variant"),
    })
}

/// Helper to evaluate an effect with owned args and a fold.
fn evaluate_effect_with_owned_args_fold<F: EvalFold>(
    fold: &mut F,
    effect: &Effect,
    ctx: &EvalContext,
    rules: &[Rule],
    owned_args: Vec<String>,
    bound_facts: ContextFacts,
) -> Result<F::EffectOut, EvalError> {
    let merged_facts = ctx.facts.merge(&bound_facts);
    let inner_ctx = EvalContext {
        command: ctx.command,
        args: &owned_args,
        facts: &merged_facts,
        bindings: ctx.bindings.clone(),
        recursion_depth: ctx.recursion_depth,
        recursion_limit: ctx.recursion_limit,
        convention: ctx.convention.clone(),
        args_styles: ctx.args_styles,
    };
    evaluate_effect_fold(fold, effect, &inner_ctx, rules)
}

/// Extract inner command from args for may-i recursion.
///
/// The remaining args may contain a quoted string like `"rm -rf /"` that
/// represents a complete sub-command. We join all args into a single string
/// and re-parse through the shell parser to correctly handle quoting.
pub(crate) fn extract_inner_command(args: &[String]) -> Option<(String, Vec<String>)> {
    if args.is_empty() {
        return None;
    }

    // Join remaining args and re-parse as a shell command to handle cases
    // like ssh host "rm -rf /" where the quoted string is a single arg
    // containing a full command.
    let joined = args.join(" ");
    may_i_shell_parser::parse_simple_command(&joined).or_else(|| {
        // Fallback: use first arg as command, rest as args
        let cmd = args[0].clone();
        let remaining = args[1..].to_vec();
        Some((cmd, remaining))
    })
}
