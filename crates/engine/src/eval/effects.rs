use may_i_core::ast::{Effect, EffectResult, Rule};
use may_i_core::pattern::{ArgPattern, CommandPattern};
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
        Effect::Allow(reason) => fold.effect_terminal(
            effect,
            EffectResult::Decision(Decision::Allow, reason.clone()),
        ),
        Effect::Ask(reason) => fold.effect_terminal(
            effect,
            EffectResult::Decision(Decision::Ask, reason.clone()),
        ),
        Effect::Deny(reason) => fold.effect_terminal(
            effect,
            EffectResult::Decision(Decision::Deny, reason.clone()),
        ),

        // Command pattern
        Effect::CommandPattern(pattern) => {
            let matched = match_command_pattern(pattern, ctx.command);
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
        Effect::MayI { pattern } => match extract_inner_command(pattern, ctx.args) {
            Some((inner_cmd, inner_args)) => {
                let evaluator = Evaluator::new(rules);
                let mut inner_facts = ctx.facts.clone();
                inner_facts.push(Keyword::new(":via").unwrap(), ctx.command);
                let expanded_inner = expand_combined_flags(&inner_args);
                let inner_ctx = EvalContext {
                    command: &inner_cmd,
                    args: &expanded_inner,
                    facts: &inner_facts,
                    recursion_depth: ctx.recursion_depth + 1,
                    recursion_limit: ctx.recursion_limit,
                };
                fold.begin_recursive_eval();
                let eval_result = evaluator.evaluate(fold, &inner_ctx)?;
                let inner_result = EffectResult::Decision(eval_result.decision, eval_result.reason);
                let inner_out = fold.effect_terminal(&Effect::Allow(None), inner_result.clone());
                fold.effect_may_i(pattern, &inner_cmd, &inner_args, inner_result, inner_out)
            }
            None => fold.effect_may_i_no_match(pattern),
        },
    })
}

/// Check if a command pattern matches a command string.
pub(crate) fn match_command_pattern(pattern: &CommandPattern, command: &str) -> bool {
    match pattern {
        CommandPattern::Literal(s) => s == command,
        CommandPattern::Regex(re) => re.is_match(command),
        CommandPattern::Or(patterns) => patterns.iter().any(|p| match p {
            CommandPattern::Literal(s) => s == command,
            CommandPattern::Regex(re) => re.is_match(command),
            CommandPattern::Or(_) => false,
        }),
    }
}

/// Evaluate an arg pattern as an effect with a fold.
fn evaluate_arg_pattern_effect_fold<F: EvalFold>(
    fold: &mut F,
    pattern: &ArgPattern,
    ctx: &EvalContext,
    rules: &[Rule],
) -> Result<F::EffectOut, EvalError> {
    Ok(match pattern {
        ArgPattern::Positional {
            patterns,
            continuation,
        } => {
            let positional_args: Vec<&String> = positional_args(ctx.args);

            let (matched, consumed, bound_facts) =
                match_positional_patterns(&positional_args, patterns);
            let elements =
                build_positional_element_details(&positional_args, patterns, matched, consumed);
            if matched {
                // Check for explicit continuation first, then trailing Expr::Cond
                let effective_continuation = continuation
                    .as_deref()
                    .or_else(|| resolve_trailing_cond_effect(patterns, &positional_args, consumed));
                if let Some(cont) = effective_continuation {
                    let remaining_args: Vec<String> = self::positional_args(ctx.args)
                        .into_iter()
                        .skip(consumed)
                        .map(|s| s.to_string())
                        .collect();
                    let cont_out = evaluate_effect_with_owned_args_fold(
                        fold,
                        cont,
                        ctx,
                        rules,
                        remaining_args,
                        bound_facts,
                    )?;
                    let detail = ArgMatchDetail {
                        search_tokens: vec![],
                        arg_set: ctx.args.to_vec(),
                        matched: true,
                        positional_elements: elements,
                    };
                    fold.effect_arg_continuation(pattern, ctx.args, detail, cont_out)
                } else {
                    let detail = ArgMatchDetail {
                        search_tokens: vec![],
                        arg_set: ctx.args.to_vec(),
                        matched: true,
                        positional_elements: elements,
                    };
                    fold.effect_arg_match(pattern, ctx.args, true, detail)
                }
            } else {
                let detail = ArgMatchDetail {
                    search_tokens: vec![],
                    arg_set: ctx.args.to_vec(),
                    matched: false,
                    positional_elements: elements,
                };
                fold.effect_arg_match(pattern, ctx.args, false, detail)
            }
        }
        ArgPattern::Exact {
            patterns,
            continuation,
        } => {
            let positional_args: Vec<&String> = positional_args(ctx.args);

            let (matched, consumed, bound_facts) =
                match_positional_patterns(&positional_args, patterns);
            let exact_match = consumed == positional_args.len() && matched;
            let elements =
                build_positional_element_details(&positional_args, patterns, exact_match, consumed);
            if exact_match {
                let effective_continuation = continuation
                    .as_deref()
                    .or_else(|| resolve_trailing_cond_effect(patterns, &positional_args, consumed));
                if let Some(cont) = effective_continuation {
                    let remaining_args: Vec<String> = ctx
                        .args
                        .iter()
                        .filter(|arg| arg.starts_with('-'))
                        .map(|s| s.to_string())
                        .collect();
                    let cont_out = evaluate_effect_with_owned_args_fold(
                        fold,
                        cont,
                        ctx,
                        rules,
                        remaining_args,
                        bound_facts,
                    )?;
                    let detail = ArgMatchDetail {
                        search_tokens: vec![],
                        arg_set: ctx.args.to_vec(),
                        matched: true,
                        positional_elements: elements,
                    };
                    fold.effect_arg_continuation(pattern, ctx.args, detail, cont_out)
                } else {
                    let detail = ArgMatchDetail {
                        search_tokens: vec![],
                        arg_set: ctx.args.to_vec(),
                        matched: true,
                        positional_elements: elements,
                    };
                    fold.effect_arg_match(pattern, ctx.args, true, detail)
                }
            } else {
                let detail = ArgMatchDetail {
                    search_tokens: vec![],
                    arg_set: ctx.args.to_vec(),
                    matched: false,
                    positional_elements: elements,
                };
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
        recursion_depth: ctx.recursion_depth,
        recursion_limit: ctx.recursion_limit,
    };
    evaluate_effect_fold(fold, effect, &inner_ctx, rules)
}

/// Extract inner command from args for may-i recursion.
///
/// The remaining args may contain a quoted string like `"rm -rf /"` that
/// represents a complete sub-command. We join all args into a single string
/// and re-parse through the shell parser to correctly handle quoting.
pub(crate) fn extract_inner_command(
    _pattern: &ArgPattern,
    args: &[String],
) -> Option<(String, Vec<String>)> {
    if args.is_empty() {
        return None;
    }

    // Join remaining args and re-parse as a shell command to handle cases
    // like ssh host "rm -rf /" where the quoted string is a single arg
    // containing a full command.
    let joined = args.join(" ");
    let parsed = may_i_shell_parser::parse(&joined);

    match parsed {
        may_i_shell_parser::Command::Simple(sc) if !sc.words.is_empty() => {
            let cmd = sc.words[0].to_str();
            let inner_args: Vec<String> = sc.words[1..].iter().map(|w| w.to_str()).collect();
            Some((cmd, inner_args))
        }
        _ => {
            // Fallback: use first arg as command, rest as args
            let cmd = args[0].clone();
            let remaining = args[1..].to_vec();
            Some((cmd, remaining))
        }
    }
}
