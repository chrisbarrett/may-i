use may_i_core::ast::{Effect, EffectResult, Rule};
use may_i_core::pattern::{ArgPattern, MatchMode, ParameterForm, flag_token_for_name};
use may_i_core::{ContextFacts, Decision, Keyword};

use crate::EvalError;
#[cfg(test)]
use crate::fold::PureFold;
use crate::fold::{ArgMatchDetail, ChildResult, EvalFold};

use super::context::{EvalContext, PredicateResult};
use super::entry::Evaluator;
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
                let mut inner_facts = ctx.facts.clone();
                inner_facts.insert_scalar(Keyword::new(":via").unwrap(), ctx.command);
                let inner_parser = match ctx.config {
                    Some(cfg) => cfg.parser_for_with_rules(&inner_cmd),
                    None => may_i_core::ast::ResolvedParser::synthetic_gnu(&inner_cmd),
                };
                fold.record_parser(&inner_cmd, &inner_parser);
                let expanded_inner = super::entry::tokenise(&inner_args, &inner_parser);
                let evaluator = Evaluator::new(rules);
                let inner_ctx = EvalContext {
                    command: &inner_cmd,
                    args: &expanded_inner,
                    facts: &inner_facts,
                    bindings: ctx.bindings.clone(),
                    recursion_depth: ctx.recursion_depth + 1,
                    recursion_limit: ctx.recursion_limit,
                    parser: inner_parser,
                    config: ctx.config,
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
    let outer_args: &[String] = matcher_scope(ctx);
    Ok(match pattern {
        ArgPattern::Ordered {
            mode,
            patterns,
            continuation,
        } => {
            let pos_args: Vec<&str> = super::entry::parser_positional_args(outer_args, &ctx.parser);

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
                        MatchMode::Positional => {
                            super::entry::parser_positional_args(outer_args, &ctx.parser)
                                .into_iter()
                                .skip(consumed)
                                .map(|s| s.to_string())
                                .collect()
                        }
                        MatchMode::Exact => outer_args
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
            // Honour `--` as a flag-stop: tokens after `--` are
            // path/positional, not flag-shaped, so `(anywhere "--foo")`
            // SHALL NOT match `git diff -- --foo`. Combined with the
            // wrapper-tail scope: outer_args excludes the tail, and
            // scan_until_double_dash further trims at `--`.
            let outer = scan_until_double_dash(outer_args);
            let mut matched = false;
            let search_tokens: Vec<String> = exprs.iter().map(|e| format!("{e}")).collect();
            for expr in exprs {
                if outer.iter().any(|arg| expr.is_match(arg)) {
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
            // Same `--` and tail boundary as `(anywhere …)`.
            let outer = scan_until_double_dash(outer_args);
            let mut found_forbidden = false;
            let search_tokens: Vec<String> = exprs.iter().map(|e| format!("{e}")).collect();
            for expr in exprs {
                if outer.iter().any(|arg| expr.is_match(arg)) {
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
        ArgPattern::Flag { names } => {
            let matched = flag_present_in_with_parser(outer_args, names, &ctx.parser);
            let search_tokens: Vec<String> =
                names.iter().map(|n| ctx.parser.token_for_name(n)).collect();
            let detail = ArgMatchDetail {
                search_tokens,
                arg_set: ctx.args.to_vec(),
                matched,
                positional_elements: vec![],
            };
            fold.effect_arg_match(pattern, ctx.args, matched, detail)
        }
        ArgPattern::Parameter { names, form } => {
            evaluate_parameter_fold(fold, pattern, names, form, ctx, rules)?
        }
        ArgPattern::Tail => evaluate_tail_authorise_fold(fold, pattern, ctx, rules)?,
        _ => unreachable!("unknown ArgPattern variant"),
    })
}

/// Evaluate `(tail (authorise))`. Resolves the tail slice from the
/// parser's `(tail (after …))` declaration and recurses on it as a
/// command line via [`extract_inner_command`].
fn evaluate_tail_authorise_fold<F: EvalFold>(
    fold: &mut F,
    pattern: &ArgPattern,
    ctx: &EvalContext,
    rules: &[Rule],
) -> Result<F::EffectOut, EvalError> {
    let split = super::entry::split_outer_tail(ctx.args, &ctx.parser);
    // When the parser declares no tail, fall back to the full argv —
    // this matches the legacy `(may-i *)` semantics for rule bodies that
    // recurse without a wrapper-boundary spec.
    let tail_slice: &[String] = split.tail.unwrap_or(ctx.args);
    let owned: Vec<String> = tail_slice.to_vec();
    Ok(match extract_inner_command(&owned) {
        Some((inner_cmd, inner_args)) => {
            let mut inner_facts = ctx.facts.clone();
            inner_facts.insert_scalar(Keyword::new(":via").unwrap(), ctx.command);
            let inner_parser = match ctx.config {
                Some(cfg) => cfg.parser_for_with_rules(&inner_cmd),
                None => may_i_core::ast::ResolvedParser::synthetic_gnu(&inner_cmd),
            };
            fold.record_parser(&inner_cmd, &inner_parser);
            let expanded_inner = super::entry::tokenise(&inner_args, &inner_parser);
            let evaluator = Evaluator::new(rules);
            let inner_ctx = EvalContext {
                command: &inner_cmd,
                args: &expanded_inner,
                facts: &inner_facts,
                bindings: ctx.bindings.clone(),
                recursion_depth: ctx.recursion_depth + 1,
                recursion_limit: ctx.recursion_limit,
                parser: inner_parser,
                config: ctx.config,
            };
            fold.begin_recursive_eval();
            let eval_result = evaluator.evaluate(fold, &inner_ctx)?;
            let detail = ArgMatchDetail {
                search_tokens: vec!["(authorise)".to_string()],
                arg_set: ctx.args.to_vec(),
                matched: true,
                positional_elements: vec![],
            };
            // Surface the recursive decision via effect_arg_continuation
            // so the trace renders the inner evaluation as a child.
            let inner_terminal = fold.effect_terminal(
                &Effect::Terminal {
                    decision: eval_result.decision,
                    reason: eval_result.reason.clone(),
                },
                EffectResult::Decision(eval_result.decision, eval_result.reason),
            );
            fold.effect_arg_continuation(pattern, ctx.args, detail, inner_terminal)
        }
        None => {
            let detail = ArgMatchDetail {
                search_tokens: vec!["(authorise)".to_string()],
                arg_set: ctx.args.to_vec(),
                matched: false,
                positional_elements: vec![],
            };
            fold.effect_arg_match(pattern, ctx.args, false, detail)
        }
    })
}

/// Effective argv slice for argv-matchers. When the parser declares
/// `(tail (after …))` the slice is restricted to the outer span; the
/// tail is exclusively addressable via `(tail (authorise))`.
pub(super) fn matcher_scope<'a>(ctx: &'a EvalContext) -> &'a [String] {
    super::entry::split_outer_tail(ctx.args, &ctx.parser).outer
}

/// Slice of `args` up to (but not including) the first literal `--`
/// token. Used by `(anywhere …)` and `(forbidden …)` so a token after
/// the GNU flag-stop is treated as a path/positional rather than a flag.
pub(super) fn scan_until_double_dash(args: &[String]) -> &[String] {
    match args.iter().position(|a| a == "--") {
        Some(idx) => &args[..idx],
        None => args,
    }
}

/// Style-aware tokens for a list of canonical names.
fn tokens_for_names_with_parser(
    parser: &may_i_core::ast::ResolvedParser,
    names: &[String],
) -> Vec<String> {
    names.iter().map(|n| parser.token_for_name(n)).collect()
}

/// Check whether any spelling of a `(flag …)`/`(parameter …)` named flag is
/// present in the (already-tokenised) argument stream. `--` ends the search.
fn flag_present_in_with_parser(
    args: &[String],
    names: &[String],
    parser: &may_i_core::ast::ResolvedParser,
) -> bool {
    find_flag_position_with_parser(args, names, parser).is_some()
}

/// Predicate-position view of `flag_present_in_with_parser`.
pub(super) fn flag_present_in_for_predicate(
    args: &[String],
    names: &[String],
    parser: &may_i_core::ast::ResolvedParser,
) -> bool {
    flag_present_in_with_parser(args, names, parser)
}

/// Predicate-position view of `find_parameter_value_with_parser`.
pub(super) fn find_parameter_value_for_predicate(
    args: &[String],
    names: &[String],
    parser: &may_i_core::ast::ResolvedParser,
) -> Option<String> {
    find_parameter_value_with_parser(args, names, parser)
}

fn find_flag_position_with_parser(
    args: &[String],
    names: &[String],
    parser: &may_i_core::ast::ResolvedParser,
) -> Option<usize> {
    let tokens = tokens_for_names_with_parser(parser, names);
    for (i, arg) in args.iter().enumerate() {
        if arg == "--" {
            return None;
        }
        for tok in &tokens {
            if arg == tok {
                return Some(i);
            }
            if equals_value(arg, tok).is_some() {
                return Some(i);
            }
        }
    }
    None
}

/// Extract the value of a named flag from the tokenised stream, supporting
/// `-X VAL`, `-X=VAL`, `--name VAL`, and `--name=VAL` (and style-specific
/// separators). Returns `None` when no spelling is present or when the
/// value is missing.
///
/// When the parameter's `capture` is `ManyTill`, the value is the
/// space-joined token sequence from after the parameter occurrence up
/// to (but not including) the terminator-matching token. Inline
/// `name=val` is treated as a single-token capture even for ManyTill —
/// the inline form lacks the multi-token shape.
fn find_parameter_value_with_parser(
    args: &[String],
    names: &[String],
    parser: &may_i_core::ast::ResolvedParser,
) -> Option<String> {
    let tokens = tokens_for_names_with_parser(parser, names);
    let separators: Vec<String> = parser
        .style
        .separators()
        .iter()
        .filter(|s| !s.trim().is_empty() && s.as_str() != "=")
        .cloned()
        .collect();
    let many_till_terminator =
        parser
            .parameter_decl_for_token_in(&tokens)
            .and_then(|d| match &d.capture {
                may_i_core::ast::Capture::ManyTill { terminator } => Some(terminator.clone()),
                _ => None,
            });
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            return None;
        }
        for tok in &tokens {
            if arg == tok {
                if let Some(term) = &many_till_terminator {
                    return collect_many_till(args, i + 1, term);
                }
                return args.get(i + 1).cloned();
            }
            if let Some(value) = equals_value(arg, tok) {
                return Some(value.to_string());
            }
            for sep in &separators {
                let prefix = format!("{tok}{sep}");
                if let Some(rest) = arg.strip_prefix(&prefix) {
                    return Some(rest.to_string());
                }
            }
        }
        i += 1;
    }
    None
}

/// If `arg` is the `=`-attached form of `tok`, return `Some(value)`. Empty
/// values are preserved so `--name=` parses as the empty string.
/// Walk `args` from `start` collecting tokens until one matches
/// `terminator`. Returns `Some(joined)` on a hit (terminator consumed)
/// and `None` if end-of-argv was reached without a match — per spec,
/// the missing-terminator case surfaces as "no value available", which
/// floors the rule body's decision to `:ask` via the existing combiner.
fn collect_many_till(
    args: &[String],
    start: usize,
    terminator: &may_i_core::pattern::Expr<may_i_core::ast::Effect>,
) -> Option<String> {
    let mut captured: Vec<String> = Vec::new();
    let mut i = start;
    while i < args.len() {
        if terminator.is_match(&args[i]) {
            return Some(captured.join(" "));
        }
        captured.push(args[i].clone());
        i += 1;
    }
    None
}

fn equals_value<'a>(arg: &'a str, tok: &str) -> Option<&'a str> {
    let prefix = format!("{tok}=");
    arg.strip_prefix(&prefix)
}

fn evaluate_parameter_fold<F: EvalFold>(
    fold: &mut F,
    pattern: &ArgPattern,
    names: &[String],
    form: &ParameterForm,
    ctx: &EvalContext,
    rules: &[Rule],
) -> Result<F::EffectOut, EvalError> {
    let search_tokens: Vec<String> = names.iter().map(|n| flag_token_for_name(n)).collect();
    let outer_args = matcher_scope(ctx);
    let value = find_parameter_value_with_parser(outer_args, names, &ctx.parser);
    let matched = value.is_some() && parameter_form_matches(form, value.as_deref().unwrap_or(""));
    if let Some(value) = value
        && let ParameterForm::MayI = form
    {
        // (parameter X (may-i …)) — recurse with the value parsed as a
        // command line. Skip extract_inner_command's join step because the
        // value is already exactly the inner command line.
        let parsed = may_i_shell_parser::parse_simple_command(&value).or_else(|| {
            // Fallback: treat the value as a single-token command with no
            // args. Conservative — recursion will likely return Ask if no
            // rule covers it.
            Some((value.clone(), Vec::new()))
        });
        if let Some((inner_cmd, inner_args)) = parsed {
            let evaluator = Evaluator::new(rules);
            let mut inner_facts = ctx.facts.clone();
            inner_facts.insert_scalar(Keyword::new(":via").unwrap(), ctx.command);
            let inner_parser = match ctx.config {
                Some(cfg) => cfg.parser_for_with_rules(&inner_cmd),
                None => may_i_core::ast::ResolvedParser::synthetic_gnu(&inner_cmd),
            };
            fold.record_parser(&inner_cmd, &inner_parser);
            let expanded_inner = super::entry::tokenise(&inner_args, &inner_parser);
            let inner_ctx = EvalContext {
                command: &inner_cmd,
                args: &expanded_inner,
                facts: &inner_facts,
                bindings: ctx.bindings.clone(),
                recursion_depth: ctx.recursion_depth + 1,
                recursion_limit: ctx.recursion_limit,
                parser: inner_parser,
                config: ctx.config,
            };
            fold.begin_recursive_eval();
            let eval_result = evaluator.evaluate(fold, &inner_ctx)?;
            // Translate the recursed decision back into an EffectResult and
            // route it through the same fold seam used by `(may-i …)`.
            let inner_result = EffectResult::Decision(eval_result.decision, eval_result.reason);
            let inner_out = fold.effect_terminal(
                &Effect::Terminal {
                    decision: Decision::Allow,
                    reason: None,
                },
                inner_result.clone(),
            );
            let _ = search_tokens;
            // Re-use effect_may_i so traces show the recursion.
            return Ok(fold.effect_may_i(
                &may_i_core::pattern::ArgPattern::positional(vec![]),
                &inner_cmd,
                &inner_args,
                inner_result,
                inner_out,
            ));
        }
        // Unreachable in practice — the fallback above always returns Some.
        unreachable!("parse_simple_command fallback should always succeed");
    }
    let detail = ArgMatchDetail {
        search_tokens,
        arg_set: ctx.args.to_vec(),
        matched,
        positional_elements: vec![],
    };
    Ok(fold.effect_arg_match(pattern, ctx.args, matched, detail))
}

/// Apply a non-recursive parameter form (anything other than `MayI`) to a
/// single-token value.
fn parameter_form_matches(form: &ParameterForm, value: &str) -> bool {
    match form {
        ParameterForm::Match(expr) => expr.is_match(value),
        ParameterForm::MayI => false, // handled in caller
    }
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
        parser: ctx.parser.clone(),
        config: ctx.config,
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

#[cfg(test)]
mod scan_double_dash_tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_terminator_returns_full_slice() {
        let args = argv(&["-r", "-f", "/tmp/x"]);
        assert_eq!(scan_until_double_dash(&args), &args[..]);
    }

    #[test]
    fn terminator_truncates_slice() {
        let args = argv(&["diff", "--", "--foo"]);
        assert_eq!(scan_until_double_dash(&args), &["diff".to_string()]);
    }

    #[test]
    fn terminator_at_start_yields_empty() {
        let args = argv(&["--", "--foo"]);
        assert_eq!(scan_until_double_dash(&args), &[] as &[String]);
    }
}
