use may_i_core::ast::{Effect, EffectResult, Rule};
use may_i_core::pattern::{ArgPattern, MatchMode, ParameterForm, flag_token_for_name};
use may_i_core::{ContextFacts, Decision};

use crate::EvalError;
use crate::fold::PureFold;
use crate::fold::{ArgMatchDetail, ChildResult, EvalFold};

use super::context::{EvalContext, PredicateResult};
use super::positional::{build_positional_element_details, resolve_trailing_cond_effect};
use super::predicates::{captured_facts, evaluate_predicate_fold};

/// Evaluate `body` after `predicate` matched, threading any facts the
/// predicate captured under a quantifier (`(every? #v [:k *])` /
/// `(some? …)`) into the body's fact environment. With no captures the
/// body sees `ctx` unchanged.
fn eval_body_with_captures<F: EvalFold>(
    fold: &mut F,
    predicate: &may_i_core::ast::Predicate,
    body: &Effect,
    ctx: &EvalContext,
    rules: &[Rule],
) -> Result<F::EffectOut, EvalError> {
    let captured = captured_facts(predicate, ctx);
    if captured.is_empty() {
        return evaluate_effect_fold(fold, body, ctx, rules);
    }
    let merged = ctx.facts.merge(&captured);
    let derived = EvalContext {
        command: ctx.command,
        args: ctx.args,
        arg_expansions: ctx.arg_expansions.clone(),
        facts: &merged,
        bindings: ctx.bindings.clone(),
        recursion_depth: ctx.recursion_depth,
        recursion_limit: ctx.recursion_limit,
        parser: ctx.parser.clone(),
        parser_bindings: ctx.parser_bindings.clone(),
        unresolved: ctx.unresolved.clone(),
        config: ctx.config,
    };
    evaluate_effect_fold(fold, body, &derived, rules)
}

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
                let body_out =
                    eval_body_with_captures(fold, &predicate.value, &body.value, ctx, rules)?;
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
                let then_out = eval_body_with_captures(
                    fold,
                    &predicate.value,
                    &then_effect.value,
                    ctx,
                    rules,
                )?;
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
                        let body_out = eval_body_with_captures(
                            fold,
                            &predicate.value,
                            &branch_effect.value,
                            ctx,
                            rules,
                        )?;
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

        // `(authorise #var)` — resolve `#var` against the active
        // parser-binding environment and recurse. Unbound or empty
        // values are no-match, matching the boundary-absent semantics
        // that the legacy `(tail …)` form encoded.
        //
        // Dispatch on the binding's kind: a single-string capture
        // (e.g. `(parameter "c" #cmd)`) re-parses as a command line;
        // a token-list capture (e.g. `(rest #cmd)`,
        // `(positional #var *|+)`) preserves each token as one
        // argument so the outer-shell-established boundaries reach
        // the inner parser intact. Joining tokens with single spaces
        // and re-parsing is the bypass closed by the
        // `authorise-token-list-quoting` change.
        Effect::Authorise { binding, .. } => {
            let value = ctx.parser_bindings.get(binding);
            if value.is_empty() {
                return Ok(fold.effect_nil(effect));
            }
            recurse_into_bound_command(fold, effect, &value, ctx, rules)?
        }
    })
}

/// Recursion path for `(authorise #var)`. Mirrors
/// `recurse_into_inner_command` but emits the inner decision via
/// `effect_terminal` instead of `effect_arg_continuation` — the verb
/// has no surrounding `ArgPattern` to wrap.
///
/// String bindings route through `evaluate_authorised_string` (parse
/// as a full command line, decompose, aggregate strictest-wins).
/// Token-list bindings route through `evaluate_authorised_tokens`,
/// which preserves each token as one inner-argv element so an
/// outer-shell-quoted argument carrying shell metacharacters reaches
/// the inner parser as one preserved string rather than as
/// re-exposed structure at the carrier's frame.
fn recurse_into_bound_command<F: EvalFold>(
    fold: &mut F,
    effect: &Effect,
    value: &super::bindings::BindingValue,
    ctx: &EvalContext,
    rules: &[Rule],
) -> Result<F::EffectOut, EvalError> {
    let _ = rules;
    fold.begin_recursive_eval();
    let eval_result = match value {
        super::bindings::BindingValue::Token(t) => {
            // A string binding re-parses as a command line. When the
            // captured token was expansion-bearing, that text is
            // unfaithful to what will run — record it so an inner
            // `:allow` cannot stand. (The token-list path below threads
            // per-token provenance into the inner evaluation instead.)
            if let Some(display) = &t.expansion {
                ctx.record_unresolved(display);
            }
            super::command::evaluate_authorised_string(
                &t.text,
                ctx.config,
                ctx.facts,
                fold,
                ctx.recursion_depth + 1,
                Some(ctx.command),
            )?
        }
        super::bindings::BindingValue::Tokens(v) => {
            let (texts, expansions): (Vec<String>, Vec<super::decompose::Expansion>) = v
                .iter()
                .map(|t| (t.text.clone(), t.expansion.clone()))
                .unzip();
            super::command::evaluate_authorised_tokens(
                &texts,
                &expansions,
                ctx.config,
                ctx.facts,
                fold,
                ctx.recursion_depth + 1,
                Some(ctx.command),
            )?
        }
        super::bindings::BindingValue::Unbound => {
            // Caller checks `is_empty()` before dispatching; reaching
            // this arm means the surrounding contract is broken.
            unreachable!("recurse_into_bound_command invoked on Unbound binding")
        }
        super::bindings::BindingValue::Count(_) => {
            // `(authorise #count)` is rejected by the shape checker at
            // load time; eval never legitimately reaches this arm.
            unreachable!("recurse_into_bound_command invoked on a Count binding")
        }
    };
    Ok(fold.effect_terminal(
        effect,
        EffectResult::Decision(
            eval_result.decision,
            eval_result.reason.map(|r| r.to_string()),
        ),
    ))
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
            let outer_exp = ctx.expansions_for_prefix(outer_args.len());
            let pos_idx = super::entry::parser_positional_indices(outer_args, &ctx.parser);
            let pos_args: Vec<&str> = pos_idx.iter().map(|&i| outer_args[i].as_str()).collect();
            let pos_exp: Vec<&super::decompose::Expansion> =
                pos_idx.iter().map(|&i| &outer_exp[i]).collect();

            let m = super::positional::match_positional_patterns_budgeted(
                &pos_args,
                &pos_exp,
                patterns,
                ctx.matcher_budget(),
            );
            let (pat_matched, consumed, bound_facts) = (m.matched, m.consumed, m.facts);
            let matched =
                pat_matched && (*mode == MatchMode::Positional || consumed == pos_args.len());
            if matched {
                for w in &m.unresolved {
                    ctx.record_unresolved(w);
                }
            }
            let elements = build_positional_element_details(&pos_args, patterns, &m.elements);
            if matched {
                let effective_continuation = continuation
                    .as_deref()
                    .or_else(|| resolve_trailing_cond_effect(patterns, &pos_args, consumed));
                if let Some(cont) = effective_continuation {
                    let (remaining_args, remaining_exp): (
                        Vec<String>,
                        Vec<super::decompose::Expansion>,
                    ) = match mode {
                        MatchMode::Positional => pos_idx
                            .iter()
                            .skip(consumed)
                            .map(|&i| (outer_args[i].clone(), outer_exp[i].clone()))
                            .unzip(),
                        MatchMode::Exact => outer_args
                            .iter()
                            .zip(outer_exp)
                            .filter(|(arg, _)| arg.starts_with('-'))
                            .map(|(arg, exp)| (arg.clone(), exp.clone()))
                            .unzip(),
                    };
                    let cont_out = evaluate_effect_with_owned_args_fold(
                        fold,
                        cont,
                        ctx,
                        rules,
                        remaining_args,
                        remaining_exp,
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
            // carrier-tail scope: outer_args excludes the tail, and
            // scan_until_double_dash further trims at `--`.
            let outer = scan_until_double_dash(outer_args);
            let outer_exp = ctx.expansions_for_prefix(outer.len());
            let mut matched = false;
            let search_tokens: Vec<String> = exprs.iter().map(|e| format!("{e}")).collect();
            for expr in exprs {
                if anywhere_match(expr, outer, outer_exp, ctx) {
                    matched = true;
                    break;
                }
            }
            let detail = ArgMatchDetail {
                search_tokens,
                arg_set: ctx.args.to_vec(),
                matched,
                positional_elements: vec![],
                captured_value: None,
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
                captured_value: None,
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
                captured_value: None,
            };
            fold.effect_arg_match(pattern, ctx.args, matched, detail)
        }
        ArgPattern::Parameter { names, form } => {
            evaluate_parameter_fold(fold, pattern, names, form, ctx, rules)?
        }
        ArgPattern::Tail => evaluate_tail_authorise_fold(fold, pattern, ctx, rules)?,
    })
}

/// Evaluate `(tail (authorise))`. Resolves the tail slice from the
/// parser's `(tail (after …))` declaration and recurses on it as a
/// full command line via the shared `evaluate_authorised_string`
/// helper.
fn evaluate_tail_authorise_fold<F: EvalFold>(
    fold: &mut F,
    pattern: &ArgPattern,
    ctx: &EvalContext,
    rules: &[Rule],
) -> Result<F::EffectOut, EvalError> {
    let split = super::entry::split_outer_tail(ctx.args, &ctx.parser);
    // When the parser declares a tail-bearing flags_mode but the
    // boundary is absent in argv, treat the matcher as a no-match —
    // falling back to the full argv would silently re-fire the rule
    // on the same command. The fallback only applies under
    // FlagsMode::Permute (no boundary, no recurse target).
    let permissive_fallback = matches!(ctx.parser.flags_mode, may_i_core::ast::FlagsMode::Permute);
    let tail_slice: &[String] = match split.tail {
        Some(slice) => slice,
        None if permissive_fallback => ctx.args,
        None => {
            let detail = ArgMatchDetail {
                search_tokens: vec![],
                arg_set: ctx.args.to_vec(),
                matched: false,
                positional_elements: vec![],
                captured_value: None,
            };
            return Ok(fold.effect_arg_match(pattern, ctx.args, false, detail));
        }
    };
    let owned: Vec<String> = tail_slice.to_vec();
    // The tail is a suffix of the full argv, so its expansion slice
    // aligns by length.
    let tail_exp: Vec<super::decompose::Expansion> =
        ctx.arg_expansions[ctx.args.len() - owned.len()..].to_vec();
    // `captured_value` is a trace-surface display string; the
    // recursion itself routes through `evaluate_authorised_tokens`
    // so the tail's token boundaries reach the inner parser intact.
    let tail_value = owned.join(" ");
    let _ = rules;
    Ok(if owned.is_empty() {
        let detail = ArgMatchDetail {
            search_tokens: vec![],
            arg_set: ctx.args.to_vec(),
            matched: false,
            positional_elements: vec![],
            captured_value: Some(tail_value),
        };
        fold.effect_arg_match(pattern, ctx.args, false, detail)
    } else {
        fold.begin_recursive_eval();
        let eval_result = super::command::evaluate_authorised_tokens(
            &owned,
            &tail_exp,
            ctx.config,
            ctx.facts,
            fold,
            ctx.recursion_depth + 1,
            Some(ctx.command),
        )?;
        let detail = ArgMatchDetail {
            search_tokens: vec![],
            arg_set: ctx.args.to_vec(),
            matched: true,
            positional_elements: vec![],
            captured_value: Some(tail_value.clone()),
        };
        let inner_terminal = fold.effect_terminal(
            &Effect::Terminal {
                decision: eval_result.decision,
                reason: eval_result.reason.as_ref().map(|r| r.to_string()),
            },
            EffectResult::Decision(
                eval_result.decision,
                eval_result.reason.map(|r| r.to_string()),
            ),
        );
        fold.effect_arg_continuation(pattern, ctx.args, detail, inner_terminal)
    })
}

/// Effective argv slice for argv-matchers. When the parser declares
/// `(tail (after …))` the slice is restricted to the outer span; the
/// tail is exclusively addressable via `(tail (authorise))`.
pub(super) fn matcher_scope<'a>(ctx: &'a EvalContext) -> &'a [String] {
    super::entry::split_outer_tail(ctx.args, &ctx.parser).outer
}

/// `(anywhere …)`-style match of one expression over a token slice,
/// recording an unresolved word when the match is allow-unsound. The
/// match is provable only when some *literal* token satisfies the
/// expression; when every satisfying token is expansion-bearing (and the
/// expression constrains the value), the textual match cannot be proven
/// for the runtime value, so it is recorded for the rule evaluator's
/// allow-floor. The match itself still reports true — firing toward
/// `:ask`/`:deny` errs toward caution.
pub(super) fn anywhere_match(
    expr: &may_i_core::pattern::Expr<may_i_core::ast::Effect>,
    args: &[String],
    expansions: &[super::decompose::Expansion],
    ctx: &EvalContext,
) -> bool {
    debug_assert_eq!(args.len(), expansions.len());
    let mut first_unresolved: Option<&str> = None;
    for (arg, exp) in args.iter().zip(expansions) {
        if !expr.is_match(arg) {
            continue;
        }
        match exp {
            None => return true, // provable: a literal token matched
            Some(display) => {
                if first_unresolved.is_none() {
                    first_unresolved = Some(display);
                }
            }
        }
    }
    match first_unresolved {
        Some(display) => {
            if !expr.matches_any_value() {
                ctx.record_unresolved(display);
            }
            true
        }
        None => false,
    }
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

/// Predicate-position view of `find_parameter_value_with_parser`,
/// pairing the value with its source token's expansion provenance.
pub(super) fn find_parameter_value_for_predicate(
    args: &[String],
    expansions: &[super::decompose::Expansion],
    names: &[String],
    parser: &may_i_core::ast::ResolvedParser,
) -> Option<(String, super::decompose::Expansion)> {
    find_parameter_value_with_parser(args, expansions, names, parser)
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
    expansions: &[super::decompose::Expansion],
    names: &[String],
    parser: &may_i_core::ast::ResolvedParser,
) -> Option<(String, super::decompose::Expansion)> {
    debug_assert_eq!(args.len(), expansions.len());
    let tokens = tokens_for_names_with_parser(parser, names);
    let separators: Vec<String> = parser
        .style
        .separators()
        .iter()
        .filter(|s| !s.trim().is_empty() && s.as_str() != "=")
        .cloned()
        .collect();
    let many_till_terminator = parser.parameter_decl_for_token_in(&tokens).and_then(|d| {
        // `Capture` is `#[non_exhaustive]`; only `ManyTill` is relevant here.
        #[allow(clippy::wildcard_enum_match_arm)]
        match &d.capture {
            may_i_core::ast::Capture::ManyTill { terminator } => Some(terminator.clone()),
            _ => None,
        }
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
                    return collect_many_till(args, expansions, i + 1, term);
                }
                return args
                    .get(i + 1)
                    .map(|v| (v.clone(), expansions[i + 1].clone()));
            }
            if let Some(value) = equals_value(arg, tok) {
                return Some((value.to_string(), expansions[i].clone()));
            }
            for sep in &separators {
                let prefix = format!("{tok}{sep}");
                if let Some(rest) = arg.strip_prefix(&prefix) {
                    return Some((rest.to_string(), expansions[i].clone()));
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
    expansions: &[super::decompose::Expansion],
    start: usize,
    terminator: &may_i_core::pattern::Expr<may_i_core::ast::Effect>,
) -> Option<(String, super::decompose::Expansion)> {
    let mut captured: Vec<String> = Vec::new();
    let mut expansion: super::decompose::Expansion = None;
    let mut i = start;
    while i < args.len() {
        if terminator.is_match(&args[i]) {
            return Some((captured.join(" "), expansion));
        }
        if expansion.is_none() {
            expansion = expansions[i].clone();
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

    // Many-till + (authorise): each occurrence is its own recursion.
    // The strictest decision across occurrences wins (Deny > Ask > Allow),
    // matching the rule body's existing strictness combiner.
    let tokens = tokens_for_names_with_parser(&ctx.parser, names);
    let many_till = ctx
        .parser
        .parameter_decl_for_token_in(&tokens)
        .and_then(|d| {
            // `Capture` is `#[non_exhaustive]`; only `ManyTill` is relevant here.
            #[allow(clippy::wildcard_enum_match_arm)]
            match &d.capture {
                may_i_core::ast::Capture::ManyTill { terminator } => Some(terminator.clone()),
                _ => None,
            }
        });
    let outer_exp = ctx.expansions_for_prefix(outer_args.len());
    if matches!(form, ParameterForm::Authorise)
        && let Some(terminator) = many_till
    {
        let values = find_many_till_values_with_parser(
            outer_args,
            outer_exp,
            names,
            &ctx.parser,
            &terminator,
        );
        return evaluate_multi_occurrence_authorise(
            fold,
            pattern,
            &values,
            ctx,
            rules,
            search_tokens,
        );
    }

    let captured = find_parameter_value_with_parser(outer_args, outer_exp, names, &ctx.parser);
    let matched = match &captured {
        Some((value, expansion)) => {
            let m = parameter_form_matches(form, value);
            if m && let Some(display) = expansion
                && let ParameterForm::Match(expr) = form
                && !expr.matches_any_value()
            {
                // The value's runtime form is unknown; the textual match
                // cannot prove the constraint toward `:allow`.
                ctx.record_unresolved(display);
            }
            m
        }
        None => false,
    };
    if let Some((value, expansion)) = captured
        && let ParameterForm::Authorise = form
    {
        // (parameter X (authorise)) single-token capture — recurse with the
        // value parsed as a command line. An expansion-bearing value
        // re-parses as unfaithful text: record it so an inner `:allow`
        // cannot stand.
        if let Some(display) = &expansion {
            ctx.record_unresolved(display);
        }
        let _ = search_tokens;
        return recurse_into_inner_command(fold, pattern, &value, ctx, rules);
    }
    let detail = ArgMatchDetail {
        search_tokens,
        arg_set: ctx.args.to_vec(),
        matched,
        positional_elements: vec![],
        captured_value: None,
    };
    Ok(fold.effect_arg_match(pattern, ctx.args, matched, detail))
}

/// Recurse into a captured command-line value (single occurrence).
///
/// Parses the value as a full shell command line via
/// `evaluate_authorised_string`, so compound inner forms are handled
/// uniformly with strictest-wins aggregation. Surfaces the inner
/// decision via `effect_arg_continuation` so the parameter pattern
/// remains visible in the rule body and the captured value lands as a
/// right-column annotation.
fn recurse_into_inner_command<F: EvalFold>(
    fold: &mut F,
    pattern: &ArgPattern,
    value: &str,
    ctx: &EvalContext,
    rules: &[Rule],
) -> Result<F::EffectOut, EvalError> {
    let _ = rules;
    fold.begin_recursive_eval();
    let eval_result = super::command::evaluate_authorised_string(
        value,
        ctx.config,
        ctx.facts,
        fold,
        ctx.recursion_depth + 1,
        Some(ctx.command),
    )?;
    let detail = ArgMatchDetail {
        search_tokens: vec![],
        arg_set: ctx.args.to_vec(),
        matched: true,
        positional_elements: vec![],
        captured_value: Some(value.to_string()),
    };
    let inner_terminal = fold.effect_terminal(
        &Effect::Terminal {
            decision: eval_result.decision,
            reason: eval_result.reason.as_ref().map(|r| r.to_string()),
        },
        EffectResult::Decision(
            eval_result.decision,
            eval_result.reason.map(|r| r.to_string()),
        ),
    );
    Ok(fold.effect_arg_continuation(pattern, ctx.args, detail, inner_terminal))
}

/// Evaluate `(parameter NAME (authorise))` against a many-till capture
/// that may have multiple occurrences in argv.
///
/// Each occurrence's captured command is evaluated independently. The
/// strictest decision wins (Deny > Ask > Allow). When more than one
/// occurrence is present, the dry-run uses `PureFold` to find the
/// strictest occurrence; only that occurrence is then re-evaluated under
/// the caller's fold so trace fidelity goes to the deciding command.
fn evaluate_multi_occurrence_authorise<F: EvalFold>(
    fold: &mut F,
    pattern: &ArgPattern,
    values: &[(String, super::decompose::Expansion)],
    ctx: &EvalContext,
    rules: &[Rule],
    search_tokens: Vec<String>,
) -> Result<F::EffectOut, EvalError> {
    // Any expansion-bearing occurrence re-parses as unfaithful text:
    // record it so an inner `:allow` cannot stand.
    for (_, expansion) in values {
        if let Some(display) = expansion {
            ctx.record_unresolved(display);
        }
    }
    if values.is_empty() {
        let detail = ArgMatchDetail {
            search_tokens,
            arg_set: ctx.args.to_vec(),
            matched: false,
            positional_elements: vec![],
            captured_value: None,
        };
        return Ok(fold.effect_arg_match(pattern, ctx.args, false, detail));
    }
    if values.len() == 1 {
        return recurse_into_inner_command(fold, pattern, &values[0].0, ctx, rules);
    }

    let mut winner_idx = 0;
    let mut winner_decision: Option<Decision> = None;
    for (i, (value, _)) in values.iter().enumerate() {
        let mut pure = PureFold;
        let result = recurse_into_inner_command(&mut pure, pattern, value, ctx, rules)?;
        if let EffectResult::Decision(decision, _) = result {
            let stricter = match winner_decision {
                None => true,
                Some(prev) => decision > prev,
            };
            if stricter {
                winner_decision = Some(decision);
                winner_idx = i;
            }
        }
    }
    recurse_into_inner_command(fold, pattern, &values[winner_idx].0, ctx, rules)
}

/// Walk the entire arg slice collecting every many-till occurrence's
/// captured value (tokens between the parameter token and its
/// terminator, joined with single spaces). A `--` token short-circuits
/// the scan. An occurrence whose terminator is missing from argv is
/// dropped — the rule cannot match against an unbounded capture.
fn find_many_till_values_with_parser(
    args: &[String],
    expansions: &[super::decompose::Expansion],
    names: &[String],
    parser: &may_i_core::ast::ResolvedParser,
    terminator: &may_i_core::pattern::Expr<may_i_core::ast::Effect>,
) -> Vec<(String, super::decompose::Expansion)> {
    debug_assert_eq!(args.len(), expansions.len());
    let tokens = tokens_for_names_with_parser(parser, names);
    let separators: Vec<String> = parser
        .style
        .separators()
        .iter()
        .filter(|s| !s.trim().is_empty() && s.as_str() != "=")
        .cloned()
        .collect();

    let mut values = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            break;
        }
        let mut consumed = false;
        for tok in &tokens {
            if arg == tok {
                let start = i + 1;
                let mut j = start;
                while j < args.len() && !terminator.is_match(&args[j]) {
                    j += 1;
                }
                if j < args.len() {
                    let expansion = expansions[start..j].iter().find_map(|e| e.clone());
                    values.push((args[start..j].join(" "), expansion));
                    i = j + 1;
                    consumed = true;
                } else {
                    return values;
                }
                break;
            }
            if let Some(value) = equals_value(arg, tok) {
                values.push((value.to_string(), expansions[i].clone()));
                i += 1;
                consumed = true;
                break;
            }
            let mut sep_inline = false;
            for sep in &separators {
                let prefix = format!("{tok}{sep}");
                if let Some(rest) = arg.strip_prefix(&prefix) {
                    values.push((rest.to_string(), expansions[i].clone()));
                    sep_inline = true;
                    break;
                }
            }
            if sep_inline {
                i += 1;
                consumed = true;
                break;
            }
        }
        if !consumed {
            i += 1;
        }
    }
    values
}

/// Apply a non-recursive parameter form (anything other than `MayI`) to a
/// single-token value.
fn parameter_form_matches(form: &ParameterForm, value: &str) -> bool {
    match form {
        ParameterForm::Match(expr) => expr.is_match(value),
        ParameterForm::Authorise => false, // handled in caller
    }
}

/// Helper to evaluate an effect with owned args and a fold.
fn evaluate_effect_with_owned_args_fold<F: EvalFold>(
    fold: &mut F,
    effect: &Effect,
    ctx: &EvalContext,
    rules: &[Rule],
    owned_args: Vec<String>,
    owned_expansions: Vec<super::decompose::Expansion>,
    bound_facts: ContextFacts,
) -> Result<F::EffectOut, EvalError> {
    let merged_facts = ctx.facts.merge(&bound_facts);
    let (_residual, inner_parser_bindings) =
        super::bindings::parse_argv(&ctx.parser, &owned_args, &owned_expansions);
    let inner_ctx = EvalContext {
        command: ctx.command,
        args: &owned_args,
        arg_expansions: owned_expansions,
        facts: &merged_facts,
        bindings: ctx.bindings.clone(),
        recursion_depth: ctx.recursion_depth,
        recursion_limit: ctx.recursion_limit,
        parser: ctx.parser.clone(),
        parser_bindings: inner_parser_bindings,
        unresolved: ctx.unresolved.clone(),
        config: ctx.config,
    };
    evaluate_effect_fold(fold, effect, &inner_ctx, rules)
}

#[cfg(test)]
mod tail_authorise_fold_tests {
    use super::*;
    use may_i_core::ast::{FlagsMode, ResolvedParser};

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn parser_with_flags_mode(command: &str, mode: FlagsMode) -> ResolvedParser {
        let mut p = ResolvedParser::synthetic_gnu(command);
        p.flags_mode = mode;
        p
    }

    /// Evaluate `(tail (authorise))` directly so the test exercises the
    /// boundary-absent branch without needing a full parse pipeline.
    fn run(command: &str, args: &[String], parser: ResolvedParser) -> EffectResult {
        let facts = may_i_core::ContextFacts::default();
        let bindings = std::collections::HashMap::new();
        let mut ctx = EvalContext::new(command, args, &facts, bindings);
        ctx.parser = parser;
        let pattern = ArgPattern::Tail;
        let effect = Effect::ArgPattern(pattern);
        let rules: Vec<Rule> = Vec::new();
        evaluate_effect(&effect, &ctx, &rules).expect("effect evaluates")
    }

    #[test]
    fn boundary_absent_with_until_mode_returns_no_match() {
        let args = argv(&["shell", "pkg"]);
        let parser = parser_with_flags_mode(
            "nix",
            FlagsMode::Until(vec!["--command".to_string(), "-c".to_string()]),
        );
        let result = run("nix", &args, parser);
        assert!(
            result.is_nil(),
            "expected no-match (Nil) when boundary absent under (flags (until …)); got {result:?}"
        );
    }

    #[test]
    fn permute_mode_falls_back_to_full_argv() {
        // Under `(flags permute)` the parser declares no boundary;
        // `(tail (authorise))` recurses on the full argv.
        let args = argv(&["rm", "-rf", "/tmp/x"]);
        let parser = parser_with_flags_mode("sudo", FlagsMode::Permute);
        let result = run("sudo", &args, parser);
        assert!(
            !result.is_nil(),
            "permute parser must fall back to full-argv recursion; got {result:?}"
        );
    }
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
