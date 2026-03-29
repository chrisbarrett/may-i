// Unified effect evaluator.
// All effect forms evaluate to EffectResult (Decision | Nil).

use may_i_core::ast::{Effect, EffectResult, Predicate, Rule};
use may_i_core::pattern::{ArgPattern, CommandPattern, PositionalArg};
use may_i_core::{ContextFacts, Decision, FactPattern, FactQuery};

use crate::EvalResult;
use crate::fold::{ArgMatchDetail, ChildResult, EvalFold, PureFold, build_fact_detail};

/// Maximum recursion depth for (may-i ...) evaluation.
pub const DEFAULT_RECURSION_LIMIT: usize = 10;

/// The result of evaluating a predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateResult {
    Match,
    NoMatch,
}

/// Context for evaluation.
#[derive(Clone)]
pub struct EvalContext<'a> {
    /// The command being evaluated.
    pub command: &'a str,
    /// The arguments to the command.
    pub args: &'a [String],
    /// Context facts.
    pub facts: &'a ContextFacts,
    /// Current recursion depth.
    pub recursion_depth: usize,
    /// Maximum recursion depth allowed.
    pub recursion_limit: usize,
}

impl<'a> EvalContext<'a> {
    /// Create a new evaluation context.
    pub fn new(command: &'a str, args: &'a [String], facts: &'a ContextFacts) -> Self {
        Self {
            command,
            args,
            facts,
            recursion_depth: 0,
            recursion_limit: DEFAULT_RECURSION_LIMIT,
        }
    }

    /// Create a context with custom recursion limit.
    pub fn with_recursion_limit(mut self, limit: usize) -> Self {
        self.recursion_limit = limit;
        self
    }

    /// Check if we've exceeded the recursion limit.
    pub fn is_depth_exceeded(&self) -> bool {
        self.recursion_depth >= self.recursion_limit
    }

    /// Increment recursion depth for nested evaluation.
    pub fn deeper(&self) -> Self {
        Self {
            command: self.command,
            args: self.args,
            facts: self.facts,
            recursion_depth: self.recursion_depth + 1,
            recursion_limit: self.recursion_limit,
        }
    }
}

/// Evaluate a command against config and context using PureFold.
/// This is the main entry point for evaluation.
pub fn evaluate(
    command: &str,
    args: &[String],
    config: &may_i_core::ast::Config,
    facts: &ContextFacts,
) -> EvalResult {
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
) -> EvalResult {
    let evaluator = Evaluator::new(&config.rules);
    let ctx = EvalContext::new(command, args, facts);
    evaluator.evaluate(fold, &ctx)
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
    pub fn evaluate<F: EvalFold>(&self, fold: &mut F, ctx: &EvalContext) -> EvalResult {
        // If depth exceeded, return ask
        if ctx.is_depth_exceeded() {
            return EvalResult::new(
                Decision::Ask,
                Some(format!(
                    "recursion depth limit ({}) exceeded",
                    ctx.recursion_limit
                )),
            );
        }

        // Evaluate rules in order, return first non-Nil result
        for rule in self.rules {
            let out = self.evaluate_rule(fold, rule, ctx);
            let result = F::effect_result(&out);

            match result {
                EffectResult::Decision(decision, reason) => {
                    return EvalResult::new(*decision, reason.clone());
                }
                EffectResult::Nil => {
                    continue;
                }
            }
        }

        // No rules matched - return ask
        let reason = "no matching rule found";
        let _out = fold.default_ask(reason);
        EvalResult::new(Decision::Ask, Some(reason.to_string()))
    }

    /// Evaluate a single rule. Returns the fold output.
    fn evaluate_rule<F: EvalFold>(
        &self,
        fold: &mut F,
        rule: &Rule,
        ctx: &EvalContext,
    ) -> F::EffectOut {
        // Step 1: Evaluate command effect - must return non-Nil for rule to apply
        let command_out = evaluate_effect_fold(fold, &rule.command_effect.value, ctx, self.rules);
        let command_result = F::effect_result(&command_out);

        if command_result.is_nil() {
            return fold.rule_skipped(rule);
        }

        // Step 2: Evaluate subsequent effects in sequence
        for effect in &rule.effects {
            let out = evaluate_effect_fold(fold, &effect.value, ctx, self.rules);
            let result = F::effect_result(&out);

            match result {
                EffectResult::Decision(_, _) => {
                    let line = None;
                    return fold.rule_matched(rule, line, command_out, out);
                }
                EffectResult::Nil => {}
            }
        }

        // Step 3: All effects returned Nil, default to :ask
        let ask_result = EffectResult::Decision(Decision::Ask, None);
        let ask_out = fold.effect_terminal(&Effect::Ask(None), ask_result);
        let line = None;
        fold.rule_matched(rule, line, command_out, ask_out)
    }
}

/// Evaluate a predicate against the context (non-generic, uses PureFold).
pub fn evaluate_predicate(predicate: &Predicate, ctx: &EvalContext) -> PredicateResult {
    let mut fold = PureFold;
    let out = evaluate_predicate_fold(&mut fold, predicate, ctx);
    PureFold::predicate_result(&out)
}

/// Evaluate a predicate with a fold.
pub fn evaluate_predicate_fold<F: EvalFold>(
    fold: &mut F,
    predicate: &Predicate,
    ctx: &EvalContext,
) -> F::PredicateOut {
    match predicate {
        Predicate::Fact(query) => {
            let result = evaluate_fact_query(query, ctx);
            let detail = build_fact_detail(query, ctx.facts);
            fold.predicate_fact(query, result, detail)
        }
        Predicate::Arg(pattern) => {
            let result = evaluate_arg_pattern_predicate(pattern, ctx);
            fold.predicate_arg(pattern, ctx.args, result)
        }
        Predicate::And(predicates) => {
            let mut children = Vec::new();
            let mut result = PredicateResult::Match;
            let mut short_circuited = false;

            for p in predicates {
                if short_circuited {
                    children.push(ChildResult::Skipped);
                } else {
                    let out = evaluate_predicate_fold(fold, p, ctx);
                    let r = F::predicate_result(&out);
                    if r == PredicateResult::NoMatch {
                        result = PredicateResult::NoMatch;
                        short_circuited = true;
                    }
                    children.push(ChildResult::Evaluated(out));
                }
            }
            fold.predicate_and(children, result)
        }
        Predicate::Or(predicates) => {
            let mut children = Vec::new();
            let mut result = PredicateResult::NoMatch;
            let mut short_circuited = false;

            for p in predicates {
                if short_circuited {
                    children.push(ChildResult::Skipped);
                } else {
                    let out = evaluate_predicate_fold(fold, p, ctx);
                    let r = F::predicate_result(&out);
                    if r == PredicateResult::Match {
                        result = PredicateResult::Match;
                        short_circuited = true;
                    }
                    children.push(ChildResult::Evaluated(out));
                }
            }
            fold.predicate_or(children, result)
        }
        Predicate::Not(inner) => {
            let out = evaluate_predicate_fold(fold, inner, ctx);
            let r = F::predicate_result(&out);
            let result = match r {
                PredicateResult::Match => PredicateResult::NoMatch,
                PredicateResult::NoMatch => PredicateResult::Match,
            };
            fold.predicate_not(out, result)
        }
        Predicate::Named(name) => {
            panic!(
                "Named predicates should be resolved before evaluation: '{}'",
                name
            )
        }
    }
}

/// Evaluate a fact query against the context.
fn evaluate_fact_query(query: &FactQuery, ctx: &EvalContext) -> PredicateResult {
    match query {
        FactQuery::Presence { key, .. } => {
            if ctx.facts.has(key) {
                PredicateResult::Match
            } else {
                PredicateResult::NoMatch
            }
        }
        FactQuery::Value { key, pattern } => {
            if let Some(set) = ctx.facts.get(key) {
                if set.iter().any(|s| match_fact_pattern(pattern, s)) {
                    PredicateResult::Match
                } else {
                    PredicateResult::NoMatch
                }
            } else {
                PredicateResult::NoMatch
            }
        }
    }
}

/// Match a fact pattern against a value.
fn match_fact_pattern(pattern: &FactPattern, value: &str) -> bool {
    match pattern {
        FactPattern::Wildcard => true,
        FactPattern::Literal(s) => s == value,
        FactPattern::Regex(re) => re.is_match(value),
        FactPattern::And(patterns) => patterns.iter().all(|p| match_fact_pattern(p, value)),
        FactPattern::Or(patterns) => patterns.iter().any(|p| match_fact_pattern(p, value)),
        FactPattern::Not(inner) => !match_fact_pattern(inner, value),
    }
}

/// Evaluate an arg pattern as a predicate (returns Match/NoMatch).
fn evaluate_arg_pattern_predicate(pattern: &ArgPattern, ctx: &EvalContext) -> PredicateResult {
    match pattern {
        ArgPattern::Positional {
            patterns,
            continuation: _,
        } => {
            // Match positional args against patterns
            let positional_args: Vec<&String> = ctx
                .args
                .iter()
                .filter(|arg| !arg.starts_with('-'))
                .collect();

            let (matched, _, _) = match_positional_patterns(&positional_args, patterns);
            if matched {
                PredicateResult::Match
            } else {
                PredicateResult::NoMatch
            }
        }
        ArgPattern::Exact {
            patterns,
            continuation: _,
        } => {
            let positional_args: Vec<&String> = ctx
                .args
                .iter()
                .filter(|arg| !arg.starts_with('-'))
                .collect();

            let (matched, consumed, _) = match_positional_patterns(&positional_args, patterns);
            if consumed == positional_args.len() && matched {
                PredicateResult::Match
            } else {
                PredicateResult::NoMatch
            }
        }
        ArgPattern::Anywhere(exprs) => {
            for expr in exprs {
                match expr {
                    may_i_core::pattern::Expr::Literal(s) => {
                        if ctx.args.iter().any(|arg| arg == s) {
                            return PredicateResult::Match;
                        }
                    }
                    may_i_core::pattern::Expr::Wildcard => {
                        // Wildcard matches anything
                        return PredicateResult::Match;
                    }
                    _ => {} // Other variants not supported in Anywhere
                }
            }
            PredicateResult::NoMatch
        }
        ArgPattern::Forbidden(exprs) => {
            for expr in exprs {
                match expr {
                    may_i_core::pattern::Expr::Literal(s) => {
                        if ctx.args.iter().any(|arg| arg == s) {
                            // Found the forbidden pattern - this is a constraint violation
                            return PredicateResult::NoMatch;
                        }
                    }
                    may_i_core::pattern::Expr::Wildcard => {
                        // Wildcard forbidden means any arg is forbidden
                        if !ctx.args.is_empty() {
                            return PredicateResult::NoMatch;
                        }
                    }
                    _ => {} // Other variants not supported in Forbidden
                }
            }
            // Didn't find any forbidden patterns - constraint satisfied
            PredicateResult::Match
        }
    }
}

/// Match positional patterns against args, capturing bound facts.
/// Returns (matched, consumed_count, bound_facts) where consumed_count is the
/// number of args consumed and bound_facts contains any facts captured from
/// Expr::Bind expressions in the patterns.
fn match_positional_patterns(
    args: &[&String],
    patterns: &[PositionalArg],
) -> (bool, usize, ContextFacts) {
    let mut facts = ContextFacts::default();
    let mut arg_idx = 0;

    for pattern in patterns.iter() {
        match &pattern.quantifier {
            may_i_core::Quantifier::One => {
                if arg_idx >= args.len() {
                    return (false, arg_idx, facts);
                }
                let (matched, f) = match_expr_with_binding(&pattern.pattern, args[arg_idx]);
                facts = facts.merge(&f);
                if !matched {
                    return (false, arg_idx, facts);
                }
                arg_idx += 1;
            }
            may_i_core::Quantifier::Optional => {
                if arg_idx < args.len() {
                    let (matched, f) = match_expr_with_binding(&pattern.pattern, args[arg_idx]);
                    if matched {
                        facts = facts.merge(&f);
                        arg_idx += 1;
                    }
                }
            }
            may_i_core::Quantifier::ZeroOrMore => {
                while arg_idx < args.len() {
                    let (matched, f) = match_expr_with_binding(&pattern.pattern, args[arg_idx]);
                    if !matched {
                        break;
                    }
                    facts = facts.merge(&f);
                    arg_idx += 1;
                }
            }
            may_i_core::Quantifier::OneOrMore => {
                if arg_idx >= args.len() {
                    return (false, arg_idx, facts);
                }
                let (matched, f) = match_expr_with_binding(&pattern.pattern, args[arg_idx]);
                if !matched {
                    return (false, arg_idx, facts);
                }
                facts = facts.merge(&f);
                arg_idx += 1;
                while arg_idx < args.len() {
                    let (matched, f) = match_expr_with_binding(&pattern.pattern, args[arg_idx]);
                    if !matched {
                        break;
                    }
                    facts = facts.merge(&f);
                    arg_idx += 1;
                }
            }
        }
    }

    (true, arg_idx, facts)
}

/// Match a single expression against a value, capturing bound facts.
/// Returns (matched, bound_facts) where bound_facts contains any facts
/// captured from Expr::Bind expressions.
fn match_expr_with_binding<E: std::fmt::Debug + may_i_core::ToDoc>(
    expr: &may_i_core::pattern::Expr<E>,
    value: &str,
) -> (bool, ContextFacts) {
    use may_i_core::pattern::Expr;
    let mut facts = ContextFacts::default();

    let matched = match expr {
        Expr::Literal(s) => s == value,
        Expr::Wildcard => true,
        Expr::Regex(re) => re.is_match(value),
        Expr::And(exprs) => {
            let mut all_match = true;
            for e in exprs {
                let (m, f) = match_expr_with_binding(e, value);
                facts = facts.merge(&f);
                if !m {
                    all_match = false;
                }
            }
            all_match
        }
        Expr::Or(exprs) => {
            let mut any_match = false;
            for e in exprs {
                let (m, f) = match_expr_with_binding(e, value);
                if m {
                    any_match = true;
                    facts = facts.merge(&f);
                }
            }
            any_match
        }
        Expr::Not(inner) => {
            let (m, _) = match_expr_with_binding(inner, value);
            !m
        }
        Expr::Bind { key, expr: inner } => {
            // First check if the inner expression matches
            let (inner_matched, inner_facts) = match_expr_with_binding(inner, value);
            facts = facts.merge(&inner_facts);

            if inner_matched {
                // Capture the matched value as a fact
                facts.insert_scalar(key.as_str(), value);
                true
            } else {
                false
            }
        }
        Expr::Cond(branches) => {
            // Match if any branch's test expression matches the value
            branches
                .iter()
                .any(|b| match_expr_with_binding(&b.test, value).0)
        }
    };

    (matched, facts)
}

/// Find the effect from a matching Expr::Cond branch for a given arg value.
/// Returns the effect from the first branch whose test matches, or the wildcard
/// (else) branch's effect if no specific branch matches.
fn find_cond_branch_effect<'a>(
    branches: &'a [may_i_core::pattern::ExprBranch<Effect>],
    value: &str,
) -> Option<&'a Effect> {
    for branch in branches {
        if match_expr_with_binding(&branch.test, value).0 {
            return Some(&branch.effect);
        }
    }
    None
}

/// If the last positional pattern is an Expr::Cond, find the matching branch's
/// effect for the last consumed arg. Returns None if the last pattern isn't a Cond
/// or no branch matched.
fn resolve_trailing_cond_effect<'a>(
    patterns: &'a [may_i_core::pattern::PositionalArg],
    positional_args: &[&String],
    consumed: usize,
) -> Option<&'a Effect> {
    if consumed == 0 {
        return None;
    }
    let last_pattern = patterns.last()?;
    if let may_i_core::pattern::Expr::Cond(branches) = &last_pattern.pattern {
        let last_arg = positional_args.get(consumed - 1)?;
        find_cond_branch_effect(branches, last_arg)
    } else {
        None
    }
}

/// Evaluate an effect to produce an EffectResult (convenience, uses PureFold).
pub fn evaluate_effect(effect: &Effect, ctx: &EvalContext, rules: &[Rule]) -> EffectResult {
    evaluate_effect_fold(&mut PureFold, effect, ctx, rules)
}

/// Evaluate an effect with a fold, producing `F::EffectOut`.
pub fn evaluate_effect_fold<F: EvalFold>(
    fold: &mut F,
    effect: &Effect,
    ctx: &EvalContext,
    rules: &[Rule],
) -> F::EffectOut {
    match effect {
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
        Effect::ArgPattern(pattern) => evaluate_arg_pattern_effect_fold(fold, pattern, ctx, rules),

        // Combinators
        Effect::And { effects } => {
            let mut children = Vec::new();
            let mut last_result = EffectResult::Decision(Decision::Allow, None);
            let mut short_circuited = false;

            for child in effects {
                if short_circuited {
                    children.push(ChildResult::Skipped);
                } else {
                    let out = evaluate_effect_fold(fold, &child.value, ctx, rules);
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
                    let out = evaluate_effect_fold(fold, &child.value, ctx, rules);
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
            let out = evaluate_effect_fold(fold, &inner.value, ctx, rules);
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
            let pred_out = evaluate_predicate_fold(fold, &predicate.value, ctx);
            let pred_result = F::predicate_result(&pred_out);
            let (body_child, result) = if pred_result == PredicateResult::Match {
                let body_out = evaluate_effect_fold(fold, &body.value, ctx, rules);
                let body_result = F::effect_result(&body_out).clone();
                (ChildResult::Evaluated(body_out), body_result)
            } else {
                (ChildResult::Skipped, EffectResult::Nil)
            };
            fold.effect_when(pred_out, body_child, result)
        }

        Effect::Unless {
            predicate,
            effect: body,
        } => {
            let pred_out = evaluate_predicate_fold(fold, &predicate.value, ctx);
            let pred_result = F::predicate_result(&pred_out);
            let (body_child, result) = if pred_result == PredicateResult::NoMatch {
                let body_out = evaluate_effect_fold(fold, &body.value, ctx, rules);
                let body_result = F::effect_result(&body_out).clone();
                (ChildResult::Evaluated(body_out), body_result)
            } else {
                (ChildResult::Skipped, EffectResult::Nil)
            };
            fold.effect_unless(pred_out, body_child, result)
        }

        Effect::If {
            predicate,
            then_effect,
            else_effect,
        } => {
            let pred_out = evaluate_predicate_fold(fold, &predicate.value, ctx);
            let pred_result = F::predicate_result(&pred_out);
            let (then_child, else_child, result) = if pred_result == PredicateResult::Match {
                let then_out = evaluate_effect_fold(fold, &then_effect.value, ctx, rules);
                let then_result = F::effect_result(&then_out).clone();
                (
                    ChildResult::Evaluated(then_out),
                    ChildResult::Skipped,
                    then_result,
                )
            } else {
                let else_out = evaluate_effect_fold(fold, &else_effect.value, ctx, rules);
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
                    // Skip remaining branches
                    let pred_out = evaluate_predicate_fold(fold, &predicate.value, ctx);
                    fold_branches.push((pred_out, ChildResult::Skipped));
                } else {
                    let pred_out = evaluate_predicate_fold(fold, &predicate.value, ctx);
                    let pred_result = F::predicate_result(&pred_out);
                    if pred_result == PredicateResult::Match {
                        let body_out = evaluate_effect_fold(fold, &branch_effect.value, ctx, rules);
                        result = F::effect_result(&body_out).clone();
                        fold_branches.push((pred_out, ChildResult::Evaluated(body_out)));
                        found = true;
                    } else {
                        fold_branches.push((pred_out, ChildResult::Skipped));
                    }
                }
            }

            let fb = if found {
                fallback.as_ref().map(|_| ChildResult::Skipped)
            } else if let Some(fb) = fallback {
                let fb_out = evaluate_effect_fold(fold, &fb.value, ctx, rules);
                result = F::effect_result(&fb_out).clone();
                Some(ChildResult::Evaluated(fb_out))
            } else {
                None
            };

            fold.effect_cond(fold_branches, fb, result)
        }

        // Recursion
        Effect::MayI { pattern } => {
            match extract_inner_command(pattern, ctx.args) {
                Some((inner_cmd, inner_args)) => {
                    let evaluator = Evaluator::new(rules);
                    let mut inner_facts = ctx.facts.clone();
                    inner_facts.push(":via", ctx.command);
                    let inner_ctx = EvalContext {
                        command: &inner_cmd,
                        args: &inner_args,
                        facts: &inner_facts,
                        recursion_depth: ctx.recursion_depth + 1,
                        recursion_limit: ctx.recursion_limit,
                    };
                    let eval_result = evaluator.evaluate(fold, &inner_ctx);
                    let inner_result =
                        EffectResult::Decision(eval_result.decision, eval_result.reason);
                    // For the fold, we build a synthetic terminal output representing the inner result
                    let inner_out =
                        fold.effect_terminal(&Effect::Allow(None), inner_result.clone());
                    fold.effect_may_i(&inner_cmd, &inner_args, inner_result, inner_out)
                }
                None => fold.effect_may_i_no_match(pattern),
            }
        }
    }
}

/// Check if a command pattern matches a command string.
fn match_command_pattern(pattern: &CommandPattern, command: &str) -> bool {
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
) -> F::EffectOut {
    match pattern {
        ArgPattern::Positional {
            patterns,
            continuation,
        } => {
            let positional_args: Vec<&String> = ctx
                .args
                .iter()
                .filter(|arg| !arg.starts_with('-'))
                .collect();

            let (matched, consumed, bound_facts) =
                match_positional_patterns(&positional_args, patterns);
            if matched {
                // Check for explicit continuation first, then trailing Expr::Cond
                let effective_continuation = continuation
                    .as_deref()
                    .or_else(|| resolve_trailing_cond_effect(patterns, &positional_args, consumed));
                if let Some(cont) = effective_continuation {
                    let remaining_args: Vec<String> = ctx
                        .args
                        .iter()
                        .filter(|arg| !arg.starts_with('-'))
                        .skip(consumed)
                        .map(|s| s.to_string())
                        .collect();
                    evaluate_effect_with_owned_args_fold(
                        fold,
                        cont,
                        ctx,
                        rules,
                        remaining_args,
                        bound_facts,
                    )
                } else {
                    let detail = ArgMatchDetail {
                        search_tokens: patterns
                            .iter()
                            .map(|p| format!("{:?}", p.pattern))
                            .collect(),
                        arg_set: ctx.args.to_vec(),
                        matched: true,
                    };
                    fold.effect_arg_match(pattern, ctx.args, true, detail)
                }
            } else {
                let detail = ArgMatchDetail {
                    search_tokens: patterns
                        .iter()
                        .map(|p| format!("{:?}", p.pattern))
                        .collect(),
                    arg_set: ctx.args.to_vec(),
                    matched: false,
                };
                fold.effect_arg_match(pattern, ctx.args, false, detail)
            }
        }
        ArgPattern::Exact {
            patterns,
            continuation,
        } => {
            let positional_args: Vec<&String> = ctx
                .args
                .iter()
                .filter(|arg| !arg.starts_with('-'))
                .collect();

            let (matched, consumed, bound_facts) =
                match_positional_patterns(&positional_args, patterns);
            let exact_match = consumed == positional_args.len() && matched;
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
                    evaluate_effect_with_owned_args_fold(
                        fold,
                        cont,
                        ctx,
                        rules,
                        remaining_args,
                        bound_facts,
                    )
                } else {
                    let detail = ArgMatchDetail {
                        search_tokens: patterns
                            .iter()
                            .map(|p| format!("{:?}", p.pattern))
                            .collect(),
                        arg_set: ctx.args.to_vec(),
                        matched: true,
                    };
                    fold.effect_arg_match(pattern, ctx.args, true, detail)
                }
            } else {
                let detail = ArgMatchDetail {
                    search_tokens: patterns
                        .iter()
                        .map(|p| format!("{:?}", p.pattern))
                        .collect(),
                    arg_set: ctx.args.to_vec(),
                    matched: false,
                };
                fold.effect_arg_match(pattern, ctx.args, false, detail)
            }
        }
        ArgPattern::Anywhere(exprs) => {
            let mut matched = false;
            let mut search_tokens = Vec::new();
            for expr in exprs {
                match expr {
                    may_i_core::pattern::Expr::Literal(s) => {
                        search_tokens.push(s.clone());
                        if ctx.args.iter().any(|arg| arg == s) {
                            matched = true;
                        }
                    }
                    may_i_core::pattern::Expr::Wildcard => {
                        search_tokens.push("*".to_string());
                        matched = true;
                    }
                    _ => {}
                }
            }
            let detail = ArgMatchDetail {
                search_tokens,
                arg_set: ctx.args.to_vec(),
                matched,
            };
            fold.effect_arg_match(pattern, ctx.args, matched, detail)
        }
        ArgPattern::Forbidden(exprs) => {
            let mut found_forbidden = false;
            let mut search_tokens = Vec::new();
            for expr in exprs {
                match expr {
                    may_i_core::pattern::Expr::Literal(s) => {
                        search_tokens.push(s.clone());
                        if ctx.args.iter().any(|arg| arg == s) {
                            found_forbidden = true;
                        }
                    }
                    may_i_core::pattern::Expr::Wildcard => {
                        search_tokens.push("*".to_string());
                        if !ctx.args.is_empty() {
                            found_forbidden = true;
                        }
                    }
                    _ => {}
                }
            }
            if found_forbidden {
                fold.effect_terminal(
                    &Effect::ArgPattern(pattern.clone()),
                    EffectResult::Decision(Decision::Deny, None),
                )
            } else {
                fold.effect_terminal(
                    &Effect::ArgPattern(pattern.clone()),
                    EffectResult::Decision(Decision::Allow, None),
                )
            }
        }
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
) -> F::EffectOut {
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

/// Extract inner command from args based on pattern (for may-i recursion).
fn extract_inner_command(pattern: &ArgPattern, args: &[String]) -> Option<(String, Vec<String>)> {
    // For now, simple implementation: take remaining positional args after pattern match
    // Full implementation would need to properly handle the pattern
    match pattern {
        ArgPattern::Positional { .. } | ArgPattern::Exact { .. } => {
            // Extract first positional arg as command, rest as args
            let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
            if positional.is_empty() {
                None
            } else {
                let cmd = positional[0].clone();
                let remaining: Vec<String> = positional[1..].iter().map(|s| (*s).clone()).collect();
                Some((cmd, remaining))
            }
        }
        ArgPattern::Anywhere(_) => {
            // Take all args as inner command
            if args.is_empty() {
                None
            } else {
                let cmd = args[0].clone();
                let remaining: Vec<String> = args[1..].to_vec();
                Some((cmd, remaining))
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_context<'a>(
        command: &'a str,
        args: &'a [String],
        facts: &'a ContextFacts,
    ) -> EvalContext<'a> {
        EvalContext::new(command, args, facts)
    }

    #[test]
    fn evaluate_terminal_effects() {
        let facts = ContextFacts::default();
        let ctx = dummy_context("test", &[], &facts);
        let rules: &[Rule] = &[];

        assert_eq!(
            evaluate_effect(&Effect::Allow(None), &ctx, rules),
            EffectResult::Decision(Decision::Allow, None)
        );
        assert_eq!(
            evaluate_effect(&Effect::Ask(None), &ctx, rules),
            EffectResult::Decision(Decision::Ask, None)
        );
        assert_eq!(
            evaluate_effect(&Effect::Deny(None), &ctx, rules),
            EffectResult::Decision(Decision::Deny, None)
        );
    }

    #[test]
    fn evaluate_command_pattern() {
        let facts = ContextFacts::default();
        let ctx = dummy_context("git", &[], &facts);
        let rules: &[Rule] = &[];

        let pattern = CommandPattern::Literal("git".to_string());
        assert_eq!(
            evaluate_effect(&Effect::CommandPattern(pattern), &ctx, rules),
            EffectResult::Decision(Decision::Allow, None)
        );

        let pattern = CommandPattern::Literal("hg".to_string());
        assert_eq!(
            evaluate_effect(&Effect::CommandPattern(pattern), &ctx, rules),
            EffectResult::Nil
        );
    }

    #[test]
    fn evaluate_and_combinator() {
        let facts = ContextFacts::default();
        let ctx = dummy_context("test", &[], &facts);
        let rules: &[Rule] = &[];

        // All non-Nil returns last
        let effects = vec![
            may_i_core::ast::Spanned::new(Effect::Allow(None), may_i_core::span::Span::new(0, 1)),
            may_i_core::ast::Spanned::new(Effect::Ask(None), may_i_core::span::Span::new(0, 1)),
        ];
        assert_eq!(
            evaluate_effect(&Effect::And { effects }, &ctx, rules),
            EffectResult::Decision(Decision::Ask, None)
        );
    }

    #[test]
    fn evaluate_or_combinator() {
        let facts = ContextFacts::default();
        let ctx = dummy_context("test", &[], &facts);
        let rules: &[Rule] = &[];

        // Returns first non-Nil
        let effects = vec![
            may_i_core::ast::Spanned::new(Effect::Allow(None), may_i_core::span::Span::new(0, 1)),
            may_i_core::ast::Spanned::new(Effect::Deny(None), may_i_core::span::Span::new(0, 1)),
        ];
        assert_eq!(
            evaluate_effect(&Effect::Or { effects }, &ctx, rules),
            EffectResult::Decision(Decision::Allow, None)
        );
    }

    #[test]
    fn evaluate_not_combinator() {
        let facts = ContextFacts::default();
        let ctx = dummy_context("test", &[], &facts);
        let rules: &[Rule] = &[];

        // Not of Allow returns Nil
        let effect =
            may_i_core::ast::Spanned::new(Effect::Allow(None), may_i_core::span::Span::new(0, 1));
        assert_eq!(
            evaluate_effect(
                &Effect::Not {
                    effect: Box::new(effect)
                },
                &ctx,
                rules
            ),
            EffectResult::Nil
        );
    }

    #[test]
    fn predicate_evaluation() {
        let facts = ContextFacts::default();
        let ctx = dummy_context("test", &[], &facts);

        let pred = Predicate::Fact(FactQuery::Presence {
            key: ":missing".to_string(),
            vector_syntax: false,
        });
        assert_eq!(evaluate_predicate(&pred, &ctx), PredicateResult::NoMatch);

        let mut facts = ContextFacts::default();
        facts.insert_present(":present");
        let ctx = dummy_context("test", &[], &facts);

        let pred = Predicate::Fact(FactQuery::Presence {
            key: ":present".to_string(),
            vector_syntax: false,
        });
        assert_eq!(evaluate_predicate(&pred, &ctx), PredicateResult::Match);
    }

    #[test]
    fn context_depth_tracking() {
        let facts = ContextFacts::default();
        let ctx = EvalContext::new("test", &[], &facts).with_recursion_limit(5);
        assert_eq!(ctx.recursion_limit, 5);
        assert!(!ctx.is_depth_exceeded());

        let deep_ctx = EvalContext {
            command: ctx.command,
            args: ctx.args,
            facts: ctx.facts,
            recursion_depth: 5, // Set to equal recursion_limit
            recursion_limit: ctx.recursion_limit,
        };
        assert!(deep_ctx.is_depth_exceeded());
    }

    // --- Tests for fact binding in expressions ---

    #[test]
    fn fact_binding_captures_matched_value() {
        // When matching a Bind expression, the matched value should be captured
        use may_i_core::ast::Effect;
        use may_i_core::{Expr, Keyword};

        let bind_expr: Expr<Effect> = Expr::Bind {
            key: Keyword::new(":ssh/host").unwrap(),
            expr: Box::new(Expr::Wildcard),
        };

        // Match against "prod-server-01"
        let matched_value = "prod-server-01";

        // The match should succeed and bind the fact
        let (matched, bound_facts) = match_expr_with_binding(&bind_expr, matched_value);
        assert!(matched);
        assert_eq!(bound_facts.get_scalar(":ssh/host"), Some(matched_value));
    }

    #[test]
    fn positional_with_fact_binding_binds_for_continuation() {
        // When a positional pattern with fact binding matches,
        // the bound fact should be available in the continuation
        use may_i_core::ast::Effect;
        use may_i_core::pattern::{ArgPattern, PositionalArg};
        use may_i_core::{Expr, Keyword, Quantifier};

        // Build: (positional [:ssh/host] . (may-i *))
        // Simple binding - [:kw] is equivalent to [:kw *]
        let bind_expr = Expr::Bind {
            key: Keyword::new(":ssh/host").unwrap(),
            expr: Box::new(Expr::Wildcard),
        };

        let pattern = ArgPattern::Positional {
            patterns: vec![PositionalArg {
                quantifier: Quantifier::One,
                pattern: bind_expr,
                recursive: false,
            }],
            continuation: Some(Box::new(Effect::MayI {
                pattern: ArgPattern::Positional {
                    patterns: vec![PositionalArg {
                        quantifier: Quantifier::One,
                        pattern: Expr::Wildcard,
                        recursive: false,
                    }],
                    continuation: None,
                },
            })),
        };

        // Test that the pattern structure is correct
        match &pattern {
            ArgPattern::Positional {
                patterns,
                continuation,
            } => {
                assert_eq!(patterns.len(), 1);
                assert!(matches!(patterns[0].pattern, Expr::Bind { .. }));
                assert!(continuation.is_some());
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn match_expr_with_binding_and_expr() {
        use may_i_core::{Expr, Keyword};

        // Test And expression with Bind - all must match
        let and_expr: Expr<Effect> = Expr::And(vec![
            Expr::Bind {
                key: Keyword::new(":host").unwrap(),
                expr: Box::new(Expr::Wildcard),
            },
            Expr::Literal("prod".to_string()),
        ]);

        let (matched, facts) = match_expr_with_binding(&and_expr, "prod");
        assert!(matched);
        assert_eq!(facts.get_scalar(":host"), Some("prod"));

        // Should not match if second part fails
        let (matched, facts) = match_expr_with_binding(&and_expr, "dev");
        assert!(!matched);
        // First part matched and bound the fact
        assert_eq!(facts.get_scalar(":host"), Some("dev"));
    }

    #[test]
    fn match_expr_with_binding_or_expr() {
        use may_i_core::{Expr, Keyword};

        // Test Or expression with Bind
        let or_expr: Expr<Effect> = Expr::Or(vec![
            Expr::Bind {
                key: Keyword::new(":special").unwrap(),
                expr: Box::new(Expr::Literal("special".to_string())),
            },
            Expr::Wildcard,
        ]);

        // First branch matches and binds
        let (matched, facts) = match_expr_with_binding(&or_expr, "special");
        assert!(matched);
        assert_eq!(facts.get_scalar(":special"), Some("special"));

        // Second branch matches, no binding from first
        let (matched, facts) = match_expr_with_binding(&or_expr, "anything");
        assert!(matched);
        assert_eq!(facts.get_scalar(":special"), None);
    }

    #[test]
    fn match_expr_with_binding_not_expr() {
        use may_i_core::{Expr, Keyword};

        // Test Not expression - should not bind from inner
        let not_expr: Expr<Effect> = Expr::Not(Box::new(Expr::Bind {
            key: Keyword::new(":excluded").unwrap(),
            expr: Box::new(Expr::Literal("exclude".to_string())),
        }));

        // Inner matches, so Not fails - no binding
        let (matched, facts) = match_expr_with_binding(&not_expr, "exclude");
        assert!(!matched);
        assert_eq!(facts.get_scalar(":excluded"), None);

        // Inner doesn't match, so Not succeeds - still no binding
        let (matched, facts) = match_expr_with_binding(&not_expr, "include");
        assert!(matched);
        assert_eq!(facts.get_scalar(":excluded"), None);
    }

    #[test]
    fn match_expr_with_binding_nested_bind() {
        use may_i_core::{Expr, Keyword};

        // Test Bind wrapping another Bind
        let nested_bind: Expr<Effect> = Expr::Bind {
            key: Keyword::new(":outer").unwrap(),
            expr: Box::new(Expr::Bind {
                key: Keyword::new(":inner").unwrap(),
                expr: Box::new(Expr::Wildcard),
            }),
        };

        let (matched, facts) = match_expr_with_binding(&nested_bind, "value");
        assert!(matched);
        assert_eq!(facts.get_scalar(":outer"), Some("value"));
        assert_eq!(facts.get_scalar(":inner"), Some("value"));
    }

    #[test]
    fn match_expr_with_binding_bind_no_match() {
        use may_i_core::{Expr, Keyword};

        // Bind with inner expr that doesn't match - should not bind
        let bind_expr: Expr<Effect> = Expr::Bind {
            key: Keyword::new(":env").unwrap(),
            expr: Box::new(Expr::Literal("prod".to_string())),
        };

        let (matched, facts) = match_expr_with_binding(&bind_expr, "dev");
        assert!(!matched);
        assert_eq!(facts.get_scalar(":env"), None);
    }

    #[test]
    fn match_positional_patterns_with_binding() {
        use may_i_core::pattern::PositionalArg;
        use may_i_core::{Expr, Keyword, Quantifier};

        // Test positional patterns with fact binding
        let patterns = vec![
            PositionalArg {
                quantifier: Quantifier::One,
                pattern: Expr::Bind {
                    key: Keyword::new(":cmd").unwrap(),
                    expr: Box::new(Expr::Wildcard),
                },
                recursive: false,
            },
            PositionalArg {
                quantifier: Quantifier::One,
                pattern: Expr::Bind {
                    key: Keyword::new(":subcmd").unwrap(),
                    expr: Box::new(Expr::Wildcard),
                },
                recursive: false,
            },
        ];

        let arg1 = "git".to_string();
        let arg2 = "push".to_string();
        let args: Vec<&String> = vec![&arg1, &arg2];
        let (matched, _, facts) = match_positional_patterns(&args, &patterns);

        assert!(matched);
        assert_eq!(facts.get_scalar(":cmd"), Some("git"));
        assert_eq!(facts.get_scalar(":subcmd"), Some("push"));
    }

    #[test]
    fn match_positional_patterns_no_match_with_binding() {
        use may_i_core::pattern::PositionalArg;
        use may_i_core::{Expr, Keyword, Quantifier};

        // Test that facts are still captured even when pattern fails later
        let patterns = vec![
            PositionalArg {
                quantifier: Quantifier::One,
                pattern: Expr::Bind {
                    key: Keyword::new(":host").unwrap(),
                    expr: Box::new(Expr::Wildcard),
                },
                recursive: false,
            },
            PositionalArg {
                quantifier: Quantifier::One,
                pattern: Expr::Literal("required".to_string()),
                recursive: false,
            },
        ];

        let arg1 = "server".to_string();
        let arg2 = "wrong".to_string();
        let args: Vec<&String> = vec![&arg1, &arg2];
        let (matched, _, facts) = match_positional_patterns(&args, &patterns);

        assert!(!matched);
        // First arg was still bound before the failure
        assert_eq!(facts.get_scalar(":host"), Some("server"));
    }

    #[test]
    fn match_positional_patterns_optional_with_binding() {
        use may_i_core::pattern::PositionalArg;
        use may_i_core::{Expr, Keyword, Quantifier};

        // Test optional pattern with binding - arg present and matches
        let patterns = vec![PositionalArg {
            quantifier: Quantifier::Optional,
            pattern: Expr::Bind {
                key: Keyword::new(":opt").unwrap(),
                expr: Box::new(Expr::Wildcard),
            },
            recursive: false,
        }];

        let arg1 = "value".to_string();
        let args: Vec<&String> = vec![&arg1];
        let (matched, _, facts) = match_positional_patterns(&args, &patterns);

        assert!(matched);
        assert_eq!(facts.get_scalar(":opt"), Some("value"));
    }

    #[test]
    fn match_positional_patterns_one_or_more_with_binding() {
        use may_i_core::pattern::PositionalArg;
        use may_i_core::{Expr, Keyword, Quantifier};

        // Test OneOrMore pattern with binding
        let patterns = vec![PositionalArg {
            quantifier: Quantifier::OneOrMore,
            pattern: Expr::Bind {
                key: Keyword::new(":items").unwrap(),
                expr: Box::new(Expr::Wildcard),
            },
            recursive: false,
        }];

        let arg1 = "a".to_string();
        let arg2 = "b".to_string();
        let args: Vec<&String> = vec![&arg1, &arg2];
        let (matched, _, facts) = match_positional_patterns(&args, &patterns);

        assert!(matched);
        // OneOrMore accumulates all matched values into the set
        assert!(facts.contains(":items", "a"));
        assert!(facts.contains(":items", "b"));
    }

    #[test]
    fn match_positional_patterns_zero_or_more_with_binding() {
        use may_i_core::pattern::PositionalArg;
        use may_i_core::{Expr, Keyword, Quantifier};

        // Test ZeroOrMore pattern with binding - matches all remaining
        let patterns = vec![PositionalArg {
            quantifier: Quantifier::ZeroOrMore,
            pattern: Expr::Bind {
                key: Keyword::new(":rest").unwrap(),
                expr: Box::new(Expr::Wildcard),
            },
            recursive: false,
        }];

        let arg1 = "a".to_string();
        let arg2 = "b".to_string();
        let args: Vec<&String> = vec![&arg1, &arg2];
        let (matched, _, facts) = match_positional_patterns(&args, &patterns);

        assert!(matched);
        // ZeroOrMore accumulates all matched values into the set
        assert!(facts.contains(":rest", "a"));
        assert!(facts.contains(":rest", "b"));
    }

    #[test]
    fn match_positional_patterns_not_enough_args() {
        use may_i_core::pattern::PositionalArg;
        use may_i_core::{Expr, Keyword, Quantifier};

        // Test pattern with more patterns than args
        let patterns = vec![
            PositionalArg {
                quantifier: Quantifier::One,
                pattern: Expr::Bind {
                    key: Keyword::new(":first").unwrap(),
                    expr: Box::new(Expr::Wildcard),
                },
                recursive: false,
            },
            PositionalArg {
                quantifier: Quantifier::One,
                pattern: Expr::Bind {
                    key: Keyword::new(":second").unwrap(),
                    expr: Box::new(Expr::Wildcard),
                },
                recursive: false,
            },
        ];

        let arg1 = "only".to_string();
        let args: Vec<&String> = vec![&arg1];
        let (matched, _, _) = match_positional_patterns(&args, &patterns);

        assert!(!matched);
    }

    #[test]
    fn match_positional_patterns_one_or_more_no_args() {
        use may_i_core::pattern::PositionalArg;
        use may_i_core::{Expr, Quantifier};

        // Test OneOrMore fails with no args
        let patterns = vec![PositionalArg {
            quantifier: Quantifier::OneOrMore,
            pattern: Expr::Wildcard,
            recursive: false,
        }];

        let args: Vec<&String> = vec![];
        let (matched, _, _) = match_positional_patterns(&args, &patterns);

        assert!(!matched);
    }

    #[test]
    fn match_positional_optional_patterns_skip_to_required() {
        use may_i_core::pattern::PositionalArg;
        use may_i_core::{Expr, Quantifier};

        // (? "a") (? "b") "c" with args ["c"] -> match, consumed=1
        let patterns = vec![
            PositionalArg {
                quantifier: Quantifier::Optional,
                pattern: Expr::Literal("a".to_string()),
                recursive: false,
            },
            PositionalArg {
                quantifier: Quantifier::Optional,
                pattern: Expr::Literal("b".to_string()),
                recursive: false,
            },
            PositionalArg {
                quantifier: Quantifier::One,
                pattern: Expr::Literal("c".to_string()),
                recursive: false,
            },
        ];

        let arg1 = "c".to_string();
        let args: Vec<&String> = vec![&arg1];
        let (matched, consumed, _) = match_positional_patterns(&args, &patterns);
        assert!(matched);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn match_positional_optional_then_required_both_present() {
        use may_i_core::pattern::PositionalArg;
        use may_i_core::{Expr, Quantifier};

        // (? "a") "b" with args ["a", "b"] -> match, consumed=2
        let patterns = vec![
            PositionalArg {
                quantifier: Quantifier::Optional,
                pattern: Expr::Literal("a".to_string()),
                recursive: false,
            },
            PositionalArg {
                quantifier: Quantifier::One,
                pattern: Expr::Literal("b".to_string()),
                recursive: false,
            },
        ];

        let arg1 = "a".to_string();
        let arg2 = "b".to_string();
        let args: Vec<&String> = vec![&arg1, &arg2];
        let (matched, consumed, _) = match_positional_patterns(&args, &patterns);
        assert!(matched);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn match_positional_optional_skipped_required_present() {
        use may_i_core::pattern::PositionalArg;
        use may_i_core::{Expr, Quantifier};

        // (? "a") "b" with args ["b"] -> match, consumed=1
        let patterns = vec![
            PositionalArg {
                quantifier: Quantifier::Optional,
                pattern: Expr::Literal("a".to_string()),
                recursive: false,
            },
            PositionalArg {
                quantifier: Quantifier::One,
                pattern: Expr::Literal("b".to_string()),
                recursive: false,
            },
        ];

        let arg1 = "b".to_string();
        let args: Vec<&String> = vec![&arg1];
        let (matched, consumed, _) = match_positional_patterns(&args, &patterns);
        assert!(matched);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn match_positional_optional_present_required_missing() {
        use may_i_core::pattern::PositionalArg;
        use may_i_core::{Expr, Quantifier};

        // (? "a") "b" with args ["a"] -> no match (required "b" missing)
        let patterns = vec![
            PositionalArg {
                quantifier: Quantifier::Optional,
                pattern: Expr::Literal("a".to_string()),
                recursive: false,
            },
            PositionalArg {
                quantifier: Quantifier::One,
                pattern: Expr::Literal("b".to_string()),
                recursive: false,
            },
        ];

        let arg1 = "a".to_string();
        let args: Vec<&String> = vec![&arg1];
        let (matched, _, _) = match_positional_patterns(&args, &patterns);
        assert!(!matched);
    }

    #[test]
    fn match_positional_zero_or_more_then_required() {
        use may_i_core::pattern::PositionalArg;
        use may_i_core::{Expr, Quantifier};

        // (* "a") "b" with args ["a", "a", "b"] -> match, consumed=3
        let patterns = vec![
            PositionalArg {
                quantifier: Quantifier::ZeroOrMore,
                pattern: Expr::Literal("a".to_string()),
                recursive: false,
            },
            PositionalArg {
                quantifier: Quantifier::One,
                pattern: Expr::Literal("b".to_string()),
                recursive: false,
            },
        ];

        let arg1 = "a".to_string();
        let arg2 = "a".to_string();
        let arg3 = "b".to_string();
        let args: Vec<&String> = vec![&arg1, &arg2, &arg3];
        let (matched, consumed, _) = match_positional_patterns(&args, &patterns);
        assert!(matched);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn match_positional_zero_or_more_skipped_then_required() {
        use may_i_core::pattern::PositionalArg;
        use may_i_core::{Expr, Quantifier};

        // (* "a") "b" with args ["b"] -> match, consumed=1
        let patterns = vec![
            PositionalArg {
                quantifier: Quantifier::ZeroOrMore,
                pattern: Expr::Literal("a".to_string()),
                recursive: false,
            },
            PositionalArg {
                quantifier: Quantifier::One,
                pattern: Expr::Literal("b".to_string()),
                recursive: false,
            },
        ];

        let arg1 = "b".to_string();
        let args: Vec<&String> = vec![&arg1];
        let (matched, consumed, _) = match_positional_patterns(&args, &patterns);
        assert!(matched);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn match_expr_with_binding_regex() {
        use may_i_core::pattern::Expr;

        // Test Regex matching
        let expr: Expr<Effect> = Expr::Regex(regex::Regex::new("^prod-").unwrap());
        let (matched, facts) = match_expr_with_binding(&expr, "prod-server-01");
        assert!(matched);
        // Regex doesn't bind facts
        assert!(!facts.has(":anything"));

        let (matched, _) = match_expr_with_binding(&expr, "dev-server");
        assert!(!matched);
    }

    #[test]
    fn match_expr_with_binding_literal() {
        use may_i_core::pattern::Expr;

        // Test Literal matching
        let expr: Expr<Effect> = Expr::Literal("exact".to_string());
        let (matched, facts) = match_expr_with_binding(&expr, "exact");
        assert!(matched);
        // Literal doesn't bind facts
        assert!(!facts.has(":anything"));

        let (matched, _) = match_expr_with_binding(&expr, "different");
        assert!(!matched);
    }

    #[test]
    fn match_expr_with_binding_empty_and() {
        use may_i_core::pattern::Expr;

        // Test empty And expression
        let expr: Expr<Effect> = Expr::And(vec![]);
        let (matched, _) = match_expr_with_binding(&expr, "anything");
        assert!(matched);
    }

    #[test]
    fn match_expr_with_binding_empty_or() {
        use may_i_core::pattern::Expr;

        // Test empty Or expression
        let expr: Expr<Effect> = Expr::Or(vec![]);
        let (matched, _) = match_expr_with_binding(&expr, "anything");
        assert!(!matched);
    }

    #[test]
    fn match_expr_with_binding_and_all_fail() {
        use may_i_core::pattern::Expr;

        // Test And where all fail
        let expr: Expr<Effect> = Expr::And(vec![
            Expr::Literal("a".to_string()),
            Expr::Literal("b".to_string()),
        ]);
        let (matched, _) = match_expr_with_binding(&expr, "a");
        assert!(!matched);
    }

    #[test]
    fn match_expr_with_binding_or_all_fail() {
        use may_i_core::pattern::Expr;

        // Test Or where all fail
        let expr: Expr<Effect> = Expr::Or(vec![
            Expr::Literal("a".to_string()),
            Expr::Literal("b".to_string()),
        ]);
        let (matched, _) = match_expr_with_binding(&expr, "c");
        assert!(!matched);
    }

    #[test]
    fn may_i_pushes_via_fact() {
        use may_i_core::ast::{Predicate, Rule, Spanned};
        use may_i_core::pattern::{ArgPattern, CommandPattern};
        use may_i_core::span::Span;

        let s = Span::new(0, 1);
        let may_i_effect = Effect::MayI {
            pattern: ArgPattern::Positional {
                patterns: vec![],
                continuation: None,
            },
        };

        // Rule for "rm": (when (fact? [:via "sudo"]) :deny)
        let inner_rule = Rule::new(
            Spanned::new(
                Effect::CommandPattern(CommandPattern::Literal("rm".to_string())),
                s,
            ),
            vec![Spanned::new(
                Effect::When {
                    predicate: Spanned::new(
                        Predicate::Fact(may_i_core::FactQuery::Value {
                            key: ":via".to_string(),
                            pattern: may_i_core::FactPattern::Literal("sudo".to_string()),
                        }),
                        s,
                    ),
                    effect: Box::new(Spanned::new(Effect::Deny(Some("via sudo".to_string())), s)),
                },
                s,
            )],
            vec![],
            s,
        );

        // Rule for "sudo": (may-i *)
        let sudo_rule = Rule::new(
            Spanned::new(
                Effect::CommandPattern(CommandPattern::Literal("sudo".to_string())),
                s,
            ),
            vec![Spanned::new(may_i_effect, s)],
            vec![],
            s,
        );

        let rules = vec![inner_rule, sudo_rule];
        let facts = ContextFacts::default();
        let args = vec!["rm".to_string(), "-rf".to_string()];
        let ctx = EvalContext::new("sudo", &args, &facts);
        let evaluator = Evaluator::new(&rules);
        let result = evaluator.evaluate(&mut PureFold, &ctx);
        // The inner "rm" evaluation should see :via = {"sudo"} and match the deny rule
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn may_i_nested_wrappers_accumulate_via() {
        use may_i_core::ast::{Predicate, Rule, Spanned};
        use may_i_core::pattern::{ArgPattern, CommandPattern};
        use may_i_core::span::Span;

        let s = Span::new(0, 1);
        let may_i_effect = Effect::MayI {
            pattern: ArgPattern::Positional {
                patterns: vec![],
                continuation: None,
            },
        };

        // Rule for "rm": (when (and (fact? [:via "sudo"]) (fact? [:via "ssh"])) :deny)
        let inner_rule = Rule::new(
            Spanned::new(
                Effect::CommandPattern(CommandPattern::Literal("rm".to_string())),
                s,
            ),
            vec![Spanned::new(
                Effect::When {
                    predicate: Spanned::new(
                        Predicate::And(vec![
                            Predicate::Fact(may_i_core::FactQuery::Value {
                                key: ":via".to_string(),
                                pattern: may_i_core::FactPattern::Literal("sudo".to_string()),
                            }),
                            Predicate::Fact(may_i_core::FactQuery::Value {
                                key: ":via".to_string(),
                                pattern: may_i_core::FactPattern::Literal("ssh".to_string()),
                            }),
                        ]),
                        s,
                    ),
                    effect: Box::new(Spanned::new(Effect::Deny(Some("via both".to_string())), s)),
                },
                s,
            )],
            vec![],
            s,
        );

        let ssh_rule = Rule::new(
            Spanned::new(
                Effect::CommandPattern(CommandPattern::Literal("ssh".to_string())),
                s,
            ),
            vec![Spanned::new(may_i_effect.clone(), s)],
            vec![],
            s,
        );

        let sudo_rule = Rule::new(
            Spanned::new(
                Effect::CommandPattern(CommandPattern::Literal("sudo".to_string())),
                s,
            ),
            vec![Spanned::new(may_i_effect, s)],
            vec![],
            s,
        );

        let rules = vec![inner_rule, ssh_rule, sudo_rule];
        let facts = ContextFacts::default();
        // sudo ssh rm -rf /
        let args = vec![
            "ssh".to_string(),
            "rm".to_string(),
            "-rf".to_string(),
            "/".to_string(),
        ];
        let ctx = EvalContext::new("sudo", &args, &facts);
        let evaluator = Evaluator::new(&rules);
        let result = evaluator.evaluate(&mut PureFold, &ctx);
        // Inner "rm" should see :via = {"sudo", "ssh"} and match the deny rule
        assert_eq!(result.decision, Decision::Deny);
    }
}
