// v2 unified effect evaluator.
// All effect forms evaluate to EffectResult (Decision | Nil).

use may_i_core::types::{ContextFacts, Decision, EvalResult};
use may_i_core::types::{FactPattern, FactQuery};
use may_i_core::v2::ast::{Effect, EffectResult, Predicate, Rule};
use may_i_core::v2::pattern::{ArgPattern, CommandPattern, PositionalArg};

use crate::v2::trace::{EffectTrace, PredicateTrace, TraceEntry};

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

/// Evaluate a command against v2 config and context.
/// This is the main entry point for v2 evaluation.
pub fn evaluate_v2(
    command: &str,
    args: &[String],
    config: &may_i_core::v2::ast::Config,
    facts: &ContextFacts,
) -> EvalResult {
    let evaluator = Evaluator::new(&config.rules);
    let ctx = EvalContext::new(command, args, facts);
    evaluator.evaluate(&ctx)
}

/// Evaluator for v2 rules with unified effect model.
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
    pub fn evaluate(&self, ctx: &EvalContext) -> EvalResult {
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
            let (result, _trace) = self.evaluate_rule_with_trace(rule, ctx);

            // Convert EffectResult to EvalResult
            match result {
                EffectResult::Decision(decision, reason) => {
                    let eval_result = EvalResult::new(decision, reason);
                    // TODO: Add trace integration
                    return eval_result;
                }
                EffectResult::Nil => {
                    // Rule didn't match, continue to next
                    continue;
                }
            }
        }

        // No rules matched - return ask
        EvalResult::new(Decision::Ask, Some("no matching rule found".to_string()))
    }

    /// Evaluate a rule with tracing.
    /// Returns (EffectResult, trace) where EffectResult is Decision | Nil.
    fn evaluate_rule_with_trace(
        &self,
        rule: &Rule,
        ctx: &EvalContext,
    ) -> (EffectResult, Option<crate::v2::trace::TraceEntry>) {
        // Step 1: Evaluate command effect - must return non-Nil for rule to apply
        let command_result = evaluate_effect(&rule.command_effect.value, ctx, self.rules);

        if command_result.is_nil() {
            // Command didn't match - rule doesn't apply
            let trace = TraceEntry::RuleEvaluation {
                rule: Box::new(rule.clone()),
                matched: false,
                effect: None,
                predicate_traces: vec![],
                effect_trace: None,
            };
            return (EffectResult::Nil, Some(trace));
        }

        // Step 2: Evaluate subsequent effects in sequence
        let mut effect_traces = Vec::new();

        for effect in &rule.effects {
            let (result, trace) = evaluate_effect_with_trace(&effect.value, ctx, self.rules);
            effect_traces.push(trace);

            match result {
                EffectResult::Decision(_, _) => {
                    // Found a terminal decision
                    let trace = TraceEntry::RuleEvaluation {
                        rule: Box::new(rule.clone()),
                        matched: true,
                        effect: Some(effect.value.clone()),
                        predicate_traces: vec![],
                        effect_trace: Some(Box::new(effect_traces.last().unwrap().clone())),
                    };
                    return (result, Some(trace));
                }
                EffectResult::Nil => {
                    // Effect returned Nil, continue to next
                }
            }
        }

        // Step 3: All effects returned Nil, use default effect
        let (default_result, default_trace) =
            evaluate_effect_with_trace(&rule.default_effect.value, ctx, self.rules);
        effect_traces.push(default_trace);

        let trace = TraceEntry::RuleEvaluation {
            rule: Box::new(rule.clone()),
            matched: true,
            effect: Some(rule.default_effect.value.clone()),
            predicate_traces: vec![],
            effect_trace: Some(Box::new(effect_traces.last().unwrap().clone())),
        };

        (default_result, Some(trace))
    }
}

/// Evaluate a predicate against the context.
/// Predicates are used in conditional contexts (when/unless/if/cond).
pub fn evaluate_predicate(predicate: &Predicate, ctx: &EvalContext) -> PredicateResult {
    match predicate {
        Predicate::Fact(query) => evaluate_fact_query(query, ctx),
        Predicate::Arg(pattern) => evaluate_arg_pattern_predicate(pattern, ctx),
        Predicate::And(predicates) => {
            for p in predicates {
                if evaluate_predicate(p, ctx) == PredicateResult::NoMatch {
                    return PredicateResult::NoMatch;
                }
            }
            PredicateResult::Match
        }
        Predicate::Or(predicates) => {
            for p in predicates {
                if evaluate_predicate(p, ctx) == PredicateResult::Match {
                    return PredicateResult::Match;
                }
            }
            PredicateResult::NoMatch
        }
        Predicate::Not(inner) => match evaluate_predicate(inner, ctx) {
            PredicateResult::Match => PredicateResult::NoMatch,
            PredicateResult::NoMatch => PredicateResult::Match,
        },
        Predicate::Named(_) => {
            // Named predicates should have been resolved before evaluation
            panic!("Named predicates should be resolved before evaluation")
        }
    }
}

/// Evaluate a predicate with tracing.
pub fn evaluate_predicate_with_trace(
    predicate: &Predicate,
    ctx: &EvalContext,
) -> (PredicateResult, PredicateTrace) {
    use crate::v2::trace::PredicateResult as TracePredResult;

    let result = evaluate_predicate(predicate, ctx);
    let trace_result = match result {
        PredicateResult::Match => TracePredResult::Match,
        PredicateResult::NoMatch => TracePredResult::NoMatch,
    };
    (result, PredicateTrace::new(predicate.clone(), trace_result))
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
            if let Some(value) = ctx.facts.get(key) {
                match value {
                    may_i_core::types::ContextValue::Scalar(s) => {
                        if match_fact_pattern(pattern, s) {
                            PredicateResult::Match
                        } else {
                            PredicateResult::NoMatch
                        }
                    }
                    may_i_core::types::ContextValue::Present => PredicateResult::NoMatch,
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

            if match_positional_patterns(&positional_args, patterns) {
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

            if positional_args.len() == patterns.len()
                && match_positional_patterns(&positional_args, patterns)
            {
                PredicateResult::Match
            } else {
                PredicateResult::NoMatch
            }
        }
        ArgPattern::Anywhere(exprs) => {
            for expr in exprs {
                match expr {
                    may_i_core::types::Expr::Literal(s) => {
                        if ctx.args.iter().any(|arg| arg == s) {
                            return PredicateResult::Match;
                        }
                    }
                    may_i_core::types::Expr::Wildcard => {
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
                    may_i_core::types::Expr::Literal(s) => {
                        if ctx.args.iter().any(|arg| arg == s) {
                            // Found the forbidden pattern - this is a constraint violation
                            return PredicateResult::NoMatch;
                        }
                    }
                    may_i_core::types::Expr::Wildcard => {
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
        ArgPattern::At { position, pattern } => {
            if *position > 0 && *position <= ctx.args.len() {
                let arg = &ctx.args[*position - 1];
                match pattern {
                    may_i_core::types::Expr::Literal(s) => {
                        if arg == s {
                            PredicateResult::Match
                        } else {
                            PredicateResult::NoMatch
                        }
                    }
                    may_i_core::types::Expr::Wildcard => PredicateResult::Match,
                    _ => PredicateResult::NoMatch, // Other variants not supported in At
                }
            } else {
                PredicateResult::NoMatch
            }
        }
    }
}

/// Match positional patterns against args.
fn match_positional_patterns(args: &[&String], patterns: &[PositionalArg]) -> bool {
    if args.len() < patterns.len() {
        return false;
    }

    for (i, pattern) in patterns.iter().enumerate() {
        let arg = args[i];

        match &pattern.quantifier {
            may_i_core::types::Quantifier::One => {
                if !match_expr(&pattern.pattern, arg) {
                    return false;
                }
            }
            may_i_core::types::Quantifier::Optional => {
                // Optional pattern - if arg exists, it must match
                if i < args.len() && !match_expr(&pattern.pattern, arg) {
                    return false;
                }
            }
            may_i_core::types::Quantifier::OneOrMore => {
                // OneOrMore pattern - at least one arg must match, then continue
                if i >= args.len() {
                    return false;
                }
                for arg in args.iter().skip(i) {
                    if !match_expr(&pattern.pattern, arg) {
                        return false;
                    }
                }
                return true;
            }
            may_i_core::types::Quantifier::ZeroOrMore => {
                // ZeroOrMore pattern - all remaining args must match
                for arg in args.iter().skip(i) {
                    if !match_expr(&pattern.pattern, arg) {
                        return false;
                    }
                }
                return true;
            }
        }
    }

    true
}

/// Match a single expression against a value.
fn match_expr(expr: &may_i_core::types::Expr, value: &str) -> bool {
    match expr {
        may_i_core::types::Expr::Literal(s) => s == value,
        may_i_core::types::Expr::Wildcard => true,
        may_i_core::types::Expr::Regex(re) => re.is_match(value),
        may_i_core::types::Expr::And(exprs) => exprs.iter().all(|e| match_expr(e, value)),
        may_i_core::types::Expr::Or(exprs) => exprs.iter().any(|e| match_expr(e, value)),
        may_i_core::types::Expr::Not(inner) => !match_expr(inner, value),
        _ => false, // Cond not supported in simple matching
    }
}

/// Evaluate an effect to produce an EffectResult (Decision | Nil).
/// This is the core of the unified effect model.
fn evaluate_effect(effect: &Effect, ctx: &EvalContext, rules: &[Rule]) -> EffectResult {
    match effect {
        // Terminal effects return a decision with reason
        Effect::Allow(reason) => EffectResult::Decision(Decision::Allow, reason.clone()),
        Effect::Ask(reason) => EffectResult::Decision(Decision::Ask, reason.clone()),
        Effect::Deny(reason) => EffectResult::Decision(Decision::Deny, reason.clone()),

        // Pattern effects return Allow on match, Nil otherwise
        Effect::CommandPattern(pattern) => {
            let matches = match pattern {
                CommandPattern::Literal(s) => s == ctx.command,
                CommandPattern::Regex(re) => re.is_match(ctx.command),
                CommandPattern::Or(patterns) => patterns.iter().any(|p| {
                    match p {
                        CommandPattern::Literal(s) => s == ctx.command,
                        CommandPattern::Regex(re) => re.is_match(ctx.command),
                        CommandPattern::Or(_) => false, // Nested or not expected
                    }
                }),
            };
            if matches {
                EffectResult::Decision(Decision::Allow, None)
            } else {
                EffectResult::Nil
            }
        }
        Effect::ArgPattern(pattern) => evaluate_arg_pattern_effect(pattern, ctx, rules),

        // Combinators with Nil handling
        Effect::And { effects } => {
            // Evaluate left-to-right, return first Nil or last effect's result
            let mut last_result = EffectResult::Decision(Decision::Allow, None);
            for effect in effects {
                let result = evaluate_effect(&effect.value, ctx, rules);
                if result.is_nil() {
                    return EffectResult::Nil;
                }
                last_result = result;
            }
            last_result
        }
        Effect::Or { effects } => {
            // Evaluate left-to-right, return first non-Nil or Nil
            for effect in effects {
                let result = evaluate_effect(&effect.value, ctx, rules);
                if !result.is_nil() {
                    return result;
                }
            }
            EffectResult::Nil
        }
        Effect::Not { effect } => {
            // Invert Allow/Nil, pass through Ask/Deny
            let result = evaluate_effect(&effect.value, ctx, rules);
            match result {
                EffectResult::Nil => EffectResult::Decision(Decision::Allow, None),
                EffectResult::Decision(Decision::Allow, _) => EffectResult::Nil,
                EffectResult::Decision(ask_or_deny, reason) => {
                    EffectResult::Decision(ask_or_deny, reason)
                }
            }
        }

        // Conditionals
        Effect::When { predicate, effect } => {
            if evaluate_predicate(&predicate.value, ctx) == PredicateResult::Match {
                evaluate_effect(&effect.value, ctx, rules)
            } else {
                EffectResult::Nil
            }
        }
        Effect::Unless { predicate, effect } => {
            if evaluate_predicate(&predicate.value, ctx) == PredicateResult::NoMatch {
                evaluate_effect(&effect.value, ctx, rules)
            } else {
                EffectResult::Nil
            }
        }
        Effect::If {
            predicate,
            then_effect,
            else_effect,
        } => {
            if evaluate_predicate(&predicate.value, ctx) == PredicateResult::Match {
                evaluate_effect(&then_effect.value, ctx, rules)
            } else {
                evaluate_effect(&else_effect.value, ctx, rules)
            }
        }
        Effect::Cond { branches, fallback } => {
            for (predicate, branch_effect) in branches {
                if evaluate_predicate(&predicate.value, ctx) == PredicateResult::Match {
                    return evaluate_effect(&branch_effect.value, ctx, rules);
                }
            }
            // No branch matched - use fallback or return Nil
            if let Some(fb) = fallback {
                evaluate_effect(&fb.value, ctx, rules)
            } else {
                EffectResult::Nil
            }
        }

        // Recursion
        Effect::MayI { pattern } => {
            match extract_inner_command(pattern, ctx.args) {
                Some((inner_cmd, inner_args)) => {
                    let evaluator = Evaluator::new(rules);
                    let inner_ctx = EvalContext {
                        command: &inner_cmd,
                        args: &inner_args,
                        facts: ctx.facts,
                        recursion_depth: ctx.recursion_depth + 1,
                        recursion_limit: ctx.recursion_limit,
                    };
                    let eval_result = evaluator.evaluate(&inner_ctx);
                    EffectResult::Decision(eval_result.decision, eval_result.reason)
                }
                None => {
                    // Pattern didn't match - return Nil
                    EffectResult::Nil
                }
            }
        }
    }
}

/// Evaluate an arg pattern as an effect (returns EffectResult).
fn evaluate_arg_pattern_effect(
    pattern: &ArgPattern,
    ctx: &EvalContext,
    rules: &[Rule],
) -> EffectResult {
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

            if match_positional_patterns(&positional_args, patterns) {
                if let Some(cont) = continuation {
                    // Calculate remaining args after consuming matched patterns
                    let consumed_count = patterns
                        .iter()
                        .map(|p| match p.quantifier {
                            may_i_core::types::Quantifier::One => 1,
                            _ => 1, // For now, treat all as consuming 1
                        })
                        .sum::<usize>();
                    let remaining_args: Vec<String> = ctx
                        .args
                        .iter()
                        .filter(|arg| !arg.starts_with('-'))
                        .skip(consumed_count)
                        .map(|s| s.to_string())
                        .collect();
                    // Evaluate continuation with remaining args
                    evaluate_effect_with_owned_args(cont, ctx, rules, remaining_args)
                } else {
                    EffectResult::Decision(Decision::Allow, None)
                }
            } else {
                EffectResult::Nil
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

            if positional_args.len() == patterns.len()
                && match_positional_patterns(&positional_args, patterns)
            {
                if let Some(cont) = continuation {
                    // For exact patterns, no positional args remain after exact match
                    // But we should still pass any flags that weren't part of the pattern
                    let remaining_args: Vec<String> = ctx
                        .args
                        .iter()
                        .filter(|arg| arg.starts_with('-'))
                        .map(|s| s.to_string())
                        .collect();
                    evaluate_effect_with_owned_args(cont, ctx, rules, remaining_args)
                } else {
                    EffectResult::Decision(Decision::Allow, None)
                }
            } else {
                EffectResult::Nil
            }
        }
        ArgPattern::Anywhere(exprs) => {
            for expr in exprs {
                match expr {
                    may_i_core::types::Expr::Literal(s) => {
                        if ctx.args.iter().any(|arg| arg == s) {
                            return EffectResult::Decision(Decision::Allow, None);
                        }
                    }
                    may_i_core::types::Expr::Wildcard => {
                        return EffectResult::Decision(Decision::Allow, None);
                    }
                    _ => {}
                }
            }
            EffectResult::Nil
        }
        ArgPattern::Forbidden(exprs) => {
            for expr in exprs {
                match expr {
                    may_i_core::types::Expr::Literal(s) => {
                        if ctx.args.iter().any(|arg| arg == s) {
                            return EffectResult::Decision(Decision::Deny, None);
                        }
                    }
                    may_i_core::types::Expr::Wildcard => {
                        if !ctx.args.is_empty() {
                            return EffectResult::Decision(Decision::Deny, None);
                        }
                    }
                    _ => {}
                }
            }
            EffectResult::Decision(Decision::Allow, None)
        }
        ArgPattern::At { position, pattern } => {
            if *position > 0 && *position <= ctx.args.len() {
                let arg = &ctx.args[*position - 1];
                match pattern {
                    may_i_core::types::Expr::Literal(s) => {
                        if arg == s {
                            EffectResult::Decision(Decision::Allow, None)
                        } else {
                            EffectResult::Nil
                        }
                    }
                    may_i_core::types::Expr::Wildcard => {
                        EffectResult::Decision(Decision::Allow, None)
                    }
                    _ => EffectResult::Nil,
                }
            } else {
                EffectResult::Nil
            }
        }
    }
}

/// Helper to evaluate an effect with owned args.
fn evaluate_effect_with_owned_args(
    effect: &Effect,
    ctx: &EvalContext,
    rules: &[Rule],
    owned_args: Vec<String>,
) -> EffectResult {
    let _args_ref: Vec<&str> = owned_args.iter().map(|s| s.as_str()).collect();
    let inner_ctx = EvalContext {
        command: ctx.command,
        args: &owned_args,
        facts: ctx.facts,
        recursion_depth: ctx.recursion_depth,
        recursion_limit: ctx.recursion_limit,
    };
    evaluate_effect(effect, &inner_ctx, rules)
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

/// Evaluate an effect with tracing.
fn evaluate_effect_with_trace(
    effect: &Effect,
    ctx: &EvalContext,
    rules: &[Rule],
) -> (EffectResult, EffectTrace) {
    let result = evaluate_effect(effect, ctx, rules);

    let trace = match effect {
        Effect::Allow(reason) => EffectTrace::Terminal {
            effect: effect.clone(),
            decision: Decision::Allow,
            reason: reason.clone(),
        },
        Effect::Ask(reason) => EffectTrace::Terminal {
            effect: effect.clone(),
            decision: Decision::Ask,
            reason: reason.clone(),
        },
        Effect::Deny(reason) => EffectTrace::Terminal {
            effect: effect.clone(),
            decision: Decision::Deny,
            reason: reason.clone(),
        },
        Effect::CommandPattern(_) => EffectTrace::Terminal {
            effect: effect.clone(),
            decision: match result {
                EffectResult::Decision(d, _) => d,
                EffectResult::Nil => Decision::Allow, // Should not happen
            },
            reason: None,
        },
        Effect::ArgPattern(_) => EffectTrace::Terminal {
            effect: effect.clone(),
            decision: match result {
                EffectResult::Decision(d, _) => d,
                EffectResult::Nil => Decision::Allow, // Should not happen
            },
            reason: None,
        },
        Effect::And { .. } | Effect::Or { .. } | Effect::Not { .. } => EffectTrace::Terminal {
            effect: effect.clone(),
            decision: match result {
                EffectResult::Decision(d, _) => d,
                EffectResult::Nil => Decision::Allow,
            },
            reason: None,
        },
        Effect::When { .. } | Effect::Unless { .. } | Effect::If { .. } | Effect::Cond { .. } => {
            EffectTrace::Terminal {
                effect: effect.clone(),
                decision: match result {
                    EffectResult::Decision(d, _) => d,
                    EffectResult::Nil => Decision::Allow,
                },
                reason: None,
            }
        }
        Effect::MayI { .. } => EffectTrace::Terminal {
            effect: effect.clone(),
            decision: match result {
                EffectResult::Decision(d, _) => d,
                EffectResult::Nil => Decision::Allow,
            },
            reason: None,
        },
    };

    (result, trace)
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
            may_i_core::v2::ast::Spanned::new(
                Effect::Allow(None),
                may_i_core::span::Span::new(0, 1),
            ),
            may_i_core::v2::ast::Spanned::new(Effect::Ask(None), may_i_core::span::Span::new(0, 1)),
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
            may_i_core::v2::ast::Spanned::new(
                Effect::Allow(None),
                may_i_core::span::Span::new(0, 1),
            ),
            may_i_core::v2::ast::Spanned::new(
                Effect::Deny(None),
                may_i_core::span::Span::new(0, 1),
            ),
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
        let effect = may_i_core::v2::ast::Spanned::new(
            Effect::Allow(None),
            may_i_core::span::Span::new(0, 1),
        );
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
            recursion_depth: 5,
            recursion_limit: 5,
        };
        assert!(deep_ctx.is_depth_exceeded());
    }
}
