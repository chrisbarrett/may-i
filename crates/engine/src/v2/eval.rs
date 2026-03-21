// v2 evaluator for the unified rule DSL.
// Tasks 4.1-4.10: Predicate/effect evaluation, boolean combinators, recursion, etc.

use may_i_core::types::Expr;
use may_i_core::types::{ContextFacts, Decision, EvalResult, TraceEntry as CoreTraceEntry};
use may_i_core::types::{FactPattern, FactQuery};
use may_i_core::v2::ast::{Effect, Rule};
use may_i_core::v2::pattern::{ArgPattern, PositionalArg};
use may_i_core::v2::predicate::Predicate;

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

/// Evaluator for v2 rules.
pub struct Evaluator<'a> {
    rules: &'a [Rule],
}

impl<'a> Evaluator<'a> {
    /// Create a new evaluator with the given rules.
    pub fn new(rules: &'a [Rule]) -> Self {
        Self { rules }
    }

    /// Evaluate a command against all rules.
    /// Returns the most restrictive effect from matching rules.
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

        let mut results = Vec::new();
        let mut rule_traces = Vec::new();

        for rule in self.rules {
            let (effect, trace) = self.evaluate_rule_with_trace(rule, ctx);
            if let Some(eff) = effect {
                results.push(eff);
            }
            if let Some(t) = trace {
                rule_traces.push(t);
            }
        }

        // Build final result with traces
        let mut result = if results.is_empty() {
            // No rules matched - return ask with a reason
            EvalResult::new(Decision::Ask, Some("no matching rule found".to_string()))
        } else {
            // Combine effects: most restrictive wins
            combine_effects(&results, ctx, self.rules)
        };

        // Convert v2 trace entries to core trace entries
        // For now, we store them as DefaultAsk entries with description
        // This is a temporary approach until full trace integration is complete
        for trace in rule_traces {
            // Create a simple trace entry - full integration would convert properly
            let desc = match &trace {
                crate::v2::trace::TraceEntry::RuleEvaluation { matched, .. } => {
                    format!("Rule evaluation: matched={}", matched)
                }
                crate::v2::trace::TraceEntry::Decision { decision, .. } => {
                    format!("Decision: {:?}", decision)
                }
                crate::v2::trace::TraceEntry::RecursiveEvaluation { depth, .. } => {
                    format!("Recursive evaluation at depth {}", depth)
                }
                crate::v2::trace::TraceEntry::DepthLimitExceeded { limit } => {
                    format!("Depth limit exceeded: {}", limit)
                }
                crate::v2::trace::TraceEntry::DefaultAsk { reason } => {
                    format!("Default ask: {}", reason)
                }
            };
            result
                .trace
                .push(CoreTraceEntry::DefaultAsk { reason: desc });
        }

        result
    }

    /// Evaluate a rule with tracing.
    /// Returns (effect, trace) where trace captures predicate evaluations.
    fn evaluate_rule_with_trace(
        &self,
        rule: &Rule,
        ctx: &EvalContext,
    ) -> (Option<Effect>, Option<crate::v2::trace::TraceEntry>) {
        // Check if command matches
        if !rule.command.value.is_match(ctx.command) {
            // Rule didn't match - create trace showing command mismatch
            let trace = TraceEntry::RuleEvaluation {
                rule: Box::new(rule.clone()),
                matched: false,
                effect: None,
                predicate_traces: vec![],
                effect_trace: None,
            };
            return (None, Some(trace));
        }

        // Evaluate predicates and collect traces
        let mut predicate_traces = Vec::new();
        let mut all_match = true;

        for predicate in &rule.predicates {
            let (result, trace) = evaluate_predicate_with_trace(&predicate.value, ctx);
            predicate_traces.push(trace);
            if result == PredicateResult::NoMatch {
                all_match = false;
            }
        }

        if all_match {
            // All predicates matched - evaluate effect with tracing
            let (_result, effect_trace) =
                evaluate_effect_with_trace(&rule.effect.value, ctx, self.rules);
            let trace = TraceEntry::RuleEvaluation {
                rule: Box::new(rule.clone()),
                matched: true,
                effect: Some(rule.effect.value.clone()),
                predicate_traces,
                effect_trace: Some(Box::new(effect_trace)),
            };
            (Some(rule.effect.value.clone()), Some(trace))
        } else {
            // Some predicates didn't match
            let trace = TraceEntry::RuleEvaluation {
                rule: Box::new(rule.clone()),
                matched: false,
                effect: None,
                predicate_traces,
                effect_trace: None,
            };
            (None, Some(trace))
        }
    }
}

/// Evaluate a predicate against the context.
pub fn evaluate_predicate(predicate: &Predicate, ctx: &EvalContext) -> PredicateResult {
    match predicate {
        Predicate::Has(query) => evaluate_fact_query(query, ctx),
        Predicate::Arg(pattern) => evaluate_arg_pattern(pattern, ctx),
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
/// Returns the result and a trace entry capturing the evaluation.
pub fn evaluate_predicate_with_trace(
    predicate: &Predicate,
    ctx: &EvalContext,
) -> (PredicateResult, PredicateTrace) {
    use crate::v2::trace::PredicateResult as TracePredResult;

    match predicate {
        Predicate::Has(query) => {
            let result = evaluate_fact_query(query, ctx);
            let trace_result = match result {
                PredicateResult::Match => TracePredResult::Match,
                PredicateResult::NoMatch => TracePredResult::NoMatch,
            };
            (result, PredicateTrace::new(predicate.clone(), trace_result))
        }
        Predicate::Arg(pattern) => {
            let result = evaluate_arg_pattern(pattern, ctx);
            let trace_result = match result {
                PredicateResult::Match => TracePredResult::Match,
                PredicateResult::NoMatch => TracePredResult::NoMatch,
            };
            (result, PredicateTrace::new(predicate.clone(), trace_result))
        }
        Predicate::And(predicates) => {
            let mut children = Vec::new();
            let mut all_match = true;

            for p in predicates {
                let (result, child_trace) = evaluate_predicate_with_trace(p, ctx);
                children.push(child_trace);
                if result == PredicateResult::NoMatch {
                    all_match = false;
                }
            }

            let result = if all_match {
                PredicateResult::Match
            } else {
                PredicateResult::NoMatch
            };
            let trace_result = if all_match {
                TracePredResult::Match
            } else {
                TracePredResult::NoMatch
            };

            (
                result,
                PredicateTrace::with_children(predicate.clone(), trace_result, children),
            )
        }
        Predicate::Or(predicates) => {
            let mut children = Vec::new();
            let mut any_match = false;

            for p in predicates {
                let (result, child_trace) = evaluate_predicate_with_trace(p, ctx);
                children.push(child_trace);
                if result == PredicateResult::Match {
                    any_match = true;
                }
            }

            let result = if any_match {
                PredicateResult::Match
            } else {
                PredicateResult::NoMatch
            };
            let trace_result = if any_match {
                TracePredResult::Match
            } else {
                TracePredResult::NoMatch
            };

            (
                result,
                PredicateTrace::with_children(predicate.clone(), trace_result, children),
            )
        }
        Predicate::Not(inner) => {
            let (inner_result, inner_trace) = evaluate_predicate_with_trace(inner, ctx);
            let result = match inner_result {
                PredicateResult::Match => PredicateResult::NoMatch,
                PredicateResult::NoMatch => PredicateResult::Match,
            };
            let trace_result = match result {
                PredicateResult::Match => TracePredResult::Match,
                PredicateResult::NoMatch => TracePredResult::NoMatch,
            };
            (
                result,
                PredicateTrace::with_children(predicate.clone(), trace_result, vec![inner_trace]),
            )
        }
        Predicate::Named(_) => {
            // Named predicates should have been resolved before evaluation
            panic!("Named predicates should be resolved before evaluation")
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
        FactQuery::Value { key, pattern } => match ctx.facts.get_scalar(key) {
            Some(value) => {
                if match_fact_pattern(pattern, value) {
                    PredicateResult::Match
                } else {
                    PredicateResult::NoMatch
                }
            }
            None => PredicateResult::NoMatch,
        },
    }
}

/// Match a fact pattern against a value.
fn match_fact_pattern(pattern: &FactPattern, value: &str) -> bool {
    match pattern {
        FactPattern::Literal(lit) => lit == value,
        FactPattern::Wildcard => true,
        FactPattern::Regex(re) => re.is_match(value),
        FactPattern::And(patterns) => patterns.iter().all(|p| match_fact_pattern(p, value)),
        FactPattern::Or(patterns) => patterns.iter().any(|p| match_fact_pattern(p, value)),
        FactPattern::Not(inner) => !match_fact_pattern(inner, value),
    }
}

/// Evaluate an argument pattern against the context.
fn evaluate_arg_pattern(pattern: &ArgPattern, ctx: &EvalContext) -> PredicateResult {
    match pattern {
        ArgPattern::Positional(pargs) => evaluate_positional(pargs, ctx.args, false),
        ArgPattern::Exact(pargs) => evaluate_positional(pargs, ctx.args, true),
        ArgPattern::Anywhere(exprs) => {
            // All expressions must match somewhere in args
            for expr in exprs {
                if !expr_matches_anywhere(expr, ctx.args) {
                    return PredicateResult::NoMatch;
                }
            }
            PredicateResult::Match
        }
        ArgPattern::Forbidden(exprs) => {
            // None of the expressions should match
            for expr in exprs {
                if expr_matches_anywhere(expr, ctx.args) {
                    return PredicateResult::NoMatch;
                }
            }
            PredicateResult::Match
        }
        ArgPattern::At { position, pattern } => {
            // Match at specific position (1-indexed)
            let idx = position.saturating_sub(1);
            if idx < ctx.args.len() {
                if match_expr(pattern, &ctx.args[idx]) {
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

/// Evaluate positional arguments.
/// If exact is true, requires exactly the right number of positional args.
fn evaluate_positional(pargs: &[PositionalArg], args: &[String], exact: bool) -> PredicateResult {
    let mut arg_idx = 0;

    for parg in pargs {
        match parg.quantifier {
            may_i_core::types::Quantifier::One => {
                if arg_idx >= args.len() {
                    return PredicateResult::NoMatch;
                }
                if !match_expr(&parg.pattern, &args[arg_idx]) {
                    return PredicateResult::NoMatch;
                }
                arg_idx += 1;
            }
            may_i_core::types::Quantifier::Optional => {
                if arg_idx < args.len() && match_expr(&parg.pattern, &args[arg_idx]) {
                    arg_idx += 1;
                }
                // Optional args can match 0 times
            }
            may_i_core::types::Quantifier::OneOrMore => {
                if arg_idx >= args.len() {
                    return PredicateResult::NoMatch;
                }
                if !match_expr(&parg.pattern, &args[arg_idx]) {
                    return PredicateResult::NoMatch;
                }
                arg_idx += 1;
                // Continue matching while pattern matches
                while arg_idx < args.len() && match_expr(&parg.pattern, &args[arg_idx]) {
                    arg_idx += 1;
                }
            }
            may_i_core::types::Quantifier::ZeroOrMore => {
                // Match as many as possible
                while arg_idx < args.len() && match_expr(&parg.pattern, &args[arg_idx]) {
                    arg_idx += 1;
                }
            }
        }
    }

    // If exact, all args must have been consumed
    if exact && arg_idx < args.len() {
        return PredicateResult::NoMatch;
    }

    PredicateResult::Match
}

/// Check if an expression matches any argument.
fn expr_matches_anywhere(expr: &Expr, args: &[String]) -> bool {
    args.iter().any(|arg| match_expr(expr, arg))
}

/// Match an expression against a string.
fn match_expr(expr: &Expr, value: &str) -> bool {
    expr.is_match(value)
}

/// Combine multiple effects, returning the most restrictive.
fn combine_effects(effects: &[Effect], ctx: &EvalContext, rules: &[Rule]) -> EvalResult {
    // Start with Allow (least restrictive)
    let mut result = EvalResult::new(Decision::Allow, None);

    for effect in effects {
        let eval_result = evaluate_effect(effect, ctx, rules);
        // Most restrictive wins
        if eval_result.decision > result.decision {
            result = eval_result;
        } else if eval_result.decision == result.decision && result.reason.is_none() {
            // Same decision but we don't have a reason yet - use the new one
            result.reason = eval_result.reason;
        }
    }

    result
}

/// Evaluate an effect to produce a decision result.
fn evaluate_effect(effect: &Effect, ctx: &EvalContext, rules: &[Rule]) -> EvalResult {
    match effect {
        Effect::Allow(reason) => EvalResult::new(Decision::Allow, reason.clone()),
        Effect::Ask(reason) => EvalResult::new(Decision::Ask, reason.clone()),
        Effect::Deny(reason) => EvalResult::new(Decision::Deny, reason.clone()),
        Effect::Evaluate(pattern) => {
            // Task 4.7: Recursive evaluation for (may-i ...)
            // Extract inner command from args based on the pattern
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
                    evaluator.evaluate(&inner_ctx)
                }
                None => {
                    // Pattern didn't match - no inner command to evaluate
                    EvalResult::new(
                        Decision::Ask,
                        Some("no inner command to evaluate".to_string()),
                    )
                }
            }
        }
        Effect::Case { branches, fallback } => {
            // Find first matching branch
            for (predicate, branch_effect) in branches {
                if evaluate_predicate(&predicate.value, ctx) == PredicateResult::Match {
                    return evaluate_effect(&branch_effect.value, ctx, rules);
                }
            }
            // No branch matched - use fallback or return ask
            if let Some(fb) = fallback {
                evaluate_effect(&fb.value, ctx, rules)
            } else {
                EvalResult::new(Decision::Ask, Some("no case branch matched".to_string()))
            }
        }
        Effect::When { predicate, effect } => {
            if evaluate_predicate(&predicate.value, ctx) == PredicateResult::Match {
                evaluate_effect(&effect.value, ctx, rules)
            } else {
                EvalResult::new(
                    Decision::Ask,
                    Some("when predicate did not match".to_string()),
                )
            }
        }
        Effect::Unless { predicate, effect } => {
            if evaluate_predicate(&predicate.value, ctx) == PredicateResult::NoMatch {
                evaluate_effect(&effect.value, ctx, rules)
            } else {
                EvalResult::new(Decision::Ask, Some("unless predicate matched".to_string()))
            }
        }
        Effect::If {
            predicate,
            then_effect,
            else_effect,
        } => {
            if evaluate_predicate(&predicate.value, ctx) == PredicateResult::Match {
                evaluate_effect(&then_effect.value, ctx, rules)
            } else if let Some(else_eff) = else_effect {
                evaluate_effect(&else_eff.value, ctx, rules)
            } else {
                EvalResult::new(
                    Decision::Ask,
                    Some("if predicate did not match and no else".to_string()),
                )
            }
        }
    }
}

/// Evaluate an effect with tracing.
/// Returns the evaluation result and a trace of the effect evaluation.
fn evaluate_effect_with_trace(
    effect: &Effect,
    ctx: &EvalContext,
    rules: &[Rule],
) -> (EvalResult, EffectTrace) {
    use crate::v2::trace::PredicateResult as TracePredResult;

    match effect {
        Effect::Allow(reason) => {
            let result = EvalResult::new(Decision::Allow, reason.clone());
            let trace = EffectTrace::Terminal {
                effect: effect.clone(),
                decision: Decision::Allow,
                reason: reason.clone(),
            };
            (result, trace)
        }
        Effect::Ask(reason) => {
            let result = EvalResult::new(Decision::Ask, reason.clone());
            let trace = EffectTrace::Terminal {
                effect: effect.clone(),
                decision: Decision::Ask,
                reason: reason.clone(),
            };
            (result, trace)
        }
        Effect::Deny(reason) => {
            let result = EvalResult::new(Decision::Deny, reason.clone());
            let trace = EffectTrace::Terminal {
                effect: effect.clone(),
                decision: Decision::Deny,
                reason: reason.clone(),
            };
            (result, trace)
        }
        Effect::Evaluate(pattern) => {
            // Task 5.6: Trace generation for recursive evaluation
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
                    let result = evaluator.evaluate(&inner_ctx);

                    // Build recursive evaluation trace
                    let trace = EffectTrace::Recursive {
                        pattern: pattern.clone(),
                        command: inner_cmd.clone(),
                        args: inner_args.clone(),
                        depth: ctx.recursion_depth + 1,
                        result: result.clone(),
                        nested: Vec::new(), // Would capture from result if TraceEntry was stored there
                    };

                    (result, trace)
                }
                None => {
                    // Pattern didn't match - no inner command to evaluate
                    let result = EvalResult::new(
                        Decision::Ask,
                        Some("no inner command to evaluate".to_string()),
                    );
                    let trace = EffectTrace::Recursive {
                        pattern: pattern.clone(),
                        command: String::new(),
                        args: vec![],
                        depth: ctx.recursion_depth + 1,
                        result: result.clone(),
                        nested: Vec::new(),
                    };
                    (result, trace)
                }
            }
        }
        Effect::Case { branches, fallback } => {
            // Task 5.5: Trace generation for case effects
            let mut branch_traces = Vec::new();

            for (predicate, branch_effect) in branches {
                let pred_result = evaluate_predicate(&predicate.value, ctx);
                let trace_pred_result = match pred_result {
                    PredicateResult::Match => TracePredResult::Match,
                    PredicateResult::NoMatch => TracePredResult::NoMatch,
                };

                if pred_result == PredicateResult::Match {
                    let (result, effect_trace) =
                        evaluate_effect_with_trace(&branch_effect.value, ctx, rules);
                    branch_traces.push((
                        predicate.value.clone(),
                        trace_pred_result,
                        Box::new(effect_trace),
                    ));
                    let trace = EffectTrace::Case {
                        branches: branch_traces,
                        fallback: None,
                        decision: result.decision,
                        reason: result.reason.clone(),
                    };
                    return (result, trace);
                } else {
                    branch_traces.push((
                        predicate.value.clone(),
                        trace_pred_result,
                        Box::new(EffectTrace::Terminal {
                            effect: Effect::Ask(None),
                            decision: Decision::Ask,
                            reason: None,
                        }),
                    ));
                }
            }

            // No branch matched - use fallback or return ask
            if let Some(fb) = fallback {
                let (result, fallback_trace) = evaluate_effect_with_trace(&fb.value, ctx, rules);
                let trace = EffectTrace::Case {
                    branches: branch_traces,
                    fallback: Some(Box::new(fallback_trace)),
                    decision: result.decision,
                    reason: result.reason.clone(),
                };
                (result, trace)
            } else {
                let result =
                    EvalResult::new(Decision::Ask, Some("no case branch matched".to_string()));
                let trace = EffectTrace::Case {
                    branches: branch_traces,
                    fallback: None,
                    decision: Decision::Ask,
                    reason: Some("no case branch matched".to_string()),
                };
                (result, trace)
            }
        }
        Effect::When { predicate, effect } => {
            let pred_result = evaluate_predicate(&predicate.value, ctx);
            let trace_pred_result = match pred_result {
                PredicateResult::Match => TracePredResult::Match,
                PredicateResult::NoMatch => TracePredResult::NoMatch,
            };

            if pred_result == PredicateResult::Match {
                let (result, effect_trace) = evaluate_effect_with_trace(&effect.value, ctx, rules);
                let trace = EffectTrace::When {
                    predicate: predicate.value.clone(),
                    predicate_result: trace_pred_result,
                    effect: Box::new(effect_trace),
                    decision: result.decision,
                    reason: result.reason.clone(),
                };
                (result, trace)
            } else {
                let result = EvalResult::new(
                    Decision::Ask,
                    Some("when predicate did not match".to_string()),
                );
                let trace = EffectTrace::When {
                    predicate: predicate.value.clone(),
                    predicate_result: trace_pred_result,
                    effect: Box::new(EffectTrace::Terminal {
                        effect: Effect::Ask(None),
                        decision: Decision::Ask,
                        reason: Some("when predicate did not match".to_string()),
                    }),
                    decision: Decision::Ask,
                    reason: Some("when predicate did not match".to_string()),
                };
                (result, trace)
            }
        }
        Effect::Unless { predicate, effect } => {
            let pred_result = evaluate_predicate(&predicate.value, ctx);
            let trace_pred_result = match pred_result {
                PredicateResult::Match => TracePredResult::Match,
                PredicateResult::NoMatch => TracePredResult::NoMatch,
            };

            if pred_result == PredicateResult::NoMatch {
                let (result, effect_trace) = evaluate_effect_with_trace(&effect.value, ctx, rules);
                let trace = EffectTrace::Unless {
                    predicate: predicate.value.clone(),
                    predicate_result: trace_pred_result,
                    effect: Box::new(effect_trace),
                    decision: result.decision,
                    reason: result.reason.clone(),
                };
                (result, trace)
            } else {
                let result =
                    EvalResult::new(Decision::Ask, Some("unless predicate matched".to_string()));
                let trace = EffectTrace::Unless {
                    predicate: predicate.value.clone(),
                    predicate_result: trace_pred_result,
                    effect: Box::new(EffectTrace::Terminal {
                        effect: Effect::Ask(None),
                        decision: Decision::Ask,
                        reason: Some("unless predicate matched".to_string()),
                    }),
                    decision: Decision::Ask,
                    reason: Some("unless predicate matched".to_string()),
                };
                (result, trace)
            }
        }
        Effect::If {
            predicate,
            then_effect,
            else_effect,
        } => {
            let pred_result = evaluate_predicate(&predicate.value, ctx);
            let trace_pred_result = match pred_result {
                PredicateResult::Match => TracePredResult::Match,
                PredicateResult::NoMatch => TracePredResult::NoMatch,
            };

            if pred_result == PredicateResult::Match {
                let (result, then_trace) =
                    evaluate_effect_with_trace(&then_effect.value, ctx, rules);
                let trace = EffectTrace::If {
                    predicate: predicate.value.clone(),
                    predicate_result: trace_pred_result,
                    then_effect: Box::new(then_trace),
                    else_effect: None,
                    decision: result.decision,
                    reason: result.reason.clone(),
                };
                (result, trace)
            } else if let Some(else_eff) = else_effect {
                let (result, else_trace) = evaluate_effect_with_trace(&else_eff.value, ctx, rules);
                let trace = EffectTrace::If {
                    predicate: predicate.value.clone(),
                    predicate_result: trace_pred_result,
                    then_effect: Box::new(EffectTrace::Terminal {
                        effect: Effect::Ask(None),
                        decision: Decision::Ask,
                        reason: None,
                    }),
                    else_effect: Some(Box::new(else_trace)),
                    decision: result.decision,
                    reason: result.reason.clone(),
                };
                (result, trace)
            } else {
                let result = EvalResult::new(
                    Decision::Ask,
                    Some("if predicate did not match and no else".to_string()),
                );
                let trace = EffectTrace::If {
                    predicate: predicate.value.clone(),
                    predicate_result: trace_pred_result,
                    then_effect: Box::new(EffectTrace::Terminal {
                        effect: Effect::Ask(None),
                        decision: Decision::Ask,
                        reason: None,
                    }),
                    else_effect: None,
                    decision: Decision::Ask,
                    reason: Some("if predicate did not match and no else".to_string()),
                };
                (result, trace)
            }
        }
    }
}

/// Extract an inner command from args based on an arg pattern.
/// Returns Some((command, args)) if a command can be extracted, None otherwise.
///
/// For patterns with the `recursive` flag set on a positional arg, the remaining
/// args after that position become the inner command.
fn extract_inner_command(pattern: &ArgPattern, args: &[String]) -> Option<(String, Vec<String>)> {
    match pattern {
        ArgPattern::Positional(pargs) | ArgPattern::Exact(pargs) => {
            // Find the recursive marker in positional args
            let mut arg_idx = 0;
            for (parg_idx, parg) in pargs.iter().enumerate() {
                if parg.recursive {
                    // Skip matched args up to this point
                    let consumed = count_matched_args(&pargs[..parg_idx], args)?;
                    let remaining = &args[consumed..];
                    if remaining.is_empty() {
                        return None;
                    }
                    let inner_cmd = remaining[0].clone();
                    let inner_args = remaining[1..].to_vec();
                    return Some((inner_cmd, inner_args));
                }
                // Advance arg_idx based on quantifier
                match parg.quantifier {
                    may_i_core::types::Quantifier::One => {
                        if arg_idx < args.len() && match_expr(&parg.pattern, &args[arg_idx]) {
                            arg_idx += 1;
                        }
                    }
                    may_i_core::types::Quantifier::Optional => {
                        if arg_idx < args.len() && match_expr(&parg.pattern, &args[arg_idx]) {
                            arg_idx += 1;
                        }
                    }
                    may_i_core::types::Quantifier::OneOrMore => {
                        if arg_idx < args.len() && match_expr(&parg.pattern, &args[arg_idx]) {
                            arg_idx += 1;
                            while arg_idx < args.len() && match_expr(&parg.pattern, &args[arg_idx])
                            {
                                arg_idx += 1;
                            }
                        }
                    }
                    may_i_core::types::Quantifier::ZeroOrMore => {
                        while arg_idx < args.len() && match_expr(&parg.pattern, &args[arg_idx]) {
                            arg_idx += 1;
                        }
                    }
                }
            }
            // No recursive marker found - try to use all args as inner command
            if !args.is_empty() {
                let inner_cmd = args[0].clone();
                let inner_args = args[1..].to_vec();
                Some((inner_cmd, inner_args))
            } else {
                None
            }
        }
        ArgPattern::Anywhere(_) | ArgPattern::Forbidden(_) | ArgPattern::At { .. } => {
            // These patterns don't define a clear inner command structure
            // Just use all args as the inner command
            if !args.is_empty() {
                let inner_cmd = args[0].clone();
                let inner_args = args[1..].to_vec();
                Some((inner_cmd, inner_args))
            } else {
                None
            }
        }
    }
}

/// Count how many args are consumed by the given positional arg patterns.
fn count_matched_args(pargs: &[PositionalArg], args: &[String]) -> Option<usize> {
    let mut arg_idx = 0;
    for parg in pargs {
        match parg.quantifier {
            may_i_core::types::Quantifier::One => {
                if arg_idx >= args.len() || !match_expr(&parg.pattern, &args[arg_idx]) {
                    return None;
                }
                arg_idx += 1;
            }
            may_i_core::types::Quantifier::Optional => {
                if arg_idx < args.len() && match_expr(&parg.pattern, &args[arg_idx]) {
                    arg_idx += 1;
                }
            }
            may_i_core::types::Quantifier::OneOrMore => {
                if arg_idx >= args.len() || !match_expr(&parg.pattern, &args[arg_idx]) {
                    return None;
                }
                arg_idx += 1;
                while arg_idx < args.len() && match_expr(&parg.pattern, &args[arg_idx]) {
                    arg_idx += 1;
                }
            }
            may_i_core::types::Quantifier::ZeroOrMore => {
                while arg_idx < args.len() && match_expr(&parg.pattern, &args[arg_idx]) {
                    arg_idx += 1;
                }
            }
        }
    }
    Some(arg_idx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_core::span::Span;
    use may_i_core::v2::Spanned;
    use may_i_core::v2::ast::{Effect, Rule};
    use may_i_core::v2::pattern::CommandPattern;

    fn dummy_span() -> Span {
        Span::new(0, 0)
    }

    fn create_rule(command: &str, predicates: Vec<Predicate>, effect: Effect) -> Rule {
        Rule {
            command: Spanned::new(CommandPattern::Literal(command.to_string()), dummy_span()),
            predicates: predicates
                .into_iter()
                .map(|p| Spanned::new(p, dummy_span()))
                .collect(),
            effect: Spanned::new(effect, dummy_span()),
            span: dummy_span(),
        }
    }

    #[test]
    fn evaluate_simple_rule() {
        let rules = vec![create_rule("git", vec![], Effect::Allow(None))];
        let evaluator = Evaluator::new(&rules);
        let facts = ContextFacts::default();
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn command_mismatch_returns_ask() {
        let rules = vec![create_rule("hg", vec![], Effect::Allow(None))];
        let evaluator = Evaluator::new(&rules);
        let facts = ContextFacts::default();
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn predicate_no_match_returns_ask() {
        let rules = vec![create_rule(
            "git",
            vec![Predicate::has_presence(":nonexistent")],
            Effect::Allow(None),
        )];
        let evaluator = Evaluator::new(&rules);
        let facts = ContextFacts::default();
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn fact_presence_match() {
        let mut facts = ContextFacts::default();
        facts.insert_present(":via/ssh");
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluate_predicate(&Predicate::has_presence(":via/ssh"), &ctx);
        assert_eq!(result, PredicateResult::Match);
    }

    #[test]
    fn and_predicate_all_match() {
        let mut facts = ContextFacts::default();
        facts.insert_present(":a");
        facts.insert_present(":b");
        let ctx = EvalContext::new("git", &[], &facts);

        let pred = Predicate::And(vec![
            Predicate::has_presence(":a"),
            Predicate::has_presence(":b"),
        ]);
        assert_eq!(evaluate_predicate(&pred, &ctx), PredicateResult::Match);
    }

    #[test]
    fn and_predicate_one_no_match() {
        let mut facts = ContextFacts::default();
        facts.insert_present(":a");
        let ctx = EvalContext::new("git", &[], &facts);

        let pred = Predicate::And(vec![
            Predicate::has_presence(":a"),
            Predicate::has_presence(":b"),
        ]);
        assert_eq!(evaluate_predicate(&pred, &ctx), PredicateResult::NoMatch);
    }

    #[test]
    fn or_predicate_one_matches() {
        let mut facts = ContextFacts::default();
        facts.insert_present(":a");
        let ctx = EvalContext::new("git", &[], &facts);

        let pred = Predicate::Or(vec![
            Predicate::has_presence(":a"),
            Predicate::has_presence(":b"),
        ]);
        assert_eq!(evaluate_predicate(&pred, &ctx), PredicateResult::Match);
    }

    #[test]
    fn not_predicate_inverts() {
        let facts = ContextFacts::default();
        let ctx = EvalContext::new("git", &[], &facts);

        let pred = Predicate::Not(Box::new(Predicate::has_presence(":nonexistent")));
        assert_eq!(evaluate_predicate(&pred, &ctx), PredicateResult::Match);
    }

    #[test]
    fn deny_is_most_restrictive() {
        let rules = vec![
            create_rule("git", vec![], Effect::Allow(None)),
            create_rule("git", vec![], Effect::Deny(None)),
        ];
        let evaluator = Evaluator::new(&rules);
        let facts = ContextFacts::default();
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn ask_over_allow() {
        let rules = vec![
            create_rule("git", vec![], Effect::Allow(None)),
            create_rule("git", vec![], Effect::Ask(None)),
        ];
        let evaluator = Evaluator::new(&rules);
        let facts = ContextFacts::default();
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn recursion_limit_enforced() {
        let rules = vec![];
        let evaluator = Evaluator::new(&rules);
        let facts = ContextFacts::default();
        let ctx = EvalContext::new("git", &[], &facts).with_recursion_limit(5);

        // Manually set depth to exceed limit
        let deep_ctx = EvalContext {
            command: ctx.command,
            args: ctx.args,
            facts: ctx.facts,
            recursion_depth: 5,
            recursion_limit: 5,
        };

        let result = evaluator.evaluate(&deep_ctx);
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.unwrap().contains("recursion"));
    }

    // Task 7.5: Additional evaluator tests for all effect types

    #[test]
    fn effect_allow_with_reason_evaluates_to_allow() {
        // Test that Allow effect with reason evaluates correctly
        let rules = vec![create_rule(
            "git",
            vec![],
            Effect::Allow(Some("safe operation".to_string())),
        )];
        let evaluator = Evaluator::new(&rules);
        let facts = ContextFacts::default();
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn when_effect_predicate_true() {
        let mut facts = ContextFacts::default();
        facts.insert_present(":via/ssh");

        let rules = vec![create_rule(
            "git",
            vec![],
            Effect::When {
                predicate: Spanned::new(Predicate::has_presence(":via/ssh"), dummy_span()),
                effect: Box::new(Spanned::new(Effect::Allow(None), dummy_span())),
            },
        )];
        let evaluator = Evaluator::new(&rules);
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn when_effect_predicate_false() {
        let facts = ContextFacts::default();

        let rules = vec![create_rule(
            "git",
            vec![],
            Effect::When {
                predicate: Spanned::new(Predicate::has_presence(":via/ssh"), dummy_span()),
                effect: Box::new(Spanned::new(Effect::Allow(None), dummy_span())),
            },
        )];
        let evaluator = Evaluator::new(&rules);
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn unless_effect_predicate_false() {
        let facts = ContextFacts::default();

        let rules = vec![create_rule(
            "git",
            vec![],
            Effect::Unless {
                predicate: Spanned::new(Predicate::has_presence(":via/ssh"), dummy_span()),
                effect: Box::new(Spanned::new(Effect::Allow(None), dummy_span())),
            },
        )];
        let evaluator = Evaluator::new(&rules);
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn unless_effect_predicate_true() {
        let mut facts = ContextFacts::default();
        facts.insert_present(":via/ssh");

        let rules = vec![create_rule(
            "git",
            vec![],
            Effect::Unless {
                predicate: Spanned::new(Predicate::has_presence(":via/ssh"), dummy_span()),
                effect: Box::new(Spanned::new(Effect::Allow(None), dummy_span())),
            },
        )];
        let evaluator = Evaluator::new(&rules);
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn if_effect_predicate_true() {
        let mut facts = ContextFacts::default();
        facts.insert_present(":via/ssh");

        let rules = vec![create_rule(
            "git",
            vec![],
            Effect::If {
                predicate: Spanned::new(Predicate::has_presence(":via/ssh"), dummy_span()),
                then_effect: Box::new(Spanned::new(Effect::Allow(None), dummy_span())),
                else_effect: Some(Box::new(Spanned::new(Effect::Deny(None), dummy_span()))),
            },
        )];
        let evaluator = Evaluator::new(&rules);
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn if_effect_predicate_false_with_else() {
        let facts = ContextFacts::default();

        let rules = vec![create_rule(
            "git",
            vec![],
            Effect::If {
                predicate: Spanned::new(Predicate::has_presence(":via/ssh"), dummy_span()),
                then_effect: Box::new(Spanned::new(Effect::Allow(None), dummy_span())),
                else_effect: Some(Box::new(Spanned::new(Effect::Deny(None), dummy_span()))),
            },
        )];
        let evaluator = Evaluator::new(&rules);
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn if_effect_predicate_false_no_else() {
        let facts = ContextFacts::default();

        let rules = vec![create_rule(
            "git",
            vec![],
            Effect::If {
                predicate: Spanned::new(Predicate::has_presence(":via/ssh"), dummy_span()),
                then_effect: Box::new(Spanned::new(Effect::Allow(None), dummy_span())),
                else_effect: None,
            },
        )];
        let evaluator = Evaluator::new(&rules);
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn case_effect_first_branch_matches() {
        let mut facts = ContextFacts::default();
        facts.insert_present(":via/ssh");

        let rules = vec![create_rule(
            "git",
            vec![],
            Effect::Case {
                branches: vec![
                    (
                        Spanned::new(Predicate::has_presence(":via/ssh"), dummy_span()),
                        Spanned::new(Effect::Allow(None), dummy_span()),
                    ),
                    (
                        Spanned::new(Predicate::has_presence(":local"), dummy_span()),
                        Spanned::new(Effect::Deny(None), dummy_span()),
                    ),
                ],
                fallback: None,
            },
        )];
        let evaluator = Evaluator::new(&rules);
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn case_effect_second_branch_matches() {
        let mut facts = ContextFacts::default();
        facts.insert_present(":local");

        let rules = vec![create_rule(
            "git",
            vec![],
            Effect::Case {
                branches: vec![
                    (
                        Spanned::new(Predicate::has_presence(":via/ssh"), dummy_span()),
                        Spanned::new(Effect::Allow(None), dummy_span()),
                    ),
                    (
                        Spanned::new(Predicate::has_presence(":local"), dummy_span()),
                        Spanned::new(Effect::Deny(None), dummy_span()),
                    ),
                ],
                fallback: None,
            },
        )];
        let evaluator = Evaluator::new(&rules);
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn case_effect_no_branch_matches_uses_fallback() {
        let facts = ContextFacts::default();

        let rules = vec![create_rule(
            "git",
            vec![],
            Effect::Case {
                branches: vec![(
                    Spanned::new(Predicate::has_presence(":via/ssh"), dummy_span()),
                    Spanned::new(Effect::Allow(None), dummy_span()),
                )],
                fallback: Some(Box::new(Spanned::new(Effect::Deny(None), dummy_span()))),
            },
        )];
        let evaluator = Evaluator::new(&rules);
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn case_effect_no_branch_matches_no_fallback() {
        let facts = ContextFacts::default();

        let rules = vec![create_rule(
            "git",
            vec![],
            Effect::Case {
                branches: vec![(
                    Spanned::new(Predicate::has_presence(":via/ssh"), dummy_span()),
                    Spanned::new(Effect::Allow(None), dummy_span()),
                )],
                fallback: None,
            },
        )];
        let evaluator = Evaluator::new(&rules);
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn multiple_rules_all_match_most_restrictive_wins() {
        let rules = vec![
            create_rule("git", vec![], Effect::Allow(None)),
            create_rule("git", vec![], Effect::Ask(None)),
            create_rule("git", vec![], Effect::Allow(None)),
        ];
        let evaluator = Evaluator::new(&rules);
        let facts = ContextFacts::default();
        let ctx = EvalContext::new("git", &[], &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn arg_pattern_positional_match() {
        let rules = vec![create_rule(
            "git",
            vec![Predicate::Arg(ArgPattern::Positional(vec![
                PositionalArg {
                    pattern: Expr::Literal("push".to_string()),
                    quantifier: may_i_core::types::Quantifier::One,
                    recursive: false,
                },
            ]))],
            Effect::Allow(None),
        )];
        let evaluator = Evaluator::new(&rules);
        let facts = ContextFacts::default();
        let args = vec!["push".to_string()];
        let ctx = EvalContext::new("git", &args, &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn arg_pattern_positional_no_match() {
        let rules = vec![create_rule(
            "git",
            vec![Predicate::Arg(ArgPattern::Positional(vec![
                PositionalArg {
                    pattern: Expr::Literal("push".to_string()),
                    quantifier: may_i_core::types::Quantifier::One,
                    recursive: false,
                },
            ]))],
            Effect::Allow(None),
        )];
        let evaluator = Evaluator::new(&rules);
        let facts = ContextFacts::default();
        let args = vec!["status".to_string()];
        let ctx = EvalContext::new("git", &args, &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn arg_pattern_anywhere_match() {
        let rules = vec![create_rule(
            "git",
            vec![Predicate::Arg(ArgPattern::Anywhere(vec![Expr::Literal(
                "--force".to_string(),
            )]))],
            Effect::Deny(None),
        )];
        let evaluator = Evaluator::new(&rules);
        let facts = ContextFacts::default();
        let args = vec!["push".to_string(), "--force".to_string()];
        let ctx = EvalContext::new("git", &args, &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn arg_pattern_forbidden_match() {
        let rules = vec![create_rule(
            "git",
            vec![Predicate::Arg(ArgPattern::Forbidden(vec![Expr::Literal(
                "--dangerous".to_string(),
            )]))],
            Effect::Allow(None),
        )];
        let evaluator = Evaluator::new(&rules);
        let facts = ContextFacts::default();
        let args = vec!["status".to_string()];
        let ctx = EvalContext::new("git", &args, &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn arg_pattern_forbidden_violated() {
        let rules = vec![create_rule(
            "git",
            vec![Predicate::Arg(ArgPattern::Forbidden(vec![Expr::Literal(
                "--dangerous".to_string(),
            )]))],
            Effect::Allow(None),
        )];
        let evaluator = Evaluator::new(&rules);
        let facts = ContextFacts::default();
        let args = vec!["--dangerous".to_string()];
        let ctx = EvalContext::new("git", &args, &facts);

        let result = evaluator.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Ask);
    }
}
