// Unified effect evaluator.
// All effect forms evaluate to EffectResult (Decision | Nil).

use may_i_core::ast::{Effect, EffectResult, Predicate, Rule};
use may_i_core::pattern::{ArgPattern, CommandPattern, PositionalArg};
use may_i_core::{ContextFacts, Decision, FactPattern, FactQuery};

use crate::EvalResult;
use crate::fold::{ArgMatchDetail, ChildResult, EvalFold, PureFold, build_fact_detail};

/// Maximum recursion depth for (may-i ...) evaluation.
pub(crate) const DEFAULT_RECURSION_LIMIT: usize = 10;

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
    #[cfg(test)]
    pub(crate) fn with_recursion_limit(mut self, limit: usize) -> Self {
        self.recursion_limit = limit;
        self
    }

    /// Check if we've exceeded the recursion limit.
    pub(crate) fn is_depth_exceeded(&self) -> bool {
        self.recursion_depth >= self.recursion_limit
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

/// Check if an effect is a pure arg-matching predicate/guard.
///
/// ArgPattern effects (anywhere, forbidden, positional, exact) are predicates
/// that gate the rule. When they return Nil (no match), the rule is skipped.
/// When they return Decision::Allow (match), execution continues to the next
/// effect rather than treating it as a terminal.
///
/// Or/And/Not wrapping only arg predicates also act as predicates.
fn is_arg_predicate(effect: &Effect) -> bool {
    match effect {
        Effect::ArgPattern(_) => true,
        Effect::Or { effects } => effects.iter().all(|e| is_arg_predicate(&e.value)),
        Effect::And { effects } => effects.iter().all(|e| is_arg_predicate(&e.value)),
        Effect::Not { effect: inner } => is_arg_predicate(&inner.value),
        _ => false,
    }
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
        let mut any_command_matched = false;
        for rule in self.rules {
            let out = self.evaluate_rule(fold, rule, ctx);
            let result = F::effect_result(&out);

            match result {
                EffectResult::Decision(decision, reason) => {
                    return EvalResult::new(*decision, reason.clone());
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
        EvalResult::new(Decision::Ask, Some(reason))
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

        // Step 2: Evaluate subsequent effects in sequence.
        // Nil from any effect means "no match" → skip rule.
        // ArgPattern Allow (no reason) is a passed predicate → continue.
        // Any other Decision is a terminal → return as rule result.
        let mut effect_outs: Vec<F::EffectOut> = Vec::new();
        for effect in &rule.effects {
            let out = evaluate_effect_fold(fold, &effect.value, ctx, self.rules);
            let result = F::effect_result(&out);

            match result {
                EffectResult::Nil => {
                    effect_outs.push(out);
                    return fold.rule_not_matched(rule, ctx.facts, command_out, effect_outs);
                }
                EffectResult::Decision(Decision::Allow, None)
                    if is_arg_predicate(&effect.value) =>
                {
                    // ArgPattern Allow with no reason means "predicate passed,
                    // continue to the next effect". Allow with a reason comes
                    // from an embedded continuation (trailing Expr::Cond) and
                    // IS a terminal.
                    effect_outs.push(out);
                }
                EffectResult::Decision(_, _) => {
                    effect_outs.push(out);
                    let line = None;
                    return fold.rule_matched(rule, line, ctx.facts, command_out, effect_outs);
                }
            }
        }

        // Step 3: No terminal effect fired.
        if !effect_outs.is_empty() {
            // All predicates passed but no terminal → use last predicate result.
            let line = None;
            fold.rule_matched(rule, line, ctx.facts, command_out, effect_outs)
        } else if rule.effects.is_empty() {
            // Bare command match → default to :ask.
            let ask_result = EffectResult::Decision(Decision::Ask, None);
            let ask_out = fold.effect_terminal(&Effect::Ask(None), ask_result);
            let line = None;
            fold.rule_matched(rule, line, ctx.facts, command_out, vec![ask_out])
        } else {
            fold.rule_not_matched(rule, ctx.facts, command_out, effect_outs)
        }
    }
}

/// Evaluate a predicate against the context (non-generic, uses PureFold).
#[cfg(test)]
pub(crate) fn evaluate_predicate(predicate: &Predicate, ctx: &EvalContext) -> PredicateResult {
    let mut fold = PureFold;
    let out = evaluate_predicate_fold(&mut fold, predicate, ctx);
    PureFold::predicate_result(&out)
}

/// Evaluate a predicate with a fold.
pub(crate) fn evaluate_predicate_fold<F: EvalFold>(
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
            let positional_args: Vec<&String> = positional_args(ctx.args);

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
            let positional_args: Vec<&String> = positional_args(ctx.args);

            let (matched, consumed, _) = match_positional_patterns(&positional_args, patterns);
            if consumed == positional_args.len() && matched {
                PredicateResult::Match
            } else {
                PredicateResult::NoMatch
            }
        }
        ArgPattern::Anywhere(exprs) => {
            for expr in exprs {
                if ctx.args.iter().any(|arg| expr.is_match(arg)) {
                    return PredicateResult::Match;
                }
            }
            PredicateResult::NoMatch
        }
        ArgPattern::Forbidden(exprs) => {
            for expr in exprs {
                if ctx.args.iter().any(|arg| expr.is_match(arg)) {
                    return PredicateResult::NoMatch;
                }
            }
            PredicateResult::Match
        }
    }
}

/// Match positional patterns against args, capturing bound facts.
/// Returns (matched, consumed_count, bound_facts) where consumed_count is the
/// number of args consumed and bound_facts contains any facts captured from
/// Expr::Bind expressions in the patterns.
///
/// Uses backtracking for Optional/ZeroOrMore/OneOrMore quantifiers: tries the
/// greedy match first, then progressively shorter matches if subsequent
/// patterns fail.
pub(crate) fn match_positional_patterns(
    args: &[&String],
    patterns: &[PositionalArg],
) -> (bool, usize, ContextFacts) {
    match_positional_recursive(args, patterns, 0, 0, ContextFacts::default())
}

fn match_positional_recursive(
    args: &[&String],
    patterns: &[PositionalArg],
    pat_idx: usize,
    arg_idx: usize,
    facts: ContextFacts,
) -> (bool, usize, ContextFacts) {
    // All patterns consumed → success
    if pat_idx >= patterns.len() {
        return (true, arg_idx, facts);
    }

    let pattern = &patterns[pat_idx];

    match &pattern.quantifier {
        may_i_core::Quantifier::One => {
            if arg_idx >= args.len() {
                return (false, arg_idx, facts);
            }
            let (matched, f) = match_expr_with_binding(&pattern.pattern, args[arg_idx]);
            if !matched {
                return (false, arg_idx, facts);
            }
            match_positional_recursive(args, patterns, pat_idx + 1, arg_idx + 1, facts.merge(&f))
        }
        may_i_core::Quantifier::Optional => {
            // Try consuming one arg first (greedy), then try skipping
            if arg_idx < args.len() {
                let (matched, f) = match_expr_with_binding(&pattern.pattern, args[arg_idx]);
                if matched {
                    let result = match_positional_recursive(
                        args,
                        patterns,
                        pat_idx + 1,
                        arg_idx + 1,
                        facts.merge(&f),
                    );
                    if result.0 {
                        return result;
                    }
                }
            }
            // Skip (consume zero)
            match_positional_recursive(args, patterns, pat_idx + 1, arg_idx, facts)
        }
        may_i_core::Quantifier::ZeroOrMore => {
            // Count maximum matching args
            let mut max_consume = 0;
            while arg_idx + max_consume < args.len() {
                let (matched, _) =
                    match_expr_with_binding(&pattern.pattern, args[arg_idx + max_consume]);
                if !matched {
                    break;
                }
                max_consume += 1;
            }
            // Try from greedy (max) down to 0, backtracking
            for consume in (0..=max_consume).rev() {
                let mut f = facts.clone();
                for i in 0..consume {
                    let (_, fi) = match_expr_with_binding(&pattern.pattern, args[arg_idx + i]);
                    f = f.merge(&fi);
                }
                let result =
                    match_positional_recursive(args, patterns, pat_idx + 1, arg_idx + consume, f);
                if result.0 {
                    return result;
                }
            }
            (false, arg_idx, facts)
        }
        may_i_core::Quantifier::OneOrMore => {
            if arg_idx >= args.len() {
                return (false, arg_idx, facts);
            }
            let (first_matched, _) = match_expr_with_binding(&pattern.pattern, args[arg_idx]);
            if !first_matched {
                return (false, arg_idx, facts);
            }
            // Count maximum matching args (starting from 1)
            let mut max_consume = 1;
            while arg_idx + max_consume < args.len() {
                let (matched, _) =
                    match_expr_with_binding(&pattern.pattern, args[arg_idx + max_consume]);
                if !matched {
                    break;
                }
                max_consume += 1;
            }
            // Try from greedy (max) down to 1, backtracking
            for consume in (1..=max_consume).rev() {
                let mut f = facts.clone();
                for i in 0..consume {
                    let (_, fi) = match_expr_with_binding(&pattern.pattern, args[arg_idx + i]);
                    f = f.merge(&fi);
                }
                let result =
                    match_positional_recursive(args, patterns, pat_idx + 1, arg_idx + consume, f);
                if result.0 {
                    return result;
                }
            }
            (false, arg_idx, facts)
        }
    }
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

/// Build per-element match details for positional patterns.
/// Re-walks the patterns against the matched args to capture binding and
/// expression match info for annotation purposes.
fn build_positional_element_details(
    args: &[&String],
    patterns: &[PositionalArg],
    matched: bool,
    consumed: usize,
) -> Vec<crate::fold::PositionalElementDetail> {
    use may_i_core::pattern::Expr;

    if !matched {
        return vec![];
    }

    let mut details = Vec::new();
    let mut arg_idx = 0;

    for (pat_idx, pattern) in patterns.iter().enumerate() {
        // Determine how many args this pattern consumed.
        // For One quantifier: exactly 1 if matched
        // For others: we need to re-match to find out
        let (consume_count, element_matched) = match &pattern.quantifier {
            may_i_core::Quantifier::One => {
                if arg_idx < consumed {
                    (1, true)
                } else {
                    (0, false)
                }
            }
            may_i_core::Quantifier::Optional => {
                if arg_idx < consumed {
                    let (m, _) = match_expr_with_binding(&pattern.pattern, args[arg_idx]);
                    if m { (1, true) } else { (0, true) }
                } else {
                    (0, true)
                }
            }
            may_i_core::Quantifier::ZeroOrMore | may_i_core::Quantifier::OneOrMore => {
                let mut count = 0;
                let mut idx = arg_idx;
                while idx < consumed {
                    let (m, _) = match_expr_with_binding(&pattern.pattern, args[idx]);
                    if m {
                        count += 1;
                        idx += 1;
                    } else {
                        break;
                    }
                }
                // Check if remaining patterns can match remaining args
                // (simplified: for the detail pass, just consume greedily)
                (
                    count,
                    count > 0 || matches!(pattern.quantifier, may_i_core::Quantifier::ZeroOrMore),
                )
            }
        };

        let consumed_args: Vec<String> = (0..consume_count)
            .map(|i| args[arg_idx + i].to_string())
            .collect();

        let binding = if let Expr::Bind { key, expr: inner } = &pattern.pattern
            && !consumed_args.is_empty()
        {
            let value = consumed_args.first().map(|v| v.to_string());
            let inner_match = value
                .as_ref()
                .and_then(|v| build_expr_match_detail(inner, v));
            Some(crate::fold::BindDetail {
                key: key.to_string(),
                value,
                inner_match,
            })
        } else {
            None
        };

        let expr_match = if binding.is_none() && !consumed_args.is_empty() {
            consumed_args
                .first()
                .and_then(|v| build_expr_match_detail(&pattern.pattern, v))
        } else {
            None
        };

        let cond_branch_index = if let Expr::Cond(branches) = &pattern.pattern
            && !consumed_args.is_empty()
        {
            let value = &consumed_args[0];
            branches
                .iter()
                .position(|b| match_expr_with_binding(&b.test, value).0)
        } else {
            None
        };

        details.push(crate::fold::PositionalElementDetail {
            pattern_index: pat_idx,
            consumed_args,
            binding,
            expr_match,
            matched: element_matched,
            cond_branch_index,
        });

        arg_idx += consume_count;
    }

    details
}

/// Build expression match detail for a single expression against a value.
fn build_expr_match_detail<E: std::fmt::Debug + may_i_core::ToDoc>(
    expr: &may_i_core::pattern::Expr<E>,
    value: &str,
) -> Option<crate::fold::ExprMatchDetail> {
    use may_i_core::pattern::Expr;
    match expr {
        Expr::Literal(s) => Some(crate::fold::ExprMatchDetail::Literal {
            expected: s.clone(),
            actual: value.to_string(),
            matched: s == value,
        }),
        Expr::Regex(re) => Some(crate::fold::ExprMatchDetail::Regex {
            pattern: re.as_str().to_string(),
            actual: value.to_string(),
            matched: re.is_match(value),
        }),
        Expr::Wildcard => Some(crate::fold::ExprMatchDetail::Wildcard {
            actual: value.to_string(),
        }),
        // For compound expressions, don't generate top-level detail
        _ => None,
    }
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
#[cfg(test)]
pub(crate) fn evaluate_effect(effect: &Effect, ctx: &EvalContext, rules: &[Rule]) -> EffectResult {
    evaluate_effect_fold(&mut PureFold, effect, ctx, rules)
}

/// Evaluate an effect with a fold, producing `F::EffectOut`.
pub(crate) fn evaluate_effect_fold<F: EvalFold>(
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
            fold.effect_when(pred_out, body_child, &body.value, result)
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
            fold.effect_unless(pred_out, body_child, &body.value, result)
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
                    let expanded_inner = expand_combined_flags(&inner_args);
                    let inner_ctx = EvalContext {
                        command: &inner_cmd,
                        args: &expanded_inner,
                        facts: &inner_facts,
                        recursion_depth: ctx.recursion_depth + 1,
                        recursion_limit: ctx.recursion_limit,
                    };
                    fold.begin_recursive_eval();
                    let eval_result = evaluator.evaluate(fold, &inner_ctx);
                    let inner_result =
                        EffectResult::Decision(eval_result.decision, eval_result.reason);
                    // For the fold, we build a synthetic terminal output representing the inner result
                    let inner_out =
                        fold.effect_terminal(&Effect::Allow(None), inner_result.clone());
                    fold.effect_may_i(pattern, &inner_cmd, &inner_args, inner_result, inner_out)
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
                    );
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
                    );
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

/// Extract inner command from args for may-i recursion.
///
/// The remaining args may contain a quoted string like `"rm -rf /"` that
/// represents a complete sub-command. We join all args into a single string
/// and re-parse through the shell parser to correctly handle quoting.
fn extract_inner_command(_pattern: &ArgPattern, args: &[String]) -> Option<(String, Vec<String>)> {
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

    // ── Property tests ────────────────────────────────────────────────

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 256, max_shrink_iters: 50, .. Default::default() })]

        #[test]
        fn expr_cond_matches_iff_any_branch_test_matches(
            branches_tests in proptest::collection::vec(
                crate::test_generators::any_match_string(),
                1..5,
            ),
            value in crate::test_generators::any_match_string(),
        ) {
            use may_i_core::pattern::{Expr, ExprBranch};

            let branches: Vec<ExprBranch<Effect>> = branches_tests
                .iter()
                .map(|s| ExprBranch {
                    test: Expr::Literal(s.clone()),
                    effect: Effect::Allow(None),
                })
                .collect();

            let expr = Expr::Cond(branches);
            let (matched, _facts) = match_expr_with_binding(&expr, &value);
            let expected = branches_tests.iter().any(|s| s == &value);
            proptest::prop_assert_eq!(matched, expected);
        }

        #[test]
        fn build_expr_match_detail_consistency(
            expr in crate::test_generators::any_expr(2),
            value in crate::test_generators::any_match_string(),
        ) {
            use may_i_core::pattern::Expr;

            let detail = build_expr_match_detail(&expr, &value);
            let (matched, _) = match_expr_with_binding(&expr, &value);

            match &expr {
                Expr::Literal(_) => {
                    let d = detail.expect("Literal should produce detail");
                    if let crate::fold::ExprMatchDetail::Literal { matched: dm, .. } = d {
                        proptest::prop_assert_eq!(dm, matched);
                    } else {
                        return Err(proptest::test_runner::TestCaseError::Fail("expected Literal detail".into()));
                    }
                }
                Expr::Wildcard => {
                    let d = detail.expect("Wildcard should produce detail");
                    let is_wildcard = matches!(d, crate::fold::ExprMatchDetail::Wildcard { .. });
                    proptest::prop_assert!(is_wildcard);
                }
                // Compound expressions return None
                _ => {
                    proptest::prop_assert!(detail.is_none());
                }
            }
        }
    }

    // --- Targeted branch-coverage unit tests ---

    #[test]
    fn build_expr_match_detail_regex() {
        use may_i_core::pattern::Expr;

        let expr: Expr<Effect> = Expr::Regex(regex::Regex::new("^prod").unwrap());
        let detail = build_expr_match_detail(&expr, "prod-01");
        match detail {
            Some(crate::fold::ExprMatchDetail::Regex {
                pattern,
                actual,
                matched,
            }) => {
                assert_eq!(pattern, "^prod");
                assert_eq!(actual, "prod-01");
                assert!(matched);
            }
            other => panic!("expected Regex detail, got {other:?}"),
        }

        let detail_miss = build_expr_match_detail(&expr, "dev-01");
        match detail_miss {
            Some(crate::fold::ExprMatchDetail::Regex { matched, .. }) => {
                assert!(!matched);
            }
            other => panic!("expected Regex detail, got {other:?}"),
        }
    }

    #[test]
    fn match_command_pattern_or_with_regex() {
        let re = regex::Regex::new("^git").unwrap();
        let pat = CommandPattern::Or(vec![
            CommandPattern::Literal("ls".into()),
            CommandPattern::Regex(re),
        ]);
        assert!(match_command_pattern(&pat, "ls"));
        assert!(match_command_pattern(&pat, "git-push"));
        assert!(!match_command_pattern(&pat, "rm"));
    }

    #[test]
    fn extract_inner_command_fallback_for_non_simple() {
        // A compound command (with &&) should hit the fallback branch
        let args = vec!["echo".to_string(), "&&".to_string(), "ls".to_string()];
        let result = extract_inner_command(
            &may_i_core::pattern::ArgPattern::Positional {
                patterns: vec![],
                continuation: None,
            },
            &args,
        );
        // Should return Some — either parsed or fallback
        assert!(result.is_some());
    }

    #[test]
    fn evaluate_fallback_reason_command_matched_but_args_failed() {
        use may_i_core::ast::{Config, Rule, Spanned};
        use may_i_core::pattern::{ArgPattern, CommandPattern, Expr, PositionalArg, Quantifier};
        use may_i_core::span::Span;

        let s = Span::new(0, 1);
        // Rule: "ls" with (positional "specific-arg") — will not match "ls other"
        let rule = Rule::new(
            Spanned::new(
                Effect::CommandPattern(CommandPattern::Literal("ls".into())),
                s,
            ),
            vec![Spanned::new(
                Effect::ArgPattern(ArgPattern::Positional {
                    patterns: vec![PositionalArg {
                        quantifier: Quantifier::One,
                        pattern: Expr::Literal("specific-arg".into()),
                        recursive: false,
                    }],
                    continuation: None,
                }),
                s,
            )],
            vec![],
            s,
        );

        let config = Config {
            rules: vec![rule],
            ..Config::default()
        };
        let facts = ContextFacts::default();
        let args = vec!["other".to_string()];
        let result = evaluate("ls", &args, &config, &facts);
        assert_eq!(result.decision, Decision::Ask);
        assert!(
            result.reason.as_ref().unwrap().contains("ls"),
            "reason should mention the command: {:?}",
            result.reason
        );
    }

    #[test]
    fn evaluate_rule_nil_short_circuits() {
        use may_i_core::ast::{Rule, Spanned};
        use may_i_core::pattern::{ArgPattern, CommandPattern, Expr};
        use may_i_core::span::Span;

        let s = Span::new(0, 1);
        // Rule with (forbidden "bad") — if arg is present, Nil is returned
        let rule = Rule::new(
            Spanned::new(
                Effect::CommandPattern(CommandPattern::Literal("test".into())),
                s,
            ),
            vec![Spanned::new(
                Effect::ArgPattern(ArgPattern::Forbidden(vec![Expr::Literal("bad".into())])),
                s,
            )],
            vec![],
            s,
        );

        let rules = vec![rule];
        let facts = ContextFacts::default();
        let args = vec!["bad".to_string()];
        let ctx = EvalContext::new("test", &args, &facts);
        let evaluator = Evaluator::new(&rules);
        let result = evaluator.evaluate(&mut PureFold, &ctx);
        // Forbidden found → Nil → rule_not_matched → falls through to ask
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn evaluate_rule_predicate_allow_continues() {
        use may_i_core::ast::{Rule, Spanned};
        use may_i_core::pattern::{ArgPattern, CommandPattern, Expr, PositionalArg, Quantifier};
        use may_i_core::span::Span;

        let s = Span::new(0, 1);
        // Rule: "cmd" (positional "ok") :allow "done"
        // The positional predicate matches, continues, then terminal fires.
        let rule = Rule::new(
            Spanned::new(
                Effect::CommandPattern(CommandPattern::Literal("cmd".into())),
                s,
            ),
            vec![
                Spanned::new(
                    Effect::ArgPattern(ArgPattern::Positional {
                        patterns: vec![PositionalArg {
                            quantifier: Quantifier::One,
                            pattern: Expr::Literal("ok".into()),
                            recursive: false,
                        }],
                        continuation: None,
                    }),
                    s,
                ),
                Spanned::new(Effect::Allow(Some("done".into())), s),
            ],
            vec![],
            s,
        );

        let rules = vec![rule];
        let facts = ContextFacts::default();
        let args = vec!["ok".to_string()];
        let ctx = EvalContext::new("cmd", &args, &facts);
        let evaluator = Evaluator::new(&rules);
        let result = evaluator.evaluate(&mut PureFold, &ctx);
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.reason.as_deref(), Some("done"));
    }

    #[test]
    fn build_positional_element_details_with_bind() {
        use may_i_core::Keyword;
        use may_i_core::pattern::{Expr, PositionalArg, Quantifier};

        let patterns = vec![PositionalArg {
            quantifier: Quantifier::One,
            pattern: Expr::Bind {
                key: Keyword::new_unchecked(String::from(":host")),
                expr: Box::new(Expr::Wildcard),
            },
            recursive: false,
        }];

        let arg = "prod-01".to_string();
        let args: Vec<&String> = vec![&arg];
        let details = build_positional_element_details(&args, &patterns, true, 1);
        assert_eq!(details.len(), 1);
        let detail = &details[0];
        assert!(detail.binding.is_some());
        let bind = detail.binding.as_ref().unwrap();
        assert_eq!(bind.key, ":host");
        assert_eq!(bind.value, Some("prod-01".to_string()));
    }

    #[test]
    fn build_positional_element_details_with_cond_branch_index() {
        use may_i_core::pattern::{Expr, ExprBranch, PositionalArg, Quantifier};

        let patterns = vec![PositionalArg {
            quantifier: Quantifier::One,
            pattern: Expr::Cond(vec![
                ExprBranch {
                    test: Expr::Literal("a".into()),
                    effect: Effect::Allow(None),
                },
                ExprBranch {
                    test: Expr::Literal("b".into()),
                    effect: Effect::Deny(None),
                },
            ]),
            recursive: false,
        }];

        let arg = "b".to_string();
        let args: Vec<&String> = vec![&arg];
        let details = build_positional_element_details(&args, &patterns, true, 1);
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].cond_branch_index, Some(1));
    }

    // --- FactPattern combinator tests ---

    #[test]
    fn match_fact_pattern_and() {
        let pat = FactPattern::And(vec![
            FactPattern::Regex(regex::Regex::new("^prod").unwrap()),
            FactPattern::Regex(regex::Regex::new("server$").unwrap()),
        ]);
        assert!(match_fact_pattern(&pat, "prod-server"));
        assert!(!match_fact_pattern(&pat, "prod-host"));
        assert!(!match_fact_pattern(&pat, "dev-server"));
    }

    #[test]
    fn match_fact_pattern_or() {
        let pat = FactPattern::Or(vec![
            FactPattern::Literal("a".to_string()),
            FactPattern::Literal("b".to_string()),
        ]);
        assert!(match_fact_pattern(&pat, "a"));
        assert!(match_fact_pattern(&pat, "b"));
        assert!(!match_fact_pattern(&pat, "c"));
    }

    #[test]
    fn match_fact_pattern_not() {
        let pat = FactPattern::Not(Box::new(FactPattern::Literal("bad".to_string())));
        assert!(!match_fact_pattern(&pat, "bad"));
        assert!(match_fact_pattern(&pat, "good"));
    }

    #[test]
    fn match_fact_pattern_nested_combinators() {
        // (and (not "exclude") (or "a" "b"))
        let pat = FactPattern::And(vec![
            FactPattern::Not(Box::new(FactPattern::Literal("exclude".to_string()))),
            FactPattern::Or(vec![
                FactPattern::Literal("a".to_string()),
                FactPattern::Literal("b".to_string()),
            ]),
        ]);
        assert!(match_fact_pattern(&pat, "a"));
        assert!(match_fact_pattern(&pat, "b"));
        assert!(!match_fact_pattern(&pat, "c"));
        assert!(!match_fact_pattern(&pat, "exclude"));
    }

    // --- Backtracking tests ---

    #[test]
    fn zero_or_more_wildcard_backtracks_for_required() {
        use may_i_core::pattern::PositionalArg;
        use may_i_core::{Expr, Quantifier};

        // (* *) "end" — wildcard * greedily consumes all, must backtrack for "end"
        let patterns = vec![
            PositionalArg {
                quantifier: Quantifier::ZeroOrMore,
                pattern: Expr::Wildcard,
                recursive: false,
            },
            PositionalArg {
                quantifier: Quantifier::One,
                pattern: Expr::Literal("end".to_string()),
                recursive: false,
            },
        ];

        let args_owned: Vec<String> = vec!["a", "b", "c", "end"]
            .into_iter()
            .map(String::from)
            .collect();
        let args: Vec<&String> = args_owned.iter().collect();
        let (matched, consumed, _) = match_positional_patterns(&args, &patterns);
        assert!(matched);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn one_or_more_wildcard_backtracks_for_required() {
        use may_i_core::pattern::PositionalArg;
        use may_i_core::{Expr, Quantifier};

        // (+ *) "end" — must consume at least 1, then backtrack for "end"
        let patterns = vec![
            PositionalArg {
                quantifier: Quantifier::OneOrMore,
                pattern: Expr::Wildcard,
                recursive: false,
            },
            PositionalArg {
                quantifier: Quantifier::One,
                pattern: Expr::Literal("end".to_string()),
                recursive: false,
            },
        ];

        let args_owned: Vec<String> = vec!["x", "y", "end"]
            .into_iter()
            .map(String::from)
            .collect();
        let args: Vec<&String> = args_owned.iter().collect();
        let (matched, consumed, _) = match_positional_patterns(&args, &patterns);
        assert!(matched);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn one_or_more_wildcard_fails_when_only_required() {
        use may_i_core::pattern::PositionalArg;
        use may_i_core::{Expr, Quantifier};

        // (+ *) "end" with args ["end"] — can't consume 1+ AND have "end" left
        let patterns = vec![
            PositionalArg {
                quantifier: Quantifier::OneOrMore,
                pattern: Expr::Wildcard,
                recursive: false,
            },
            PositionalArg {
                quantifier: Quantifier::One,
                pattern: Expr::Literal("end".to_string()),
                recursive: false,
            },
        ];

        let args_owned = vec!["end".to_string()];
        let args: Vec<&String> = args_owned.iter().collect();
        let (matched, _, _) = match_positional_patterns(&args, &patterns);
        assert!(!matched);
    }

    // --- check.rs coverage: compound commands and run_checks ---

    #[test]
    fn evaluate_empty_command() {
        let config = may_i_core::ast::Config::default();
        let facts = ContextFacts::default();
        let result = crate::check::run_checks(&config);
        assert!(result.is_empty());

        // Also: assignment-only commands should be allowed
        let result = crate::eval::evaluate("", &[], &config, &facts);
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn run_checks_with_rule_level_checks() {
        use may_i_core::ast::{Check, Config, Rule, Spanned};
        use may_i_core::pattern::CommandPattern;
        use may_i_core::span::Span;

        let s = Span::new(0, 1);
        let rule = Rule {
            command_effect: Spanned::new(
                Effect::CommandPattern(CommandPattern::Literal("ls".into())),
                s,
            ),
            effects: vec![Spanned::new(Effect::Allow(Some("ok".into())), s)],
            checks: vec![Check {
                command: "ls -la".into(),
                expected: Decision::Allow,
                context: ContextFacts::default(),
                span: s,
            }],
            span: s,
        };

        let config = Config {
            rules: vec![rule],
            ..Config::default()
        };

        let results = crate::check::run_checks(&config);
        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
    }

    #[test]
    fn run_checks_with_config_level_checks() {
        use may_i_core::ast::{Check, Config, Rule, Spanned};
        use may_i_core::pattern::CommandPattern;
        use may_i_core::span::Span;

        let s = Span::new(0, 1);
        let rule = Rule {
            command_effect: Spanned::new(
                Effect::CommandPattern(CommandPattern::Literal("git".into())),
                s,
            ),
            effects: vec![Spanned::new(Effect::Deny(Some("no git".into())), s)],
            checks: vec![],
            span: s,
        };

        let config = Config {
            rules: vec![rule],
            checks: vec![Check {
                command: "git push".into(),
                expected: Decision::Deny,
                context: ContextFacts::default(),
                span: s,
            }],
            ..Config::default()
        };

        let results = crate::check::run_checks(&config);
        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
        assert_eq!(results[0].actual, Decision::Deny);
    }
}
