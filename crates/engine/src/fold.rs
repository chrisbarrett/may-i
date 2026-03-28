// Fold trait for parameterising the evaluator over its output type.
//
// The evaluator drives traversal and short-circuiting; the fold observes each
// step and produces output alongside the evaluation result. This enables a
// zygomorphism where evaluation and annotation compose in a single pass.

use may_i_core::ast::{Effect, EffectResult, Rule};
use may_i_core::pattern::{ArgPattern, CommandPattern};
use may_i_core::{ContextFacts, Decision, FactQuery};

use crate::eval::PredicateResult;

/// Distinguishes evaluated vs short-circuited children.
#[derive(Debug, Clone)]
pub enum ChildResult<T> {
    Evaluated(T),
    Skipped,
}

/// Detail about how an argument pattern matched (for annotations).
#[derive(Debug, Clone)]
pub struct ArgMatchDetail {
    /// The tokens searched for.
    pub search_tokens: Vec<String>,
    /// The full argument set.
    pub arg_set: Vec<String>,
    /// Whether the overall match succeeded.
    pub matched: bool,
}

/// Detail about how a fact query resolved (for annotations).
#[derive(Debug, Clone)]
pub struct FactDetail {
    /// The observed values (if any).
    pub observed: Option<Vec<String>>,
    /// Why the query failed (if it did).
    pub failure_reason: Option<String>,
}

/// Trait that parameterises the evaluator over its output type.
///
/// The engine extracts decisions via projection methods for control flow
/// (short-circuiting, branching). Each fold method receives the evaluation
/// detail and produces the fold's output type.
pub trait EvalFold {
    type EffectOut;
    type PredicateOut;

    // -- Projection: engine extracts decisions for control flow --

    fn effect_result(out: &Self::EffectOut) -> &EffectResult;
    fn predicate_result(out: &Self::PredicateOut) -> PredicateResult;

    // -- Effect algebra --

    fn effect_terminal(&mut self, effect: &Effect, result: EffectResult) -> Self::EffectOut;
    fn effect_nil(&mut self, effect: &Effect) -> Self::EffectOut;
    fn effect_command_match(
        &mut self,
        pattern: &CommandPattern,
        cmd: &str,
        matched: bool,
    ) -> Self::EffectOut;
    fn effect_arg_match(
        &mut self,
        pattern: &ArgPattern,
        args: &[String],
        matched: bool,
        detail: ArgMatchDetail,
    ) -> Self::EffectOut;
    fn effect_and(
        &mut self,
        children: Vec<ChildResult<Self::EffectOut>>,
        result: EffectResult,
    ) -> Self::EffectOut;
    fn effect_or(
        &mut self,
        children: Vec<ChildResult<Self::EffectOut>>,
        result: EffectResult,
    ) -> Self::EffectOut;
    fn effect_not(&mut self, child: Self::EffectOut, result: EffectResult) -> Self::EffectOut;
    fn effect_when(
        &mut self,
        pred: Self::PredicateOut,
        body: ChildResult<Self::EffectOut>,
        result: EffectResult,
    ) -> Self::EffectOut;
    fn effect_unless(
        &mut self,
        pred: Self::PredicateOut,
        body: ChildResult<Self::EffectOut>,
        result: EffectResult,
    ) -> Self::EffectOut;
    fn effect_if(
        &mut self,
        pred: Self::PredicateOut,
        then_: ChildResult<Self::EffectOut>,
        else_: ChildResult<Self::EffectOut>,
        result: EffectResult,
    ) -> Self::EffectOut;
    fn effect_cond(
        &mut self,
        branches: Vec<(Self::PredicateOut, ChildResult<Self::EffectOut>)>,
        fallback: Option<ChildResult<Self::EffectOut>>,
        result: EffectResult,
    ) -> Self::EffectOut;
    fn effect_may_i(
        &mut self,
        inner_cmd: &str,
        inner_args: &[String],
        inner_result: EffectResult,
        inner_out: Self::EffectOut,
    ) -> Self::EffectOut;
    fn effect_may_i_no_match(&mut self, pattern: &ArgPattern) -> Self::EffectOut;

    // -- Predicate algebra --

    fn predicate_fact(
        &mut self,
        query: &FactQuery,
        result: PredicateResult,
        detail: FactDetail,
    ) -> Self::PredicateOut;
    fn predicate_arg(
        &mut self,
        pattern: &ArgPattern,
        args: &[String],
        result: PredicateResult,
    ) -> Self::PredicateOut;
    fn predicate_and(
        &mut self,
        children: Vec<ChildResult<Self::PredicateOut>>,
        result: PredicateResult,
    ) -> Self::PredicateOut;
    fn predicate_or(
        &mut self,
        children: Vec<ChildResult<Self::PredicateOut>>,
        result: PredicateResult,
    ) -> Self::PredicateOut;
    fn predicate_not(
        &mut self,
        child: Self::PredicateOut,
        result: PredicateResult,
    ) -> Self::PredicateOut;
    fn predicate_named(
        &mut self,
        name: &str,
        resolved: Self::PredicateOut,
        result: PredicateResult,
    ) -> Self::PredicateOut;

    // -- Rule-level --

    fn rule_matched(
        &mut self,
        rule: &Rule,
        line: Option<usize>,
        out: Self::EffectOut,
    ) -> Self::EffectOut;
    fn rule_skipped(&mut self, rule: &Rule) -> Self::EffectOut;
    fn default_ask(&mut self, reason: &str) -> Self::EffectOut;
}

/// Zero-overhead fold that simply returns evaluation results unchanged.
pub struct PureFold;

impl EvalFold for PureFold {
    type EffectOut = EffectResult;
    type PredicateOut = PredicateResult;

    fn effect_result(out: &EffectResult) -> &EffectResult {
        out
    }

    fn predicate_result(out: &PredicateResult) -> PredicateResult {
        *out
    }

    fn effect_terminal(&mut self, _effect: &Effect, result: EffectResult) -> EffectResult {
        result
    }

    fn effect_nil(&mut self, _effect: &Effect) -> EffectResult {
        EffectResult::Nil
    }

    fn effect_command_match(
        &mut self,
        _pattern: &CommandPattern,
        _cmd: &str,
        matched: bool,
    ) -> EffectResult {
        if matched {
            EffectResult::Decision(Decision::Allow, None)
        } else {
            EffectResult::Nil
        }
    }

    fn effect_arg_match(
        &mut self,
        _pattern: &ArgPattern,
        _args: &[String],
        matched: bool,
        _detail: ArgMatchDetail,
    ) -> EffectResult {
        if matched {
            EffectResult::Decision(Decision::Allow, None)
        } else {
            EffectResult::Nil
        }
    }

    fn effect_and(
        &mut self,
        _children: Vec<ChildResult<EffectResult>>,
        result: EffectResult,
    ) -> EffectResult {
        result
    }

    fn effect_or(
        &mut self,
        _children: Vec<ChildResult<EffectResult>>,
        result: EffectResult,
    ) -> EffectResult {
        result
    }

    fn effect_not(&mut self, _child: EffectResult, result: EffectResult) -> EffectResult {
        result
    }

    fn effect_when(
        &mut self,
        _pred: PredicateResult,
        _body: ChildResult<EffectResult>,
        result: EffectResult,
    ) -> EffectResult {
        result
    }

    fn effect_unless(
        &mut self,
        _pred: PredicateResult,
        _body: ChildResult<EffectResult>,
        result: EffectResult,
    ) -> EffectResult {
        result
    }

    fn effect_if(
        &mut self,
        _pred: PredicateResult,
        _then: ChildResult<EffectResult>,
        _else: ChildResult<EffectResult>,
        result: EffectResult,
    ) -> EffectResult {
        result
    }

    fn effect_cond(
        &mut self,
        _branches: Vec<(PredicateResult, ChildResult<EffectResult>)>,
        _fallback: Option<ChildResult<EffectResult>>,
        result: EffectResult,
    ) -> EffectResult {
        result
    }

    fn effect_may_i(
        &mut self,
        _inner_cmd: &str,
        _inner_args: &[String],
        _inner_result: EffectResult,
        inner_out: EffectResult,
    ) -> EffectResult {
        inner_out
    }

    fn effect_may_i_no_match(&mut self, _pattern: &ArgPattern) -> EffectResult {
        EffectResult::Nil
    }

    fn predicate_fact(
        &mut self,
        _query: &FactQuery,
        result: PredicateResult,
        _detail: FactDetail,
    ) -> PredicateResult {
        result
    }

    fn predicate_arg(
        &mut self,
        _pattern: &ArgPattern,
        _args: &[String],
        result: PredicateResult,
    ) -> PredicateResult {
        result
    }

    fn predicate_and(
        &mut self,
        _children: Vec<ChildResult<PredicateResult>>,
        result: PredicateResult,
    ) -> PredicateResult {
        result
    }

    fn predicate_or(
        &mut self,
        _children: Vec<ChildResult<PredicateResult>>,
        result: PredicateResult,
    ) -> PredicateResult {
        result
    }

    fn predicate_not(
        &mut self,
        _child: PredicateResult,
        result: PredicateResult,
    ) -> PredicateResult {
        result
    }

    fn predicate_named(
        &mut self,
        _name: &str,
        _resolved: PredicateResult,
        result: PredicateResult,
    ) -> PredicateResult {
        result
    }

    fn rule_matched(
        &mut self,
        _rule: &Rule,
        _line: Option<usize>,
        out: EffectResult,
    ) -> EffectResult {
        out
    }

    fn rule_skipped(&mut self, _rule: &Rule) -> EffectResult {
        EffectResult::Nil
    }

    fn default_ask(&mut self, reason: &str) -> EffectResult {
        EffectResult::Decision(Decision::Ask, Some(reason.to_string()))
    }
}

/// Build a FactDetail for a fact query against the given context.
pub fn build_fact_detail(query: &FactQuery, facts: &ContextFacts) -> FactDetail {
    match query {
        FactQuery::Presence { key, .. } => {
            if facts.has(key) {
                FactDetail {
                    observed: Some(
                        facts
                            .get(key)
                            .map(|s| s.iter().cloned().collect())
                            .unwrap_or_default(),
                    ),
                    failure_reason: None,
                }
            } else {
                FactDetail {
                    observed: None,
                    failure_reason: Some("absent".to_string()),
                }
            }
        }
        FactQuery::Value { key, .. } => {
            if let Some(set) = facts.get(key) {
                let values: Vec<String> = set.iter().cloned().collect();
                FactDetail {
                    observed: Some(values),
                    failure_reason: None,
                }
            } else {
                FactDetail {
                    observed: None,
                    failure_reason: Some("absent".to_string()),
                }
            }
        }
    }
}
