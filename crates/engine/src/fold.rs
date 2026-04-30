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
    /// Per-element match details for positional/exact patterns (bindings, regex, etc.).
    pub positional_elements: Vec<PositionalElementDetail>,
}

impl ArgMatchDetail {
    pub fn new(
        arg_set: Vec<String>,
        matched: bool,
        positional_elements: Vec<PositionalElementDetail>,
    ) -> Self {
        Self {
            search_tokens: vec![],
            arg_set,
            matched,
            positional_elements,
        }
    }
}

/// Detail about a single positional pattern element's match result.
#[derive(Debug, Clone)]
pub struct PositionalElementDetail {
    /// Index of this pattern in the positional pattern list.
    pub pattern_index: usize,
    /// The arg values consumed by this pattern element.
    pub consumed_args: Vec<String>,
    /// If this was a Bind expression, the key and bound value.
    pub binding: Option<BindDetail>,
    /// Kind-specific match detail (expr match, cond branch, or none).
    pub match_kind: PositionalMatchKind,
    /// Whether this element matched.
    pub matched: bool,
}

/// What kind of match detail a positional element carries.
#[derive(Debug, Clone)]
pub enum PositionalMatchKind {
    /// No additional match detail.
    None,
    /// An expression match (literal, regex, or wildcard).
    Expr(ExprMatchDetail),
    /// A cond branch matched; stores the index of the matching branch.
    CondBranch(usize),
}

/// Detail about a fact binding from a positional Bind expression.
#[derive(Debug, Clone)]
pub struct BindDetail {
    /// The fact key (e.g. ":ssh/host").
    pub key: may_i_core::Keyword,
    /// The value that was bound (if matched).
    pub value: Option<String>,
    /// Inner expression match detail (for regex/literal binds).
    pub inner_match: Option<ExprMatchDetail>,
}

/// Detail about how an expression matched a value.
#[derive(Debug, Clone)]
pub enum ExprMatchDetail {
    /// Literal equality check.
    Literal {
        expected: String,
        actual: String,
        matched: bool,
    },
    /// Regex match.
    Regex {
        pattern: String,
        actual: String,
        matched: bool,
    },
    /// Wildcard (always matches).
    Wildcard { actual: String },
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
        body_effect: &Effect,
        result: EffectResult,
    ) -> Self::EffectOut;
    fn effect_unless(
        &mut self,
        pred: Self::PredicateOut,
        body: ChildResult<Self::EffectOut>,
        body_effect: &Effect,
        result: EffectResult,
    ) -> Self::EffectOut;
    fn effect_if(
        &mut self,
        pred: Self::PredicateOut,
        then_: ChildResult<Self::EffectOut>,
        else_: ChildResult<Self::EffectOut>,
        result: EffectResult,
    ) -> Self::EffectOut;
    #[allow(clippy::type_complexity)]
    fn effect_cond(
        &mut self,
        branches: Vec<(
            ChildResult<Self::PredicateOut>,
            ChildResult<Self::EffectOut>,
        )>,
        fallback: Option<ChildResult<Self::EffectOut>>,
        result: EffectResult,
    ) -> Self::EffectOut;
    fn effect_arg_continuation(
        &mut self,
        pattern: &ArgPattern,
        args: &[String],
        detail: ArgMatchDetail,
        continuation: Self::EffectOut,
    ) -> Self::EffectOut;
    /// Called before a recursive may-i evaluation begins.
    /// TracingFold uses this to track where inner traces start.
    fn begin_recursive_eval(&mut self) {}
    /// Called once per evaluation entry with the resolved tokenisation
    /// convention. Default: no-op.
    fn record_convention(&mut self, _command: &str, _convention: &may_i_core::ast::Convention) {}
    fn effect_may_i(
        &mut self,
        pattern: &ArgPattern,
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
        facts: &ContextFacts,
        command_out: Self::EffectOut,
        effect_out: Self::EffectOut,
    ) -> Self::EffectOut;
    /// Command matched but the body effect returned Nil.
    fn rule_not_matched(
        &mut self,
        rule: &Rule,
        facts: &ContextFacts,
        command_out: Self::EffectOut,
        effect_out: Self::EffectOut,
    ) -> Self::EffectOut;
    fn rule_skipped(&mut self, rule: &Rule) -> Self::EffectOut;
    fn default_ask(&mut self, reason: &str) -> Self::EffectOut;

    /// Called when an embedded command (substitution) has been evaluated.
    /// Default implementation is a no-op.
    fn embedded_command(&mut self, _source: &str, _decision: Decision) {}
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
        _body_effect: &Effect,
        result: EffectResult,
    ) -> EffectResult {
        result
    }

    fn effect_unless(
        &mut self,
        _pred: PredicateResult,
        _body: ChildResult<EffectResult>,
        _body_effect: &Effect,
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
        _branches: Vec<(ChildResult<PredicateResult>, ChildResult<EffectResult>)>,
        _fallback: Option<ChildResult<EffectResult>>,
        result: EffectResult,
    ) -> EffectResult {
        result
    }

    fn effect_arg_continuation(
        &mut self,
        _pattern: &ArgPattern,
        _args: &[String],
        _detail: ArgMatchDetail,
        continuation: EffectResult,
    ) -> EffectResult {
        continuation
    }

    fn effect_may_i(
        &mut self,
        _pattern: &ArgPattern,
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
        _facts: &ContextFacts,
        _command_out: EffectResult,
        effect_out: EffectResult,
    ) -> EffectResult {
        effect_out
    }

    fn rule_not_matched(
        &mut self,
        _rule: &Rule,
        _facts: &ContextFacts,
        _command_out: EffectResult,
        _effect_out: EffectResult,
    ) -> EffectResult {
        EffectResult::Nil
    }

    fn rule_skipped(&mut self, _rule: &Rule) -> EffectResult {
        EffectResult::Nil
    }

    fn default_ask(&mut self, reason: &str) -> EffectResult {
        EffectResult::Decision(Decision::Ask, Some(reason.to_string()))
    }
}

/// Build a FactDetail for a fact query against the given context.
pub(crate) fn build_fact_detail(query: &FactQuery, facts: &ContextFacts) -> FactDetail {
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
