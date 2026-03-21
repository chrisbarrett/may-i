// Trace generation for v2 unified rule DSL evaluator.
//
// This module provides trace generation for the v2 evaluator, capturing
// evaluation steps in a hierarchical structure that mirrors the unified
// predicate and effect syntax.

use may_i_core::types::{Decision, EvalResult};
use may_i_core::v2::ast::{Effect, Rule};
use may_i_core::v2::pattern::ArgPattern;
use may_i_core::v2::predicate::Predicate;

/// A trace entry representing one step in the evaluation process.
#[derive(Debug, Clone)]
pub enum TraceEntry {
    /// Evaluation of a rule: includes the rule and the result
    RuleEvaluation {
        /// The rule that was evaluated
        rule: Box<Rule>,
        /// Whether the rule matched
        matched: bool,
        /// The effect produced (if matched)
        effect: Option<Effect>,
        /// Nested trace entries for predicates
        predicate_traces: Vec<PredicateTrace>,
        /// Trace of effect evaluation (if rule matched)
        effect_trace: Option<Box<EffectTrace>>,
    },

    /// A terminal decision was reached
    Decision {
        decision: Decision,
        reason: Option<String>,
    },

    /// Recursive evaluation of an inner command
    RecursiveEvaluation {
        /// The inner command being evaluated
        command: String,
        /// Arguments to the inner command
        args: Vec<String>,
        /// The recursion depth
        depth: usize,
        /// Result of the recursive evaluation
        result: EvalResult,
        /// Nested trace entries
        nested: Vec<TraceEntry>,
    },

    /// Depth limit was exceeded
    DepthLimitExceeded { limit: usize },

    /// No rules matched, returning default ask
    DefaultAsk { reason: String },
}

/// Trace of an effect evaluation.
#[derive(Debug, Clone)]
pub enum EffectTrace {
    /// Terminal effect: Allow, Ask, or Deny
    Terminal {
        effect: Effect,
        decision: Decision,
        reason: Option<String>,
    },

    /// Recursive evaluation via (may-i ...)
    Recursive {
        pattern: ArgPattern,
        command: String,
        args: Vec<String>,
        depth: usize,
        result: EvalResult,
        nested: Vec<TraceEntry>,
    },

    /// Case expression evaluation
    Case {
        branches: Vec<(Predicate, PredicateResult, Box<EffectTrace>)>,
        fallback: Option<Box<EffectTrace>>,
        decision: Decision,
        reason: Option<String>,
    },

    /// When expression evaluation
    When {
        predicate: Predicate,
        predicate_result: PredicateResult,
        effect: Box<EffectTrace>,
        decision: Decision,
        reason: Option<String>,
    },

    /// Unless expression evaluation
    Unless {
        predicate: Predicate,
        predicate_result: PredicateResult,
        effect: Box<EffectTrace>,
        decision: Decision,
        reason: Option<String>,
    },

    /// If expression evaluation
    If {
        predicate: Predicate,
        predicate_result: PredicateResult,
        then_effect: Box<EffectTrace>,
        else_effect: Option<Box<EffectTrace>>,
        decision: Decision,
        reason: Option<String>,
    },
}

/// Trace of a predicate evaluation.
#[derive(Debug, Clone)]
pub struct PredicateTrace {
    /// The predicate that was evaluated
    pub predicate: Predicate,
    /// The result of evaluation
    pub result: PredicateResult,
    /// Nested traces for compound predicates
    pub children: Vec<PredicateTrace>,
}

/// Result of predicate evaluation for tracing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateResult {
    Match,
    NoMatch,
}

impl PredicateTrace {
    /// Create a new predicate trace.
    pub fn new(predicate: Predicate, result: PredicateResult) -> Self {
        Self {
            predicate,
            result,
            children: Vec::new(),
        }
    }

    /// Create a trace with children.
    pub fn with_children(
        predicate: Predicate,
        result: PredicateResult,
        children: Vec<PredicateTrace>,
    ) -> Self {
        Self {
            predicate,
            result,
            children,
        }
    }
}

/// Builder for collecting trace entries during evaluation.
#[derive(Debug, Clone, Default)]
pub struct TraceBuilder {
    entries: Vec<TraceEntry>,
}

impl TraceBuilder {
    /// Create a new trace builder.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a trace entry.
    pub fn add(&mut self, entry: TraceEntry) {
        self.entries.push(entry);
    }

    /// Add a rule evaluation entry.
    pub fn add_rule_evaluation(
        &mut self,
        rule: Rule,
        matched: bool,
        effect: Option<Effect>,
        predicate_traces: Vec<PredicateTrace>,
        effect_trace: Option<Box<EffectTrace>>,
    ) {
        self.entries.push(TraceEntry::RuleEvaluation {
            rule: Box::new(rule),
            matched,
            effect,
            predicate_traces,
            effect_trace,
        });
    }

    /// Add a decision entry.
    pub fn add_decision(&mut self, decision: Decision, reason: Option<String>) {
        self.entries.push(TraceEntry::Decision { decision, reason });
    }

    /// Add a recursive evaluation entry.
    pub fn add_recursive_evaluation(
        &mut self,
        command: String,
        args: Vec<String>,
        depth: usize,
        result: EvalResult,
        nested: Vec<TraceEntry>,
    ) {
        self.entries.push(TraceEntry::RecursiveEvaluation {
            command,
            args,
            depth,
            result,
            nested,
        });
    }

    /// Add a depth limit exceeded entry.
    pub fn add_depth_limit_exceeded(&mut self, limit: usize) {
        self.entries.push(TraceEntry::DepthLimitExceeded { limit });
    }

    /// Add a default ask entry.
    pub fn add_default_ask(&mut self, reason: impl Into<String>) {
        self.entries.push(TraceEntry::DefaultAsk {
            reason: reason.into(),
        });
    }

    /// Build and return the collected trace entries.
    pub fn build(self) -> Vec<TraceEntry> {
        self.entries
    }

    /// Get the current entries (for inspection).
    pub fn entries(&self) -> &[TraceEntry] {
        &self.entries
    }

    /// Check if the trace is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Convert internal predicate result to trace predicate result.
pub fn to_trace_result(result: super::eval::PredicateResult) -> PredicateResult {
    match result {
        super::eval::PredicateResult::Match => PredicateResult::Match,
        super::eval::PredicateResult::NoMatch => PredicateResult::NoMatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_builder_collects_entries() {
        let mut builder = TraceBuilder::new();
        builder.add_decision(Decision::Allow, Some("test".to_string()));
        builder.add_default_ask("no match");

        let trace = builder.build();
        assert_eq!(trace.len(), 2);
    }

    #[test]
    fn predicate_trace_with_children() {
        let child = PredicateTrace::new(Predicate::has_presence(":test"), PredicateResult::Match);
        let parent = PredicateTrace::with_children(
            Predicate::And(vec![]),
            PredicateResult::Match,
            vec![child],
        );

        assert_eq!(parent.children.len(), 1);
        assert_eq!(parent.result, PredicateResult::Match);
    }
}
