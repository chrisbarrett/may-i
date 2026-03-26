// Trace generation for the unified rule DSL evaluator.
//
// This module provides trace generation for the evaluator, capturing
// evaluation steps in a hierarchical structure that mirrors the unified
// predicate and effect syntax.

use may_i_core::ast::{Effect, Predicate, Rule};
use may_i_core::pattern::ArgPattern;
use may_i_core::types::{Decision, EvalResult};

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

    /// And expression evaluation - all effects must succeed
    And {
        effects: Vec<EffectTrace>,
        decision: Decision,
        reason: Option<String>,
    },

    /// Or expression evaluation - at least one effect must succeed
    Or {
        effects: Vec<EffectTrace>,
        decision: Decision,
        reason: Option<String>,
    },

    /// Not expression evaluation - negates an effect's decision
    Not {
        effect: Box<EffectTrace>,
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
        let child = PredicateTrace::new(Predicate::fact_presence(":test"), PredicateResult::Match);
        let parent = PredicateTrace::with_children(
            Predicate::And(vec![]),
            PredicateResult::Match,
            vec![child],
        );

        assert_eq!(parent.children.len(), 1);
        assert_eq!(parent.result, PredicateResult::Match);
    }

    #[test]
    fn trace_builder_add_recursive_evaluation() {
        let mut builder = TraceBuilder::new();
        let result = EvalResult::new(Decision::Allow, Some("allowed".into()));
        builder.add_recursive_evaluation("echo".into(), vec!["hello".into()], 1, result, vec![]);

        let trace = builder.build();
        assert_eq!(trace.len(), 1);
        match &trace[0] {
            TraceEntry::RecursiveEvaluation {
                command,
                args,
                depth,
                ..
            } => {
                assert_eq!(command, "echo");
                assert_eq!(args, &["hello"]);
                assert_eq!(*depth, 1);
            }
            _ => panic!("Expected RecursiveEvaluation"),
        }
    }

    #[test]
    fn trace_builder_add_depth_limit_exceeded() {
        let mut builder = TraceBuilder::new();
        builder.add_depth_limit_exceeded(10);

        let trace = builder.build();
        assert_eq!(trace.len(), 1);
        match &trace[0] {
            TraceEntry::DepthLimitExceeded { limit } => {
                assert_eq!(*limit, 10);
            }
            _ => panic!("Expected DepthLimitExceeded"),
        }
    }

    #[test]
    fn trace_builder_inspection_methods() {
        let mut builder = TraceBuilder::new();
        assert!(builder.is_empty());

        builder.add_decision(Decision::Allow, None);
        assert!(!builder.is_empty());
        assert_eq!(builder.entries().len(), 1);
    }

    #[test]
    fn effect_trace_terminal() {
        let trace = EffectTrace::Terminal {
            effect: Effect::Allow(None),
            decision: Decision::Allow,
            reason: Some("test".into()),
        };

        match trace {
            EffectTrace::Terminal {
                effect,
                decision,
                reason,
            } => {
                assert!(matches!(effect, Effect::Allow(None)));
                assert_eq!(decision, Decision::Allow);
                assert_eq!(reason, Some("test".into()));
            }
            _ => panic!("Expected Terminal"),
        }
    }

    #[test]
    fn effect_trace_recursive() {
        let result = EvalResult::new(Decision::Deny, Some("denied".into()));
        let trace = EffectTrace::Recursive {
            pattern: ArgPattern::exact(vec![]),
            command: "ls".into(),
            args: vec!["-la".into()],
            depth: 2,
            result,
            nested: vec![],
        };

        match trace {
            EffectTrace::Recursive {
                command,
                args,
                depth,
                ..
            } => {
                assert_eq!(command, "ls");
                assert_eq!(args, &["-la"]);
                assert_eq!(depth, 2);
            }
            _ => panic!("Expected Recursive"),
        }
    }

    #[test]
    fn effect_trace_case() {
        let trace = EffectTrace::Case {
            branches: vec![],
            fallback: None,
            decision: Decision::Ask,
            reason: Some("asked".into()),
        };

        match trace {
            EffectTrace::Case {
                decision, reason, ..
            } => {
                assert_eq!(decision, Decision::Ask);
                assert_eq!(reason, Some("asked".into()));
            }
            _ => panic!("Expected Case"),
        }
    }

    #[test]
    fn effect_trace_when() {
        let trace = EffectTrace::When {
            predicate: Predicate::fact_presence(":test"),
            predicate_result: PredicateResult::Match,
            effect: Box::new(EffectTrace::Terminal {
                effect: Effect::Allow(None),
                decision: Decision::Allow,
                reason: None,
            }),
            decision: Decision::Allow,
            reason: None,
        };

        match trace {
            EffectTrace::When {
                predicate_result,
                decision,
                ..
            } => {
                assert_eq!(predicate_result, PredicateResult::Match);
                assert_eq!(decision, Decision::Allow);
            }
            _ => panic!("Expected When"),
        }
    }

    #[test]
    fn effect_trace_unless() {
        let trace = EffectTrace::Unless {
            predicate: Predicate::fact_presence(":test"),
            predicate_result: PredicateResult::NoMatch,
            effect: Box::new(EffectTrace::Terminal {
                effect: Effect::Deny(Some("test".into())),
                decision: Decision::Deny,
                reason: Some("denied".into()),
            }),
            decision: Decision::Deny,
            reason: Some("denied".into()),
        };

        match trace {
            EffectTrace::Unless {
                predicate_result,
                decision,
                ..
            } => {
                assert_eq!(predicate_result, PredicateResult::NoMatch);
                assert_eq!(decision, Decision::Deny);
            }
            _ => panic!("Expected Unless"),
        }
    }

    #[test]
    fn effect_trace_if() {
        let trace = EffectTrace::If {
            predicate: Predicate::fact_presence(":test"),
            predicate_result: PredicateResult::Match,
            then_effect: Box::new(EffectTrace::Terminal {
                effect: Effect::Allow(None),
                decision: Decision::Allow,
                reason: None,
            }),
            else_effect: Some(Box::new(EffectTrace::Terminal {
                effect: Effect::Deny(Some("else".into())),
                decision: Decision::Deny,
                reason: Some("else".into()),
            })),
            decision: Decision::Allow,
            reason: None,
        };

        match trace {
            EffectTrace::If {
                predicate_result,
                else_effect,
                decision,
                ..
            } => {
                assert_eq!(predicate_result, PredicateResult::Match);
                assert!(else_effect.is_some());
                assert_eq!(decision, Decision::Allow);
            }
            _ => panic!("Expected If"),
        }
    }

    #[test]
    fn trace_entry_decision() {
        let entry = TraceEntry::Decision {
            decision: Decision::Deny,
            reason: Some("reason".into()),
        };

        match entry {
            TraceEntry::Decision { decision, reason } => {
                assert_eq!(decision, Decision::Deny);
                assert_eq!(reason, Some("reason".into()));
            }
            _ => panic!("Expected Decision"),
        }
    }

    #[test]
    fn trace_entry_default_ask() {
        let entry = TraceEntry::DefaultAsk {
            reason: "no rules matched".into(),
        };

        match entry {
            TraceEntry::DefaultAsk { reason } => {
                assert_eq!(reason, "no rules matched");
            }
            _ => panic!("Expected DefaultAsk"),
        }
    }

    #[test]
    fn to_trace_result_converts_match() {
        let result = to_trace_result(crate::eval::PredicateResult::Match);
        assert_eq!(result, PredicateResult::Match);
    }

    #[test]
    fn to_trace_result_converts_no_match() {
        let result = to_trace_result(crate::eval::PredicateResult::NoMatch);
        assert_eq!(result, PredicateResult::NoMatch);
    }
}
