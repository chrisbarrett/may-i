// Rule engine — evaluates against unified rule DSL with recursive evaluation

pub mod audit_fold;
pub mod check;
pub mod eval;
pub mod fold;
pub mod shape;
pub mod shape_check;
pub mod trust;

#[cfg(any(test, feature = "test-generators"))]
pub mod test_generators;

use may_i_core::Decision;

/// A per-unit decision with the byte range of that unit in the original input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentDecision {
    pub start: usize,
    pub end: usize,
    pub decision: Decision,
}

/// Error type for evaluation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvalError {
    /// A named predicate was not resolved before evaluation.
    UnresolvedPredicate { name: String },
}

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvalError::UnresolvedPredicate { name } => {
                write!(f, "unresolved predicate: '{name}'")
            }
        }
    }
}

impl std::error::Error for EvalError {}

/// Result of evaluating a command.
#[derive(Debug, Clone)]
pub struct EvalResult {
    pub decision: Decision,
    pub reason: Option<String>,
    pub parse_diagnostics: Vec<may_i_shell_parser::ParseDiagnostic>,
    /// Per-unit decisions with byte ranges in the original input. Top-level
    /// entries are pairwise non-overlapping; embedded-command entries may be
    /// fully contained within their enclosing entry's range.
    pub segment_decisions: Vec<SegmentDecision>,
}

impl EvalResult {
    /// Create a new EvalResult with the given decision and optional reason.
    #[must_use]
    pub fn new(decision: Decision, reason: Option<String>) -> Self {
        Self {
            decision,
            reason,
            parse_diagnostics: Vec::new(),
            segment_decisions: Vec::new(),
        }
    }
}

// Re-export canonical evaluator items
pub use audit_fold::{AuditFold, ComposedFold};
pub use eval::{
    EvalContext, Evaluator, PredicateResult, evaluate, evaluate_command, evaluate_command_with_fold,
};
pub use fold::{ChildResult, EvalFold, PureFold};
