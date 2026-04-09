// Rule engine — evaluates against unified rule DSL with recursive evaluation

pub mod check;
pub mod eval;
pub mod fold;

#[cfg(any(test, feature = "test-generators"))]
pub mod test_generators;

use may_i_core::Decision;

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
}

impl EvalResult {
    /// Create a new EvalResult with the given decision and optional reason.
    pub fn new(decision: Decision, reason: Option<String>) -> Self {
        Self { decision, reason }
    }
}

// Re-export canonical evaluator items
pub use eval::{EvalContext, Evaluator, PredicateResult, evaluate};
pub use fold::{ChildResult, EvalFold, PureFold};
