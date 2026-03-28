// Rule engine — evaluates against unified rule DSL with recursive evaluation

pub(crate) mod check;
pub mod eval;
pub mod fold;

#[cfg(test)]
mod test_generators;

use may_i_core::Decision;

pub use check::{CheckResult, run_checks};

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
pub use eval::{DEFAULT_RECURSION_LIMIT, EvalContext, Evaluator, PredicateResult, evaluate};
pub use fold::{ChildResult, EvalFold, PureFold};

/// Aggregate multiple results: most restrictive decision wins.
pub fn aggregate_results(results: Vec<EvalResult>) -> EvalResult {
    debug_assert!(
        !results.is_empty(),
        "aggregate_results called with empty vec"
    );
    results
        .into_iter()
        .max_by_key(|r| r.decision)
        .unwrap_or_else(|| EvalResult::new(Decision::Allow, None))
}

#[cfg(test)]
mod lib_tests {
    use super::*;

    #[test]
    fn test_aggregate_results_single() {
        let results = vec![EvalResult::new(Decision::Allow, None)];
        let result = aggregate_results(results);
        assert_eq!(result.decision, Decision::Allow);
    }
}
