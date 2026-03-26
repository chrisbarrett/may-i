// Evaluator module for unified rule DSL.

pub mod eval;
pub mod trace;

#[cfg(test)]
mod integration_tests;

pub use eval::{
    evaluate, evaluate_predicate, EvalContext, Evaluator, PredicateResult, DEFAULT_RECURSION_LIMIT,
};
pub use trace::{
    PredicateResult as TracePredicateResult, PredicateTrace, TraceBuilder, TraceEntry,
};
