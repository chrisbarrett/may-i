// v2 evaluator module for unified rule DSL.

pub mod eval;
pub mod trace;

#[cfg(test)]
mod integration_tests;

pub use eval::{
    DEFAULT_RECURSION_LIMIT, EvalContext, Evaluator, PredicateResult, evaluate_predicate,
    evaluate_v2,
};
pub use trace::{
    PredicateResult as TracePredicateResult, PredicateTrace, TraceBuilder, TraceEntry,
};
