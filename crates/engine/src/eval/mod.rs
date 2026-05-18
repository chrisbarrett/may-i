// Unified effect evaluator.
// All effect forms evaluate to EffectResult (Decision | Nil).
//
// Public surface (any addition requires a corresponding `code-quality` spec
// update — see `openspec/specs/code-quality/spec.md`, requirement
// "Engine crate public surface is bounded"):
//
//   - `Evaluator`, `EvalContext`, `PredicateResult`
//   - `evaluate`, `evaluate_with_fold`
//   - `evaluate_command`, `evaluate_command_with_fold`
//
// Everything else in this module is `pub(crate)` or narrower.

pub(crate) mod bindings;
mod command;
mod context;
pub(crate) mod decompose;
pub(crate) mod effects;
pub(crate) mod entry;
pub(crate) mod positional;
pub(crate) mod predicates;

pub use command::{evaluate_command, evaluate_command_with_fold};
pub use context::{EvalContext, PredicateResult};
pub use entry::{Evaluator, evaluate, evaluate_with_fold};

#[cfg(test)]
pub(crate) use effects::{evaluate_effect, evaluate_effect_fold};
#[cfg(test)]
pub(crate) use positional::match_positional_patterns;
#[cfg(test)]
pub(crate) use predicates::evaluate_predicate;

#[cfg(test)]
mod tests;
