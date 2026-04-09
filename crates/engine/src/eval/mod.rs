// Unified effect evaluator.
// All effect forms evaluate to EffectResult (Decision | Nil).

mod context;
pub(crate) mod effects;
mod entry;
pub(crate) mod positional;
pub(crate) mod predicates;

pub use context::{EvalContext, PredicateResult};
pub use entry::{Evaluator, evaluate, evaluate_with_fold};

#[cfg(test)]
pub(crate) use effects::{evaluate_effect, evaluate_effect_fold};
#[cfg(test)]
pub(crate) use entry::{expand_combined_flags, positional_args};
#[cfg(test)]
pub(crate) use positional::match_positional_patterns;
#[cfg(test)]
pub(crate) use predicates::evaluate_predicate;

#[cfg(test)]
mod tests;
