// Unified effect evaluator.
// All effect forms evaluate to EffectResult (Decision | Nil).

pub(crate) mod bindings;
mod command;
mod context;
mod decompose;
pub(crate) mod effects;
mod entry;
pub(crate) mod positional;
pub(crate) mod predicates;

pub use bindings::{BindingValue, Bindings, parse_argv};
pub use command::{evaluate_command, evaluate_command_with_fold};
pub use context::{EvalContext, PredicateResult};
pub use decompose::{EvalUnit, decompose};
pub use entry::{Evaluator, evaluate, evaluate_with_fold, parser_positional_args, tokenise};

#[cfg(test)]
pub(crate) use effects::{evaluate_effect, evaluate_effect_fold};
#[cfg(test)]
pub(crate) use positional::match_positional_patterns;
#[cfg(test)]
pub(crate) use predicates::evaluate_predicate;

#[cfg(test)]
mod tests;
