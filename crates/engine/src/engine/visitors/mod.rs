// Visitor trait and concrete visitor implementations for the engine.

mod traits;
pub(crate) mod dynamic_parts;
pub(crate) mod code_execution;
pub(crate) mod function_call;
pub(crate) mod read_builtin;
pub(crate) mod wrapper_unwrap;
pub(crate) mod rule_match;

pub(crate) use traits::{CommandVisitor, VisitOutcome, VisitorContext};
