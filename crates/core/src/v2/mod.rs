// v2 AST types for the unified rule DSL.
// Unified effect model: all forms return Decision | Nil.

pub mod ast;
pub mod pattern;

pub use ast::{
    Config, Define, Effect, EffectResult, FactQuery, Predicate, Rule, SecurityConfig, Spanned,
    SpannedPredicate,
};
pub use pattern::{ArgPattern, CommandPattern, PositionalArg};

// Re-export v1 types that v2 still uses
pub use crate::types::{ContextFacts, Decision};
