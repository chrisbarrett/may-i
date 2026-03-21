// v2 AST types for the unified rule DSL.
// These types replace the v1 types (ContextExpr, BoolExpr, ArgMatcher) with
// a unified Predicate type that can query both facts and arguments.

pub mod ast;
pub mod pattern;
pub mod predicate;

pub use ast::{Config, Define, Effect, Rule, SecurityConfig, Spanned};
pub use pattern::{ArgPattern, CommandPattern, PositionalArg};
pub use predicate::Predicate;

// Re-export v1 types that v2 still uses
pub use crate::types::{ContextFacts, FactQuery};
