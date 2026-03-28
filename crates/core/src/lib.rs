#![feature(coverage_attribute)]

pub mod ast;
pub mod context;
pub mod doc;
pub mod pattern;
pub mod predicates;
pub mod primitives;
pub mod span;

#[cfg(any(test, feature = "test-generators"))]
pub mod test_generators;

#[cfg(feature = "arbitrary")]
mod arbitrary_impls;

pub use doc::{Doc, DocF, LayoutHint};
pub use span::{Span, offset_to_line_col};

// Re-export primitive types
pub use primitives::{Decision, Keyword, ToDoc};

// Re-export context types
pub use context::{ContextFacts, ContextValue};

// Re-export predicate types
pub use predicates::{FactPattern, FactQuery};

// Re-export canonical types
pub use ast::{
    Config, Define, Effect, EffectResult, Predicate, Rule, SecurityConfig, Spanned,
    SpannedPredicate,
};
pub use pattern::{ArgPattern, CommandPattern, Expr, ExprBranch, PositionalArg, Quantifier};
