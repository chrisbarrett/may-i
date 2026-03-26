#![feature(coverage_attribute)]

pub mod ast;
pub mod context;
pub mod doc;
pub mod pattern;
pub mod predicates;
pub mod primitives;
pub mod span;

pub use doc::{Doc, DocF, LayoutHint};
pub use span::{offset_to_line_col, Span};

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
