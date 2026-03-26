#![feature(coverage_attribute)]

pub mod ast;
pub mod doc;
pub mod legacy;
pub mod pattern;
pub mod span;
pub mod types;

pub use doc::{Doc, DocF, LayoutHint};
pub use span::{offset_to_line_col, Span};

// Re-export canonical types
pub use ast::{
    Config, Define, Effect, EffectResult, FactQuery, Predicate, Rule, SecurityConfig, Spanned,
    SpannedPredicate,
};
pub use pattern::{ArgPattern, CommandPattern, PositionalArg};

// Re-export types that are shared between legacy and canonical
pub use types::{ContextFacts, Decision, ToDoc};

// Legacy v1 types - deprecated, use types from crate root or legacy module
pub use crate::types::{
    ArgMatcher, BoolExpr, Check, CommandMatcher, CondArm, CondBranch, ConfigWarning, ContextExpr,
    ContextFailureReason, ContextValue, EvalAnn, EvalResult, Expr, ExprBranch, FactPattern,
    FactPatternEval, Keyword, MatcherCondPredicate, PolymorphicCondArm, PolymorphicCondBranch,
    PosExpr, Quantifier, RuleBody, SourceInfo, TraceEntry, Wrapper, WrapperPattern, WrapperStep,
};
