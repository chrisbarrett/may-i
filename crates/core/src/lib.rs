pub mod doc;
pub mod span;
pub mod types;
pub mod v2;

pub use doc::{Doc, DocF, LayoutHint};
pub use span::{Span, offset_to_line_col};

// Re-export v2 types
pub use v2::{
    ArgPattern as V2ArgPattern, CommandPattern, Config as V2Config, Define, Effect as V2Effect,
    PositionalArg, Predicate, Rule as V2Rule, SecurityConfig as V2SecurityConfig, Spanned,
};

// Re-export v1 types (used by CLI and legacy code)
pub use crate::types::{
    ArgMatcher, BoolExpr, Check, CommandMatcher, CondArm, CondBranch, Config, ConfigWarning,
    ContextExpr, ContextFacts, ContextFailureReason, ContextValue, Decision, Effect, EvalAnn,
    EvalResult, Expr, ExprBranch, FactPattern, FactPatternEval, FactQuery, MatcherCondPredicate,
    PolymorphicCondArm, PolymorphicCondBranch, PosExpr, Quantifier, Rule, RuleBody, SecurityConfig,
    SourceInfo, ToDoc, TraceEntry, Wrapper, WrapperPattern, WrapperStep,
};
