// Legacy v1 types (deprecated - use canonical types from crate root).
//
// These types are kept for backward compatibility with existing code.
// New code should use the canonical types re-exported from may_i_core directly.

pub use crate::types::{
    ArgMatcher, BoolExpr, Check, CommandMatcher, CondArm, CondBranch, Config, ConfigWarning,
    ContextExpr, ContextFacts, ContextFailureReason, ContextValue, Decision, Effect, EvalAnn,
    EvalResult, Expr, ExprBranch, FactPattern, FactPatternEval, FactQuery, Keyword,
    MatcherCondPredicate, PolymorphicCondArm, PolymorphicCondBranch, PosExpr, Quantifier, Rule,
    RuleBody, SecurityConfig, SourceInfo, ToDoc, TraceEntry, Wrapper, WrapperPattern, WrapperStep,
};
