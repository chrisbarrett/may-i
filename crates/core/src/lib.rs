#![feature(coverage_attribute)]

pub mod ast;
pub mod context;
pub mod doc;
pub mod pattern;
pub mod predicates;
pub mod primitives;
pub mod safe_source;
pub mod safe_text;
pub mod span;
pub mod trivia;

// Test-support strategies; their tests assert one variant and treat the rest
// as the catch-all, so the exhaustive-match lint does not apply.
#[cfg(any(test, feature = "test-generators"))]
#[allow(clippy::wildcard_enum_match_arm)]
pub mod test_generators;

#[cfg(any(test, feature = "arbitrary"))]
mod arbitrary_impls;

pub use doc::{Doc, DocF, LayoutHint};
pub use safe_source::SafeSource;
pub use safe_text::SafeText;
pub use span::Span;
pub use trivia::{Trivia, TriviaAnn, TriviaSource};

// Re-export primitive types
pub use primitives::{Decision, Keyword, ToDoc};

// Re-export context types
pub use context::{ContextFacts, EntryEnv};

// Re-export predicate types
pub use predicates::{FactPattern, FactQuery};

// Re-export canonical types
pub use ast::{
    Config, Define, Effect, EffectResult, EnvScopeMatcher, MatcherBudget, ParameterDecl,
    ParameterTreatment, Parser, Predicate, Provenance, PunPolicy, ResolvedParser, Rule,
    SecurityConfig, Spanned, Style, StyleRegistry, StyleResolveError, StyleSpec,
};
pub use pattern::{ArgPattern, CommandPattern, Expr, ExprBranch, PosTerm, PosTermView, Quantifier};
