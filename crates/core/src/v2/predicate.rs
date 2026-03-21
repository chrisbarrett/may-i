// Unified Predicate type for querying facts and arguments.

use crate::v2::FactQuery;
use crate::v2::pattern::ArgPattern;

/// A unified predicate that can query both facts and arguments.
/// This replaces the separate ContextExpr, BoolExpr, and ArgMatcher types from v1.
#[derive(Debug, Clone)]
pub enum Predicate {
    /// Fact query: checks if a fact exists or matches a pattern.
    /// Syntax: `(has FACT-QUERY)`
    Has(FactQuery),

    /// Argument pattern match: checks if arguments match a pattern.
    /// Syntax: `(positional ...)`, `(exact ...)`, `(anywhere ...)`, etc.
    Arg(ArgPattern),

    /// Reference to a named predicate defined with `(define NAME PREDICATE)`.
    /// Syntax: `NAME` (atom reference, resolved during validation)
    Named(String),

    /// All sub-predicates must be true.
    /// Syntax: `(and PREDICATE ...)`
    And(Vec<Predicate>),

    /// Any sub-predicate must be true.
    /// Syntax: `(or PREDICATE ...)`
    Or(Vec<Predicate>),

    /// Inverts a sub-predicate.
    /// Syntax: `(not PREDICATE)`
    Not(Box<Predicate>),
}

impl Predicate {
    /// Create a simple fact presence check.
    pub fn has_presence(key: impl Into<String>) -> Self {
        Predicate::Has(FactQuery::Presence {
            key: key.into(),
            vector_syntax: false,
        })
    }

    /// Create a fact value check with a literal pattern.
    pub fn has_value(key: impl Into<String>, value: impl Into<String>) -> Self {
        use crate::types::FactPattern;
        Predicate::Has(FactQuery::Value {
            key: key.into(),
            pattern: FactPattern::Literal(value.into()),
        })
    }

    /// Create an argument pattern predicate.
    pub fn arg(pattern: ArgPattern) -> Self {
        Predicate::Arg(pattern)
    }

    /// Create an AND combination of predicates.
    pub fn and(predicates: Vec<Predicate>) -> Self {
        if predicates.len() == 1 {
            predicates.into_iter().next().unwrap()
        } else {
            Predicate::And(predicates)
        }
    }

    /// Create an OR combination of predicates.
    pub fn or(predicates: Vec<Predicate>) -> Self {
        if predicates.len() == 1 {
            predicates.into_iter().next().unwrap()
        } else {
            Predicate::Or(predicates)
        }
    }

    /// Create a NOT predicate.
    pub fn negate(predicate: Predicate) -> Self {
        Predicate::Not(Box::new(predicate))
    }
}

/// A predicate with source span tracking.
pub type SpannedPredicate = crate::v2::ast::Spanned<Predicate>;
