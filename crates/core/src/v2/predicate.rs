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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FactPattern, FactQuery};

    #[test]
    fn predicate_has_presence_creates_correctly() {
        let pred = Predicate::has_presence(":via/ssh");
        assert!(matches!(
            pred,
            Predicate::Has(FactQuery::Presence { key, vector_syntax: false })
            if key == ":via/ssh"
        ));
    }

    #[test]
    fn predicate_has_value_creates_correctly() {
        let pred = Predicate::has_value(":opencode/agent", "build");
        assert!(matches!(
            pred,
            Predicate::Has(FactQuery::Value { key, pattern: FactPattern::Literal(val) })
            if key == ":opencode/agent" && val == "build"
        ));
    }

    #[test]
    fn predicate_arg_creates_correctly() {
        use crate::v2::pattern::ArgPattern;
        let pattern = ArgPattern::positional(vec![]);
        let pred = Predicate::arg(pattern);
        assert!(matches!(pred, Predicate::Arg(ArgPattern::Positional(_))));
    }

    #[test]
    fn predicate_and_with_single_returns_unwrapped() {
        let pred = Predicate::has_presence("test");
        let result = Predicate::and(vec![pred]);
        assert!(matches!(result, Predicate::Has(_)));
    }

    #[test]
    fn predicate_and_with_multiple_creates_and() {
        let preds = vec![Predicate::has_presence("a"), Predicate::has_presence("b")];
        let result = Predicate::and(preds);
        assert!(matches!(result, Predicate::And(children) if children.len() == 2));
    }

    #[test]
    fn predicate_or_with_single_returns_unwrapped() {
        let pred = Predicate::has_presence("test");
        let result = Predicate::or(vec![pred]);
        assert!(matches!(result, Predicate::Has(_)));
    }

    #[test]
    fn predicate_or_with_multiple_creates_or() {
        let preds = vec![Predicate::has_presence("a"), Predicate::has_presence("b")];
        let result = Predicate::or(preds);
        assert!(matches!(result, Predicate::Or(children) if children.len() == 2));
    }

    #[test]
    fn predicate_negate_creates_not() {
        let inner = Predicate::has_presence("test");
        let result = Predicate::negate(inner);
        assert!(
            matches!(result, Predicate::Not(boxed) if matches!(boxed.as_ref(), Predicate::Has(_)))
        );
    }
}
