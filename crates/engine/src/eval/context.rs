use std::collections::HashMap;

use may_i_core::ContextFacts;
use may_i_core::ast::{Define, Predicate};

/// Maximum recursion depth for (may-i ...) evaluation.
pub(crate) const DEFAULT_RECURSION_LIMIT: usize = 10;

/// The result of evaluating a predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateResult {
    Match,
    NoMatch,
}

/// Context for evaluation.
#[derive(Clone)]
pub struct EvalContext<'a> {
    /// The command being evaluated.
    pub command: &'a str,
    /// The arguments to the command.
    pub args: &'a [String],
    /// Context facts.
    pub facts: &'a ContextFacts,
    /// Named predicate bindings (define name → predicate body).
    pub bindings: HashMap<&'a str, &'a Predicate>,
    /// Current recursion depth.
    pub recursion_depth: usize,
    /// Maximum recursion depth allowed.
    pub recursion_limit: usize,
}

impl<'a> EvalContext<'a> {
    /// Create a new evaluation context.
    pub fn new(
        command: &'a str,
        args: &'a [String],
        facts: &'a ContextFacts,
        bindings: HashMap<&'a str, &'a Predicate>,
    ) -> Self {
        Self {
            command,
            args,
            facts,
            bindings,
            recursion_depth: 0,
            recursion_limit: DEFAULT_RECURSION_LIMIT,
        }
    }

    /// Build bindings from a slice of defines.
    pub fn build_bindings(defines: &[Define]) -> HashMap<&str, &Predicate> {
        defines
            .iter()
            .map(|d| (d.name.as_str(), &d.predicate.value))
            .collect()
    }

    /// Create a context with custom recursion limit.
    #[cfg(test)]
    pub(crate) fn with_recursion_limit(mut self, limit: usize) -> Self {
        self.recursion_limit = limit;
        self
    }

    /// Check if we've exceeded the recursion limit.
    pub(crate) fn is_depth_exceeded(&self) -> bool {
        self.recursion_depth >= self.recursion_limit
    }
}
