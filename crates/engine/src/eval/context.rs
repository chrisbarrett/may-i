use std::collections::HashMap;

use may_i_core::ContextFacts;
use may_i_core::ast::{ArgsStyle, Convention, Define, Predicate};

/// Maximum recursion depth for (may-i ...) evaluation.
pub(super) const DEFAULT_RECURSION_LIMIT: usize = 10;

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
    /// Tokenisation convention for the current command.
    pub convention: Convention,
    /// All declared `args-style` entries — needed to resolve the inner
    /// command's convention during `(may-i ...)` recursion.
    pub args_styles: &'a [ArgsStyle],
}

impl<'a> EvalContext<'a> {
    /// Create a new evaluation context with a `:gnu` convention and no
    /// `args-style` declarations. Used by tests; production callers go
    /// through `with_convention`.
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
            convention: Convention::gnu(),
            args_styles: &[],
        }
    }

    /// Create a new evaluation context with a resolved convention.
    pub fn with_convention(
        command: &'a str,
        args: &'a [String],
        facts: &'a ContextFacts,
        bindings: HashMap<&'a str, &'a Predicate>,
        convention: Convention,
        args_styles: &'a [ArgsStyle],
    ) -> Self {
        Self {
            command,
            args,
            facts,
            bindings,
            recursion_depth: 0,
            recursion_limit: DEFAULT_RECURSION_LIMIT,
            convention,
            args_styles,
        }
    }

    /// Resolve the convention for `command` against the carried
    /// `args_styles`. Falls back to `:gnu` when no declaration matches.
    pub fn convention_for(&self, command: &str) -> Convention {
        self.args_styles
            .iter()
            .rev()
            .find(|s| s.program == command)
            .map(|s| s.convention.clone())
            .unwrap_or_default()
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
