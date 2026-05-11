use std::collections::HashMap;

use may_i_core::ContextFacts;
use may_i_core::ast::{Config, Define, Predicate, ResolvedParser};

use super::bindings::Bindings;

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
    /// Resolved parser (style + parameter declarations) for the current
    /// command. Drives both tokenisation and parser-level recursion.
    pub parser: ResolvedParser,
    /// Parser-bound names produced by `parse_argv`. Consulted by the
    /// rule-body verbs `(authorise #var)`, `(bound? #var)`, and
    /// `(matches? #var PAT)`.
    pub parser_bindings: Bindings,
    /// Full config — needed by `(may-i …)` recursion to resolve the
    /// inner command's parser.
    pub config: Option<&'a Config>,
}

impl<'a> EvalContext<'a> {
    /// Create a new evaluation context with a synthetic GNU parser and
    /// no config. Used by tests; production callers go through
    /// `with_parser`.
    pub fn new(
        command: &'a str,
        args: &'a [String],
        facts: &'a ContextFacts,
        bindings: HashMap<&'a str, &'a Predicate>,
    ) -> Self {
        let parser = ResolvedParser::synthetic_gnu(command);
        Self {
            command,
            args,
            facts,
            bindings,
            recursion_depth: 0,
            recursion_limit: DEFAULT_RECURSION_LIMIT,
            parser,
            parser_bindings: Bindings::new(),
            config: None,
        }
    }

    /// Create a new evaluation context with a fully-resolved parser
    /// and full-config access for parser lookups during recursion.
    pub fn with_parser(
        command: &'a str,
        args: &'a [String],
        facts: &'a ContextFacts,
        bindings: HashMap<&'a str, &'a Predicate>,
        parser: ResolvedParser,
        config: &'a Config,
    ) -> Self {
        let (_residual, parser_bindings) = super::bindings::parse_argv(&parser, args);
        Self {
            command,
            args,
            facts,
            bindings,
            recursion_depth: 0,
            recursion_limit: DEFAULT_RECURSION_LIMIT,
            parser,
            parser_bindings,
            config: Some(config),
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
