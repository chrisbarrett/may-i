use std::collections::HashMap;

use may_i_core::ContextFacts;
use may_i_core::ast::{Config, Define, Predicate, ResolvedParser};
use may_i_shell_parser::Dialect;

use super::bindings::Bindings;

/// Maximum recursion depth for (may-i ...) evaluation.
pub(super) const DEFAULT_RECURSION_LIMIT: usize = 10;

/// The result of evaluating a predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateResult {
    Match,
    NoMatch,
}

/// The scope of an environment write currently under evaluation — the raw
/// `(scope …)` value an `(env …)` decision can branch on. A write only ever
/// produces an evaluation unit when it reaches a child process, so an
/// `EnvScope` is present exactly when the write is a reaching write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvScope {
    /// A command prefix (`NAME=VALUE cmd`).
    Prefix,
    /// An exported declaration (`export …`, `declare -x …`), or any
    /// declaration made reaching by an active `set -a`.
    Export,
    /// A bare assignment (`NAME=VALUE` as its own command) made reaching by the
    /// entry environment or an active `set -a`.
    Bare,
}

/// Context for evaluation.
#[derive(Clone)]
pub struct EvalContext<'a> {
    /// The command being evaluated.
    pub command: &'a str,
    /// The arguments to the command.
    pub args: &'a [String],
    /// Per-token expansion provenance, aligned with `args`. `None` marks a
    /// literal token; `Some(display)` marks an expansion-bearing token and
    /// carries its source-faithful rendering for floor reasons.
    pub(crate) arg_expansions: Vec<super::decompose::Expansion>,
    /// Display texts of expansion-bearing words that satisfied a
    /// non-wildcard matcher during the current rule's evaluation. Shared
    /// (single-threaded) across the derived contexts a rule body creates;
    /// the rule evaluator drains it per rule and floors an `:allow`
    /// decision that relied on any entry. See the expansion-bearing-word
    /// requirement.
    pub(crate) unresolved: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
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
    pub(crate) parser_bindings: Bindings,
    /// Full config — needed by `(may-i …)` recursion to resolve the
    /// inner command's parser.
    pub config: Option<&'a Config>,
    /// The scope of the environment write currently being evaluated, for the
    /// `(scope …)` predicate inside an `(env …)` decision. `None` outside an
    /// env-write evaluation (e.g. a rule body), so `(scope …)` never matches
    /// there.
    pub(crate) env_scope: Option<EnvScope>,
    /// The shell dialect the command line was parsed under, so recursive
    /// re-parses of embedded/captured command sources inherit it. Observed
    /// ground truth (from the executing shell), never a Fact. Defaults to
    /// [`Dialect::Bash`]; set by `evaluate_at_depth` from the resolved
    /// invocation dialect.
    pub(crate) dialect: Dialect,
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
            arg_expansions: vec![None; args.len()],
            args,
            facts,
            bindings,
            recursion_depth: 0,
            recursion_limit: DEFAULT_RECURSION_LIMIT,
            parser,
            parser_bindings: Bindings::new(),
            unresolved: Default::default(),
            config: None,
            env_scope: None,
            dialect: Dialect::Bash,
        }
    }

    /// Create a new evaluation context with a fully-resolved parser
    /// and full-config access for parser lookups during recursion.
    /// `arg_expansions` carries per-token expansion provenance aligned
    /// with `args`.
    pub(crate) fn with_parser(
        command: &'a str,
        args: &'a [String],
        arg_expansions: Vec<super::decompose::Expansion>,
        facts: &'a ContextFacts,
        bindings: HashMap<&'a str, &'a Predicate>,
        parser: ResolvedParser,
        config: &'a Config,
    ) -> Self {
        debug_assert_eq!(args.len(), arg_expansions.len());
        let (_residual, parser_bindings) =
            super::bindings::parse_argv(&parser, args, &arg_expansions);
        Self {
            command,
            args,
            arg_expansions,
            facts,
            bindings,
            recursion_depth: 0,
            recursion_limit: DEFAULT_RECURSION_LIMIT,
            parser,
            parser_bindings,
            unresolved: Default::default(),
            config: Some(config),
            env_scope: None,
            dialect: Dialect::Bash,
        }
    }

    /// Record that `display` (an expansion-bearing word) satisfied a
    /// non-wildcard matcher. The rule evaluator floors an `:allow`
    /// decision that relied on any recorded entry.
    pub(crate) fn record_unresolved(&self, display: &str) {
        self.unresolved.borrow_mut().push(display.to_string());
    }

    /// Expansion provenance for a prefix slice of `self.args` (the
    /// outer/matcher scope is always a prefix of the full argv).
    pub(crate) fn expansions_for_prefix(&self, len: usize) -> &[super::decompose::Expansion] {
        &self.arg_expansions[..len]
    }

    /// The positional-matcher step budget from the config, or the default when
    /// no config is attached (test contexts).
    pub(crate) fn matcher_budget(&self) -> u64 {
        self.config
            .map(|c| c.matcher_budget.steps())
            .unwrap_or_else(|| may_i_core::MatcherBudget::default().steps())
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
