pub mod canonicalise;
pub(crate) mod command;
pub(crate) mod config;
pub(crate) mod effect;
pub(crate) mod errors;
pub(crate) mod io;
pub mod migrate;
pub(crate) mod parser_form;
pub(crate) mod pattern;
pub(crate) mod predicate;
pub mod prelude;
pub mod resolve;
pub(crate) mod rule;
pub(crate) mod style;

#[cfg(test)]
mod migration_tests;
#[cfg(test)]
mod parser_properties;
#[cfg(test)]
mod rule_body_tests;

pub use canonicalise::canonicalise_forms;
pub use config::{parse_config, parse_config_from_sexprs};
pub use errors::ConfigError;
pub use io::{LoadResult, load, load_and_resolve, resolve_path, walk_load_graph};
pub use rule::parse_rule;

// ── Load-time advisories (typed channel to the host's output sink) ──
//
// The config crate is a library with no access to the binary's output sink and
// must not write to a process stream. Load/parse-time warnings (deprecated
// syntax, duplicate declarations, empty globs, …) are recorded here and drained
// by the host after a load via [`take_advisories`], which routes them through
// the single sink (escaping any input-derived text). A thread-local buffer keeps
// the recording call signature-free, matching the crate's existing thread-local
// configuration pattern; a load is synchronous and single-threaded per
// invocation.
thread_local! {
    static ADVISORIES: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Record a load-time advisory. Drained by the host via [`take_advisories`].
pub fn record_advisory(message: impl Into<String>) {
    ADVISORIES.with(|a| a.borrow_mut().push(message.into()));
}

/// Drain and return all advisories recorded since the last call.
#[must_use]
pub fn take_advisories() -> Vec<String> {
    ADVISORIES.with(|a| std::mem::take(&mut *a.borrow_mut()))
}

/// Crate-internal entry point for rule-body parsing. Returns
/// contributor-vocabulary types (`Effect`, `Predicate`, `ArgPattern`)
/// that intentionally do not leak past the config crate's API seam.
///
/// For parsing the surrounding `(rule …)` form, see [`parse_rule`].
#[allow(dead_code)]
pub(crate) fn parse_rule_body(
    sexpr: &may_i_sexpr::Sexpr,
) -> Result<may_i_core::ast::Spanned<may_i_core::ast::Effect>, may_i_sexpr::RawError> {
    crate::effect::parse_effect(sexpr)
}

pub(crate) fn is_reserved_keyword(atom: &str) -> bool {
    matches!(
        atom,
        "rule"
            | "define"
            | "fact?"
            | "and"
            | "or"
            | "not"
            | "positional"
            | "exact"
            | "anywhere"
            | "forbidden"
            | "flag"
            | "parameter"
            | "="
            | "effect"
            | "allow"
            | "ask"
            | "deny"
            | "may-i"
            | "authorise"
            | "tail"
            | "cond"
            | "when"
            | "unless"
            | "if"
            | "define-arg-style"
            | "parser"
    )
}
