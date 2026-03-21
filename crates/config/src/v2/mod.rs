// v2 parser for the unified rule DSL.
// This parser implements the new syntax defined in the unified-rule-dsl design.

pub mod command;
pub mod config;
pub mod effect;
pub mod migrate;
pub mod pattern;
pub mod predicate;
pub mod resolve;
pub mod rule;

#[cfg(test)]
mod migration_tests;

pub use command::parse_command_pattern;
pub use config::parse_config;
pub use effect::parse_effect;
pub use pattern::{parse_arg_pattern, parse_positional_arg};
pub use predicate::parse_predicate;
pub use rule::{parse_define, parse_rule};

use may_i_core::v2::Spanned;
use may_i_sexpr::Sexpr;

/// Parse a spanned value from an s-expression.
pub fn spanned<T>(value: T, sexpr: &Sexpr) -> Spanned<T> {
    Spanned::new(value, sexpr.span())
}

/// Helper to check if an atom is a reserved keyword.
pub fn is_reserved_keyword(atom: &str) -> bool {
    matches!(
        atom,
        "rule"
            | "define"
            | "has"
            | "and"
            | "or"
            | "not"
            | "positional"
            | "exact"
            | "anywhere"
            | "forbidden"
            | "="
            | "effect"
            | "may-i"
            | "case"
            | "when"
            | "unless"
            | "if"
            | "safe-env-vars"
            | "check"
    )
}
