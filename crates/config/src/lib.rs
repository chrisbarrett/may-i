pub mod command;
pub mod config;
pub mod effect;
pub mod errors;
pub(crate) mod io;
pub mod migrate;
pub mod pattern;
pub mod predicate;
pub mod resolve;
pub mod rule;

#[cfg(test)]
mod migration_tests;

pub use command::{parse_command_pattern, parse_command_pattern_from_atom};
pub use config::{parse_config, parse_config_from_sexprs};
pub use effect::parse_effect;
pub use errors::ConfigError;
pub use io::{load, load_legacy, resolve_path};
pub use pattern::{parse_arg_pattern, parse_positional_arg};
pub use predicate::parse_predicate;
pub use rule::{parse_define, parse_rule, parse_shorthand_effect};

/// Helper to check if an atom is a reserved keyword.
pub fn is_reserved_keyword(atom: &str) -> bool {
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
            | "="
            | "effect"
            | "may-i"
            | "cond"
            | "when"
            | "unless"
            | "if"
    )
}
