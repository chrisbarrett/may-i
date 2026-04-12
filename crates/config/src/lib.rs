pub(crate) mod command;
pub(crate) mod config;
pub(crate) mod effect;
pub(crate) mod errors;
pub(crate) mod io;
pub mod migrate;
pub(crate) mod pattern;
pub(crate) mod predicate;
pub mod resolve;
pub(crate) mod rule;

#[cfg(test)]
mod migration_tests;
#[cfg(test)]
mod parser_properties;

pub use command::parse_command_pattern;
pub use config::{parse_config, parse_config_from_sexprs, parse_config_from_tagged_sexprs};
pub use effect::parse_effect;
pub use errors::ConfigError;
pub use io::{LoadResult, load, load_and_resolve, resolve_path};
pub use pattern::{parse_arg_pattern, parse_positional_arg};
pub use predicate::parse_predicate;
pub use rule::{parse_define, parse_rule};

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
            | "="
            | "effect"
            | "may-i"
            | "cond"
            | "when"
            | "unless"
            | "if"
    )
}
