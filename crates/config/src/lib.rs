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

pub use canonicalise::{canonicalise_forms, canonicalise_node};
pub use command::parse_command_pattern;
pub use config::{parse_config, parse_config_from_sexprs, parse_config_from_tagged_sexprs};
pub use errors::ConfigError;
pub use io::{
    LoadResult, discover_repo_local_files, discover_repo_root, load, load_and_resolve,
    load_and_resolve_with_cwd, resolve_path, walk_load_graph,
};
pub use parser_form::parse_parser_form;
pub use rule::{parse_define, parse_rule};
pub use style::parse_style_definition;

/// Parse the body of a `(rule …)` form — everything between the
/// command-pattern position and the trailing optional `(check …)`
/// forms. This is the **only** public entry point for rule-body
/// parsing; the sub-parsers it dispatches to (`parse_effect`,
/// `parse_predicate`, `parse_arg_pattern`, `parse_positional_arg`)
/// are crate-internal and produce contributor-vocabulary types
/// (`Effect`, `Predicate`, `ArgPattern`) that intentionally do not
/// leak past the config crate's API seam.
///
/// For parsing the surrounding `(rule …)` form, see [`parse_rule`].
pub fn parse_rule_body(
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
