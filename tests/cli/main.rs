// CLI-surface integration tests: end-to-end behaviour of the `may-i` binary
// across the parse, eval, fmt, hook, load, and migrate-flag subcommands.

#[path = "../common/mod.rs"]
mod common;

mod check_integration;
mod eval_defines;
mod eval_stdin;
mod fmt_integration;
mod hook_integration;
mod load_directive;
mod local_function_calls;
mod migrate_flag_smoke;
mod parse_diagnostics_integration;
mod parse_integration;
mod undeclared_long_flag_arity;
