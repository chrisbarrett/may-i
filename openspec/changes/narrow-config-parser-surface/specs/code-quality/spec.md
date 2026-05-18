## ADDED Requirements

### Requirement: Config crate public surface is bounded

The `may-i-config` crate SHALL export only items that have at least one consumer outside the crate. The supported surface comprises `LoadResult`, `ConfigError`, `parse_rule`, `parse_config`, `parse_config_from_sexprs`, `parse_config_from_tagged_sexprs`, `canonicalise_forms`, `load`, `load_and_resolve`, `load_and_resolve_with_cwd`, `resolve_path`, `walk_load_graph`, `discover_repo_root`, and `discover_repo_local_files`, plus the `migrate` and `prelude` modules and the `resolve::validate_and_resolve` entry.

Items not listed above SHALL be `pub(crate)` or narrower. In particular, sub-form parsers that return contributor-vocabulary types (`Effect`, `Predicate`, `ArgPattern`, `Define`, `Parser`, `Style`, `CommandPattern`) SHALL NOT be publicly callable.

#### Scenario: Demoted parsers are crate-private

- **WHEN** `crates/config/src/lib.rs` is inspected
- **THEN** `parse_define`, `parse_parser_form`, `parse_style_definition`, `parse_command_pattern`, `parse_rule_body`, and `canonicalise_node` SHALL NOT appear in a `pub use` or `pub fn` statement

#### Scenario: Documented surface compiles in isolation

- **WHEN** `cargo check --workspace` runs after the visibility change
- **THEN** the build SHALL succeed without any consumer reaching for a demoted item
