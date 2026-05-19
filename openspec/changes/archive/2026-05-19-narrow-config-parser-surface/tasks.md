## 1. Verify caller inventory

- [x] 1.1 Confirm zero external callers for each demotion target: `parse_define`, `parse_parser_form`, `parse_style_definition`, `parse_command_pattern`, `parse_rule_body`, `canonicalise_node`, `parse_config_from_tagged_sexprs`, `load_and_resolve_with_cwd`, `discover_repo_root`, `discover_repo_local_files`. Grep `src/`, `crates/` (excluding `crates/config/`), and `tests/`.
- [x] 1.2 Confirm external callers for each retained export: `parse_rule`, `parse_config`, `parse_config_from_sexprs`, `LoadResult`, `ConfigError`, `canonicalise_forms`, `load`, `load_and_resolve`, `resolve_path`, `walk_load_graph`.

## 2. Demote re-exports

- [x] 2.1 Edit `crates/config/src/lib.rs`: remove `parse_define`, `parse_parser_form`, `parse_style_definition`, `parse_command_pattern`, and `canonicalise_node` from the `pub use` statements; downgrade their underlying `pub fn` declarations to `pub(crate)` where needed.
- [x] 2.2 Demote `parse_rule_body` from `pub fn` to `pub(crate) fn` in `crates/config/src/lib.rs`. Update its doc comment to reflect that it is now the crate-internal entry point for rule-body parsing.
- [x] 2.3 Demote `parse_config_from_tagged_sexprs` to `pub(crate)` in `crates/config/src/config.rs`; remove from `pub use` in `lib.rs`. Update in-crate callers to use the module path.
- [x] 2.4 Demote `load_and_resolve_with_cwd`, `discover_repo_root`, and `discover_repo_local_files` to `pub(crate)` in `crates/config/src/io.rs`; remove from `pub use` in `lib.rs`.

## 3. Verify

- [x] 3.1 Run `cargo check --workspace`. Resolve any consumer that was missed by the grep audit.
- [x] 3.2 Run `cargo test --workspace`. Confirm no test regressions.
- [x] 3.3 Run `openspec validate narrow-config-parser-surface --strict`.
