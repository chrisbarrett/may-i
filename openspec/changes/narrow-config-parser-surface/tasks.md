## 1. Verify caller inventory

- [ ] 1.1 Confirm zero external callers for each demotion target: `parse_define`, `parse_parser_form`, `parse_style_definition`, `parse_command_pattern`, `parse_rule_body`, `canonicalise_node`. Grep `src/`, `crates/` (excluding `crates/config/`), and `tests/`.
- [ ] 1.2 Confirm external callers for each retained export: `parse_rule`, `parse_config*`, `LoadResult`, `ConfigError`, `canonicalise_forms`, `load`, `load_and_resolve`, `load_and_resolve_with_cwd`, `resolve_path`, `walk_load_graph`, `discover_repo_root`, `discover_repo_local_files`.

## 2. Demote re-exports

- [ ] 2.1 Edit `crates/config/src/lib.rs`: remove `parse_define`, `parse_parser_form`, `parse_style_definition`, `parse_command_pattern`, and `canonicalise_node` from the `pub use` statements; downgrade their underlying `pub fn` declarations to `pub(crate)` where needed.
- [ ] 2.2 Demote `parse_rule_body` from `pub fn` to `pub(crate) fn` in `crates/config/src/lib.rs`. Update its doc comment to reflect that it is now the crate-internal entry point for rule-body parsing.

## 3. Verify

- [ ] 3.1 Run `cargo check --workspace`. Resolve any consumer that was missed by the grep audit.
- [ ] 3.2 Run `cargo test --workspace`. Confirm no test regressions.
- [ ] 3.3 Run `openspec validate narrow-config-parser-surface --strict`.
