## Why

`crates/config/src/lib.rs` `pub use`s 19 items. A workspace grep shows six of them have zero external callers: `parse_define`, `parse_parser_form`, `parse_style_definition`, `parse_command_pattern`, `parse_rule_body`, `canonicalise_node`. The lib.rs comment for `parse_rule_body` already argues that sub-form parsers should be crate-private to keep contributor types (`Effect`, `Predicate`, `ArgPattern`) from leaking past the seam — but the principle was applied to one parser and skipped for the others. The result: a wide parsing seam that constrains internal restructuring without serving any consumer.

## What Changes

- **BREAKING** (workspace-internal only): Demote unused `parse_*` and `canonicalise_*` exports to `pub(crate)`. Targets: `parse_define`, `parse_parser_form`, `parse_style_definition`, `parse_command_pattern`, `parse_rule_body`, `canonicalise_node`.
- Keep public: `parse_rule` (used by `src/trust/rehash.rs`), `parse_config*` family, `canonicalise_forms` (used by `cmd_fmt`), `LoadResult`, `ConfigError`, the loader/resolver helpers (`load`, `load_and_resolve`, `load_and_resolve_with_cwd`, `resolve_path`, `walk_load_graph`, `discover_repo_root`, `discover_repo_local_files`). Each has a grep-verified external caller.
- Strip the now-dead doc comment for `parse_rule_body` and replace with a brief note explaining the narrowed seam.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `code-quality`: add a contributor invariant pinning the config crate's public surface so the narrowed seam is a checked rule.

## Impact

- Affected code: `crates/config/src/lib.rs`. No call-site changes expected — verified by grep.
- Affected specs: `code-quality` (delta).
- Risk: low. Pre-1.0 project; back-compat is not required.
