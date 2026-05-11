## Why

`src/loaded_config.rs` defines a `LoadedConfig` struct with four fields
(`config`, `source_text`, `pre_migration_forms`, `config_path`) and a `From`
impl that copies them one-for-one from `may_i_config::LoadResult`. The two
types are structural duplicates; `LoadedConfig` adds no behaviour, no
invariant, no constructor with side effects. Every CLI command does
`may_i_config::load_and_resolve(...)?.into()` to convert.

Apply the deletion test: deleting `LoadedConfig` removes one indirection,
and the same struct (`LoadResult`) is already available from the config
crate, with the same fields. Complexity vanishes — the wrapper is a
pass-through.

The only consumer that "knew" the wrapper shape is `TracingFold`'s
`from_loaded_config` constructor, which clones two of the four fields.
That's a one-line change to take a `LoadResult` instead.

## What Changes

- **Remove** `src/loaded_config.rs` and the `LoadedConfig` struct.
- **Use `may_i_config::LoadResult` directly** in `cmd_eval`, `cmd_check`,
  `cmd_claude_code_hook`, and `output::migration_note`.
- **Rename** `TracingFold::from_loaded_config` to `from_load_result` and
  update its signature to accept `&may_i_config::LoadResult`.
- **Re-export** `LoadResult` from `may_i_config`'s prelude if a friendlier
  name is wanted (`use may_i_config::LoadResult` already works; no rename
  needed).
- **Tests** that constructed `LoadedConfig { ... }` directly
  (`src/annotation.rs:1248`) construct `LoadResult { ... }` instead.

This is a refactor with zero user-facing behaviour change. No spec needs
updating.

## Capabilities

### New Capabilities

- `config-load-surface`: a contract that the CLI consumes
  `may_i_config::LoadResult` directly as the unit of "config loaded from
  disk and ready to evaluate"; no `src/`-side wrapper duplicates its
  shape.

### Modified Capabilities

- None.

## Impact

- `src/loaded_config.rs` — deleted.
- `src/lib.rs` — remove `pub mod loaded_config;`.
- `src/cmd_eval.rs` — `LoadedConfig` references replaced with
  `may_i_config::LoadResult`; `.into()` calls deleted.
- `src/cmd_check.rs` — same.
- `src/cmd_claude_code_hook.rs` — already uses `LoadResult` directly; no
  change.
- `src/output/mod.rs` — `migration_note(loaded: &LoadedConfig, ...)` becomes
  `migration_note(loaded: &may_i_config::LoadResult, ...)`.
- `src/annotation.rs` — `TracingFold::from_loaded_config` renamed to
  `from_load_result`; call sites in `cmd_eval` and `cmd_check` updated.
  Test fixture at line 1248 updated.
- No engine, parser, or layout-crate changes.
- No spec changes.

## Note on alternative

An earlier framing considered *deepening* `LoadedConfig` by absorbing
Trust-gate behaviour. That work belongs to the separate `unify-trust-gate`
change, where the gate becomes the deep module. Keeping a shallow
`LoadedConfig` alongside the gate would leave two competing seams; deleting
it instead lets the gate be the one place that owns "config loaded and
ready to evaluate".

If `unify-trust-gate` lands first and grows a richer return type (e.g.,
`GateOutcome::Proceed { config, advisory, ... }`), this change becomes a
trivial follow-up that drops the redundant wrapper. If this change lands
first, `unify-trust-gate` simply consumes `LoadResult` directly.
