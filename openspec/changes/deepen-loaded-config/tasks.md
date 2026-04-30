## 1. Rename TracingFold constructor

- [x] 1.1 Rename `TracingFold::from_loaded_config` → `from_load_result` in `src/annotation.rs`; parameter type becomes `&may_i_config::LoadResult`.
- [x] 1.2 Update call sites in `src/cmd_eval.rs` (`evaluate_with_colorization`) and `src/cmd_check.rs` (`run_checks_with_traces`).
- [x] 1.3 Update the test fixture in `src/annotation.rs:1248` to construct a `LoadResult { ... }`.

## 2. Update output::migration_note

- [x] 2.1 Change `migration_note` parameter type from `&LoadedConfig` to `&may_i_config::LoadResult` in `src/output/mod.rs`.
- [x] 2.2 Verify `cmd_eval` and `cmd_check` call sites compile against the new signature without intermediate conversion.

## 3. Drop the wrapper

- [x] 3.1 In `cmd_eval`, replace `let mut loaded: LoadedConfig = ...?.into();` with `let mut loaded = may_i_config::load_and_resolve(config_path)?;`.
- [x] 3.2 Same change in `cmd_check`.
- [x] 3.3 Confirm `cmd_claude_code_hook` already uses `LoadResult` directly (no change needed).
- [x] 3.4 Delete `src/loaded_config.rs`.
- [x] 3.5 Remove `pub mod loaded_config;` from `src/lib.rs`.

## 4. Verify

- [x] 4.1 `cargo fmt`, `cargo clippy --all-targets`.
- [x] 4.2 Full test suite passes unchanged.
- [x] 4.3 `cargo tarpaulin` — no coverage regression for the affected modules.
- [x] 4.4 Spot-check CLI output for `eval` and `check` against representative inputs to confirm zero behavioural drift.
