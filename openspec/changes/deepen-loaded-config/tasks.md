## 1. Rename TracingFold constructor

- [ ] 1.1 Rename `TracingFold::from_loaded_config` → `from_load_result` in `src/annotation.rs`; parameter type becomes `&may_i_config::LoadResult`.
- [ ] 1.2 Update call sites in `src/cmd_eval.rs` (`evaluate_with_colorization`) and `src/cmd_check.rs` (`run_checks_with_traces`).
- [ ] 1.3 Update the test fixture in `src/annotation.rs:1248` to construct a `LoadResult { ... }`.

## 2. Update output::migration_note

- [ ] 2.1 Change `migration_note` parameter type from `&LoadedConfig` to `&may_i_config::LoadResult` in `src/output/mod.rs`.
- [ ] 2.2 Verify `cmd_eval` and `cmd_check` call sites compile against the new signature without intermediate conversion.

## 3. Drop the wrapper

- [ ] 3.1 In `cmd_eval`, replace `let mut loaded: LoadedConfig = ...?.into();` with `let mut loaded = may_i_config::load_and_resolve(config_path)?;`.
- [ ] 3.2 Same change in `cmd_check`.
- [ ] 3.3 Confirm `cmd_claude_code_hook` already uses `LoadResult` directly (no change needed).
- [ ] 3.4 Delete `src/loaded_config.rs`.
- [ ] 3.5 Remove `pub mod loaded_config;` from `src/lib.rs`.

## 4. Verify

- [ ] 4.1 `cargo fmt`, `cargo clippy --all-targets`.
- [ ] 4.2 Full test suite passes unchanged.
- [ ] 4.3 `cargo tarpaulin` — no coverage regression for the affected modules.
- [ ] 4.4 Spot-check CLI output for `eval` and `check` against representative inputs to confirm zero behavioural drift.
