## 1. Snapshot existing advisory output

- [ ] 1.1 Capture stderr advisory boxes for representative inputs: pre-migration config, single untrusted program, multiple untrusted programs (5+), trust-store integrity failure (specific entries), trust-store fully corrupt. Commit fixtures for byte-equality replay.

## 2. Add new builders alongside existing code

- [ ] 2.1 Add `pub fn build_warning_layout(config: &Config) -> Option<Layout>` to `src/trust_advisory.rs`. Body: combine current `compute(...)` + the layout-construction logic of `output::trust_warning_note`.
- [ ] 2.2 Add `pub fn build_integrity_layout(store_path: &Path, suspect_names: Option<&[&str]>) -> Layout` to `src/trust_advisory.rs`. Body: port from `output::trust_integrity_note`.
- [ ] 2.3 Add `migration_note` in its new home — `src/notes.rs` (default) or `src/cmd_migrate.rs` (fallback if `notes.rs` would hold one function only). Port verbatim from `output::migration_note`.
- [ ] 2.4 Unit-test each new builder against representative inputs; assert byte equality with the existing `output::*` outputs.

## 3. Switch call sites

- [ ] 3.1 In `cmd_eval`, replace `output::migration_note(&loaded, ...)` with the import from its new home. Replace `trust_advisory::render(...)` with `if let Some(layout) = trust_advisory::build_warning_layout(&loaded.config) { output::write_layout(&mut stderr(), &layout, &term); }`.
- [ ] 3.2 Same changes in `cmd_check`.
- [ ] 3.3 Snapshot-verify byte equality across all step-1 fixtures.

## 4. Delete old advisory exports from `output`

- [ ] 4.1 Remove `migration_note`, `trust_warning_note`, `trust_samples`, `trust_integrity_note`, `format_name_list` from `src/output/mod.rs`.
- [ ] 4.2 Confirm `output`'s public API is exactly: `print_trace`, `write_trace`, `trace_to_json`, `colorize_decision_keyword`, `print_separator`, `render_elements`, `shorten_home`, plus the `may_i_layout` re-exports.

## 5. Trim `trust_advisory`

- [ ] 5.1 Inline `compute(...)` into `build_warning_layout` if it has no other public callers.
- [ ] 5.2 Delete `trust_advisory::render(...)` if no caller remains. (If `unify-trust-gate` lands first, this step folds into that work.)

## 6. Verify

- [ ] 6.1 `cargo fmt`, `cargo clippy --all-targets`.
- [ ] 6.2 Full test suite passes unchanged.
- [ ] 6.3 Replay step-1 snapshots — byte-equal.
- [ ] 6.4 Audit `src/output/mod.rs` line count; confirm advisory builders and helpers are gone (~120 lines removed).
