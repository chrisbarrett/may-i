## 1. Move post-migration rehash into the trust module

- [x] 1.1 Create `src/trust/rehash.rs` with `pub fn rehash_after_migration() -> miette::Result<usize>` containing the logic currently in `cmd_migrate::rehash_trust_store_class_a` (`src/cmd_migrate.rs:219`). Add `pub mod rehash;` to `src/trust/mod.rs` and re-export `pub use rehash::rehash_after_migration;` so callers see `crate::trust::rehash_after_migration`.
- [x] 1.2 Replace the body of `rehash_trust_store_class_a` in `cmd_migrate` with a call to `crate::trust::rehash_after_migration()`; delete the now-unused `use may_i::trust::store::{RuleEntry, TrustStore, default_trust_store_path};` import. Inline the call at the existing call site if the wrapping function adds no value.
- [x] 1.3 Add a unit test in `src/trust/rehash.rs` that pins the "rehash preserves approval status" scenario: build a store with one approved entry, call `rehash_after_migration`, assert the entry is still approved and counted correctly.
- [x] 1.4 Add a unit test that pins the "rehash updates entries whose canonical form changed" scenario: write a stored canonical form that, when re-canonicalised, produces a different hash; assert the rehash count increments and the new hash is approved.
- [x] 1.5 Grep audit: zero matches for `TrustStore::load` in `src/cmd_migrate.rs`.

## 2. Slim cmd_check via output intent ops

- [x] 2.1 Add `pub fn render_check_verbose_line(w: &mut impl Write, command: &str, expected: Decision, actual: Decision, passed: bool)` to `src/output/check.rs`. The body renders the existing `PASS`/`FAIL` line (`src/cmd_check.rs` verbose loop).
- [x] 2.2 Add `pub fn render_check_results_json(passed: usize, failed: usize, results: &[CheckResult<TraceExtra>]) -> serde_json::Value` to `src/output/json.rs` (or a new `src/output/check_json.rs` if it grows). Move `context_to_json` from `cmd_check` into this module as a private helper.
- [x] 2.3 Update `cmd_check`: replace the verbose loop body with a `render_check_verbose_line` call per result; replace the JSON-mode `serde_json::json!` assembly with a `render_check_results_json` call. Delete the now-unused `context_to_json` helper from `cmd_check`.
- [x] 2.4 `cmd_check.rs` line count drops materially (target: <80 non-comment lines in `cmd_check` body).

## 3. Delete the cmd_eval::write_eval_output shim

- [x] 3.1 Delete `pub fn write_eval_output` from `src/cmd_eval.rs:109`.
- [x] 3.2 Update `tests/migrated_v1_trace.rs:66` to call `may_i::output::render_eval_result(&mut buf, &term, command, &colored_command, &traces, &result, &display_path)` directly. Drop `write_eval_output` from the `use may_i::cmd_eval::{...}` import.
- [x] 3.3 Confirm all `migrated_v1_trace` snapshot tests pass byte-for-byte (the shim was a verbatim delegate, so zero drift expected).

## 4. Verify

- [x] 4.1 `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`.
- [x] 4.2 `cargo test --workspace`. Confirm all existing snapshot tests pass without modification.
- [x] 4.3 `cargo tarpaulin`; inspect `lcov.info` for uncovered branches in `src/trust/rehash.rs` and any new `output` helpers. Add surgical unit tests for any gaps.
- [x] 4.4 `openspec validate trust-pipeline-followups --strict`.
- [x] 4.5 Grep audit: zero matches for `TrustStore::load` in `src/cmd_*.rs` (excluding `cmd_trust.rs`), and zero matches for `write_eval_output` anywhere in `src/` and `tests/`.
- [x] 4.6 Run `may-i migrate` against a config whose loaded rules require re-canonicalisation; confirm the post-migration "Rehashed N trust entries" message still appears and the count matches expectations.
