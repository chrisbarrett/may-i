## Why

The `deepen-trust-pipeline` verify report surfaced three small follow-ups whose fixes were out of that change's scope but together leave the trust pipeline a step short of clean: `cmd_migrate` still calls `TrustStore::load` directly (the `trust-gate` spec says only `cmd_trust` may), `cmd_check` retains pass/fail and per-line PASS/FAIL formatting in the command body rather than `output::`, and `cmd_eval::write_eval_output` survives only as a shim for one snapshot test. None blocks merge, but all are small enough to bundle into one tidy-up pass before they accrete.

## What Changes

- Move `rehash_trust_store_class_a` (currently in `src/cmd_migrate.rs:219`) into `src/trust/` as `pub fn rehash_after_migration() -> miette::Result<usize>`. `cmd_migrate` calls the new function; no `TrustStore::load` reference remains in `cmd_migrate.rs`. Restores the `trust-gate` spec invariant that `cmd_trust` is the sole CLI caller of `TrustStore::load`.
- Add `output::render_check_verbose_line(w, term, command, expected, actual, passed)` and route `cmd_check`'s verbose PASS/FAIL printing through it. Move the JSON-result assembly (`check_result_json` / `context_to_json`) into a new `output::json::check_result_json` (or co-located helper) so `cmd_check.rs` shrinks toward the design's "thin cmd module" target.
- Delete `cmd_eval::write_eval_output` (the shim added during `deepen-trust-pipeline`) and update `tests/migrated_v1_trace.rs` to call `output::render_eval_result` directly. Removes a public function whose only purpose is preserving an old test API.
- **BREAKING (contributor surface only)**: `cmd_eval::write_eval_output` removed; test fixtures and any external callers should switch to `output::render_eval_result`.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `trust-gate`: adds a `rehash_after_migration` entry-point to the trust module so `cmd_migrate` can route its post-migration rehash through `trust::` instead of calling `TrustStore::load` directly. The existing `cmd_trust` carve-out is unchanged; `cmd_migrate` is not added to it. Bucket: `trust`. Audience: contributor.

(cmd_check / cmd_eval changes are pure hygiene per the spec-conventions rule and live in tasks.md, not as spec deltas.)

## Impact

- **Code**: `src/cmd_migrate.rs`, `src/cmd_eval.rs`, `src/cmd_check.rs`, `src/trust/mod.rs` (and possibly new `src/trust/rehash.rs`), `src/output/mod.rs` (or `src/output/check.rs` extension), `tests/migrated_v1_trace.rs`.
- **APIs (contributor)**: `cmd_eval::write_eval_output` removed; new `crate::trust::rehash_after_migration` public; new `output::render_check_verbose_line` public. No user-visible API change.
- **Tests**: existing integration tests for `migrate`, `check`, and `eval` continue to pin behaviour byte-for-byte.
- **User-visible behaviour**: none. Migration output, check output, and eval output unchanged.
- **Dependencies**: none added or removed.
