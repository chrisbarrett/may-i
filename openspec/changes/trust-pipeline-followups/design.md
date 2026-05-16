## Context

Three hygiene items from the `deepen-trust-pipeline` verify report:

1. `src/cmd_migrate.rs:219` defines `rehash_trust_store_class_a` which calls `TrustStore::load` directly. The `trust-gate` spec scenario "cmd_trust still uses TrustStore::load" reads "the trust-management subcommand is the only permitted caller". The post-migration trust-store rehash predates the deepen-pipeline change and was kept in `cmd_migrate` because the rehash is migration-driven, not trust-management. It violates the spec literal.
2. `src/cmd_check.rs` body is ~120 lines after the deepen-pipeline migration; the verbose `PASS`/`FAIL` lines and the JSON-result assembly still live in the command body. The design Decision 5 anticipated thinner cmd modules: "the per-command logic only."
3. `src/cmd_eval.rs:109` keeps `write_eval_output` as a shim delegating to `output::render_eval_result`. Its only caller is `tests/migrated_v1_trace.rs:66`. The shim was left in place during deepen-pipeline to avoid touching the test; pre-1.0 allows the test to migrate.

None of these blocks production behaviour; bundling avoids three trivial PRs.

## Goals / Non-Goals

**Goals:**

- `cmd_migrate.rs` contains no `TrustStore::load` reference; the post-migration rehash routes through the trust module.
- `cmd_check.rs` body uses only `output::*` intent calls for its rendering paths (verbose lines, failure blocks, summary, JSON-result assembly).
- `cmd_eval::write_eval_output` removed; the migrated-v1-trace test calls the intent op directly.

**Non-Goals:**

- Restructuring the rehash algorithm itself.
- Changing user-visible output bytes for migrate, check, or eval.
- Touching the trust-store on-disk format.
- Adding new spec requirements — these are pure structural/hygiene edits per the spec-conventions rule.

## Decisions

### Decision 1: `rehash_after_migration` lives in `src/trust/`

Add `pub fn rehash_after_migration() -> miette::Result<usize>` to a new `src/trust/rehash.rs` module re-exported from `crate::trust`. The function does the same work as today's `rehash_trust_store_class_a`: load store, walk entries, recompute canonical form via `may_i_engine::trust::canonical_rule` + `hash_rule`, save. `cmd_migrate` calls `trust::rehash_after_migration()`.

**Alternative considered**: keep impl in `cmd_migrate` and extend the spec carve-out to name `cmd_migrate`. Rejected — adds a second exception to a "single caller" invariant for an operation that's structurally trust-administrative, not migration-specific.

### Decision 2: `cmd_check` JSON path moves to `output::json::render_check_results`

Add `output::json::render_check_results(passed, failed, results, traces_to_json)` (or similar — exact signature TBD when implementing). Move `context_to_json` into `crate::output::json` as a private helper used by the new intent. `cmd_check` body in JSON mode becomes a single call.

Add `output::render_check_verbose_line(w, command, expected, actual, passed)` for the per-result PASS/FAIL line. `cmd_check`'s verbose loop becomes one call per result.

**Alternative considered**: pull `cmd_check`'s entire body into `output::check::run_and_render`. Rejected — `run_checks_with_traces` is engine-orchestration, not rendering; mixing them blurs the boundary the deepen change just established.

### Decision 3: Delete `write_eval_output`; update the snapshot test

Drop the shim from `cmd_eval.rs`. Update `tests/migrated_v1_trace.rs:66` to call `output::render_eval_result(&mut buf, &term, command, &colored_command, &traces, &result, &display_path)`. The test's snapshot bytes do not change (the shim was a verbatim delegate).

**Alternative considered**: keep the shim. Rejected — `deepen-trust-pipeline` introduced it as a temporary; leaving it long-term would make the migration look incomplete.

## Risks / Trade-offs

- **[Risk]** Moving `rehash_after_migration` into `trust::` exposes engine-trust knowledge from `may_i_engine::trust` (canonical_rule, hash_rule) inside `src/trust/`, which previously imported nothing from the engine's trust submodule. → **Mitigation**: `src/trust/advisory.rs` already imports `may_i_engine::trust::{canonical_rule, compute_trust_hashes, hash_rule}` — same module set. No new crate boundary crossed.
- **[Risk]** Snapshot drift in `migrated_v1_trace` tests when the shim is removed. → **Mitigation**: the shim was a verbatim delegate — no behaviour change. CI snapshot tests pin the bytes.
- **[Trade-off]** `output::json::render_check_results` couples the JSON-output module to engine `CheckResult<TraceExtra>` shape. Acceptable — the JSON shape was already determined by `cmd_check`; we're just relocating the assembly.

## Migration Plan

Pure internal refactor. No user migration. Sequenced rollout (single PR):

1. Add `src/trust/rehash.rs` with `rehash_after_migration`. Update `cmd_migrate` to call it; delete the old `rehash_trust_store_class_a` function and its `TrustStore::load` import.
2. Add `output::render_check_verbose_line` and `output::json::render_check_results` (or equivalent). Update `cmd_check` to use them; delete the moved helpers from `cmd_check.rs`.
3. Delete `cmd_eval::write_eval_output`. Update `tests/migrated_v1_trace.rs` to call `output::render_eval_result` directly.
4. Re-run snapshot tests; confirm zero drift.

Rollback: revert the PR. No persisted state changes.

## Open Questions

- Should `output::json::render_check_results` write to a writer or return the `serde_json::Value`? Tentative answer: return the value (caller serialises with `to_string`), matches today's shape and avoids serialiser-error juggling inside `output`.
