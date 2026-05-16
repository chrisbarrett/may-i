## Why

The CLI's prelude (load config, render migration note, render integrity advisory, consult Trust gate, run engine, render output) is duplicated across `cmd_eval`, `cmd_check`, and `cmd_claude_code_hook`. The Trust gate is shallow — it decides allow/block but leaves integrity advisories, store loading, and config-ownership ceremony to callers; the JSON/Hook paths load the trust store twice. The `output` module re-exports the full `may_i_layout` surface and exposes raw `Layout::Stack`/`Columns`/`Indent` to subcommands, so layout primitives leak across `src/`. Result: three commands repeat the same ~30 lines of orchestration, with subtle drift potential, and no module owns "render an eval result" or "render trust state."

## What Changes

- Deepen the Trust gate so it owns the entire Trust concern for an invocation: store loading (once), filtering, integrity advisories, warning advisory, and the block decision. `trust_advisory::compute`, `filter_trusted_rules`, `write_integrity_advisories`, `build_warning_layout`, and `UntrustedEntry`/`TrustState` become internal to the gate; the public surface shrinks to one entry point.
- Introduce a `CommandPipeline` (working name) deep module in `src/` that bundles loaded config, terminal, json flag, and writers; subcommands receive it and contribute only their per-command logic. The duplicated prelude collapses to one site.
- Replace `GateOutcome::Proceed { config: Box<Config>, advisory }` and the `mem::take(&mut loaded.config)` ceremony with an interface that borrows the loaded config in place. The pipeline orchestrates this; callers stop ping-ponging ownership.
- Make `output` a deep module: expose intent-level operations (`render_eval_result`, `render_check_failure`, `render_advisory_stack`, `render_trace`) and stop re-exporting `Layout`, `ColAlign`, `ColContent`, `ColItem`, `ColRow`, `HRuleLabel`, `Note`, `NoteLevel`, `Advisory` from `may_i_layout`. `Terminal`, `write_layout`, and `strip_ansi` remain as the thin renderer protocol. Layout assembly moves out of `cmd_check`.
- **BREAKING (contributor surface only)**: `crate::trust_gate::evaluate`, `GateOutcome`, `GateMode`, `crate::trust_advisory::*`, `crate::notes::migration_note`, and most of `crate::output::*` change signatures or visibility. No user-visible behaviour change in eval / check / hook output; existing snapshot tests pin behaviour.

## Capabilities

### New Capabilities

- `command-pipeline`: The shared per-invocation orchestration object that every `cmd_*` subcommand uses — owns `LoadResult`, `Terminal`, json flag, and the stdout/stderr writers; runs the prelude (migration note, integrity advisory, Trust gate, optional filtering) once. Bucket: `cli`. Audience: contributor.
- `output-rendering`: The contributor-facing surface of `crate::output` — intent-level operations for rendering eval results, check failures, traces, and advisory stacks. Specifies what is hidden (`Layout` primitives) and what is exposed (`Terminal`, writers). Bucket: `tracing-and-output`. Audience: contributor.

### Modified Capabilities

- `trust-gate`: Gate owns trust-store loading (loaded at most once per invocation) and integrity advisories — not just the block decision. The single entry-point becomes a method on the new `CommandPipeline` and filters the loaded config in place, replacing the `Box<Config>` round-trip. Program-name extraction and store-loading invariants tighten.

(`trust-advisory-boxes` and `harness-integration` change in implementation only — rendered output and harness contract are byte-for-byte unchanged. Per spec-conventions rule, those edits live in `tasks.md`, not as spec deltas.)

## Impact

- **Code**: `src/trust_gate.rs`, `src/trust_advisory.rs`, `src/notes.rs`, `src/output/**`, `src/cmd_eval.rs`, `src/cmd_check.rs`, `src/cmd_claude_code_hook.rs`, `src/cmd_trust.rs`, `src/cmd_migrate.rs`, `src/cmd_fmt.rs`, `src/main.rs`. Net line reduction expected in `cmd_*` and `output/mod.rs`.
- **APIs (contributor)**: `GateOutcome` reshaped; most of `trust_advisory` becomes private; `output::Layout`/`ColRow`/etc. re-exports removed. No `pub` API changes in `may_i_*` crates.
- **Tests**: existing snapshot and integration tests under `tests/` pin behaviour. Unit tests in `trust_gate.rs`, `trust_advisory.rs` consolidate. New tests cover the pipeline's prelude ordering and single-store-load property.
- **User-visible behaviour**: none. Output bytes (modulo internal reordering covered by snapshots) unchanged.
- **Dependencies**: none added or removed.
