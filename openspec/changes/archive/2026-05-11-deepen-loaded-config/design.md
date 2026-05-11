## Context

`src/loaded_config.rs` is a 26-line file defining a `LoadedConfig` struct
that is structurally identical to `may_i_config::LoadResult` (same four
fields, same types). The only behaviour is a `From<LoadResult>` impl that
copies fields. Three CLI entry points (`cmd_eval`, `cmd_check`, the
`output::migration_note` helper that they share) take `&LoadedConfig`;
`cmd_claude_code_hook` already uses `LoadResult` directly.

`TracingFold::from_loaded_config` (in `src/annotation.rs`) is the only
constructor that "knows" the wrapper shape, and it clones two of the four
fields — that's the entire reason the wrapper was once justified. With
`from_load_result(&LoadResult)`, the wrapper has no remaining purpose.

This change is independent of `unify-trust-gate` and `engine-segment-decisions`
but interacts with the former: the gate could either return a `LoadResult`
or a richer outcome carrying the filtered config. The proposal lets the
gate evolve its return shape independently; what we delete here is the
*shallow duplicate*, not the concept of a "loaded config".

## Goals / Non-Goals

**Goals:**
- One canonical type for "config loaded from disk plus metadata".
- No structural duplicate in `src/`.
- Zero behavioural change.

**Non-Goals:**
- Adding behaviour to `LoadResult`. If callers want deeper semantics
  (filtered-by-trust, post-validation, etc.), that belongs in the gate or
  another deep module — not in `LoadResult`.
- Renaming `LoadResult`.
- Touching `cmd_trust` or `cmd_migrate`'s use of config types.

## Decisions

### Decision: Delete, don't deepen
The wrapper has no invariants to enforce, no constructor logic, no
behaviour. Deepening it would mean inventing responsibility for it — a
violation of the "don't design for hypothetical future requirements"
principle. If `unify-trust-gate` lands and produces a richer "ready to
evaluate" type, that type lives there, not here.

### Decision: Rename `from_loaded_config` to `from_load_result`
Names should reflect the parameter type. `from_loaded_config` named the
wrapper; `from_load_result` names what's actually passed. Mechanical
rename across one definition and two call sites.

### Decision: `output::migration_note` accepts `&LoadResult` directly
No intermediate type. The function reads
`loaded.pre_migration_forms.is_some()` and `loaded.config_path`; both
fields exist verbatim on `LoadResult`.

### Decision: No `pub use may_i_config::LoadResult as LoadedConfig` shim
Two names for one type adds confusion. Just use `LoadResult`.

## Risks / Trade-offs

- **Risk: a transitive consumer relies on the `Into<LoadedConfig>` impl
  via blanket trait machinery.** Mitigation: grep confirms no such
  consumer; the only `From` user is the explicit `.into()` calls in
  `cmd_eval` and `cmd_check`.

- **Trade-off: future contributors may re-introduce a wrapper if they want
  to attach `src/`-only metadata.** Mitigation: the new spec records the
  rule against structural duplicates; future need for additional metadata
  belongs on a *deep* type (e.g., gate outcome) with real responsibility.

## Migration Plan

Single commit. Mechanical:

1. Rename `TracingFold::from_loaded_config` → `from_load_result`; change
   parameter type to `&may_i_config::LoadResult`.
2. Update call sites in `cmd_eval` and `cmd_check`.
3. Change `output::migration_note` parameter type to
   `&may_i_config::LoadResult`.
4. Delete `src/loaded_config.rs` and the `pub mod loaded_config;` line in
   `src/lib.rs`.
5. Update the test fixture in `src/annotation.rs:1248` to construct a
   `LoadResult` directly.
6. `cargo build`, `cargo test`.

Rollback: trivial — revert the commit.

## Open Questions

None.
