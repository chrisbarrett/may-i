## Why

Two parallel rule-metadata types keyed by hash live on either side of the engine/CLI seam:

- `crates/engine/src/trust.rs` (~1100 LOC) defines `RuleMeta`, `ProgramMeta`, and `TrustHashes` — canonical-form computation, per-rule and per-program views.
- `src/trust/store.rs` (~711 LOC) defines `RuleEntry` and `TrustStore` — on-disk persistence plus approval state.

`src/cmd_trust.rs` and `src/interactive.rs` carry both halves around and stitch them by ad-hoc lookups on the shared hash key. The correspondence between an engine `RuleMeta` and a store `RuleEntry` is by convention only; the type system does not enforce it. "I forgot to consult the store for this rule" is a silent miss at runtime, not a compile error.

The recently archived `2026-05-17-deepen-trust-pipeline` and `2026-05-17-trust-pipeline-followups` changes collapsed CLI orchestration around the trust gate and pulled per-invocation store loading into `CommandPipeline::consult_trust`. They left the data shape unchanged: the engine still produces per-rule metadata, the store still owns approval state, and listing UIs still zip the two together by hash. This change finishes the job by unifying the two halves into a single per-rule view that the engine builds and the store mutates, so the compiler — not convention — enforces that every rule shown to the user carries both its canonical form and its approval state.

## What Changes

- Introduce a contributor-internal `TrustView` per rule produced by the engine: hash + canonical form + program name + provenance (source file, position) + approval state (`Approved`, `Blocked`, `Pending`). One value per rule, owned by the engine, mutated through the trust module when approval state changes.
- Replace the `TrustHashes { rules: Vec<RuleMeta>, defines_by_program: ... }` plus `TrustStore` cross-reference pattern with a single `Vec<TrustView>` (or `TrustCatalog` owning it) produced by joining engine metadata with store state in one place: `crate::trust`. The `programs()` derived view becomes a method on the catalog.
- Port `cmd_trust` and `interactive.rs` to consume `TrustView` directly. The `BTreeMap<String, ProgramMeta>` + `&TrustStore` pair-passing disappears; listing, JSON output, and per-rule interactive review all read from the unified type.
- Port `src/trust/gate.rs` and `src/trust/advisory.rs` to consume `TrustView`. The gate's filter step becomes "drop views whose approval state is not `Approved` and whose provenance is `Loaded`"; the advisory builder reads program/source/state off the view directly instead of zipping `ProgramMeta` against the store.
- Downgrade `RuleMeta`, `ProgramMeta`, and `RuleEntry` to `pub(crate)` or delete them. The engine continues to compute canonical forms and hashes (those are stable contracts of the `trust-hashing` spec); the public engine surface narrows from "expose per-rule and per-program metadata structs" to "expose a `compute_trust_views(&Config) -> Vec<TrustView>` (or equivalent) factory that the CLI's trust module joins with store state".
- Migrate the on-disk trust store if and only if necessary. The current v3 format (`{ version, rules: { hash → RuleEntry } }`) is already keyed by hash and carries program + canonical form + status; the unified `TrustView` is a runtime join, not a disk-shape change. If implementation finds a cleaner disk shape (e.g. dropping redundant `program` field now that it's recomputed), bump to v4 with a migration step.
- **BREAKING (contributor surface only)**: `may_i_engine::trust::{RuleMeta, ProgramMeta, TrustHashes}` removed or hidden; replaced by `TrustView` (or the unified-catalog type). No user-visible behaviour change: `may-i trust`, `may-i eval`, `may-i check`, and the hook produce byte-identical output.

## Capabilities

### New Capabilities

_None._ The unification is a contributor-internal reshape of types that already exist behind the `trust-store`, `trust-hashing`, and `trust-gate` specs. The user-visible behaviour these specs govern does not change, so no new capability is introduced.

### Modified Capabilities

- `trust-store`: requirement that `compute_trust_hashes` returns "per-program metadata including the hash, canonical rule strings, and set of source file paths" updates to describe the unified `TrustView` surface — the engine produces per-rule views keyed by hash, and the CLI's trust module joins these with store state to populate approval. The per-program grouping remains observable via a derived view on the catalog. If the on-disk format moves to v4, the format requirement and v2→v3 migration scenario gain a v3→v4 migration scenario.
- `trust-gate`: requirement that the gate filters Loaded rules in place updates to specify that filtering operates on the unified `TrustView` catalog rather than on a separate `Vec<RuleMeta>` cross-referenced against a `TrustStore`. The single-store-load invariant is preserved (the catalog join still happens at most once per invocation, owned by the pipeline).

(`trust-command`, `trust-advisory-boxes`, and `trust-hashing` change in implementation only — the listing format, the advisory boxes, and the canonical-form / hash computations are byte-for-byte unchanged. Per the spec-conventions rule, those edits live in `tasks.md`, not as spec deltas.)

## Impact

- **Code**: `crates/engine/src/trust.rs` (delete or hide `RuleMeta`/`ProgramMeta`/`TrustHashes`; expose `compute_trust_views` or equivalent), `src/trust/mod.rs` (host the join: engine views + store state → catalog), `src/trust/store.rs` (delete or hide `RuleEntry`; persistence becomes "set approval state on a view"), `src/trust/gate.rs`, `src/trust/advisory.rs`, `src/cmd_trust.rs`, `src/interactive.rs`. Net line reduction expected in `cmd_trust` and `interactive` (no more pair-passing).
- **APIs (contributor)**: `may_i_engine::trust` public surface narrows; `crate::trust` (CLI) gains `TrustView` (or `TrustCatalog`) as its consumer-facing type. No `pub` API in `may_i_*` crates other than `may-i-engine` changes.
- **On-disk format**: unchanged unless the migration step is taken; if v4 is introduced, `may-i migrate` rehashes via the existing `trust::rehash_after_migration` entry point and the migration system records a v3→v4 step.
- **Tests**: existing snapshot tests for `may-i trust` (listing, JSON, interactive review) and integration tests for `may-i eval` / `may-i check` / hook pin behaviour byte-for-byte. New unit/property tests cover the join: every approved hash in the store maps to exactly one `TrustView` with state `Approved`; every Loaded rule without a store entry gets state `Pending`.
- **User-visible behaviour**: none.
- **Dependencies**: none added or removed.
