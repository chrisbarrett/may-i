## Context

The trust pipeline today routes per-rule metadata through two parallel types keyed by hash:

- `may_i_engine::trust::{RuleMeta, ProgramMeta, TrustHashes}` (`crates/engine/src/trust.rs:18-97`) — pure-Rust per-rule descriptors built from a `Config`. `RuleMeta` carries `hash`, `canonical_form`, `program`, `source_file`, `position`. `TrustHashes::programs()` derives a `BTreeMap<String, ProgramMeta>` view for listing UIs.
- `crate::trust::store::{RuleEntry, TrustStore, TrustCheck, TrustStatus}` (`src/trust/store.rs:23-104`) — on-disk approval state. `RuleEntry` carries `program`, `form`, `status` (`Approved`/`Blocked`). `TrustStore::check_rule(hash)` returns `Approved`/`Blocked`/`Pending`.

The recently archived `2026-05-17-deepen-trust-pipeline` and `2026-05-17-trust-pipeline-followups` changes pulled per-invocation trust-store loading into `CommandPipeline::consult_trust` and routed `cmd_migrate`'s rehash through `crate::trust::rehash_after_migration`. The orchestration is now clean; the data shapes are still split.

The remaining friction is visible in `src/cmd_trust.rs` and `src/interactive.rs`, where every listing/review function takes both a `&BTreeMap<String, ProgramMeta>` and a `&TrustStore` (see `cmd_trust.rs:82-83`, `175-176`, `209-210`, `282-283`; `interactive.rs:136`, `485-486`, `508`) and zips them by hash at every call site. Each zip is correct today; nothing in the type system guarantees a future caller won't forget.

`src/trust/gate.rs` already filters Loaded rules by checking each one's hash against `TrustStore::check_rule` (`gate.rs:...`). `src/trust/advisory.rs` likewise derives advisory content by zipping per-program metadata with store state. Both consume the same join pattern in slightly different shapes.

## Goals / Non-Goals

**Goals:**

- One per-rule view (`TrustView`, working name) owned by `crate::trust` and consumed by every CLI surface: gate, advisory, listing, review, JSON. The view carries hash, canonical form, program, source provenance, and approval state.
- The join (engine metadata × store state) happens in exactly one place: `crate::trust`. CLI handlers receive a fully-resolved catalog and never see the bare `RuleEntry` or bare `RuleMeta` types.
- Type-system enforcement that "every rule shown to the user carries its approval state". The missing-store-lookup bug class becomes a compile error.
- Engine surface narrows: `may_i_engine::trust` exposes the canonical-form / hash factory; `RuleMeta`/`ProgramMeta`/`TrustHashes` either disappear or become `pub(crate)`.

**Non-Goals:**

- Changing canonical-form serialisation or hash algorithm. The `trust-hashing` spec pins those; this change is data-shape-only.
- Changing user-visible behaviour of `may-i trust`, `may-i eval`, `may-i check`, or the hook. Snapshot tests must pass byte-for-byte modulo any deliberate output deltas (none planned).
- Adding new approval states (e.g. expiring, conditional). `Approved`/`Blocked`/`Pending` is the full state space.
- Changing the trust-store on-disk format unless implementation cleanup demands it (see Decisions below). If a v4 format is introduced, it ships with a migration step; otherwise the v3 format is preserved.
- Touching the `trust-command` user-facing spec body. Listing/review prose, JSON shape, and interactive flow are all preserved.

## Decisions

### One type: `TrustView` per rule, owned by `crate::trust`

The unified type lives in `crate::trust` (the CLI's trust module), not in `may_i_engine::trust`. The engine knows about canonical forms and hashes; it does not know about approval state, which is a CLI/persistence concern. Putting `TrustView` in `crate::trust` keeps the engine pure and concentrates the join in one place.

Shape (working sketch — final field set settled during implementation):

```rust
pub struct TrustView {
    hash: String,
    canonical_form: String,
    program: String,
    source_file: Option<PathBuf>,
    position: usize,
    state: TrustState,  // Approved | Blocked | Pending
}
```

Constructor is private to `crate::trust`; callers receive a `TrustCatalog` (or `Vec<TrustView>`) from a single factory that takes `&Config` + `&TrustStore`.

**Alternative considered: put `TrustView` in `may_i_engine::trust`.** Rejected — would require the engine to know about `TrustStore`, dragging persistence into a crate whose pre-condition is "pure evaluation". The engine stays at "compute canonical forms"; the join is a CLI concern.

**Alternative considered: keep both types, add a `TrustViewRef<'a> { meta: &'a RuleMeta, entry: Option<&'a RuleEntry> }` borrow type.** Rejected — solves the "forgot to consult the store" bug class but adds a third type to the existing two; net complexity rises. The goal is one type, not three.

### Engine factory: `compute_trust_views(&Config) -> Vec<…>`

Replace the public `TrustHashes` returned by `compute_trust_hashes` with a per-rule iterator/vector keyed by hash. The CLI's trust module joins these with `TrustStore` state in one place.

The `programs()` derived view becomes a method on the catalog (`TrustCatalog::group_by_program`) for the listing UI. The `defines_by_program` side-channel remains internal to canonical-form computation.

**Alternative considered: keep `TrustHashes` as the engine surface, build `TrustView` at the join.** Rejected — keeps the public engine type that needs deleting and forces every call site to translate. Migrating the engine API in the same pass costs no more.

### `TrustCatalog` as the cross-cutting consumer surface

CLI handlers receive a `TrustCatalog` (a thin owner of `Vec<TrustView>`) with intent-level methods:

- `iter() -> impl Iterator<Item = &TrustView>`
- `group_by_program() -> BTreeMap<&str, Vec<&TrustView>>`
- `untrusted_loaded() -> impl Iterator<Item = &TrustView>` (drives gate filtering and advisory body)
- `set_state(hash: &str, state: TrustState)` (drives approval / re-approval; persistence is a separate `save(&Path)` call)

The catalog owns the join; it doesn't own the store path or the `Config`. Persistence is one explicit call after the catalog mutates.

**Alternative considered: methods on `&TrustStore` taking `Vec<RuleMeta>`.** Rejected — that's the status quo with nicer ergonomics. Doesn't fix the "must remember to zip" problem.

### Visibility of legacy types

`RuleMeta`, `ProgramMeta`, `TrustHashes`, `RuleEntry` either disappear or become `pub(crate)` behind `TrustView` / `TrustCatalog`. The compiler-enforced narrowing is the point of the change; if a type stays accessible, the bug class it enables stays open.

Practical sequencing: introduce `TrustView` and `TrustCatalog` first, migrate one call site at a time (gate, advisory, listing, review), then delete or hide the old types in a final pass. Each migration step keeps the workspace compiling.

### On-disk format: stay on v3 if possible, bump to v4 only on demonstrable simplification

The v3 store shape (`{ version, rules: { hash → { program, form, status } } }`) is already keyed by hash and already carries everything `TrustView` needs to populate the `state` field at load time. The unification is a runtime join, not a persistence change.

If implementation finds the in-memory `TrustView` makes a v4 shape genuinely cleaner (e.g. dropping the redundant `program` field now that the catalog recomputes it, or co-locating `position` for stable listing order), bump to v4 and ship a v3→v4 migration step via the `migration-system` capability. Default expectation: stay on v3.

**Alternative considered: always bump to v4 to mark the API change.** Rejected — bumping the disk format with no shape change is ceremony. Pre-1.0 we can rename freely in source without disturbing on-disk users.

### Per-rule `state` field replaces `Option<&RuleEntry>` lookups

A `TrustView` always has a `state`. There is no `Option<RuleEntry>` to forget. A rule absent from the store carries `state = Pending`; a rule whose form has changed (hash mismatch) still maps to `Pending` for the new hash and is independently invalidated for the old hash.

This is the single bug-class fix the change is for: missing store entries become "state is Pending", not "we forgot to look up the store".

## Risks / Trade-offs

- **[Risk]** The engine→CLI join lives in one module now; if that module gets large, the next refactor is harder. **Mitigation:** the join is mechanical (per-rule lookup by hash). Keep the catalog constructor under ~30 LOC and test it with a property test (every store entry → matching view; every Loaded rule → present view).

- **[Risk]** Snapshot tests for `may-i trust` listings rely on stable ordering. The catalog's `group_by_program` derived view must produce the same iteration order as `TrustHashes::programs()` (lexical by program, then by `RuleMeta.position`). **Mitigation:** preserve the existing sort order in the catalog implementation; run the full snapshot suite as gate.

- **[Risk]** The advisory builder reads `provenance.source_file` to populate the "files" list. If the unified `TrustView` strips the path option to a plain `String`, advisories regress when a rule has no source file (impossible today for Loaded rules, but the type allows it). **Mitigation:** keep `source_file: Option<PathBuf>` in `TrustView` and have the advisory builder filter `None` exactly as today.

- **[Risk]** External callers of `may_i_engine::trust::{RuleMeta, ProgramMeta, TrustHashes}` exist outside the workspace. **Mitigation:** none exist (single workspace, pre-1.0). Documented as **BREAKING (contributor surface only)** in the proposal.

- **[Risk]** On-disk format bump (if taken) requires `may-i migrate` plumbing. **Mitigation:** the migration system supports trust-store rehash via `crate::trust::rehash_after_migration`; a v3→v4 step is the same pattern. Default plan is to stay on v3 and skip this risk entirely.

- **[Risk]** `pre-commit` / `prek` `cargo fmt` and `clippy` will flag any leftover dead code from the type collapse. **Mitigation:** delete unreachable types in the final task; run `cargo clippy --workspace --all-targets -- -D warnings` before staging.

## Migration Plan

User-facing migration: none if the disk format stays at v3; otherwise a v3→v4 step registered with the migration system and exercised by `may-i migrate` (existing rehash path).

Contributor-facing migration: the type collapse lands in one change. Tasks sequence the introduction of `TrustView` / `TrustCatalog`, the port of each call site, and the deletion of the legacy types as the final step, so the workspace stays green at every intermediate commit.

## Open Questions

- **v4 disk format?** Decided during implementation: if dropping `RuleEntry.program` (redundant — recomputable from the catalog) yields a noticeably simpler `TrustStore`, bump to v4 and ship the migration. Otherwise stay on v3 and document the rationale in the implementation commit.
- **Catalog mutability API.** `set_state(hash, state)` vs. returning a `&mut TrustView` for the approval flow. Final shape settled during the `cmd_trust` / `interactive` port; both are workable.
