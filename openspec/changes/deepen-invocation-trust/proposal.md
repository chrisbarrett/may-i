## Why

`CommandPipeline` owns five trust-related fields
(`store_loader`, `catalog_cache`, `catalog_attempted`,
`prelude_rendered`, `trust_warning_rendered`) and orchestrates the
trust flow by calling six free functions in `src/trust/`
(`default_store_loader`, `migration_note`,
`render_integrity_advisories`, `build_warning_advisory`,
`filter_untrusted`, `check_block`). The trust module's interface to
its sole pipeline caller is wide and shallow: six fns + four state
structs (`TrustStoreState`, `TrustCatalogState`, `TrustMode`,
`TrustBlock`), each fn doing one tiny thing on a borrowed catalog.
Trust bookkeeping (idempotency flags, lazy load, mode projection)
leaks out of `trust/` into the pipeline. Adding any trust-side
rendering today requires editing both crates of code.

## What Changes

- **BREAKING (contributor API only):** Introduce an
  `InvocationTrust` type owning the per-invocation Trust concern.
  Public methods on `&mut InvocationTrust`:
  - `consult(command, mode) -> Result<(), TrustBlock>` — lazy-loads
    the store, applies the gate, filters untrusted Loaded rules in
    place on the borrowed config.
  - `render_prelude(term, stderr)` — idempotent migration note +
    integrity advisories (no-op in JSON mode).
  - `render_warning(term, stderr)` — idempotent untrusted-loaded
    warning advisory (no-op in JSON mode).
  - `migration_note() -> Option<Layout>` — moved from
    `trust::migration_note`.
- `CommandPipeline` holds one `InvocationTrust` (instead of the four
  trust fields) and reaches Trust only through these methods.
- The lazy-load state (`catalog_attempted`, `catalog_cache`), the
  idempotency flags (`prelude_rendered`, `trust_warning_rendered`),
  the `TrustStoreState`/`TrustCatalogState` joining, and the
  `default_store_loader` injection point all move inside
  `InvocationTrust`.
- The free fns `trust::migration_note`,
  `trust::render_integrity_advisories`,
  `trust::build_warning_advisory`, `trust::filter_untrusted`,
  `trust::check_block`, `trust::default_store_loader` become
  private implementation details (or methods) of `InvocationTrust`.
- `TrustMode`, `TrustBlock`, `TrustCatalog`, `TrustView`, `TrustState`
  remain public; they are the data carriers, not the orchestration.
- The single-store-load invariant moves into `InvocationTrust`. The
  pipeline's `with_store_loader` test seam becomes
  `InvocationTrust::with_loader` (the pipeline gains a `new_with_trust`
  constructor for tests).

## Capabilities

### New Capabilities

_(none)_

### Modified Capabilities

- `command-pipeline`: the pipeline no longer owns trust state
  directly; it holds an `InvocationTrust` and delegates. The
  single-trust-store-load test seam moves to the new type. The
  prelude/warning idempotency requirements move with the rendering.
- `trust-gate`: the gate entry point is no longer "a method on the
  per-invocation `CommandPipeline` object" — it is a method on the
  per-invocation `InvocationTrust` object owned by the pipeline.
  Behaviour, mode handling, and bypass rules unchanged.

## Impact

- New file `src/trust/invocation.rs` (or `src/trust/mod.rs` impl
  block) defining `InvocationTrust`.
- `src/trust/mod.rs` — free fns become `pub(super)`-ish or private
  members; the public surface re-exports only data carriers
  (`TrustMode`, `TrustBlock`, `TrustCatalog`, `TrustState`,
  `TrustView`, `rehash_after_migration`).
- `src/pipeline.rs` — `store_loader`, `catalog_cache`,
  `catalog_attempted`, `prelude_rendered`,
  `trust_warning_rendered` fields collapse into one
  `InvocationTrust`. `render_prelude_advisories`, `consult_trust`,
  `render_trust_warning`, `ensure_trust_loaded` shrink to one-line
  delegations or disappear in favour of the typed entry points
  introduced by `typed-pipeline-mode-entrypoints` (this change
  composes cleanly with that one; either ordering works).
- Tests in `src/pipeline.rs` and `src/trust/` covering the
  single-load invariant migrate to `InvocationTrust`-level tests.
- No engine, config, or trust-store crate changes. No user-facing
  surface changes (CLI flags, JSON shapes, exit codes, advisory
  text all preserved).
