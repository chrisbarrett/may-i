## Context

The Trust concern for a single CLI invocation is currently spread
across two modules:

- `src/pipeline.rs` owns four trust-related fields and the lazy-load
  mechanics:
  - `store_loader: StoreLoader` (lines 22, 108)
  - `catalog_cache: Option<TrustCatalogState>` (line 109)
  - `catalog_attempted: bool` (line 110)
  - `prelude_rendered: bool` (line 111)
  - `trust_warning_rendered: bool` (line 112)
  - `ensure_trust_loaded` (lines 295–310) drives the loader once
- `src/trust/mod.rs` exposes six free functions:
  - `default_store_loader` (lines 84–101)
  - `migration_note` (lines 105–136)
  - `render_integrity_advisories` (lines 142–166)
  - `build_warning_advisory` (lines 172–174)
  - `filter_untrusted` (lines 179–186)
  - `check_block` (lines 189–200)
- and four state structs: `TrustStoreState` (64), `TrustCatalogState`
  (74), `TrustMode` (32), `TrustBlock` (54).

The pipeline calls each of these in a fixed sequence
(`render_prelude_advisories`, `consult_trust`,
`render_trust_warning`), threading the loaded config and the borrowed
catalog by hand. Every call site outside `cmd_trust` (the carve-out)
goes through this sequence.

The trust-gate spec already names the single-load invariant and the
"gate owns integrity advisory rendering" requirement. The
command-pipeline spec names the prelude idempotency and the
single-load test seam. Both specs implicitly tie the orchestration to
`CommandPipeline` because that is where the state lives today.

## Goals / Non-Goals

**Goals:**

- Encapsulate the per-invocation Trust state (lazy-loaded catalog,
  idempotency flags, store-loader seam, mode projection) behind one
  type with a small surface.
- Pass the deletion test: imagine deleting `InvocationTrust`. Trust
  bookkeeping reappears in the pipeline across multiple fields and
  call sites — i.e. the type earns its keep.
- Keep `CommandPipeline` focused on the per-invocation orchestration
  flow (load config, drive the closure, render the result); trust
  becomes one collaborator it talks to through a small interface.
- Preserve every spec invariant: single store load, idempotent
  prelude, JSON-mode skip, stable advisory order, integrity advisory
  ownership, hook-mode block reasons, byte-for-byte external output.
- Keep test seams: a counting store-loader fake must still verify
  exactly one load per invocation.

**Non-Goals:**

- Changing the public surface of the trust crate carve-out used by
  `cmd_trust` (it still calls `TrustStore::load` directly).
- Changing engine, config, or trust-store crates.
- Re-deriving advisory text. Layouts come from `output::Advisory`
  builders unchanged.
- Composing with `typed-pipeline-mode-entrypoints` ordering — either
  change can land first; the conflict surface is small (the
  pipeline's trust fields collapse either way) and is noted in tasks.

## Decisions

### D1. `InvocationTrust` owns the loader, state, and idempotency

```rust
pub struct InvocationTrust {
    loader: Box<dyn Fn() -> Option<TrustStoreState>>,
    json: bool,
    catalog: Option<TrustCatalogState>,
    attempted: bool,
    prelude_rendered: bool,
    warning_rendered: bool,
}

impl InvocationTrust {
    pub fn new(json: bool) -> Self;                     // default loader
    pub fn with_loader(json: bool, loader: StoreLoader) -> Self;

    pub fn consult(
        &mut self,
        loaded: &mut LoadResult,
        command: &str,
        mode: TrustMode,
    ) -> Result<(), TrustBlock>;

    pub fn render_prelude(
        &mut self,
        loaded: &LoadResult,
        term: &Terminal,
        stderr: &mut impl Write,
    );

    pub fn render_warning(
        &mut self,
        term: &Terminal,
        stderr: &mut impl Write,
    );
}
```

The four pieces of state (`catalog`, `attempted`, `prelude_rendered`,
`warning_rendered`) become private. Lazy-load is an internal method
(`ensure_loaded(&mut self, loaded: &Config)`) that the public methods
call.

**Why `&mut LoadResult` on `consult`:** the gate filters Loaded rules
in place. That edit must happen on the pipeline's `LoadResult`.
Passing it by `&mut` keeps the borrow scoped to the consult call.

**Why `&LoadResult` (not `&mut`) on `render_prelude`:** the prelude
renders the migration note from `loaded.pre_migration_forms` and
integrity advisories from `self.catalog`; no mutation needed.

**Why `json` on the struct:** the trust mode projection
(`TrustMode::for_eval(json)`) and the JSON-skip predicate both depend
on it. Putting it on the struct keeps `consult`/`render_prelude` from
taking it as a parameter every call.

### D2. Pipeline holds one `InvocationTrust` field

```rust
pub struct CommandPipeline {
    loaded: LoadResult,
    terminal: Terminal,
    json: bool,
    trust: InvocationTrust,
}
```

Four fields become two (`json` stays for renderer selection — Trust
doesn't own that). `render_prelude_advisories`, `consult_trust`,
`render_trust_warning`, `ensure_trust_loaded` collapse:

```rust
pub(crate) fn render_prelude_advisories(&mut self) {
    self.trust.render_prelude(&self.loaded, &self.terminal, &mut io::stderr());
}

pub(crate) fn consult_trust(
    &mut self,
    command: &str,
    mode: TrustMode,
) -> Result<(), TrustBlock> {
    self.trust.consult(&mut self.loaded, command, mode)
}

pub(crate) fn render_trust_warning(&mut self) {
    self.trust.render_warning(&self.terminal, &mut io::stderr());
}
```

If `typed-pipeline-mode-entrypoints` has already landed, these become
internal helpers inside the per-mode `run_*` methods and lose their
`pub(crate)` visibility entirely.

### D3. Free fns under `src/trust/` become impl methods (or private)

The current free fns map directly:

| Current free fn                          | New home                                   |
| ---------------------------------------- | ------------------------------------------ |
| `default_store_loader`                   | private fn inside `InvocationTrust::new`   |
| `migration_note(&LoadResult)`            | `InvocationTrust::migration_note(&self, &LoadResult) -> Option<Layout>` (still useful for tests) |
| `render_integrity_advisories(...)`       | private `InvocationTrust::render_integrity` |
| `build_warning_advisory(catalog)`        | private `InvocationTrust::build_warning`   |
| `filter_untrusted(config, catalog)`      | private `InvocationTrust::filter_untrusted` |
| `check_block(command, mode, catalog)`    | private `InvocationTrust::check_block`     |

The submodules `trust::advisory`, `trust::gate`, `trust::view`,
`trust::store`, `trust::rehash` keep their pure helpers
(`build_warning_layout`, `build_integrity_layout`,
`untrusted_entries`, `json_block`, `hook_block`,
`build_catalog`, `rehash_after_migration`). `InvocationTrust`
composes them.

### D4. `TrustStoreState` and `TrustCatalogState` shrink or merge

Today the pipeline holds `Option<TrustCatalogState>` and the loader
returns `Option<TrustStoreState>`. With orchestration inside
`InvocationTrust`, there is no need for two struct shapes — the
type can carry the joined state directly:

```rust
struct InvocationCatalog {
    catalog: TrustCatalog,
    suspects: Vec<SuspectEntry>,
    was_corrupt: bool,
    store_path: PathBuf,
}
```

`TrustStoreState` remains as the loader's return shape (it is the
serialisable boundary with `TrustStore::load`). `TrustCatalogState`
collapses into `InvocationCatalog` (private). Public re-exports drop
both names — they were internal coordination shapes.

### D5. Test seam moves from pipeline to trust

The single-store-load invariant is a Trust property, not a pipeline
property. `CommandPipeline::with_store_loader(loaded, json, loader)`
becomes `CommandPipeline::with_trust(loaded, json, trust)` where the
test constructs `InvocationTrust::with_loader(json, counter_loader)`
directly. The existing tests (`store_loads_once_per_invocation`,
`prelude_is_idempotent`, `json_mode_prelude_is_noop`) move to
`src/trust/invocation.rs` and exercise `InvocationTrust` directly,
plus one or two pipeline-level integration tests that confirm the
pipeline correctly threads through.

**Alternatives rejected:**

- Keep the loader on the pipeline, pass it to `InvocationTrust` per
  method call. Rejected: spreads the lazy-load state across two
  types again.
- Make `InvocationTrust` a trait so `cmd_trust` can use a stub
  implementation. Rejected: `cmd_trust` is the carve-out — it
  bypasses the orchestration on purpose, no trait needed.
- Fold trust orchestration into `CommandPipeline::run_*` methods
  (post-`typed-pipeline-mode-entrypoints`) without an intermediate
  type. Rejected: same shallow-orchestration problem moves to three
  methods instead of one.

## Risks / Trade-offs

- **[Risk] `consult` borrows `&mut LoadResult` through the trust
  type, which the pipeline also borrows for the closure.** Mitigation:
  consult is called before the closure, releases its borrow when it
  returns, and the closure borrows `LoadResult` immutably via
  `EvalContext`. The compiler enforces the discipline.
- **[Risk] `InvocationTrust::with_loader` differs slightly from
  today's `CommandPipeline::with_store_loader` signature, breaking
  the existing pipeline test fixture.** Mitigation: keep a
  `CommandPipeline::with_trust(loaded, json, trust)` constructor for
  tests; the migration is mechanical.
- **[Risk] Trust-gate spec calls the entry point a method on
  `CommandPipeline` — a literal reading.** Mitigation: this change
  amends the trust-gate requirement to name `InvocationTrust` as the
  owning type, with the pipeline as the holder. The behaviour is
  unchanged.
- **[Risk] Composition with `typed-pipeline-mode-entrypoints` if both
  changes land in parallel.** Mitigation: both touch the same
  pipeline fields. Whichever lands second updates the pipeline to
  the merged shape (per-mode methods on a pipeline that holds an
  `InvocationTrust`). Conflict surface is local and mechanical.
- **[Trade-off] One new type + one new file vs eliminating five
  fields and six free fns from the pipeline+trust seam.** The depth
  win is the trade.
