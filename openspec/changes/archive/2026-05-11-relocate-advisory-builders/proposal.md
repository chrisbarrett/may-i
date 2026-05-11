## Why

`src/output/mod.rs` (800 lines) is sold by its module doc as "shared display
helpers for trace output ... Trace-specific rendering built on top of the
`may_i_layout` crate". But it currently exports three domain-specific
advisory builders that are unrelated to trace rendering:

- `migration_note(loaded, config_path) -> Option<Layout>` — knows about
  config migration.
- `trust_warning_note(programs) -> Option<Layout>` — knows about Trust.
- `trust_integrity_note(store_path, suspect_names) -> Layout` — knows about
  the Trust store.

Trust advisory in particular is split across two modules: `trust_advisory.rs`
computes which programs are untrusted and renders to stdout/stderr;
`output::trust_warning_note` builds the `Layout` for the same data with a
different, non-overlapping API surface. The caller of `trust_warning_note`
must pass `&[(&str, &BTreeSet<PathBuf>)]` — the internal shape of
`trust_advisory`'s data, leaked across module lines.

Apply the deletion test on `output/mod.rs`'s advisory exports: removing
them, the same building blocks (`Advisory`, `NoteHeading`, `into_layout`)
remain in `may_i_layout`; only the domain-specific glue moves home. The
`output` module becomes purely "trace data → Layout", a deeper interface
with one job.

## What Changes

- **Move `migration_note`** out of `src/output/mod.rs`. Two options;
  design.md picks one:
  - Into `src/cmd_migrate.rs` as a private helper used at most by
    `cmd_migrate` itself, with an alternative `pub(crate)` consumer for
    `cmd_eval` / `cmd_check`.
  - Into a new `src/notes.rs` module that owns "advisory `Layout`
    builders that are not trace data".
- **Move `trust_warning_note` and `trust_integrity_note`** into
  `src/trust_advisory.rs`. The function `trust_advisory::build_layout`
  consumes its own internal data shape (`UntrustedEntry`,
  `SuspectEntry`) — no leak.
- **Update `trust_advisory::render`** (or its successor `build_layout` per
  the gate change): instead of writing to stdout/stderr internally, return
  `Option<Layout>`. Side effects move to the caller.
- **Tighten `output`'s public API** to:
  - trace rendering: `print_trace`, `write_trace`, `trace_to_json`,
    `colorize_decision_keyword`;
  - column-geometry / layout helpers used by `cmd_check`:
    `print_separator`, `render_elements`, `ColRow::kv`, `Layout`,
    `ColAlign`, etc. (re-exports from `may_i_layout`);
  - utilities: `shorten_home`, `Terminal::detect`, `strip_ansi`,
    `write_layout`.
- **Removed exports**: `migration_note`, `trust_warning_note`,
  `trust_integrity_note`. Each domain module owns its advisory.
- **No change** to the rendered text or layout of any advisory box. Output
  is byte-identical.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `trust-advisory-boxes`: the spec already requires a layout-based advisory
  with specific content. This change moves the *implementation* — the
  module that constructs the `Layout` — but keeps the requirements
  unchanged. Modified spec adds a requirement that the trust advisory
  builder is a pure (no-IO) function returning `Option<Layout>`, so that
  the gate (or any other caller) can route the layout to its preferred
  output sink.

## Impact

- `src/output/mod.rs` — drop ~120 lines (`migration_note`,
  `trust_warning_note`, `trust_samples`, `trust_integrity_note`,
  `format_name_list`).
- `src/trust_advisory.rs` — gain `build_warning_layout(...)`,
  `build_integrity_layout(...)`; existing `render(...)` becomes a thin
  wrapper that writes the result, or is removed entirely if the gate
  refactor (`unify-trust-gate`) lands first.
- `src/cmd_migrate.rs` (or new `src/notes.rs`) — gain `migration_note`.
- `src/cmd_eval.rs`, `src/cmd_check.rs` — call site changes for
  `migration_note` (now imported from its new home).
- `may_i_layout` — unchanged. The `Advisory` builder and `NoteHeading`
  helper continue to be the layout primitives consumed by both modules.
- Tests — unit tests for `trust_advisory::build_warning_layout` and
  `build_integrity_layout` move with the code (snapshot the rendered text).
  Snapshot tests for `cmd_eval` / `cmd_check` continue to pass
  byte-identically.
