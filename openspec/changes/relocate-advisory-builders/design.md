## Context

`src/output/mod.rs` (800 lines) advertises itself as "trace-specific
rendering". In practice it also defines three advisory builders:

| Function | Domain | Where the data lives |
|---|---|---|
| `migration_note` | config migration | `LoadResult.pre_migration_forms` |
| `trust_warning_note` | trust | `trust_advisory::compute()` output |
| `trust_integrity_note` | trust store | `TrustStore::load()` suspects |

For Trust, the seam is split: `trust_advisory.rs` produces an internal
`UntrustedEntry` shape and exposes a `render(...)` that prints to stdout;
`output::trust_warning_note(programs)` accepts a flattened
`&[(&str, &BTreeSet<PathBuf>)]` view of the same data and builds a
`Layout`. Two halves, neither owning the whole story, with the data shape
crossing the line.

`may_i_layout` already provides `Advisory`, `NoteLevel`, `NoteHeading`,
`into_layout`, `into_note_with_heading` — the primitives. The advisory
builders are domain-aware composition over those primitives. Composition
belongs with the domain.

## Goals / Non-Goals

**Goals:**
- One module per advisory owns the entire builder.
- `output` is "trace data → Layout" and layout-helper re-exports.
- Advisory builders are pure: they return `Option<Layout>` / `Layout`, no
  IO; callers route output.
- Zero change to rendered text.

**Non-Goals:**
- Changing the `Advisory` / `Note` layout primitives in `may_i_layout`.
- Changing what an advisory says.
- Implementing the Trust gate (separate change `unify-trust-gate`); this
  change leaves `trust_advisory.rs` independently consumable, which the
  gate refactor will then absorb.
- Splitting `output/mod.rs` into multiple modules along trace-rendering
  axes.

## Decisions

### Decision: Trust advisory builders move into `trust_advisory.rs`
The data shape (`UntrustedEntry`, `SuspectEntry`) lives there; the layout
should too. `pub fn build_warning_layout(&Config) -> Option<Layout>` and
`pub fn build_integrity_layout(&Path, Option<&[&str]>) -> Layout` replace
`render(...)` / the leak-shaped `trust_warning_note` / `trust_integrity_note`
pair.

Alternative: keep both halves and call them in sequence at each caller.
Rejected — that's the friction we're removing.

### Decision: Migration note moves to a `notes` module (or `cmd_migrate`)
Two viable homes. Picking *during implementation*; default to
`src/notes.rs` because:
- `cmd_migrate.rs` is a command entry point; pulling a helper consumed by
  `cmd_eval` / `cmd_check` into it crosses the wrong line.
- `src/notes.rs` cleanly captures "non-trace advisory builders" without
  tying the helper to a single command.

If `notes.rs` ends up with only one function, fall back to inlining into
`cmd_migrate` and re-exporting.

### Decision: Builders are pure
No printing inside the builder. `cmd_eval` and `cmd_check` already call
`output::write_layout(&mut std::io::stderr(), ...)` after fetching a note;
they keep doing that, just sourcing the layout from the new home. Trust
gate (separate change) consumes `build_warning_layout` directly.

### Decision: `output` shrinks to its job
Public surface after this change:
- `print_trace`, `write_trace`, `trace_to_json`, `colorize_decision_keyword`
- `print_separator`, `render_elements`
- re-exports from `may_i_layout`: `Layout`, `Advisory`, `Note`, `Terminal`,
  `ColRow`, `ColAlign`, `ColContent`, `ColItem`, `HRuleLabel`, `NoteLevel`,
  `write_layout`, `strip_ansi`
- `shorten_home`

That's a focused trace-rendering module.

## Risks / Trade-offs

- **Risk: callers grow more import statements** (`use crate::trust_advisory`
  *and* `use crate::output`). Acceptable: imports describe responsibility,
  not noise. Two narrow imports are clearer than one wide one.

- **Risk: snapshot drift if `colored` ANSI codes vary subtly during the
  move.** Mitigation: the builders are line-equivalent rewrites; snapshot
  test for advisory rendering before/after at the byte level.

- **Trade-off: `trust_advisory.rs` grows.** Acceptable: it gains the
  rendering it should already have owned.

- **Trade-off: a new `src/notes.rs` for one function.** Mitigation: only
  worth it if `migration_note` reads better detached from a command. If
  not, inline into `cmd_migrate` with `pub(crate)` and let `cmd_eval`
  import directly.

## Migration Plan

1. Add `trust_advisory::build_warning_layout` and `build_integrity_layout`
   alongside the existing `render`/`compute` (no caller change yet).
2. Add `migration_note` in its new home (`notes.rs` or `cmd_migrate.rs`)
   alongside the existing `output::migration_note` (no caller change yet).
3. Switch each call site (`cmd_eval`, `cmd_check`) to import from the new
   homes. Snapshot-verify byte equality.
4. Delete the old `output::migration_note`, `output::trust_warning_note`,
   `output::trust_integrity_note`, and any private helpers used only by
   them (`trust_samples`, `format_name_list`).
5. Delete `trust_advisory::render` if it has no remaining callers — or
   leave as a one-line wrapper around `build_warning_layout` if other code
   still uses it (the gate refactor will subsume it).

Rollback: each step is independently revertible; the old functions stay
in place until step 4.

## Open Questions

- Does `migration_note` belong in `notes.rs` or `cmd_migrate.rs`? Decide
  during implementation based on what reads better with one function.
- After this change, is `trust_advisory::compute` still meaningful as a
  public API, or does it become a private helper of
  `build_warning_layout`? Almost certainly the latter; confirm during
  implementation.
