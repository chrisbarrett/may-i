## MODIFIED Requirements

### Requirement: Output module exposes per-subcommand builders, hides Layout primitives and leaf renderers

The `crate::output` module SHALL expose, as its rendering surface, one builder type per subcommand that emits text output: `CheckOutput`, `EvalOutput`, and `TrustListing`. Each builder takes a small intent payload (typed fields, no `Layout` values) and a writer-plus-terminal pair on its `render` method, and emits the complete output for its subcommand in one call.

The module SHALL NOT re-export `may_i_layout::Layout` or its construction primitives (`ColAlign`, `ColContent`, `ColItem`, `ColRow`, `HRuleLabel`, `Note`, `NoteLevel`, `Advisory`).

The module SHALL NOT publicly re-export single-purpose leaf renderers that a builder now owns: `render_check_failure`, `render_check_summary`, `render_check_verbose_line`, `render_labelled_separator`, `render_eval_result`, `render_trusted_groups`, `render_advisory_stack`, `render_skipped_readonly_advisory`, `render_wrapper_boundary_advisory`. These SHALL be `pub(crate)` and reachable only through a builder.

The following items remain publicly re-exported from `crate::output`:

- `Terminal`, `write_layout`, `strip_ansi` — the renderer protocol surface.
- `shorten_home` — a path-display utility with multiple unrelated callers.
- `trace_to_json`, `render_check_results_json` — JSON intent operations consumed by both stdout and hook-response paths.
- `colorize_decision_keyword`, `format_flags_mode` — small text helpers reused outside trace/check rendering.

#### Scenario: Builders are the only text-output surface

- **WHEN** a subcommand in `src/cmd_*.rs` writes text output (non-JSON) for the user
- **THEN** it constructs exactly one of `CheckOutput`, `EvalOutput`, or `TrustListing` and calls its `.render(writer, &terminal)` method, without invoking any private leaf renderer

#### Scenario: Layout primitives not in the output module surface

- **WHEN** scanning the `pub use` lines and `pub` items in `src/output/mod.rs`
- **THEN** none of `Layout`, `ColAlign`, `ColContent`, `ColItem`, `ColRow`, `HRuleLabel`, `Note`, `NoteLevel`, `Advisory` appear

#### Scenario: Demoted leaf renderers are crate-private

- **WHEN** scanning the `pub use` lines and `pub` items in `src/output/mod.rs`
- **THEN** `render_check_failure`, `render_check_summary`, `render_check_verbose_line`, `render_labelled_separator`, `render_eval_result`, `render_trusted_groups`, `render_advisory_stack`, `render_skipped_readonly_advisory`, and `render_wrapper_boundary_advisory` SHALL NOT appear

### Requirement: cmd modules do not assemble Layout values or script render sequences

No `cmd_*` module SHALL construct `Layout::Stack`, `Layout::Columns`, `Layout::Indent`, `Layout::HRule`, or any other `Layout` variant directly, nor build `ColRow` / `ColItem` / `HRuleLabel` values. No `cmd_*` module SHALL invoke more than one rendering call against `crate::output` for a single text-output stream — the sequencing of prelude advisories, body, footer, and any decorative separators SHALL live inside the per-subcommand builder.

#### Scenario: No raw Layout construction in cmd modules

- **WHEN** scanning `src/cmd_*.rs` and `src/main.rs`
- **THEN** zero references to `Layout::`, `ColRow::`, `ColItem::`, or `HRuleLabel` constructors appear

#### Scenario: Single render call per text-output subcommand

- **WHEN** `cmd_check`, `cmd_eval`, or `cmd_trust` produces text output
- **THEN** the subcommand makes exactly one `.render(writer, &terminal)` call against its respective builder

### Requirement: Builders own prelude and trust-warning sequencing

Each per-subcommand builder SHALL emit the prelude advisories (migration note, trust-store integrity) and the trust-warning advisory at the canonical points in its rendering sequence, drawing on `CommandPipeline` state. Subcommands SHALL NOT call `pipeline.render_prelude_advisories()` or `pipeline.render_trust_warning()` directly when a builder will follow; the builder is the single point of emission.

#### Scenario: cmd_check delegates prelude emission to CheckOutput

- **WHEN** `cmd_check` constructs a `CheckOutput` for an invocation that has a trust-store integrity advisory
- **THEN** the integrity advisory appears in the rendered output without `cmd_check` calling `pipeline.render_prelude_advisories()` itself

### Requirement: Rendered output bytes are unchanged

The body bytes emitted by `cmd_check`, `cmd_eval`, and `cmd_trust` SHALL be byte-for-byte identical to today's output for every input covered by existing snapshot tests (`src/output/snapshots/`, `crates/may-i-output/src/snapshots/`, and integration tests under `tests/`).

#### Scenario: Eval output snapshots remain green

- **WHEN** the snapshot tests for `cmd_eval` run against the existing fixture set
- **THEN** stdout and stderr match the stored snapshots byte-for-byte

#### Scenario: Check output snapshots remain green

- **WHEN** the snapshot tests for `cmd_check` run
- **THEN** stdout and stderr match the stored snapshots byte-for-byte

#### Scenario: Trust listing snapshots remain green

- **WHEN** the snapshot tests for `cmd_trust` list mode run
- **THEN** stdout matches the stored snapshots byte-for-byte

## REMOVED Requirements

### Requirement: Advisory rendering composes via render_advisory_stack

**Reason**: `render_advisory_stack` is now a `pub(crate)` implementation detail of the per-subcommand builders; callers no longer choose between `write_layout` and `render_advisory_stack` because they no longer invoke either directly.

**Migration**: Builders internally use `render_advisory_stack` for multi-advisory emission. Any new advisory composition rule belongs in the builder's implementation, not the output module's public contract.
