## ADDED Requirements

### Requirement: Output module exposes intent operations, hides Layout primitives

The `crate::output` module SHALL expose only intent-level rendering operations (`render_eval_result`, `render_check_failure`, `render_check_summary`, `render_trace`, `render_advisory_stack`, `trace_to_json`, and decision-keyword colorisation). It SHALL NOT re-export `may_i_layout::Layout` or its construction primitives (`ColAlign`, `ColContent`, `ColItem`, `ColRow`, `HRuleLabel`, `Note`, `NoteLevel`, `Advisory`). The renderer protocol surface — `Terminal`, `write_layout`, `strip_ansi` — remains re-exported because callers must hand the rendered output to a writer.

#### Scenario: Layout primitives not in the output module surface

- **WHEN** scanning the `pub use` lines and `pub` items in `src/output/mod.rs`
- **THEN** none of `Layout`, `ColAlign`, `ColContent`, `ColItem`, `ColRow`, `HRuleLabel`, `Note`, `NoteLevel`, `Advisory` appear

#### Scenario: Terminal and write_layout remain available

- **WHEN** a subcommand needs a `Terminal` to detect width or a writer-and-layout pair
- **THEN** `output::Terminal`, `output::write_layout`, and `output::strip_ansi` remain in the public surface of `crate::output`

### Requirement: cmd modules do not assemble Layout values

No `cmd_*` module SHALL construct `Layout::Stack`, `Layout::Columns`, `Layout::Indent`, `Layout::HRule`, or any other `Layout` variant directly, nor build `ColRow` / `ColItem` / `HRuleLabel` values. All such assembly SHALL occur inside `crate::output` (or its submodules).

#### Scenario: No raw Layout construction in cmd modules

- **WHEN** scanning `src/cmd_*.rs` and `src/main.rs`
- **THEN** zero references to `Layout::`, `ColRow::`, `ColItem::`, or `HRuleLabel` constructors appear

#### Scenario: cmd_check renders failures via intent

- **WHEN** `cmd_check` reports a failed embedded check
- **THEN** it constructs a `CheckFailureView` (or equivalent intent payload) and calls `output::render_check_failure`, rather than building `Layout::Columns(rows)` itself

### Requirement: Eval and check output go through intent operations

`cmd_eval` SHALL render its result via a single `output::render_eval_result` (or equivalent intent) call that takes the trace entries, the colorised command, the evaluation result, the display path, the terminal, and a writer. `cmd_check` SHALL render its failures via `output::render_check_failure` and its summary via `output::render_check_summary`. The body bytes written for each subcommand SHALL be unchanged from today.

#### Scenario: Eval output bytes unchanged

- **WHEN** the snapshot integration tests under `tests/` run against `cmd_eval` invocations covered by existing snapshots
- **THEN** the rendered stdout and stderr match the existing snapshots byte-for-byte (modulo the ordering covered by the prelude-advisory ordering scenario in `command-pipeline`)

#### Scenario: Check output bytes unchanged

- **WHEN** the snapshot integration tests for `cmd_check` run
- **THEN** stdout and stderr match the existing snapshots byte-for-byte

### Requirement: Advisory rendering composes via render_advisory_stack

The `render_advisory_stack(writer, terminal, advisories)` operation SHALL accept an ordered slice of advisory layouts and render them with consistent spacing. It is the only sanctioned path for writing multiple advisories in sequence.

#### Scenario: Multiple advisories rendered with consistent spacing

- **WHEN** the Trust gate has both an integrity advisory and a warning advisory to render
- **THEN** they are rendered via a single `render_advisory_stack` call, not by repeated `write_layout` calls in the caller
