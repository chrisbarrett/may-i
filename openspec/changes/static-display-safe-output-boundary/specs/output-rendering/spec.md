## MODIFIED Requirements

### Requirement: Output module exposes per-subcommand builders, hides Layout primitives and leaf renderers

The `crate::output` module SHALL expose, as its rendering surface, one builder type per subcommand that emits text output: `CheckOutput`, `EvalOutput`, and `TrustListing`. Each builder takes a small intent payload (typed fields, no `Layout` values) and a writer-plus-terminal pair on its `render` method, and emits the complete output for its subcommand in one call.

The module SHALL NOT re-export `may_i_output::Layout` or its construction primitives (`ColAlign`, `ColContent`, `ColItem`, `ColRow`, `HRuleLabel`, `Note`, `NoteLevel`, `Advisory`).

The module SHALL NOT publicly re-export single-purpose leaf renderers that a builder now owns: `render_check_failure`, `render_check_summary`, `render_check_verbose_line`, `render_labelled_separator`, `render_eval_result`, `render_trusted_groups`, `render_advisory_stack`, `render_skipped_readonly_advisory`, `render_wrapper_boundary_advisory`. These SHALL be `pub(crate)` and reachable only through a builder.

The following items remain publicly re-exported from `crate::output`:

- `Terminal`, `write_layout` — the renderer protocol surface. The ANSI-stripping helpers `strip_ansi` and `visible_len` are no longer part of the surface; under color-as-data no Layout value carries embedded ANSI, so they are removed (see the `display-safe-output` capability).
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

#### Scenario: ANSI-stripping helpers are not in the surface

- **WHEN** scanning the `pub use` lines and `pub` items in `src/output/mod.rs`
- **THEN** neither `strip_ansi` nor `visible_len` appears
