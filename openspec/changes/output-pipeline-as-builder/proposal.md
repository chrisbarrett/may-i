## Why

The `output-rendering` spec already hides `Layout` primitives behind intent operations like `render_eval_result` and `render_check_failure`. The next layer of friction is sequencing: each `cmd_*` module hand-scripts the *order* of rendering steps. `cmd_check` calls `render_prelude_advisories` → `render_trust_warning` → per-result `render_check_verbose_line` → per-failure `render_check_failure` → `render_labelled_separator` → `render_check_summary`. `cmd_eval` and `cmd_trust` have analogous scripts. Most leaf renderers have exactly one external caller (grep confirms), so the wide surface earns no leverage today — every caller knows the full sequence, and changes to the prelude or footer must be replicated across commands.

## What Changes

- Introduce per-command output builders inside `crate::output` (e.g. `CheckOutput`, `EvalOutput`, `TrustListing`) that own the rendering sequence for one subcommand. Each builder takes a small intent payload (the result set, optional verbose flag, the resolved config path) and emits the complete output to a writer.
- Subcommands (`cmd_check`, `cmd_eval`, `cmd_trust`) construct the builder and call a single `.render(w)` — no scripting of intermediate leaf renderers.
- **BREAKING** (workspace-internal only): Demote single-purpose leaf renderers to `pub(crate)` where they now have only one caller (the new builder). Targets include `render_check_verbose_line`, `render_check_failure`, `render_check_summary`, `render_labelled_separator`, `render_eval_result`, `render_trusted_groups`, `render_advisory_stack`, `render_skipped_readonly_advisory`, `render_wrapper_boundary_advisory`. Keep public: `Terminal`, `write_layout`, `strip_ansi`, `shorten_home` (utility with 9 callers), `trace_to_json` and `render_check_results_json` (JSON intent, naturally per-command).
- Move the prelude/trust-warning sequencing out of `CommandPipeline` and into the builders (or keep it in the pipeline but have the builder request it via the pipeline). The aim is one place per subcommand that knows the full output script.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `output-rendering`: replace the "intent operations" requirement with a "per-subcommand builder" requirement; the surface area gets smaller and the depth increases.

## Impact

- Affected code: `src/output/mod.rs`, `src/output/check.rs`, `src/output/eval_result.rs`, `src/output/trust_groups.rs`, `src/cmd_check.rs`, `src/cmd_eval.rs`, `src/cmd_trust.rs`, `src/pipeline.rs` (prelude sequencing).
- Affected specs: `output-rendering` (delta).
- Risk: medium. More mechanical churn than the two surface-narrowing changes; snapshot tests under `src/output/snapshots/` and `crates/may-i-output/src/snapshots/` cover the rendered output and will catch regressions.
