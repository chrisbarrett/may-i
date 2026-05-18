## Context

Today's rendering pipeline has three layers:

1. `may-i-output` crate — `Layout` primitive tree and `write_layout`.
2. `src/output/` — leaf renderers built on `Layout`: `render_trace`, `render_check_failure`, `render_check_summary`, `render_eval_result`, `render_advisory_stack`, `render_trusted_groups`, `render_skipped_readonly_advisory`, `render_wrapper_boundary_advisory`, `render_check_verbose_line`, `render_labelled_separator`, plus JSON renderers.
3. `src/cmd_*.rs` — orchestration. Each subcommand knows the precise script of leaf renderers to call and in what order.

Example (`cmd_check`):

```
pipeline.render_prelude_advisories();
pipeline.render_trust_warning();
let results = run_checks_with_traces(...);
if json {
    println!(render_check_results_json(passed, failed, &results));
} else {
    for r in &results { if verbose { render_check_verbose_line(...); } }
    for r in failures { render_check_failure(...); }
    render_labelled_separator(...);
    render_check_summary(...);
}
```

`cmd_eval`, `cmd_trust`, and `cmd_claude_code_hook` follow analogous scripts. The leaf renderers are intent-level (good — the existing `output-rendering` spec earned that) but the *composition* is scattered.

## Goals / Non-Goals

**Goals:**
- One module knows the full output script for each subcommand.
- Adding a new advisory or footer requires touching one place, not every command.
- The output module's public surface shrinks to per-subcommand builders + a small utility kernel.
- Snapshot coverage is preserved or improved.

**Non-Goals:**
- Changing the rendered output. The byte-for-byte result of each command should be unchanged; existing snapshots stay green.
- Touching the `Layout` primitive crate (`may-i-output`). It already does its job.
- Replacing `Terminal::detect()` or width detection.
- Introducing a generic "presenter" trait. A struct per subcommand with explicit fields is enough; abstractions can come later if a second-subcommand pattern emerges.

## Decisions

### One builder per subcommand, not one builder for everything

Each subcommand has a distinct sequence (check: per-result lines → per-failure detail → footer; eval: trace + final decision; trust list: heading + grouped entries). A generic builder would carry per-subcommand branches and lose the narrowing benefit. Alternative considered: a single `OutputComposer` with `.add_prelude()`, `.add_check_failures()`, etc. Rejected because subcommands would still script the calls — same problem, different module.

### Builders own the sequence; commands provide intent payloads

`cmd_check` constructs a `CheckOutput { config_path, results, verbose, json }` and calls `.render(writer, &terminal)`. Internally, `CheckOutput::render` calls the (now-private) leaf renderers in the canonical order. The same approach for `EvalOutput` and `TrustListing`. Alternative considered: methods on `CommandPipeline` instead of standalone builders. Rejected because `CommandPipeline` already carries IO/trust concerns; piling rendering on top would make it a god-object.

### Prelude and trust-warning sequencing

Currently `pipeline.render_prelude_advisories()` and `pipeline.render_trust_warning()` are pipeline methods called explicitly at the top of each subcommand. Two options:

A. Each builder takes a `&mut CommandPipeline` and emits prelude + warning as part of its `render`.
B. Pipeline keeps the methods; each builder documents that it expects the caller to emit them first.

Choosing (A). It makes "the builder owns the script" literally true. Subcommands collapse to: load pipeline → construct builder → render. The `CommandPipeline` continues to *produce* the advisories (it owns the trust store and integrity state); the *emission* moves into the builder.

### JSON path

The JSON renderers (`render_check_results_json`, `trace_to_json`) stay public because callers want the `serde_json::Value` to serialise differently per protocol (stdout for `eval --json`, embedded in hook response for `claude-code-hook`). They are already intent-shaped. The text-only builders are what we're consolidating.

### Snapshot coverage

`src/output/snapshots/` (insta) covers each leaf renderer; `crates/may-i-output/src/snapshots/` covers Layout rendering. Adding per-builder snapshot tests guarantees byte-equivalence with the current scripted output across all subcommands. The leaf-renderer snapshots stay valuable as targeted regression tests for individual primitives; they don't need to be removed.

## Risks / Trade-offs

- **Risk**: Subtle ordering differences slip through (e.g. blank line between sections). → **Mitigation**: golden snapshot tests for each builder against a representative input set; require byte-equivalence before demoting any leaf renderer.
- **Risk**: A future subcommand needs to compose pieces in an unanticipated way, finds the building blocks demoted. → **Mitigation**: re-promoting a `pub(crate)` to `pub` is a one-line change. The `output-rendering` spec governs the surface, so re-widening is a deliberate spec edit.
- **Trade-off**: Three new builder types add code. The deletion of scripted sequences from three `cmd_*.rs` files compensates. Net LoC roughly neutral; locality strictly improves.
- **Trade-off**: Builders take a `&mut CommandPipeline` (for prelude/trust state). Couples builders to pipeline shape. Acceptable — they are siblings in the same binary crate, and the alternative is to thread half a dozen state references through builder constructors.
