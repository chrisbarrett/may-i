## 1. Audit current output composition

- [x] 1.1 List every `output::render_*` call in `src/cmd_check.rs`, `src/cmd_eval.rs`, `src/cmd_trust.rs`, and `src/cmd_claude_code_hook.rs`. Record the canonical order per subcommand.
- [x] 1.2 List every `pipeline.render_prelude_advisories()` and `pipeline.render_trust_warning()` call site. Confirm none live outside `cmd_*` or `pipeline` itself.
- [x] 1.3 Identify which leaf renderers have multiple distinct callers across `cmd_*` (`shorten_home` is one; others should resolve to one caller per builder after consolidation).

## 2. Build the per-subcommand builders

- [x] 2.1 Add `CheckOutput { config_path, results, verbose }` in `src/output/check.rs` (or a new submodule). Its `render(writer, &terminal, &mut CommandPipeline)` emits prelude → trust warning → verbose lines (when set) → failure details → labelled separator → summary, matching today's order.
- [x] 2.2 Add `EvalOutput { config_path, trace_entries, command, eval_result }` in `src/output/eval_result.rs` (or new submodule). `.render(...)` emits prelude → trust warning → trace + decision.
- [x] 2.3 Add `TrustListing { groups }` (or similar) in `src/output/trust_groups.rs`. `.render(...)` emits heading → grouped entries.

## 3. Rewire subcommands

- [x] 3.1 Replace the scripted leaf-renderer sequence in `cmd_check` with `CheckOutput::new(...).render(...)`.
- [x] 3.2 Replace the scripted sequence in `cmd_eval` (text path) with `EvalOutput::new(...).render(...)`. Keep the JSON path unchanged.
- [x] 3.3 Replace the scripted sequence in `cmd_trust` with `TrustListing::new(...).render(...)`.
- [x] 3.4 Confirm `cmd_claude_code_hook` is unaffected (it produces JSON only).

## 4. Demote leaf renderers

- [x] 4.1 In `src/output/mod.rs`, change the `pub use` of `render_check_failure`, `render_check_summary`, `render_check_verbose_line`, `render_labelled_separator`, `render_eval_result`, `render_trusted_groups`, `render_advisory_stack`, `render_skipped_readonly_advisory`, `render_wrapper_boundary_advisory` to `pub(crate) use`.
- [x] 4.2 Verify the new builders compile without re-promoting any of the above.

## 5. Snapshot coverage

- [x] 5.1 Add a per-builder integration test that exercises each `CheckOutput`, `EvalOutput`, and `TrustListing` with a representative fixture; commit the resulting snapshot.
- [x] 5.2 Run the existing snapshot suite (`cargo test --workspace`); confirm every existing snapshot remains green (byte-equivalent rendered output).

## 6. Verify

- [x] 6.1 Run `cargo check --workspace`.
- [x] 6.2 Run `cargo test --workspace`.
- [x] 6.3 Run `openspec validate output-pipeline-as-builder --strict`.
