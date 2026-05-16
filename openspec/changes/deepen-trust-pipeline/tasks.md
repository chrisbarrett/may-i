## 1. Behavioural pin

- [ ] 1.1 Inventory existing `tests/` integration tests covering `cmd_eval`, `cmd_check`, and `cmd_claude_code_hook` output; note any gaps where snapshots do not pin stdout+stderr bytes.
- [ ] 1.2 Add stdout+stderr snapshot tests where missing for the prelude-advisory and trust-warning paths, so any byte-level drift fails CI immediately.
- [ ] 1.3 Add an integration test for an invocation that triggers both an integrity advisory and an untrusted-program warning (covers the gate-owned ordering scenario in `trust-gate` and `command-pipeline`).

## 2. CommandPipeline skeleton

- [ ] 2.1 Create `src/pipeline.rs` (or `src/pipeline/mod.rs`) defining `CommandPipeline` per the design: owns `LoadResult`, `Terminal`, json flag, lazy trust state. Add `pub fn load(config_path, json) -> miette::Result<Self>` plus `&Config` / `&Terminal` / `&Path` / `bool` accessors.
- [ ] 2.2 Add `render_prelude_advisories(&mut self)` that, in text mode, renders migration note then integrity advisory to stderr. Make it idempotent via a `prelude_rendered: bool` flag.
- [ ] 2.3 Add a `with_store_loader` constructor variant that takes a `Box<dyn Fn() -> Option<TrustStore>>` so tests can count loads. Default `load` uses the real loader.
- [ ] 2.4 Wire `src/main.rs` to construct `CommandPipeline` once for `Eval`, `Check`, and the hook entry; pass it into each cmd. Keep `Migrate`, `Fmt`, `Trust`, `Parse`, `Reference` on the existing direct-load path.

## 3. Deepen the Trust gate

- [ ] 3.1 Create `src/trust/mod.rs` (or grow `src/trust_gate.rs` into a module). Move `TrustStore`, `trust_advisory::compute`, `filter_trusted_rules`, `build_warning_layout`, `write_integrity_advisories`, `UntrustedEntry`, `TrustState`, and the helpers (`load_store`, `json_block`, `hook_block`, `program_name`, `first_segment_text`, `segment_texts`) into this module as private items.
- [ ] 3.2 Replace `trust_gate::evaluate(config, command, mode) -> GateOutcome` with `CommandPipeline::consult_trust(&mut self, command, TrustMode) -> Result<(), TrustBlock>`. Filter the pipeline's config in place on Ok. Cache the loaded `TrustStore` on `self` so repeat calls reuse it.
- [ ] 3.3 Inside `consult_trust`, render any integrity advisory through the pipeline's stderr writer and the warning advisory through `output::render_advisory_stack` (introduced in stage 5). Order: integrity first, warning second, matching today.
- [ ] 3.4 Define `pub enum TrustMode { Text, Json, Hook }` and `pub struct TrustBlock { decision, reason, files }`. Both live in the new trust module.
- [ ] 3.5 Add the single-store-load property test: wrap loader via `CommandPipeline::with_store_loader`, run an end-to-end `cmd_eval` against a command that triggers both advisory and gate consultation, assert loader counter == 1.

## 4. Migrate cmd_eval, cmd_check, cmd_claude_code_hook

- [ ] 4.1 Rewrite `cmd_eval::cmd_eval` to take `&mut CommandPipeline` and a `&str` command + `&[String]` facts. Replace the local `load_and_resolve`, `Terminal::detect`, migration-note rendering, integrity-advisory rendering, `GateMode` dispatch, and `mem::take` ceremony with pipeline calls. Delete `evaluate_with_colorization`'s reliance on `LoadResult` shape if needed.
- [ ] 4.2 Rewrite `cmd_check::cmd_check` similarly. Replace per-failure `Layout::Columns(rows)` assembly (`src/cmd_check.rs:144`) with a `CheckFailureView` constructed in `cmd_check` and rendered by `output::render_check_failure` (introduced in stage 5). Replace the summary block with `output::render_check_summary`.
- [ ] 4.3 Rewrite `cmd_claude_code_hook::cmd_claude_code_hook` to take `&mut CommandPipeline`. Move `extract_command` and `build_context` calls before pipeline consultation; serialise the `TrustBlock` (on Err) via the existing `render_response` shape.
- [ ] 4.4 Delete `src/notes.rs`; remove the `pub mod notes;` line from `src/lib.rs`.
- [ ] 4.5 Make `src/trust_gate.rs`, `src/trust_advisory.rs`, `src/trust_store.rs` either disappear (rolled into `src/trust/`) or become `pub(crate)` shims with `#[doc(hidden)]`; remove their `pub use` from `src/lib.rs` where now-internal. Keep `cmd_trust` working — it may stay on `TrustStore` directly per the `trust-gate` spec's cmd_trust carve-out.

## 5. Seal the output module

- [ ] 5.1 Add intent operations to `crate::output`: `render_eval_result`, `render_check_failure`, `render_check_summary`, `render_trace` (rename of `write_trace`), `render_advisory_stack`. Define `CheckFailureView` as the cmd_check → output handoff struct.
- [ ] 5.2 Move the `cmd_check` per-failure layout assembly (label header, key-value rows for expected/actual/context/reason, separator, trace block) into `output::check::render_check_failure`. Move the summary block into `output::check::render_check_summary`.
- [ ] 5.3 Move `cmd_eval::write_eval_output` body (or its layout assembly) into `output::eval_result::render_eval_result`; keep colorisation helpers (`colorize_text`, `colorize_segments`, `strictest_overlapping`) where they currently live or move with the rendering — your call, but document.
- [ ] 5.4 Drop the `pub use may_i_layout::{Advisory, ColAlign, ColContent, ColItem, ColRow, HRuleLabel, Layout, Note, NoteLevel}` from `src/output/mod.rs:20-23`. Keep `Terminal`, `write_layout`, `strip_ansi`. Add a grep-based test (or rely on compile errors) to confirm no `cmd_*.rs` or `main.rs` references the removed types.
- [ ] 5.5 Make `print_separator`, `render_elements`, `print_trace` either private to `output` or remove them if subsumed. `interactive.rs` may still use `output::Terminal` and `output::write_layout` — confirm no Layout-construction usage.

## 6. Spec hygiene edits (no requirement changes)

- [ ] 6.1 Update `openspec/specs/trust-advisory-boxes/spec.md` Purpose paragraph to reference `command-pipeline` and the new `output-rendering` spec as related, since the orchestration responsibility moves. Content of requirements unchanged.
- [ ] 6.2 Update `openspec/specs/harness-integration/spec.md` Purpose paragraph to note that the hook entry consumes a `CommandPipeline`. Content of requirements unchanged.
- [ ] 6.3 Update `openspec/specs/traces/spec.md` Purpose paragraph if any wording referenced `crate::output::Layout`-level APIs; align to the new intent-operation surface. Content of requirements unchanged.

## 7. Verify

- [ ] 7.1 `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`.
- [ ] 7.2 `cargo test --workspace`. Confirm all existing snapshot tests pass without modification; investigate any drift before accepting.
- [ ] 7.3 `cargo tarpaulin`; inspect `lcov.info` for newly uncovered branches in `src/pipeline.rs`, `src/trust/`, and the new `output` submodules; add proptests or surgical unit tests for any gaps.
- [ ] 7.4 `openspec validate deepen-trust-pipeline --strict`.
- [ ] 7.5 Run `may-i` against a real config (with and without `Loaded` rules; with and without an integrity-corrupt store) and confirm prelude output ordering matches expectations.
- [ ] 7.6 Grep audit: zero matches for `Layout::`, `ColRow::`, `ColItem::`, `HRuleLabel`, `mem::take(&mut loaded.config)`, `Box<Config>` in `src/cmd_*.rs` and `src/main.rs`.
