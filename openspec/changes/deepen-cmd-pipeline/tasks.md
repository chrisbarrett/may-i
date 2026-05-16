## 1. Behavioural pin

- [ ] 1.1 Inventory `tests/` snapshots covering `cmd_eval`, `cmd_check`, and `cmd_claude_code_hook` for both text and JSON modes; note any gap (eval JSON trust-block, hook trust-block, check verbose-with-warning) where stdout+stderr bytes are not pinned.
- [ ] 1.2 Add stdout+stderr snapshot coverage for any gap surfaced in 1.1, so any byte drift in the upcoming refactor fails CI immediately.
- [ ] 1.3 Add an integration test for a trust-block invocation in `InvocationMode::Hook` to pin the `hookSpecificOutput` envelope; ditto for `InvocationMode::Eval` + JSON to pin the `{decision,reason,files}` shape.

## 2. Sketch the run signature and closure interface

- [ ] 2.1 In `src/pipeline.rs` add `pub enum InvocationMode { Eval, Check, Hook }` with doc-comments naming each mode's flow (prelude on/off, consult-vs-warning, json shape). Add `fn into_trust_mode(self, json: bool) -> TrustMode`.
- [ ] 2.2 Add `pub struct EvalContext<'a>` holding `&'a Config`, `&'a LoadResult`, `&'a Terminal`, `&'a Path` (config_path), and `String` (display_path = `shorten_home(config_path)`). No `&mut CommandPipeline` field — handlers must not re-drive the pipeline.
- [ ] 2.3 Add `pub enum EvalOutcome` with variants `Eval(EvalOutcomeBody)`, `Check(CheckOutcomeBody)`, `Hook(may_i_engine::EvalResult)`. Define the two body structs as the closure-to-output handoff carriers (eval: command, colored, result, traces, display_path; check: results, verbose, passed, failed, display_path).
- [ ] 2.4 Add `pub fn run<F>(&mut self, mode: InvocationMode, command: &str, closure: F) -> miette::Result<()> where F: FnOnce(&EvalContext<'_>) -> miette::Result<EvalOutcome>;`. Inline the prelude → trust-or-warning → closure → render-outcome flow per design Decision 1.

## 3. Factor trust-block into one path

- [ ] 3.1 Add `pub fn render_trust_block(stdout, stderr, terminal, block, mode)` to `src/output/` (likely a new `src/output/trust_block.rs`) covering all three modes per design Decision 2. Match the existing byte shapes from `cmd_eval.rs:27-38` and `cmd_claude_code_hook.rs:30-36 + 110-119`.
- [ ] 3.2 Wire `pipeline::run`'s trust-block path to call `output::render_trust_block` exactly once when `consult_trust` returns `Err`; on hook mode this also short-circuits the closure (handler is never invoked).
- [ ] 3.3 Unit-test `render_trust_block` for each `InvocationMode` against fixed `TrustBlock` values; assert exact byte output (or snapshot).

## 4. Add the outcome renderer

- [ ] 4.1 Add `pub fn render_eval_outcome(stdout, stderr, terminal, json, outcome)` to `src/output/` (likely `src/output/outcome.rs`) that matches on `EvalOutcome` and dispatches to existing text intent operations (`render_eval_result`, `render_check_failure`, `render_check_summary`, `render_labelled_separator`) or JSON shapers (`render_check_results_json`, the eval JSON builder lifted from `cmd_eval.rs:41-79`, the hook response builder lifted from `cmd_claude_code_hook.rs:111-119`).
- [ ] 4.2 Move the eval JSON builder (currently inline in `cmd_eval.rs`) into `output::render_eval_outcome`'s JSON arm. Move the hook `render_response` body likewise.
- [ ] 4.3 Snapshot-test `render_eval_outcome` for each `(EvalOutcome, json)` combination against existing fixture data.

## 5. Migrate cmd_eval to run

- [ ] 5.1 Rewrite `cmd_eval::cmd_eval` to parse facts and call `pipeline.run(InvocationMode::Eval, command, |ctx| { … })`. The closure calls `evaluate_with_colorization`, appends parse-diagnostic trace entries, prints any parse-diagnostic miette reports to stderr (this is a side-effect within the closure, not a renderer call — it is a user-feedback diagnostic, allowed), and returns `EvalOutcome::Eval(EvalOutcomeBody { … })`.
- [ ] 5.2 Delete the in-handler `if pipeline.json() { … } else { … }` fork and the in-handler trust-block serialisation. Confirm via grep: zero `serde_json` references in `src/cmd_eval.rs`.
- [ ] 5.3 Confirm all eval snapshot tests pass byte-for-byte.

## 6. Migrate cmd_check to run

- [ ] 6.1 Rewrite `cmd_check::cmd_check` to call `pipeline.run(InvocationMode::Check, "", |ctx| { … })`. The empty command string is the closure's signal that `cmd_check` evaluates many checks itself (the `command` arg to `run` is unused on the trust-warning path; document this on `InvocationMode::Check`). The closure runs `run_checks_with_traces` and returns `EvalOutcome::Check(CheckOutcomeBody { … })`.
- [ ] 6.2 Move the `CheckFailureView` assembly out of `cmd_check::cmd_check` if it survived stage 4.1 there; it now lives in `output::render_eval_outcome`'s check-text arm. Move the per-failure loop, the labelled-separator emission, and the summary emission likewise.
- [ ] 6.3 The `CheckFailure` exit-1 signal stays — `cmd_check::cmd_check` inspects the outcome's failed-count after `run` returns and emits `CheckFailure(failed).into()` as before. Document why this lives outside `run` (exit-code semantics are clap-driver concerns).
- [ ] 6.4 Confirm all check snapshot tests pass byte-for-byte.

## 7. Migrate cmd_claude_code_hook to run

- [ ] 7.1 Rewrite `cmd_claude_code_hook::cmd_claude_code_hook` to extract the command and build the context facts before calling `pipeline.run(InvocationMode::Hook, &command, |ctx| { … })`. The closure runs `evaluate_command`, wraps the result in `EvalOutcome::Hook(result)`.
- [ ] 7.2 Delete the in-handler trust-block serialisation (currently `cmd_claude_code_hook.rs:30-36`). Delete the in-handler `render_response` call site (the body moves into `output::render_eval_outcome` per task 4.2).
- [ ] 7.3 Confirm all hook snapshot tests pass byte-for-byte.

## 8. Shrink the pipeline's public surface

- [ ] 8.1 Demote `CommandPipeline::render_prelude_advisories`, `consult_trust`, `render_trust_warning` from `pub` to `pub(crate)` (or private if only `run` calls them). The unit tests in `src/pipeline.rs` still need access — keep `pub(crate)` so the existing tests compile.
- [ ] 8.2 Update `src/main.rs` to dispatch `Eval`, `Check`, and the default-no-subcommand hook entry through the handler functions only (no direct `pipeline.consult_trust` calls — there are none today; this is a pin against regression).
- [ ] 8.3 Audit `src/lib.rs` re-exports: confirm `CommandPipeline::run`, `InvocationMode`, `EvalContext`, `EvalOutcome` (and bodies if needed) are `pub` where binary handlers in `src/cmd_*.rs` and `src/main.rs` need them.

## 9. Spec hygiene edits (no requirement changes)

- [ ] 9.1 Update `openspec/specs/output-rendering/spec.md` Purpose paragraph to mention `render_eval_outcome` and `render_trust_block` as the new top-level intent operations. Existing requirements unchanged.

## 10. Verify

- [ ] 10.1 `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`.
- [ ] 10.2 `cargo test --workspace`. All existing snapshot tests pass without modification.
- [ ] 10.3 `cargo tarpaulin`; inspect `lcov.info` for newly uncovered branches in `src/pipeline.rs::run`, `src/output/trust_block.rs`, and `src/output/outcome.rs`. Prefer proptests; add surgical unit tests for hard-to-hit branches (e.g. each `(InvocationMode, json)` combination of `render_eval_outcome`, each `InvocationMode` of `render_trust_block`).
- [ ] 10.4 `openspec validate deepen-cmd-pipeline --strict`.
- [ ] 10.5 Run `may-i eval`, `may-i check`, and a hook-mode JSON payload against a real config (trusted, untrusted-program, corrupt-store cases) and confirm output bytes match pre-refactor.
- [ ] 10.6 Grep audit: zero matches in evaluation `cmd_*` modules for `render_prelude_advisories`, `consult_trust`, `render_trust_warning`, `pipeline.json()`, `serde_json::json!`, or `TrustBlock` field accesses inside output macros.
