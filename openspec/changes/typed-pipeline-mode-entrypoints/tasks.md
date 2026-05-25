## 1. Failing tests pin the new shape

- [x] 1.1 In `src/pipeline.rs` tests, replace `run_check_invokes_closure`, `run_hook_short_circuits_on_block`, and `run_eval_invokes_closure_when_trust_allows` with equivalents that call `run_check` / `run_hook` / `run_eval` directly and return the matching typed body. Tests should currently fail to compile against the existing `run<F>`.
- [x] 1.2 Add a `store_loads_once_per_invocation` variant that exercises the prelude path through `run_eval` (preserving the existing single-load invariant).
- [x] 1.3 Add a test asserting `cmd_check` cannot accidentally produce an `EvalOutcomeBody` — i.e. the closure passed to `run_check` is typed `FnOnce(&EvalContext<'_>) -> miette::Result<CheckOutcomeBody>`. A `trybuild` compile-fail test (or a doctest using `compile_fail`) is fine; alternatively, document the invariant as a comment if `trybuild` is not already a dev-dep.
- [x] 1.4 Move existing outcome-renderer tests (`eval_text_writes_result_block`, `eval_json_writes_decision_reason_trace`, `check_text_writes_summary`, `check_json_writes_envelope`, `hook_writes_envelope_regardless_of_json_flag` in `src/output/outcome.rs`) into renderer-specific tests beside their target functions (or fold into pipeline integration tests once `outcome.rs` is deleted).

## 2. Introduce per-mode entry points alongside legacy `run`

- [x] 2.1 Extract a private `CommandPipeline::prelude_and_trust(command, trust_mode, consult, warn_after) -> Result<(), TrustBlock>` helper that captures the shared flow currently lifted from `run` (prelude → trust consult or warning → block on Err). Move all `self.json` consultation for trust-mode/warn selection into its callers.
- [x] 2.2 Add `CommandPipeline::run_eval<F>(&mut self, command: &str, f: F) -> miette::Result<()>` where `F: FnOnce(&EvalContext<'_>) -> miette::Result<EvalOutcomeBody>`. Drives `prelude_and_trust` with `consult = true, warn_after = !json`, runs the closure, calls a new `output::render_eval(stdout, term, json, body)`.
- [x] 2.3 Add `CommandPipeline::run_check<F>(&mut self, f: F) -> miette::Result<()>` where `F: FnOnce(&EvalContext<'_>) -> miette::Result<CheckOutcomeBody>`. Drives `prelude_and_trust` with `consult = false, warn_after = false`, then calls a renamed-or-extracted `output::render_check(stdout, term, json, body)`. (Check still renders trust warning per the existing spec; route through `prelude_and_trust`.)
- [x] 2.4 Add `CommandPipeline::run_hook<F>(&mut self, command: &str, f: F) -> miette::Result<()>` where `F: FnOnce(&EvalContext<'_>) -> miette::Result<EvalResult>`. Drives `prelude_and_trust` skipping the prelude (Hook is JSON-only), `consult = true`. On allow, calls a new `output::render_hook(stdout, &result)`.

## 3. Move and split renderers under `src/output/`

- [x] 3.1 Add `output::render_eval(w: &mut impl Write, term: &Terminal, json: bool, body: &EvalOutcomeBody)` that internally branches on `json` and delegates to the existing text and JSON helpers (`EvalOutput::render`, `trace_to_json`). Lift body from `output/outcome.rs::render_eval_text` and `render_eval_json`.
- [x] 3.2 Add `output::render_check(w, term, json, body: &CheckOutcomeBody)` similarly, lifting from `render_check_text` / `render_check_json`.
- [x] 3.3 Add `output::render_hook(w, &EvalResult)` that emits the hook JSON envelope (lifted from the `EvalOutcome::Hook` arm in `output::render_eval_outcome`).
- [x] 3.4 Split `output::render_trust_block` into `output::render_eval_trust_block(stdout, stderr, term, &block, json)` and `output::render_hook_trust_block(stdout, &block)`. Drop the `InvocationMode` parameter.

## 4. Switch evaluation subcommands to the new entry points

- [x] 4.1 `src/cmd_eval.rs`: replace the `pipeline.run(InvocationMode::Eval, command, |ctx| Ok(EvalOutcome::Eval(EvalOutcomeBody { … })))` call with `pipeline.run_eval(command, |ctx| Ok(EvalOutcomeBody { … }))`. The closure body and `evaluate_with_colorization` stay unchanged.
- [x] 4.2 `src/cmd_check.rs`: replace `pipeline.run(InvocationMode::Check, "", |ctx| Ok(EvalOutcome::Check(CheckOutcomeBody { … })))` with `pipeline.run_check(|ctx| Ok(CheckOutcomeBody { … }))`.
- [x] 4.3 `src/cmd_claude_code_hook.rs`: replace `pipeline.run(InvocationMode::Hook, command, |ctx| Ok(EvalOutcome::Hook(eval_result)))` with `pipeline.run_hook(command, |ctx| Ok(eval_result))`.
- [x] 4.4 Run `cargo check` and confirm zero references to `pipeline::InvocationMode`, `pipeline::EvalOutcome`, `pipeline::CommandPipeline::run` (the legacy method), or `output::render_eval_outcome` remain anywhere in the workspace (including `tests/`).

## 5. Delete the legacy surface

- [x] 5.1 Delete `pipeline::InvocationMode`, `into_trust_mode`, and the legacy `CommandPipeline::run<F>` method. Each `TrustMode` value is now picked at the `run_*` call site.
- [x] 5.2 Delete `pipeline::EvalOutcome` (the enum). Keep `EvalOutcomeBody`, `CheckOutcomeBody`, and `EvalContext` — they remain the per-method body / borrowed payload.
- [x] 5.3 Delete `src/output/outcome.rs` (its body now lives in 3.1–3.3 and in the `run_*` methods). Remove the `mod outcome;` declaration and the `pub use self::outcome::render_eval_outcome;` re-export from `src/output/mod.rs`.
- [x] 5.4 Delete the original `output::render_trust_block` once 3.4's replacements compile. Update `src/output/mod.rs` re-exports.

## 6. Verification

- [x] 6.1 `cargo fmt`
- [x] 6.2 `cargo check --workspace --all-targets`
- [x] 6.3 `cargo test --workspace` — all green; the legacy outcome-dispatcher tests have moved per 1.4.
- [x] 6.4 Grep guard: `! rg --no-messages 'InvocationMode|EvalOutcome::|render_eval_outcome' src/ tests/ crates/` returns no hits.
- [x] 6.5 Manual smoke: `echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"}}' | cargo run --quiet --` produces the same hook envelope as before. `cargo run -- eval "echo hi"` and `cargo run -- eval --json "echo hi"` produce the same text / JSON output as before. `cargo run -- check` runs cleanly against the example configs.
- [x] 6.6 `cargo tarpaulin` (per `CLAUDE.md`): coverage on `src/pipeline.rs` and new `output::render_*` helpers does not regress against `lcov.info` baseline.
- [x] 6.7 `openspec validate typed-pipeline-mode-entrypoints` passes.
