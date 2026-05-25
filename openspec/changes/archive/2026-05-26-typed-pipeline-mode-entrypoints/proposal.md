## Why

`CommandPipeline::run(mode, command, closure)` enforces the
mode-to-outcome invariant at runtime: handlers return an `EvalOutcome`
enum, then `output::render_eval_outcome` re-dispatches on the same enum
plus the `json` flag. A `cmd_check` closure that returns
`EvalOutcome::Eval` typechecks and silently misrenders. Two parallel
mode switches — one in `pipeline::run`, one in `output::outcome` — drift
independently, and every cross-mode behaviour change lands in one
overloaded `run<F>` body.

## What Changes

- **BREAKING (contributor API only):** Replace
  `CommandPipeline::run<F>(mode, command, F)` with three typed entry
  points: `run_eval(command, |ctx| EvalOutcomeBody)`,
  `run_check(|ctx| CheckOutcomeBody)`, `run_hook(command, |ctx|
  EvalResult)`. Mode-shape mismatches become compile errors.
- Remove the `EvalOutcome` enum and `InvocationMode` (the type is
  redundant once each mode has its own method).
- Remove the central `output::render_eval_outcome` dispatcher; rendering
  moves next to (or is called directly from) the matching `run_*`
  method.
- Trust-block rendering keeps a single sanctioned helper
  (`output::render_trust_block`) but loses the `InvocationMode`
  parameter; the two block shapes (Eval JSON envelope vs Hook
  envelope) become two helpers selected by the calling `run_*` method.
- `cmd_eval`, `cmd_check`, `cmd_claude_code_hook` call exactly one
  `run_*` method each; the `pipeline.json()` flag is consulted only
  inside `run_eval` / `run_check`.

## Capabilities

### New Capabilities

_(none)_

### Modified Capabilities

- `command-pipeline`: replaces the single-`run`-entry contract with
  per-mode entry points; removes the `EvalOutcome` enum requirement
  and the centralised result-dispatcher requirement; tightens
  trust-block serialisation to per-mode helpers.

## Impact

- `src/pipeline.rs` — replace `run<F>` + `EvalOutcome` + `EvalContext`
  glue with three methods sharing a private `prelude_and_trust` helper.
  Delete `InvocationMode` and its `into_trust_mode` projection;
  `TrustMode` is picked directly at each call site.
- `src/output/outcome.rs` — deleted; its body folds into the three
  `run_*` methods or into per-mode renderers under `src/output/`.
- `src/cmd_eval.rs`, `src/cmd_check.rs`, `src/cmd_claude_code_hook.rs`
  — each switches from `pipeline.run(Mode::X, …)` to
  `pipeline.run_x(…)`.
- Tests in `src/pipeline.rs` (`run_check_invokes_closure`,
  `run_hook_short_circuits_on_block`, `run_eval_invokes_closure_*`,
  `into_trust_mode_projections`) and in
  `src/output/outcome.rs` migrate to the new entry points.
- No engine-crate, config-crate, or trust-spec changes. No user-facing
  surface changes (CLI flags, exit codes, JSON shapes preserved).
