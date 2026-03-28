## Why

The v2 syntax migration deleted the trace system. The installed v0.0.3 binary
produces rich two-column evaluation traces showing which rules matched and why;
the current HEAD just prints `Decision: Allow`. The `may-i check` command is
also gutted — it validates config syntax but no longer runs embedded checks as
test assertions. Without traces, users can't debug why a command was
allowed/denied, and without checks, config validation is superficial.

## What Changes

- Replace the current evaluator's monomorphic return type with a generic fold
  (zygomorphism) so evaluation and trace annotation compose in a single
  traversal
- Delete the unused `trace.rs` types and drop the `trace` field from
  `EvalResult` and `CheckResult`
- Restore `cmd_eval` to print two-column annotated traces (terminal and JSON)
- Restore `cmd_check` to run embedded checks with pass/fail reporting and traces
  on failure
- Recover the two-column renderer from git history (v0.0.3 `output.rs`) and
  adapt it to the new annotation types

## Capabilities

### New Capabilities

- `eval-fold-trait`: The `EvalFold` trait that parameterises the evaluator over
  its output type, enabling the zygomorphism where evaluation and annotation run
  in one pass
- `tracing-fold`: The `TracingFold` implementation that produces
  `(EffectResult, Doc<Ann>)` pairs, living in the CLI binary so `Doc` never
  enters the engine crate
- `trace-rendering`: Two-column terminal renderer and JSON serialiser operating
  on `Doc<Ann>` trees

### Modified Capabilities

- `human-evaluation-trace`: Annotation types change from old `EvalAnn` to new
  `Ann` enum adapted for v2 AST; rendering behaviour and output format are
  preserved
- `top-level-checks`: Check runner uses `PureFold` internally; CLI check command
  restored with full trace-on-failure output

## Impact

- `crates/engine/src/eval.rs` — evaluator functions become generic over
  `F: EvalFold`
- `crates/engine/src/lib.rs` — `EvalResult` loses `trace` field; new exports
- `crates/engine/src/trace.rs` — deleted entirely
- `crates/engine/src/check.rs` — `CheckResult` loses `trace` field
- `src/cmd_eval.rs` — full restoration with `TracingFold`
- `src/cmd_check.rs` — full restoration with `TracingFold`
- `src/output.rs` — recovered from v0.0.3 git history, adapted
- `src/annotation.rs` — new file: `Ann` enum + `TracingFold` impl
