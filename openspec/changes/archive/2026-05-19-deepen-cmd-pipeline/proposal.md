## Why

The archived `deepen-trust-pipeline` change pulled trust loading, integrity
advisories, and the migration note into `CommandPipeline` — *state* is now
owned in one place. But *flow* still isn't: every evaluation handler
(`cmd_eval`, `cmd_check`, `cmd_claude_code_hook`) hand-threads the same
sequence `render_prelude_advisories` → `consult_trust` → (build context →
evaluate) → pick a renderer. Adding a new evaluation subcommand still
means copying the dance, and the trust-block error paths have already
diverged between `eval` (prints `{decision,reason,files}` then exits Ok)
and `hook` (wraps in `hookSpecificOutput`). Renderer selection
(text vs JSON) is duplicated as an `if pipeline.json() { … } else { … }`
fork in every handler.

The fix is to let the pipeline own *flow* as well as state: `pipeline.run`
takes a domain-only closure, executes the prelude and trust consultation
itself, maps trust-blocks through one mode-aware renderer, and dispatches
the closure's output through one mode-aware result renderer. Handlers
shrink to "build context, evaluate, produce a result payload"; the
trust-block-shape invariant (`Decision::Ask` + reason + files,
mode-shaped serialisation) is enforced in one place.

## What Changes

- Add `CommandPipeline::run(mode, |ctx| { … } -> Outcome) -> miette::Result<()>`
  that owns the prelude (advisories), trust consultation, trust-block →
  mode-shaped response mapping, and renderer dispatch (text vs JSON) for
  the closure's `Outcome`.
- Define a typed `EvalContext<'a>` (config, terminal, config_path,
  display_path, parsed facts) handed to the closure — the closure does
  not see `&mut CommandPipeline`.
- Define an `EvalOutcome` ADT carrying the renderable result (eval
  result + traces + colorised command, or check results, etc.) with
  shared text/JSON rendering paths inside `output`.
- Unify the trust-block emission path: `cmd_eval` and `cmd_claude_code_hook`
  stop hand-rolling the JSON payload. Hook mode still wraps in
  `hookSpecificOutput`; the mapping lives in pipeline + output, not in
  the handler.
- Migrate `cmd_eval`, `cmd_check`, and `cmd_claude_code_hook` to the
  `run` shape. `cmd_migrate`, `cmd_fmt`, `cmd_trust`, `cmd_parse`,
  `cmd_help` keep their existing entry shape (they do not evaluate
  commands).
- Move text-vs-JSON renderer selection out of every handler into a
  single `output::render_eval_outcome` (or sibling) call sites driven by
  the pipeline.
- **BREAKING (contributor surface only)**: `cmd_eval::cmd_eval`,
  `cmd_check::cmd_check`, and `cmd_claude_code_hook::cmd_claude_code_hook`
  change signature (no longer take `&mut CommandPipeline` directly).
  `CommandPipeline::consult_trust`, `render_prelude_advisories`, and
  `render_trust_warning` become `pub(crate)` or private — handlers
  consume the new `run` entry point. No user-visible behaviour change;
  existing snapshot tests pin output bytes.

## Capabilities

### New Capabilities

_None._ The `command-pipeline` capability already covers the per-invocation
orchestration object; this change deepens its requirements rather than
adding a sibling spec.

### Modified Capabilities

- `command-pipeline`: pipeline owns *flow* — the prelude + trust + error
  mapping + renderer dispatch sequence — not just per-invocation state.
  A `run`-style entry point becomes the sole orchestration surface for
  evaluation subcommands; the previous step-by-step accessor surface
  (`render_prelude_advisories`, `consult_trust`, `render_trust_warning`
  called individually by handlers) is retracted in favour of the
  single-entry shape. Handlers contribute domain logic only.
- `trust-gate`: the "Caller does not move the config" and "Subcommand
  bypass forbidden" scenarios tighten — trust-block payloads SHALL be
  rendered through the pipeline's mode-aware path, not hand-serialised
  per handler. The single-store-load invariant is unchanged.

(`output-rendering` gains a `render_eval_outcome` / `render_trust_block`
pair, but these are implementation-detail additions to an existing
module without changing rendered bytes. Per spec-conventions, that
edit lives in `tasks.md` rather than as a spec delta — the existing
requirements already cover "cmd modules do not assemble Layout" and
"eval and check output go through intent operations".)

## Impact

- **Code**: `src/pipeline.rs` (add `run`, `EvalContext`, `EvalOutcome`,
  trust-block renderer; demote prelude/trust accessors to `pub(crate)`
  or private). `src/cmd_eval.rs`, `src/cmd_check.rs`,
  `src/cmd_claude_code_hook.rs` (shrink to closures handed to `run`).
  `src/main.rs` (dispatch through `pipeline.run` instead of separate
  `cmd_*` calls). `src/output/` (add `render_eval_outcome`,
  `render_trust_block`; move text-vs-JSON fork inside).
- **APIs (contributor)**: `cmd_eval::cmd_eval` and the other evaluation
  handler signatures change; `cmd_eval::evaluate_with_colorization`
  becomes the body of an `EvalOutcome` constructor. The
  `CommandPipeline` public method set shrinks (one `run`, plus
  accessors retained for `cmd_trust`/non-evaluation needs).
- **Tests**: existing snapshot and integration tests under `tests/`
  pin byte-for-byte output and must pass unchanged. New unit tests
  cover the `run`-shape contract: trust-block rendering for each
  `TrustMode`, error-diag → ask flooring routed through one path,
  prelude ordering preserved.
- **User-visible behaviour**: none. Output bytes, exit codes, and the
  Claude Code hook JSON shape remain unchanged.
- **Dependencies**: none added or removed.
