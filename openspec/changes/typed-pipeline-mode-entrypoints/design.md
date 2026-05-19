## Context

`CommandPipeline` was deepened in a prior change so all three
evaluation subcommands (`cmd_eval`, `cmd_check`,
`cmd_claude_code_hook`) drive their flow through one
`run<F>(InvocationMode, command, F)` method. The closure returns an
`EvalOutcome` enum whose variants mirror `InvocationMode`, and
`output::render_eval_outcome` re-dispatches on the enum + the
pipeline's `json` flag to pick a text-or-JSON renderer.

State of the relevant files (line numbers as of `src/pipeline.rs`,
`src/output/outcome.rs`):

- `pipeline.rs:30-44` — `InvocationMode` enum with `Eval`, `Check`,
  `Hook` variants.
- `pipeline.rs:46-57` — `InvocationMode::into_trust_mode(json)`
  projection.
- `pipeline.rs:65-71` — `EvalContext<'a>` borrowed payload.
- `pipeline.rs:76-102` — `EvalOutcome` enum and the per-mode body
  types `EvalOutcomeBody`, `CheckOutcomeBody`.
- `pipeline.rs:237-290` — `run<F>(mode, command, F)`, switching on
  mode for prelude / trust-warning / trust-block paths.
- `output/outcome.rs:18-56` — `render_eval_outcome` second mode
  switch, branching on enum × json.
- `output/outcome.rs:58-132` — four small renderers
  (`render_eval_text`, `render_eval_json`, `render_check_text`,
  `render_check_json`) plus the inline Hook JSON envelope.

The shape works but the mode-to-outcome correspondence is enforced
only at runtime. The same mode value is consumed in two switch sites
(`run`, then `render_eval_outcome`). Mode-specific logic is split
across both. Tests already cover each mode independently
(`run_check_invokes_closure`, `run_hook_short_circuits_on_block`,
`run_eval_invokes_closure_when_trust_allows`, and the four tests in
`outcome.rs`).

## Goals / Non-Goals

**Goals:**

- Make mode-to-body mismatch a compile error, not a runtime
  misrender.
- Replace one overloaded `run<F>` with three focused entry points,
  each readable top-to-bottom.
- Remove the `EvalOutcome` enum + `render_eval_outcome` dispatcher
  (Hickey-style "deletion test" pass — the enum exists only to bridge
  two switch sites that should not exist).
- Preserve every user-visible behaviour: stdout/stderr byte streams,
  JSON shapes, exit codes, hook envelope, trust-block phrasing.
- Preserve the single-trust-store-load invariant and the prelude
  idempotency invariants.

**Non-Goals:**

- Deepening Trust (separate candidate; not in scope).
- Changing engine, config, or trust-store crates.
- Renaming or moving the body structs (`EvalOutcomeBody`,
  `CheckOutcomeBody`) — they stay, minus the enum wrapper.
- Eliminating `EvalContext` — it remains useful as the borrowed
  payload handed to each closure.

## Decisions

### D1. Three methods on `CommandPipeline`, not a trait or generic dispatcher

```rust
impl CommandPipeline {
    pub fn run_eval<F>(&mut self, command: &str, f: F) -> miette::Result<()>
    where F: FnOnce(&EvalContext<'_>) -> miette::Result<EvalOutcomeBody>;

    pub fn run_check<F>(&mut self, f: F) -> miette::Result<()>
    where F: FnOnce(&EvalContext<'_>) -> miette::Result<CheckOutcomeBody>;

    pub fn run_hook<F>(&mut self, command: &str, f: F) -> miette::Result<()>
    where F: FnOnce(&EvalContext<'_>) -> miette::Result<EvalResult>;
}
```

Each method:
1. Calls a private `prelude_then_trust(command, trust_mode)` helper
   that captures the shared flow (prelude advisories, trust
   consultation or warning, mode-shaped trust-block emission). Returns
   `ControlFlow::Continue(())` on allow, `ControlFlow::Break(())`
   after emitting the block.
2. On Continue, builds `EvalContext`, invokes the closure, hands the
   typed body to a mode-specific renderer.

**Why methods, not a trait:** the three flows share roughly half their
body (prelude + trust) but their bodies and renderers differ in
sequence, types, and which writers they use. A trait
`PipelineMode<Body, Renderer>` would expose the same surface area as
three methods, plus a trait. Methods are the simpler shape.

**Why not generics on `run<Mode>`:** mode-dependent renderer selection
forces either an associated type or a `match` inside the generic body
— neither buys anything over three named methods.

**Alternatives rejected:**

- Keep `run` + `EvalOutcome`, add a phantom-type witness to enforce
  mode/body correspondence. Adds complexity without removing the dual
  dispatch.
- Make each command an impl of a `Subcommand` trait with `mode()` and
  `handle()` methods on the trait. Pushes the mode switch into trait
  resolution — worse cognitive load.

### D2. Delete `InvocationMode` and `EvalOutcome`

`InvocationMode` exists only to drive (a) the `run` switch and (b)
`into_trust_mode`. Once each `run_*` method picks `TrustMode` at the
call site, the enum's only remaining job is identifying which closure
ran — which the method name already encodes. Delete it.

`EvalOutcome` carries no information once each closure returns the
matching body type directly. Delete it.

`TrustMode` survives unchanged — it is still the gate's mode
projection and used by `trust::check_block`.

### D3. Rendering moves to per-mode helpers under `src/output/`

Today `output/outcome.rs` houses:
- The dispatcher (`render_eval_outcome`) — delete.
- Four small renderers — keep but expose as
  `output::render_eval(text|json)` and
  `output::render_check(text|json)` (or, simpler: one
  `output::render_eval(stdout, term, json, body)` per body type that
  internally branches on `json`).

Pick **the per-body single fn**:

- `output::render_eval(w, term, json, body)`
- `output::render_check(w, term, json, body)`
- `output::render_hook(w, hook_body)` (no `json` arg — hook is JSON
  only)

Each method on `CommandPipeline` calls exactly one renderer. The
`json` branch lives inside the body-specific renderer, not in the
caller — `pipeline.run_*` does not consult `self.json` to choose a
renderer; it passes `self.json` through. This preserves the existing
contract that "no handler-side json branch" stays true (handlers don't
touch `json`; pipeline forwards it once into the renderer).

### D4. Trust-block emission becomes per-mode helpers

`output::render_trust_block(stdout, stderr, term, &block, mode)`
currently switches on `InvocationMode` internally. With `mode` gone,
split into:

- `output::render_eval_trust_block(stdout, stderr, term, &block, json)`
- `output::render_hook_trust_block(stdout, &block)`

`Check` mode never produces a block (trust gate is not consulted), so
no Check helper exists. Each `run_*` method calls its own block helper
inline.

### D5. Shared private helper inside `CommandPipeline`

```rust
fn prelude_and_trust(
    &mut self,
    command: &str,
    trust_mode: TrustMode,
    consult: bool,         // false for Check
    warn_after: bool,      // true for Eval text mode
) -> Result<EvalContext<'_>, TrustBlock>;
```

Drives prelude advisories (skipped for Hook), trust consultation (when
`consult`), optional warning advisory (Eval text only), and builds the
borrowed context. Returns `Err(block)` to short-circuit. Each `run_*`
calls this once. The body lifts existing logic from `run` lines
237–290 without changing the per-mode sequence.

This is the only place that consults the pipeline's `json` flag for
routing (to decide `TrustMode` and whether the warning advisory
fires).

## Risks / Trade-offs

- **[Risk] Three methods duplicate prelude/trust glue.** Mitigation:
  `prelude_and_trust` is shared; each `run_*` body shrinks to ~10
  lines (helper + closure + renderer + block branch).
- **[Risk] Spec `command-pipeline` requirement "Pipeline owns
  evaluation flow via a single run entry" reads as load-bearing.**
  Mitigation: this change explicitly modifies that requirement.
  Per-mode methods preserve the spirit (subcommands drive nothing
  themselves) while killing the runtime invariant. Documented in the
  delta spec.
- **[Trade-off] Slight binary-size / monomorphisation increase from
  three generic `run_*` methods vs one.** Negligible for a CLI;
  ignored.
- **[Risk] `tests/migrated_v1_trace.rs` (integration test) imports
  `pipeline` types.** Mitigation: integration tests touch
  `EvalOutcome` only through `pipeline::run`; sweep with `cargo
  check` after refactor.
- **[Risk] `cmd_claude_code_hook` lives in `src/main.rs`'s neighbour
  (file is `src/cmd_claude_code_hook.rs`) and re-uses the public
  `EvalContext`.** Mitigation: `EvalContext` stays public, so the
  hook closure still works with `run_hook`.
