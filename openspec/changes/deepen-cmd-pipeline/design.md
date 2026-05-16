## Context

The archived `deepen-trust-pipeline` (2026-05-17) introduced
`CommandPipeline` to own per-invocation state — `LoadResult`, `Terminal`,
json flag, and a lazily-loaded trust store. It deliberately did *not*
own flow: the design's Decision 1 explicitly rejected the
`pipeline.run(|ctx| { … })` shape as "control-inversion with no real
benefit". That call landed early enough that we now have evidence to
revisit it.

Today every evaluation handler repeats the same sequence:

```rust
// src/cmd_eval.rs (after the archived refactor):
pub fn cmd_eval(pipeline: &mut CommandPipeline, command: &str, raw_facts: &[String]) -> miette::Result<()> {
    let context = parse_cli_facts(raw_facts)?;
    pipeline.render_prelude_advisories();
    let mode = TrustMode::for_eval(pipeline.json());
    if let Err(block) = pipeline.consult_trust(command, mode) {
        if pipeline.json() {
            let body = serde_json::json!({ "decision": block.decision.to_string(), … });
            println!("{}", serde_json::to_string(&body).expect(…));
        }
        return Ok(());
    }
    if pipeline.json() { /* JSON branch */ } else { /* text branch */ }
}
```

`cmd_check::cmd_check` repeats the same prelude (with
`render_trust_warning` instead of consult-with-filter — `cmd_check`
validates the config as authored), then its own text-vs-JSON fork.
`cmd_claude_code_hook::cmd_claude_code_hook` skips the prelude
(JSON-only by mode) but still hand-rolls the trust-block serialisation
into a `hookSpecificOutput` envelope. The two trust-block serialisation
paths have already drifted: `cmd_eval` emits
`{decision,reason,files}` raw, `cmd_claude_code_hook` wraps in
`hookSpecificOutput.permissionDecision`.

Constraints:

- Pre-1.0; no back-compat on contributor APIs. User-visible output
  bytes (snapshots) must not drift.
- The pipeline is `may-i`-specific. We are not building a generic
  framework.
- `cmd_migrate`, `cmd_fmt`, `cmd_trust`, `cmd_parse`, `cmd_help` do
  *not* evaluate commands; they keep their existing entry shape.

## Goals / Non-Goals

**Goals:**

- One pipeline entry point owns the per-invocation flow: prelude →
  trust → handler closure → renderer.
- Evaluation handler bodies shrink to "build context, evaluate,
  return a renderable outcome" — no advisory rendering, no trust
  consultation, no `if pipeline.json()` fork.
- Trust-block serialisation is centralised: one mapping from
  `TrustBlock` to mode-shaped output bytes, replacing the divergent
  hand-rolled paths in `cmd_eval` and `cmd_claude_code_hook`.
- Renderer choice (text Layout vs JSON) lives inside `output`, driven
  by the pipeline's `json` flag — not by every handler.

**Non-Goals:**

- A subcommand-registry trait or a generic command-runner framework.
  `clap`'s derive routing stays in `main.rs`.
- Folding `cmd_migrate`, `cmd_fmt`, `cmd_trust`, `cmd_parse`, or
  `cmd_help` into `run`. The pipeline is for evaluation flow;
  non-evaluation subcommands bypass it (this matches the existing
  escape-hatch requirement in `command-pipeline`).
- Changing user-visible output bytes, exit codes, the Claude Code hook
  JSON shape, or any DSL syntax.
- Touching `may_i_*` workspace crates. Changes confined to `src/`.
- Changing the error-diag → ask flooring rule (that lives in
  `crates/engine/src/eval/command.rs:123` and stays there).

## Decisions

### Decision 1: `pipeline.run(mode, closure) -> miette::Result<()>` is the sole evaluation entry

Revisit the archived design's Decision 1 rejection. Three handlers now
exist; each repeats prelude + trust + renderer-fork. The
control-inversion concern from the original design was theoretical;
the duplication is concrete. Pick the closure shape.

```rust
pub enum InvocationMode {
    /// `may-i eval` — text or JSON, prelude renders, trust consultation
    /// filters in place.
    Eval,
    /// `may-i check` — text or JSON, prelude renders, trust warning
    /// renders (no filtering — check validates as authored).
    Check,
    /// Claude Code hook — JSON only, no prelude, trust consultation
    /// filters in place.
    Hook,
}

pub struct EvalContext<'a> {
    pub config: &'a may_i_core::ast::Config,
    pub loaded: &'a may_i_config::LoadResult,
    pub terminal: &'a output::Terminal,
    pub config_path: &'a std::path::Path,
    pub display_path: String, // shorten_home applied once
}

pub enum EvalOutcome {
    /// `cmd_eval` result: one evaluation result + its trace + the
    /// colorised command echo + the raw command string.
    Eval(EvalOutcomeBody),
    /// `cmd_check` result: pass/fail tallies and per-check details.
    Check(CheckOutcomeBody),
    /// Hook result: a single `EvalResult`, no trace, no advisories.
    Hook(may_i_engine::EvalResult),
}

impl CommandPipeline {
    pub fn run<F>(&mut self, mode: InvocationMode, command: &str, closure: F) -> miette::Result<()>
    where
        F: FnOnce(&EvalContext<'_>) -> miette::Result<EvalOutcome>;
}
```

`run` executes:

1. If `mode != Hook`: `self.render_prelude_advisories()`.
2. If `mode == Check`: `self.render_trust_warning()` (no filtering).
   Else: `self.consult_trust(command, mode.into_trust_mode(self.json))`.
   On `Err(block)`, dispatch through one trust-block renderer and
   return `Ok(())` (or whatever exit shape the mode dictates) without
   invoking the closure.
3. Build `EvalContext` from `self`. Pass to closure. Receive
   `EvalOutcome`.
4. Dispatch the outcome through `output::render_eval_outcome(writer,
   terminal, json, &outcome)` which routes to text or JSON renderers
   internally.

Handler bodies collapse to:

```rust
pub fn cmd_eval(pipeline: &mut CommandPipeline, command: &str, raw_facts: &[String]) -> miette::Result<()> {
    let context_facts = parse_cli_facts(raw_facts)?;
    pipeline.run(InvocationMode::Eval, command, |ctx| {
        let (result, traces, colored) = evaluate_with_colorization(command, ctx.loaded, &context_facts)?;
        Ok(EvalOutcome::Eval(EvalOutcomeBody { command, colored, result, traces, display_path: ctx.display_path.clone() }))
    })
}
```

**Alternative considered**: keep the explicit-method shape (`render_prelude_advisories` →
`consult_trust` → handler body → handler picks renderer) as today. Rejected — three
sites already duplicate the same dance; a fourth (if we ever add one) compounds the
drift. The original design's "easier to read" argument was correct in the abstract
but didn't anticipate the trust-block serialisation drift.

**Alternative considered**: thread a `&mut CommandPipeline` into the closure rather
than a borrowed `EvalContext`. Rejected — handlers must not call
`render_prelude_advisories` / `consult_trust` themselves (the whole point of `run`).
A reduced-surface borrowed context enforces that at the type level.

### Decision 2: Trust-block serialisation lives in `output`, not in handlers

`output::render_trust_block(writer, terminal, &block, mode)` is the
single mapping from `TrustBlock` to mode-shaped bytes:

```rust
pub fn render_trust_block(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    terminal: &Terminal,
    block: &trust::TrustBlock,
    mode: InvocationMode,
);
```

- `InvocationMode::Eval` + text: write block reason + files to stderr
  (matching today's silence — `cmd_eval` text mode prints nothing on
  trust block beyond what the prelude already showed).
- `InvocationMode::Eval` + JSON: write `{decision, reason, files}` to
  stdout (matching `cmd_eval.rs:27-38` today).
- `InvocationMode::Check`: not reached — `cmd_check` does not consult-with-block.
- `InvocationMode::Hook`: write
  `{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision, permissionDecisionReason}}`
  to stdout (matching `cmd_claude_code_hook.rs:30-36 + 110-119` today).

Pipeline calls this once when `consult_trust` returns `Err`.

**Alternative considered**: leave trust-block serialisation in handlers and only
centralise the prelude + dispatch. Rejected — the hand-rolled paths have already
drifted (Eval emits raw JSON, Hook wraps in envelope, both build via `serde_json::json!`
inline). One canonical mapping prevents re-drift.

### Decision 3: Renderer choice is internal to `output::render_eval_outcome`

The text-vs-JSON fork moves from every handler into one dispatcher:

```rust
pub fn render_eval_outcome(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    terminal: &Terminal,
    json: bool,
    outcome: &EvalOutcome,
);
```

Internally this matches on `EvalOutcome` and routes to existing
intent operations (`render_eval_result`, `render_check_failure`,
`render_check_summary`, etc.) for text, and to existing JSON shapers
(`render_check_results_json`, the per-handler json builders) for
JSON. The JSON shapers move into `output::json` if they aren't already.

**Alternative considered**: two separate entry points (`render_eval_outcome_text`,
`render_eval_outcome_json`) called by `run` based on `self.json`. Rejected — the
internal-match shape lets us add a variant to `EvalOutcome` without touching the
dispatcher's public surface.

### Decision 4: `InvocationMode` is new; `TrustMode` is its trust-side projection

`TrustMode { Text, Json, Hook }` (introduced by the archived change)
stays — it's the trust-gate's vocabulary for *how to phrase a block
reason*. `InvocationMode { Eval, Check, Hook }` is the pipeline's
vocabulary for *which flow to run*. `InvocationMode` projects to
`TrustMode` via `mode.into_trust_mode(json: bool)`. This keeps the
trust module ignorant of whether the invocation is `eval` vs `check`
(it doesn't care; it only needs to know the response shape).

**Alternative considered**: collapse `InvocationMode` and `TrustMode` into one
enum. Rejected — `cmd_check`'s `Text` mode never consults the gate (it renders
the warning instead), so the same `TrustMode::Text` variant would mean different
things depending on caller. Keep the two concerns named separately.

### Decision 5: `cmd_check`'s no-filter path is a `run`-level flag, not a separate API

`cmd_check` validates the config as authored — it must *not* drop
untrusted Loaded rules. The archived `render_trust_warning` accessor
exists for this. Rather than expose two entry points (`run` for
filtering callers, `run_without_filter` for `cmd_check`),
`InvocationMode::Check` is the discriminator: `run`'s implementation
branches on the mode and calls `render_trust_warning` instead of
`consult_trust` when `mode == Check`.

**Alternative considered**: pass a `FilterPolicy` parameter to `run`. Rejected —
`cmd_check`'s no-filter behaviour is intrinsic to the check flow, not a per-call
choice. Encoding it in the mode keeps the call site honest.

### Decision 6: Handler-side facts parsing stays out of `run`

`cmd_eval` parses CLI fact strings; `cmd_claude_code_hook` extracts
context facts from the JSON payload. These are mode-specific and
happen *before* the pipeline can do anything useful (the trust gate
doesn't need facts; the handler does, to evaluate). The closure
captures whatever pre-parsed facts the handler built; `EvalContext`
does not carry facts. This keeps the pipeline's signature stable
across handlers with different fact-source shapes.

**Alternative considered**: add a `facts: ContextFacts` field to `EvalContext`,
forcing every handler to parse before calling `run`. Rejected — pushes a
hook-specific concern (the JSON payload's `build_context`) into the closure
prologue anyway. Better to let the closure own its facts.

## Risks / Trade-offs

- **[Risk]** Snapshot drift if the prelude order changes when the
  pipeline takes flow control. **Mitigation**: `render_prelude_advisories`
  / `consult_trust` / `render_trust_warning` are already extracted — `run`
  just calls them in the same order each handler does today. Existing
  snapshots pin the bytes.

- **[Risk]** Closure-shape API is less ergonomic to call from tests
  that want to drive the pipeline step-by-step. **Mitigation**: keep
  the underlying methods (`render_prelude_advisories`, `consult_trust`)
  as `pub(crate)` so unit tests in `src/pipeline.rs` can still drive
  them individually; production handlers use `run`.

- **[Risk]** `cmd_check`'s no-filter behaviour buried behind
  `InvocationMode::Check` is easy to miss when reading. **Mitigation**:
  doc-comment on `InvocationMode::Check` makes the intent explicit;
  the spec scenario "Check mode renders trust warning, does not
  filter" pins it.

- **[Trade-off]** A new `EvalOutcome` enum + `EvalContext` struct
  introduces two contributor-facing types not present today. They
  exist only as the closure-interface shapes between handler and
  `output`. Acceptable cost for collapsing three handler dances into
  one. Revisit if `EvalOutcome` grows past five variants.

- **[Trade-off]** Hook mode currently calls neither
  `render_prelude_advisories` nor `render_trust_warning` (it's JSON-only
  by design). `run`'s prelude step is a no-op for `InvocationMode::Hook`.
  The mode-dispatch has a small dead branch; the alternative (a
  separate `run_hook` entry) duplicates the trust-consult + handler
  + render dispatch. Accept the no-op.

## Migration Plan

Pure internal refactor. No user migration. Sequenced rollout (one PR or stacked):

1. Introduce `InvocationMode`, `EvalContext`, `EvalOutcome`,
   `pipeline::run`, and `output::render_trust_block` /
   `output::render_eval_outcome`. Don't migrate handlers yet.
2. Migrate `cmd_eval` to `run`. Snapshot tests confirm byte-for-byte
   equality.
3. Migrate `cmd_check` to `run`. Snapshots confirm equality.
4. Migrate `cmd_claude_code_hook` to `run`. Snapshots confirm.
5. Demote `render_prelude_advisories`, `consult_trust`,
   `render_trust_warning` from `pub` to `pub(crate)` (or private if
   no external `src/` caller remains). `main.rs` switches to `run`
   exclusively for evaluation subcommands.
6. Coverage sweep: `cargo tarpaulin`, surgical proptests / unit tests
   for any newly-uncovered branches in `pipeline::run` and the
   trust-block / outcome renderers.

Rollback: revert the PR(s). No persisted state changes; no DSL or
config schema changes; no trust-hash changes.

## Open Questions

- Should `EvalOutcome::Hook` carry the raw `EvalResult` (current
  proposal) or a pre-shaped `HookResponse` value? Tentative: keep
  `EvalResult` — `output::render_eval_outcome` does the shaping,
  matching the pattern for `Eval` and `Check`.
- Does `cmd_check`'s JSON path warrant its own `EvalOutcome::Check`
  variant or should it share `EvalOutcome::Eval` with a tally
  payload? Tentative: separate variant — the data shapes are
  different enough (one result vs many) that a shared variant would
  carry empty fields per case.
- Should `parse_cli_facts` (eval) and `build_context` (hook) move
  into `output` or stay in their `cmd_*` modules? Tentative: stay —
  they're mode-specific input parsing, not rendering.
