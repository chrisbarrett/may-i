## Context

Three CLI surfaces — `cmd_eval`, `cmd_check`, `cmd_claude_code_hook` — each re-implement the same invocation prelude: resolve config path → `may_i_config::load_and_resolve` → detect terminal → optionally render migration note (`crate::notes::migration_note`) → render trust integrity advisories (`crate::trust_advisory::write_integrity_advisories`) → call `trust_gate::evaluate` → handle `GateOutcome` (with `std::mem::take(&mut loaded.config)` and `Box<Config>` ping-pong) → run engine → render trace + result.

The current `trust_gate::evaluate(config, command, mode) -> GateOutcome` interface is shallow in two senses. First, it owns only the *block decision* — integrity advisories, the migration note, and the `Terminal` are still the caller's problem. Second, it takes `Config` by value and returns it boxed, forcing every caller into the same ownership dance. Internally, `evaluate_json` and `evaluate_hook` each call `trust_advisory::compute` (which loads the trust store) *and then* `load_store()` again to filter — the store loads twice on the block path (`src/trust_gate.rs:75-99`).

The `output` module re-exports the full `may_i_layout` API surface (`src/output/mod.rs:20-23`) and exposes only thin wrappers (`print_trace`, `print_separator`, `render_elements`). Callers then build raw `Layout::Stack`/`Columns`/`Indent` directly (`src/cmd_check.rs:144`). Layout primitives leak across `src/`. The module fails the deletion test: removing it would not erase complexity from callers.

Constraints:

- Pre-1.0; no back-compatibility requirement for contributor APIs.
- User-visible output bytes must not change. Existing integration tests under `tests/` and snapshots pin behaviour. New tests pin the prelude ordering and the single-store-load property.
- `may_i_*` crate boundaries (engine, config, core, sexpr, layout, pp, shell-parser) are not in scope. Changes are confined to `src/`.

## Goals / Non-Goals

**Goals:**

- One module owns the per-invocation orchestration; `cmd_*` modules shrink to per-command logic only.
- One module owns Trust for an invocation; trust-store loading happens at most once per invocation; integrity advisories, warning advisory, filtering, and the block decision are co-located.
- `Layout` and its primitives become an implementation detail of `crate::output`. Callers express intent (`render_eval_result`, `render_check_failure`, `render_advisory_stack`), not assembly.
- `GateOutcome::Proceed { config: Box<Config>, … }` and the `mem::take` ceremony go away.

**Non-Goals:**

- Changing user-visible behaviour, output bytes, exit codes, or DSL syntax.
- Touching `may_i_layout`, `may_i_engine`, `may_i_config`, or any other workspace crate.
- Building a generic command-runner framework. The pipeline is `may-i`-specific.
- Compaction of `src/annotation.rs` (1911 L) or `crates/engine/src/eval/*`. Those are deep in their own right; out of scope.
- A trait-based subcommand registry. `clap`'s derive on `Cli` in `src/main.rs` stays as the entry router.

## Decisions

### Decision 1: `CommandPipeline` is a struct, not a trait

The pipeline owns the loaded config, the detected terminal, the json flag, and the trust-resolved state. Subcommands receive `&mut CommandPipeline` (or by value where ownership transfer is helpful) and call methods that drive their stage of work.

```rust
pub struct CommandPipeline {
    loaded: may_i_config::LoadResult,
    terminal: output::Terminal,
    json: bool,
    // Lazily-initialised trust state — populated on first gate consultation.
    trust: Option<TrustOutcome>,
}

impl CommandPipeline {
    pub fn load(config_path: Option<&Path>, json: bool) -> miette::Result<Self>;
    pub fn config(&self) -> &may_i_core::ast::Config;
    pub fn terminal(&self) -> &output::Terminal;
    pub fn config_path(&self) -> &Path;

    /// Consult Trust for this invocation. Idempotent (caches). On block,
    /// returns `Err(TrustBlock { ... })` carrying the block payload — the
    /// caller renders it in mode-appropriate shape. On proceed, filters
    /// untrusted Loaded rules from `self.loaded.config` in place, and
    /// renders the integrity + warning advisories to stderr (text mode)
    /// or stores them on `self` for JSON serialisation.
    pub fn consult_trust(&mut self, command: &str, mode: TrustMode) -> Result<(), TrustBlock>;
}
```

Rationale: a struct is the simplest shape that lets each subcommand drive its own ordering. A trait would force every command into one execution shape, which they don't share (e.g. `cmd_check` evaluates many commands, `cmd_eval` evaluates one, `cmd_trust` never runs the engine).

**Alternative considered**: a `pipeline.run(|ctx| { ... })` closure-driven shape. Rejected — would push subcommands into a control-inversion shape with no real benefit; the explicit method-call style is easier to read and test.

### Decision 2: Trust gate becomes a method on the pipeline

`trust_gate::evaluate(config, command, mode) -> GateOutcome` becomes `CommandPipeline::consult_trust(&mut self, command, mode) -> Result<(), TrustBlock>`. The pipeline owns the loaded config (no `mem::take`), so filtering is an in-place mutation. The store is loaded once on first call and cached on `self`. Integrity advisories are computed during the same store load and either rendered immediately (text mode) or buffered (JSON mode).

```rust
pub enum TrustMode { Text, Json, Hook }

pub struct TrustBlock {
    pub decision: may_i_core::Decision,
    pub reason: String,
    pub files: Vec<String>,
}
```

`trust_advisory::compute`, `filter_trusted_rules`, `build_warning_layout`, `write_integrity_advisories`, `UntrustedEntry`, `TrustState`, and the helpers in `trust_gate.rs` (`load_store`, `json_block`, `hook_block`, `program_name`, `first_segment_text`, `segment_texts`) collapse into private functions in a new `src/trust/` module (or `src/trust.rs` if it fits).

**Alternative considered**: keep `trust_gate::evaluate` as a free function and feed it `&mut LoadResult`. Rejected — duplicates the lazy-store-load caching the pipeline already needs, and forces the integrity-advisory routing to live outside Trust again.

### Decision 3: `output` exposes intent operations, hides `Layout`

`output/mod.rs` stops re-exporting `Layout`, `ColAlign`, `ColContent`, `ColItem`, `ColRow`, `HRuleLabel`, `Note`, `NoteLevel`, `Advisory` (`src/output/mod.rs:20-23`). Only `Terminal`, `write_layout`, and `strip_ansi` stay re-exported — those are the renderer protocol, not assembly primitives.

The new public surface:

```rust
pub fn render_eval_result(w: &mut impl Write, term: &Terminal, command: &str, traces: &[TraceEntry], result: &EvalResult, display_path: &str);
pub fn render_check_failure(w: &mut impl Write, term: &Terminal, failure: &CheckFailureView);
pub fn render_check_summary(w: &mut impl Write, term: &Terminal, passed: usize, failed: usize, display_path: &str);
pub fn render_trace(w: &mut impl Write, term: &Terminal, entries: &[TraceEntry], command: &str, indent: &str);
pub fn render_advisory_stack(w: &mut impl Write, term: &Terminal, advisories: &[Layout]);  // Layout type private to output
```

The `CheckFailureView` is a `pub struct` in `output` carrying the cmd_check-specific data (`command`, `expected`, `actual`, `context`, `location`, `reason`, `trace`); `cmd_check.rs` constructs it and hands it off — no `Layout::Columns` assembly at the call site.

Module trees:

```
src/output/
  mod.rs           — public intents
  trace.rs         — trace_to_layout (was in mod.rs)
  eval_result.rs   — render_eval_result
  check.rs         — render_check_failure / render_check_summary (was inline in cmd_check.rs)
  advisory.rs      — render_advisory_stack
  json.rs          — unchanged
  colorize.rs      — unchanged
  render_rule.rs   — unchanged
  transform.rs     — unchanged
  annotate.rs      — unchanged
```

`Layout` becomes `pub(crate)` (or `pub(super)`) inside `output`; callers cannot touch it.

**Alternative considered**: leave `output` as a passthrough and rely on convention. Rejected — the leakage is real today (`cmd_check.rs:144` builds `Layout::Columns(rows)`); convention alone has not held.

### Decision 4: Migration note moves into the pipeline

`crate::notes::migration_note` is used only by `cmd_eval` and `cmd_check`, always rendered to stderr at the same prelude position. Move into `CommandPipeline::render_prelude_advisories(&self)` (text mode only). `src/notes.rs` deletes.

**Alternative considered**: keep `notes.rs` as a free function called by the pipeline. Rejected — it's one function, one caller after consolidation; not worth a module.

### Decision 5: `cmd_*` modules become thin

After the deepening, each `cmd_*` body looks like:

```rust
pub fn cmd_eval(pipeline: &mut CommandPipeline, command: &str, raw_facts: &[String]) -> miette::Result<()> {
    let context = parse_cli_facts(raw_facts)?;
    pipeline.render_prelude_advisories();
    if let Err(block) = pipeline.consult_trust(command, TrustMode::for_json(pipeline.json())) {
        return pipeline.emit_trust_block(block);
    }
    let (result, traces, colored_command) = evaluate_with_colorization(command, pipeline.loaded(), &context)?;
    pipeline.render_eval_output(command, &colored_command, &result, &traces);
    Ok(())
}
```

`main.rs` constructs the pipeline once per invocation and passes it to the dispatched command.

### Decision 6: One-shot store-load invariant is testable

The pipeline holds the trust-store load behind `OnceCell` (or equivalent). A unit test wraps the store loader behind a counting hook and asserts that a `cmd_eval` invocation against an untrusted-program command calls the loader exactly once. This pins the regression that motivates the consolidation.

## Risks / Trade-offs

- **[Risk]** Snapshot drift from prelude reordering inside the pipeline (advisory order, blank-line placement). → **Mitigation**: pin existing rendered output in integration tests before the refactor; assert byte-for-byte equality after.

- **[Risk]** `cmd_check` runs many evaluations against the same config; moving Trust into a pipeline that's checked once still works, but the existing per-check `TracingFold` flow must not be accidentally re-gated. → **Mitigation**: `consult_trust` is called once in the prelude; subsequent `pipeline.evaluate(...)` uses the already-filtered config.

- **[Risk]** Owning the `LoadResult` on the pipeline complicates `cmd_migrate` and `cmd_fmt`, which mutate the config or walk the load graph separately. → **Mitigation**: those subcommands skip `consult_trust` and may bypass the pipeline entirely if it doesn't fit; the pipeline is for *evaluation* subcommands. Keep an escape hatch (`pipeline.into_loaded() -> LoadResult`) for commands that need ownership back.

- **[Risk]** Hiding `Layout` from callers means the pipeline / output must cover every assembly the callers currently do. Missed cases force re-export. → **Mitigation**: audit `cmd_check.rs`, `cmd_trust.rs`, `interactive.rs` for direct `Layout::*` constructor calls before sealing the type; add intents for each found case.

- **[Trade-off]** A deeper Trust module is harder to unit-test in isolation than the current free function — the store-load step is now bound to a pipeline. → **Mitigation**: extract the store-load hook as a `pub(crate)` strategy parameter on `CommandPipeline::new_with_store_loader(...)` for tests; production callers use the default.

- **[Trade-off]** `CheckFailureView` is a new data type used only by `cmd_check` ↔ `output::render_check_failure`. It's not domain-meaningful, just an interchange struct. Acceptable cost for stopping `Layout` leakage; revisit if `cmd_check` grows more failure-rendering variants.

## Migration Plan

Pure internal refactor. No user migration. No config-file schema changes. Sequenced rollout (single PR or stacked):

1. Land a snapshot-pinning integration test pass first so behavioural drift is caught.
2. Introduce `CommandPipeline` and migrate `cmd_eval` end-to-end; keep `trust_gate` free function temporarily.
3. Migrate `cmd_check` and `cmd_claude_code_hook` to the pipeline.
4. Fold `trust_gate` and `trust_advisory` into `src/trust/`; make former modules private. Delete `src/notes.rs`.
5. Seal `output`: remove re-exports, introduce intent operations, move `cmd_check` assembly behind `render_check_failure`.
6. Add the single-store-load property test.

Rollback: revert the PR(s). No persisted state changes.

## Open Questions

- Does `cmd_migrate` benefit from the pipeline at all? It doesn't run the engine; it walks the load graph and rewrites files. Tentative answer: skip; let it call `load_and_resolve` directly. Confirm during step 3.
- Should `CheckFailureView` live in `crate::output` or `engine::check`? It's a render-time shape; output is the right home, but a thin wrapper crate boundary would be cleaner. Tentative answer: keep in `output` to avoid a new public type in `engine`.
- `Terminal::detect` lives in `may_i_layout` and is re-exported. Does that stay exposed? Tentative answer: yes — it's the renderer protocol, not an assembly primitive.
