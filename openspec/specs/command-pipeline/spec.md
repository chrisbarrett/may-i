---
audience: contributor
bucket: contributor-internals
---
# command-pipeline Specification

## Purpose

Contributor-only. The `CommandPipeline` type in the binary crate owns the per-invocation state shared by every evaluation subcommand: loaded config, terminal detection, json-output flag, and cached trust state. It centralises the prelude (config load, terminal detect, migration note, integrity advisories, trust gate consultation) that `cmd_eval`, `cmd_check`, and `cmd_claude_code_hook` previously duplicated. See `trust-gate` for the gate's contract and `output-rendering` for the intent operations the pipeline composes.

## Requirements

### Requirement: Pipeline owns per-invocation state

The system SHALL provide a `CommandPipeline` (working name) contributor-facing type in the binary crate that owns the per-invocation state shared by every evaluation subcommand: the `may_i_config::LoadResult` (loaded config + pre-migration forms + config path), the detected `output::Terminal`, the json-output flag, and an `InvocationTrust` collaborator (see `trust-gate`) that owns the per-invocation Trust concern. The pipeline SHALL NOT hold trust-store loaders, trust catalog state, trust-load-attempted flags, prelude-rendered flags, or trust-warning-rendered flags directly — those move into `InvocationTrust`. CLI subcommands SHALL NOT individually call `may_i_config::load_and_resolve` or `output::Terminal::detect`; both happen during pipeline construction.

#### Scenario: Pipeline constructed once per invocation

- **WHEN** the binary's `main` enters any evaluation subcommand (`eval`, `check`, the default hook entry)
- **THEN** exactly one `CommandPipeline` is constructed for that invocation and passed to the subcommand
- **AND** `may_i_config::load_and_resolve` and `output::Terminal::detect` are each called exactly once

#### Scenario: Subcommands borrow from the pipeline

- **WHEN** a subcommand needs the loaded config, the terminal, the config path, or the json flag
- **THEN** it accesses them through `&CommandPipeline` accessors, not by re-loading

#### Scenario: Pipeline holds exactly one InvocationTrust

- **WHEN** scanning the `CommandPipeline` struct definition in `src/pipeline.rs`
- **THEN** it contains exactly one field of type `InvocationTrust`
- **AND** it contains no field of type `Option<TrustCatalogState>`, `Box<dyn Fn() -> Option<TrustStoreState>>`, or named `catalog_attempted` / `prelude_rendered` / `trust_warning_rendered`

### Requirement: Pipeline runs the prelude exactly once

The pipeline SHALL expose a single `render_prelude_advisories` operation that delegates to `InvocationTrust::render_prelude`. The delegation SHALL render the migration note (when the loaded config was transparently migrated) followed by trust-store integrity advisories, to the pipeline's stderr. The operation SHALL be idempotent — calling it more than once in an invocation has no additional effect. The idempotency state lives on `InvocationTrust`, not on `CommandPipeline`.

#### Scenario: Prelude renders migration note then integrity advisory

- **WHEN** a subcommand calls `render_prelude_advisories` in text mode and both the migration note and an integrity advisory apply
- **THEN** the migration note is rendered first, then the integrity advisory, to stderr — matching today's ordering in `cmd_eval` and `cmd_check`

#### Scenario: JSON mode skips prelude advisories

- **WHEN** the pipeline's `json` flag is set
- **THEN** `render_prelude_advisories` is a no-op (matching today's JSON-mode behaviour)

#### Scenario: Idempotent on repeated calls

- **WHEN** `render_prelude_advisories` is called twice in one invocation
- **THEN** the second call writes nothing to stderr
- **AND** the idempotency is enforced by state inside `InvocationTrust`

### Requirement: Prelude duplication removed from cmd modules

The duplicated prelude — config loading, terminal detection, migration-note rendering, integrity-advisory rendering, trust gate consultation, and config-ownership ceremony around `GateOutcome` — SHALL exist in exactly one location (the pipeline). No `cmd_*` module SHALL re-implement any of these steps. After this change, evaluation `cmd_*` modules SHALL further not invoke the pipeline's individual prelude / trust / advisory operations: they drive the entire flow through one of the pipeline's per-mode entry points (`run_eval`, `run_check`, `run_hook`).

#### Scenario: No cmd module loads the config directly

- **WHEN** scanning `src/cmd_*.rs` for evaluation subcommands (`cmd_eval`, `cmd_check`, `cmd_claude_code_hook`)
- **THEN** none call `may_i_config::load_and_resolve`, `may_i_config::load`, or construct `LoadResult` themselves

#### Scenario: No cmd module renders migration notes directly

- **WHEN** scanning evaluation `cmd_*` modules
- **THEN** none call `notes::migration_note` (which is deleted) nor reproduce its content

#### Scenario: No cmd module renders integrity advisories directly

- **WHEN** scanning evaluation `cmd_*` modules
- **THEN** none call `trust_advisory::write_integrity_advisories` (or its successor)

#### Scenario: No mem::take of the loaded config

- **WHEN** scanning evaluation `cmd_*` modules
- **THEN** none call `std::mem::take` on `LoadResult::config`, nor box the config, nor consume-and-return it

#### Scenario: No cmd module invokes the pipeline's prelude or trust accessors directly

- **WHEN** scanning evaluation `cmd_*` modules for calls to `render_prelude_advisories`, `consult_trust`, `render_trust_warning`, or any other pipeline orchestration method
- **THEN** zero references appear; the only pipeline entry points in these modules are `CommandPipeline::run_eval`, `CommandPipeline::run_check`, and `CommandPipeline::run_hook`

### Requirement: Pipeline owns evaluation flow via per-mode entry points

The pipeline SHALL expose three typed entry points — `run_eval(command, closure)`, `run_check(closure)`, `run_hook(command, closure)` — each owning the per-invocation evaluation flow for its mode: prelude advisories (skipped for `run_hook`), trust consultation (skipped for `run_check`), invoking the handler closure on the allow path, emitting any trust block through a mode-specific helper on the block path, and dispatching the closure's typed body through the matching renderer. Evaluation subcommands (`cmd_eval`, `cmd_check`, `cmd_claude_code_hook`) SHALL drive their work through exactly one of these methods and SHALL NOT call any other pipeline orchestration method.

The closure signatures SHALL encode the mode-to-body invariant in the type system:

- `run_eval` closure returns `EvalOutcomeBody`
- `run_check` closure returns `CheckOutcomeBody`
- `run_hook` closure returns `may_i_engine::EvalResult`

There SHALL NOT exist a single `run<F>(InvocationMode, command, F)` entry point, nor an `EvalOutcome` enum that unifies the three body types at runtime, nor an `InvocationMode` enum.

#### Scenario: Eval handler dispatches through run_eval

- **WHEN** `cmd_eval` is invoked
- **THEN** its body SHALL call `pipeline.run_eval(command, closure)` exactly once
- **AND** the closure SHALL return `EvalOutcomeBody`
- **AND** the body SHALL NOT call `render_prelude_advisories`, `consult_trust`, or `render_trust_warning`

#### Scenario: Check handler dispatches through run_check

- **WHEN** `cmd_check` is invoked
- **THEN** its body SHALL call `pipeline.run_check(closure)` exactly once
- **AND** the closure SHALL return `CheckOutcomeBody`
- **AND** the body SHALL NOT call `render_prelude_advisories`, `consult_trust`, or `render_trust_warning`

#### Scenario: Hook handler dispatches through run_hook

- **WHEN** `cmd_claude_code_hook` is invoked with a Bash tool payload
- **THEN** its body SHALL call `pipeline.run_hook(command, closure)` exactly once after extracting the command
- **AND** the closure SHALL return `may_i_engine::EvalResult`
- **AND** the body SHALL NOT call `consult_trust`

#### Scenario: Closure receives a borrowed evaluation context, not the pipeline

- **WHEN** any of the three closures is invoked
- **THEN** it receives an `&EvalContext` exposing `config`, `loaded`, `terminal`, `config_path`, and `display_path`
- **AND** it does NOT receive `&mut CommandPipeline` (so it cannot re-run the prelude or re-consult trust)

#### Scenario: Mode-to-body mismatch is a compile error

- **WHEN** an evaluation handler's closure returns a body type that does not match its `run_*` method (for example a `run_check` closure attempts to return an `EvalOutcomeBody`)
- **THEN** `cargo check` produces a type error rather than a runtime misrender

#### Scenario: No InvocationMode or EvalOutcome type remains in pipeline.rs

- **WHEN** scanning `src/pipeline.rs` after the change
- **THEN** no `enum InvocationMode`, `enum EvalOutcome`, or `fn run<F>` definition appears
- **AND** no other module in the crate references `pipeline::InvocationMode` or `pipeline::EvalOutcome`

### Requirement: Renderer selection lives inside the pipeline, not in handlers

The text-versus-JSON renderer choice SHALL be made inside the pipeline's per-mode entry points (delegating to body-typed renderers under `crate::output`), driven by the pipeline's `json` flag. Evaluation handler closures SHALL return a typed body (`EvalOutcomeBody`, `CheckOutcomeBody`, or `EvalResult`) and SHALL NOT branch on `pipeline.json()` to pick a renderer themselves, nor write directly to stdout/stderr from within the closure for the primary result.

There SHALL NOT be a centralised `render_eval_outcome` dispatcher that re-switches on a mode value to choose a renderer; each `run_*` method routes its closure's body directly to its body-specific renderer.

#### Scenario: Handler closure returns a typed body, not rendered bytes

- **WHEN** any of the three handler closures produces its result
- **THEN** it returns a value of the body type declared by its `run_*` method
- **AND** does NOT call `println!`, `serde_json::to_string`, `write_layout`, or any `output::render_*` operation itself

#### Scenario: No json branch in evaluation handlers

- **WHEN** scanning `src/cmd_eval.rs`, `src/cmd_check.rs`, and `src/cmd_claude_code_hook.rs` for `pipeline.json()` references
- **THEN** zero references appear (the branch lives inside the body-typed renderer chosen by the `run_*` method)

#### Scenario: No EvalOutcome dispatcher in output

- **WHEN** scanning `src/output/` after the change
- **THEN** no `render_eval_outcome` function (or equivalent enum-dispatch over a mode value) exists
- **AND** each per-mode renderer is reachable only from its matching `CommandPipeline::run_*` method

### Requirement: Trust-block serialisation is centralised

The pipeline SHALL emit any trust block produced during a `run_*` call through a mode-specific `output::render_*_trust_block` helper, called from the matching `run_eval` or `run_hook` method with the `TrustBlock` and the pipeline's writers. Evaluation handlers SHALL NOT serialise a trust block themselves — no handler-side `serde_json::json!({...block...})` constructions, no handler-side `println!` of block payloads. There SHALL NOT be a single `render_trust_block` function that switches on an `InvocationMode` value to choose its emission shape; the two emission shapes (Eval text/JSON envelope, Hook envelope) are separate helpers.

#### Scenario: Eval mode trust block is serialised by the pipeline

- **WHEN** `cmd_eval` runs in JSON mode against a command whose program has untrusted rules
- **THEN** `run_eval` emits the block as `{"decision": ..., "reason": ..., "files": [...]}` on stdout via `output::render_eval_trust_block`
- **AND** the `cmd_eval` closure is never invoked

#### Scenario: Hook mode trust block is serialised by the pipeline

- **WHEN** `cmd_claude_code_hook` runs against a command whose program has untrusted rules
- **THEN** `run_hook` emits the block wrapped in `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": ..., "permissionDecisionReason": ...}}` on stdout via `output::render_hook_trust_block`
- **AND** the `cmd_claude_code_hook` closure is never invoked

#### Scenario: No handler serialises a trust block

- **WHEN** scanning evaluation `cmd_*` modules for references to `TrustBlock` fields or `block.decision` / `block.reason` / `block.files` inside `serde_json::json!` or `println!` macros
- **THEN** zero matches appear

#### Scenario: No InvocationMode parameter on block emission

- **WHEN** scanning `src/output/` for trust-block emission functions
- **THEN** no function takes an `InvocationMode` (or equivalent mode enum) argument; the two emission shapes are reached through two distinct named functions

### Requirement: Pipeline exposes an escape hatch for non-evaluation subcommands

Subcommands that do not evaluate a shell command (`migrate`, `fmt`, `trust`, `parse`, `reference`) MAY bypass the pipeline. When they do, they SHALL still avoid re-implementing the prelude — they either skip prelude advisories entirely (matching today's behaviour) or call a pipeline operation that builds the same state without consulting Trust.

#### Scenario: cmd_migrate does not pay for the pipeline

- **WHEN** `may-i migrate` runs
- **THEN** it loads the config without constructing a `CommandPipeline`, since it does not evaluate a command and does not consult Trust

#### Scenario: cmd_trust still uses TrustStore::load

- **WHEN** `may-i trust` runs
- **THEN** it may call `TrustStore::load` directly (the trust-management subcommand is the only permitted caller per the `trust-gate` spec)

### Requirement: Single trust-store load is observable

The pipeline SHALL ensure the trust store is loaded at most once per invocation, regardless of how many times `consult_trust` is called or how many advisories are rendered. The single-load invariant is enforced inside `InvocationTrust`. A test fake injected via `InvocationTrust::with_loader` SHALL be able to count loader calls and assert the invariant; the pipeline SHALL expose a `CommandPipeline::with_trust(loaded, json, InvocationTrust)` constructor variant that accepts a pre-built `InvocationTrust` for tests.

#### Scenario: One invocation, one store load

- **WHEN** a test wraps the store loader behind a counter, builds an `InvocationTrust::with_loader(json, counting_loader)`, passes it into `CommandPipeline::with_trust`, and runs an evaluation flow that triggers both prelude advisories and gate consultation
- **THEN** the loader counter reads exactly 1 at the end of the invocation

#### Scenario: Test seam lives on InvocationTrust

- **WHEN** scanning `src/pipeline.rs` for a `with_store_loader` constructor
- **THEN** no such constructor exists; the only test seam for injecting a custom loader is `InvocationTrust::with_loader`, with the pipeline accepting the resulting `InvocationTrust` via `CommandPipeline::with_trust`
