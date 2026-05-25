## MODIFIED Requirements

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
