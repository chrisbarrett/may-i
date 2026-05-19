## ADDED Requirements

### Requirement: Pipeline owns evaluation flow via a single run entry

The pipeline SHALL expose a single `run(mode, command, closure)` entry point that owns the per-invocation evaluation flow: prelude advisories, trust consultation (or trust-warning rendering, per mode), invoking the handler closure, mapping trust blocks through a single mode-aware renderer, and dispatching the closure's outcome through a single mode-aware result renderer. Evaluation subcommands (`cmd_eval`, `cmd_check`, `cmd_claude_code_hook`) SHALL drive their work through `run` and SHALL NOT call `render_prelude_advisories`, `consult_trust`, `render_trust_warning`, or any other pipeline orchestration method individually.

#### Scenario: Eval handler dispatches through run

- **WHEN** `cmd_eval` is invoked
- **THEN** its body SHALL call `pipeline.run(InvocationMode::Eval, command, closure)` exactly once
- **AND** SHALL NOT call `render_prelude_advisories`, `consult_trust`, or `render_trust_warning` directly

#### Scenario: Check handler dispatches through run

- **WHEN** `cmd_check` is invoked
- **THEN** its body SHALL call `pipeline.run(InvocationMode::Check, _, closure)` exactly once
- **AND** SHALL NOT call `render_prelude_advisories`, `consult_trust`, or `render_trust_warning` directly

#### Scenario: Hook handler dispatches through run

- **WHEN** `cmd_claude_code_hook` is invoked with a Bash tool payload
- **THEN** its body SHALL call `pipeline.run(InvocationMode::Hook, command, closure)` exactly once after extracting the command
- **AND** SHALL NOT call `consult_trust` directly

#### Scenario: Closure receives a borrowed evaluation context, not the pipeline

- **WHEN** the closure handed to `run` is invoked
- **THEN** it receives an `&EvalContext` exposing `config`, `loaded`, `terminal`, `config_path`, and `display_path`
- **AND** it does NOT receive `&mut CommandPipeline` (so it cannot re-run the prelude or re-consult trust)

### Requirement: Renderer selection lives inside the pipeline, not in handlers

The text-versus-JSON renderer choice SHALL be made by the pipeline's `run` (delegating to `output::render_eval_outcome` or equivalent intent operation), driven by the pipeline's `json` flag. Evaluation handler closures SHALL return a typed `EvalOutcome` value and SHALL NOT branch on `pipeline.json()` to pick a renderer themselves, nor write directly to stdout/stderr from within the closure for the primary result.

#### Scenario: Handler closure returns an outcome, not rendered bytes

- **WHEN** the closure handed to `run` produces its result
- **THEN** it returns an `EvalOutcome` value (e.g. `EvalOutcome::Eval { … }`, `EvalOutcome::Check { … }`, `EvalOutcome::Hook(EvalResult)`)
- **AND** does NOT call `println!`, `serde_json::to_string`, `write_layout`, or any `output::render_*` operation itself

#### Scenario: No json branch in evaluation handlers

- **WHEN** scanning `src/cmd_eval.rs`, `src/cmd_check.rs`, and `src/cmd_claude_code_hook.rs` for `pipeline.json()` references
- **THEN** zero references appear in handler body code (the branch lives in `pipeline::run` / `output::render_eval_outcome`)

### Requirement: Trust-block serialisation is centralised

The pipeline SHALL emit any trust block produced during `run` through a single `output::render_trust_block` (or equivalent) operation that takes the `TrustBlock`, the `InvocationMode`, and the pipeline's writers. Evaluation handlers SHALL NOT serialise a trust block themselves — no handler-side `serde_json::json!({...block...})` constructions, no handler-side `println!` of block payloads.

#### Scenario: Eval mode trust block is serialised by the pipeline

- **WHEN** `cmd_eval` runs in JSON mode against a command whose program has untrusted rules
- **THEN** the pipeline emits the block as `{"decision": ..., "reason": ..., "files": [...]}` on stdout
- **AND** the `cmd_eval` closure is never invoked

#### Scenario: Hook mode trust block is serialised by the pipeline

- **WHEN** `cmd_claude_code_hook` runs against a command whose program has untrusted rules
- **THEN** the pipeline emits the block wrapped in `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": ..., "permissionDecisionReason": ...}}` on stdout
- **AND** the `cmd_claude_code_hook` closure is never invoked

#### Scenario: No handler serialises a trust block

- **WHEN** scanning evaluation `cmd_*` modules for references to `TrustBlock` fields or `block.decision` / `block.reason` / `block.files` inside `serde_json::json!` or `println!` macros
- **THEN** zero matches appear

## MODIFIED Requirements

### Requirement: Prelude duplication removed from cmd modules

The duplicated prelude — config loading, terminal detection, migration-note rendering, integrity-advisory rendering, trust gate consultation, and config-ownership ceremony around `GateOutcome` — SHALL exist in exactly one location (the pipeline). No `cmd_*` module SHALL re-implement any of these steps. After this change, evaluation `cmd_*` modules SHALL further not invoke the pipeline's individual prelude / trust / advisory operations: they drive the entire flow through `CommandPipeline::run`.

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

- **WHEN** scanning evaluation `cmd_*` modules for calls to `render_prelude_advisories`, `consult_trust`, or `render_trust_warning`
- **THEN** zero references appear; the only pipeline entry point in these modules is `CommandPipeline::run`
