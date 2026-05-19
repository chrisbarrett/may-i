## MODIFIED Requirements

### Requirement: Single Trust gate entry-point

The system SHALL expose a single Trust gate entry-point that CLI commands consult before evaluating a shell command. The entry-point SHALL be a method on the per-invocation `InvocationTrust` object (owned by `CommandPipeline`; see the `command-pipeline` spec) that takes a mutable borrow of the pipeline's `LoadResult`, the command string, and a `TrustMode` discriminating text output, JSON output, and Claude Code hook contexts. On allow it SHALL filter untrusted Loaded rules from the borrowed `LoadResult`'s config in place and SHALL NOT return owned `Config` state to the caller. On block it SHALL return a `TrustBlock` carrying a `:ask` decision, a reason string, and the affected source files; the pipeline SHALL render the block through a single `output::render_trust_block` (or equivalent) operation shaped by the invocation mode. Evaluation `cmd_*` modules SHALL NOT consult the trust gate directly nor serialise a `TrustBlock` themselves — they drive the entire flow through `CommandPipeline::run` (see the `command-pipeline` spec).

#### Scenario: Text mode with no untrusted programs

- **WHEN** the gate is consulted in `TrustMode::Text` against a config whose loaded rules are all trusted
- **THEN** the gate returns `Ok(())` with the pipeline's config unchanged and no advisories rendered

#### Scenario: Text mode with untrusted programs not invoked by the command

- **WHEN** the config contains untrusted loaded rules for `git`, but the command is `echo hi`
- **THEN** the gate returns `Ok(())` after filtering the untrusted rules from the pipeline's config in place
- **AND** the warning advisory is rendered to the pipeline's stderr writer with text matching the existing `trust_warning_note` shape

#### Scenario: JSON mode with command invoking an untrusted program

- **WHEN** `TrustMode::Json` is used and the command's program has untrusted rules
- **THEN** the gate returns `Err(TrustBlock { decision: Ask, reason, files })` where `reason` matches the current `"Untrusted rules for X. Run: may-i trust"` format and `files` lists the source paths
- **AND** the pipeline serialises the block via `output::render_trust_block` to `{"decision": ..., "reason": ..., "files": [...]}` on stdout

#### Scenario: Hook mode block reason includes file paths

- **WHEN** `TrustMode::Hook` is used and the program has untrusted rules from `~/rules/basics.lisp`
- **THEN** the gate returns `Err(TrustBlock)` whose `reason` contains the file path, matching `cmd_claude_code_hook`'s existing message format
- **AND** the pipeline serialises the block via `output::render_trust_block` wrapped in `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": ...}}` on stdout

#### Scenario: Filtering applies before Ok

- **WHEN** the gate returns `Ok(())`
- **THEN** the pipeline's `Config` contains no Loaded rules whose hash is un-approved in the trust store

#### Scenario: Caller does not move the config

- **WHEN** any CLI subcommand consults the gate
- **THEN** the subcommand SHALL NOT extract the `Config` from `LoadResult` via `std::mem::take`, clone, or box it; the gate borrows the pipeline's config and mutates it in place

#### Scenario: Caller does not hand-serialise the block

- **WHEN** scanning evaluation `cmd_*` modules for references to `TrustBlock` field accesses inside `serde_json::json!`, `println!`, `write!`, or similar output macros
- **THEN** zero references appear; the only call site rendering a `TrustBlock` to bytes is `output::render_trust_block`, invoked by `CommandPipeline::run`

#### Scenario: Gate orchestration lives on InvocationTrust, not CommandPipeline

- **WHEN** scanning `src/pipeline.rs` for trust orchestration logic (store-loader injection, catalog construction, lazy-load flags, idempotent advisory-rendered flags, `TrustCatalogState` field types)
- **THEN** none of these appear directly on `CommandPipeline`; they live inside the `InvocationTrust` collaborator owned by the pipeline

### Requirement: Trust store loading is internal to the gate

The gate SHALL load the trust store from `default_trust_store_path()` at most once per CLI invocation, caching the loaded store on the `InvocationTrust` collaborator (owned by `CommandPipeline`) for subsequent consultations within the same invocation. The single-load invariant is enforced inside `InvocationTrust`, not by `CommandPipeline`. CLI commands other than `cmd_trust` SHALL NOT call `TrustStore::load` directly.

#### Scenario: Trust store missing or unreadable

- **WHEN** the trust store cannot be loaded (path missing, IO error)
- **THEN** the gate behaves as today's call sites do: `Ok(())` with the pipeline's config unfiltered and no advisory; failure does not propagate as an error to the caller

#### Scenario: Store loaded once per invocation

- **WHEN** a single `may-i` invocation consults the Trust gate one or more times (e.g. `cmd_check` evaluating many checks, or any subcommand combining the warning-advisory check with a block decision)
- **THEN** `TrustStore::load` SHALL be called at most once for that invocation
- **AND** a test fake counting calls to the loader passed to `InvocationTrust::with_loader` observes exactly one call per invocation

### Requirement: Gate owns integrity advisory rendering

The Trust gate SHALL own rendering of trust-store integrity advisories (the "Trust store corrupted" and "Trust store integrity failure" boxes whose content is defined in `trust-advisory-boxes`). The rendering SHALL be reached through `InvocationTrust::render_prelude` (which renders the migration note first, then integrity advisories). CLI subcommands SHALL NOT call `trust_advisory::write_integrity_advisories` (or its successor) directly. The gate SHALL render integrity advisories during the same invocation as it consults the trust store, before producing its allow/block outcome.

#### Scenario: Integrity advisory and warning advisory render in stable order

- **WHEN** a single invocation has both an integrity issue (e.g. corrupt store) and an untrusted-program warning
- **THEN** `InvocationTrust::render_prelude` renders the integrity advisory and `InvocationTrust::render_warning` renders the warning advisory, in that order, to stderr — matching today's ordering in `cmd_eval` and `cmd_check`

#### Scenario: Subcommand bypass forbidden

- **WHEN** a CLI subcommand is added or modified
- **THEN** it SHALL NOT call `write_integrity_advisories` or any other integrity-advisory routine outside the `InvocationTrust` type; the type is the sole call site
