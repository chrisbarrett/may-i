---
audience: contributor
bucket: trust
trust-relevant: true
---
# trust-gate Specification

## Purpose

Contributor-only. The single `trust_gate::evaluate` entry point that CLI commands consult before evaluating a shell command, and the runtime semantics it enforces: when an unmatched hash blocks evaluation, when first load of a new loaded program requires approval before any rule applies, when a program bypasses trust entirely (no `Loaded` content), and the hook-mode exit-code contract. Produces either a Trust-filtered config (with an optional pre-built advisory layout) or a block decision with reason and source files. See `trust-store` for hash storage, `trust-hashing` for what gets hashed, `trust-advisory-boxes` for the output formats this gate selects.

## Requirements

### Requirement: Single Trust gate entry-point

The system SHALL expose a single Trust gate entry-point that CLI commands consult before evaluating a shell command. The entry-point SHALL be a method on the per-invocation `CommandPipeline` object (working name; see the `command-pipeline` spec) that takes the command string and a `TrustMode` discriminating text output, JSON output, and Claude Code hook contexts. On allow it SHALL filter untrusted Loaded rules from the pipeline's loaded config in place and SHALL NOT return owned `Config` state to the caller. On block it SHALL return a `TrustBlock` carrying a `:ask` decision, a reason string, and the affected source files; the pipeline SHALL render the block through a single `output::render_trust_block` (or equivalent) operation shaped by the invocation mode. Evaluation `cmd_*` modules SHALL NOT consult the trust gate directly nor serialise a `TrustBlock` themselves — they drive the entire flow through `CommandPipeline::run` (see the `command-pipeline` spec).

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

### Requirement: Program-name extraction is internal to the gate

The gate SHALL extract the invoked program name from the command string using the same rules currently duplicated in `cmd_eval.rs` and `cmd_claude_code_hook.rs` (first whitespace-separated token, then last component after `/`). Callers SHALL NOT perform program-name extraction for Trust purposes outside the gate.

#### Scenario: Path-prefixed program

- **WHEN** the command is `/usr/local/bin/git status`
- **THEN** the program considered for Trust is `git`

#### Scenario: Compound command first segment

- **WHEN** the command is `git push && echo done`
- **THEN** Trust evaluation considers the program of the first segment for block decisions, matching today's behaviour

### Requirement: Trust store loading is internal to the gate

The gate SHALL load the trust store from `default_trust_store_path()` at most once per CLI invocation, caching the loaded store on the pipeline for subsequent consultations within the same invocation. CLI commands other than `cmd_trust` SHALL NOT call `TrustStore::load` directly.

#### Scenario: Trust store missing or unreadable

- **WHEN** the trust store cannot be loaded (path missing, IO error)
- **THEN** the gate behaves as today's call sites do: `Ok(())` with the pipeline's config unfiltered and no advisory; failure does not propagate as an error to the caller

#### Scenario: Store loaded once per invocation

- **WHEN** a single `may-i` invocation consults the Trust gate one or more times (e.g. `cmd_check` evaluating many checks, or any subcommand combining the warning-advisory check with a block decision)
- **THEN** `TrustStore::load` SHALL be called at most once for that invocation
- **AND** a test fake counting calls to the store loader observes exactly one call per invocation

### Requirement: Evaluation blocks on trust mismatch

When a program's computed trust hash does not match the stored hash, the gate SHALL block evaluation for that program, returning `Block` with an `:ask` decision and a reason indicating trust approval is needed.

#### Scenario: Hash mismatch blocks evaluation

- **WHEN** evaluating `"git commit"` and the trust hash for `"git"` has changed since last approved
- **THEN** the gate returns `Block` with decision `:ask` and a reason mentioning trust approval

#### Scenario: Hash match allows evaluation

- **WHEN** evaluating `"git commit"` and the trust hash for `"git"` matches the stored value
- **THEN** evaluation proceeds normally

### Requirement: First load of a program requires approval

When a program has `Loaded` content and no entry exists in the trust store, the gate SHALL treat it as a trust mismatch (no TOFU).

#### Scenario: New loaded program blocks until approved

- **WHEN** a loaded file introduces rules for `"kubectl"` and no trust entry exists
- **THEN** evaluation for `"kubectl"` blocks with a trust approval message

### Requirement: Programs without loaded content bypass trust

Programs whose rules and referenced defines are all `PrimaryConfig` SHALL bypass trust checking entirely — no hash computed, no store lookup.

#### Scenario: PrimaryConfig-only program evaluates freely

- **WHEN** program `"ls"` has only `PrimaryConfig` rules
- **THEN** evaluation proceeds without any trust check

### Requirement: Hook mode uses exit code 2 for trust blocks

In Claude Code hook mode, a trust block SHALL produce exit code 2 (blocking error), consistent with other blocking errors.

#### Scenario: Trust block in hook mode

- **WHEN** a trust mismatch occurs during hook-mode evaluation
- **THEN** the process exits with code 2 and the error message is fed back to the harness

### Requirement: External Trust behaviour preserved

The user-visible output of `eval`, `check`, and the hook SHALL be byte-for-byte identical before and after the gate is introduced for any input that does not exercise the duplicated program-name extraction inconsistency. This is a refactor; existing specs (`trust-advisory-boxes`, `trust-store`) remain authoritative for what the gate must produce.

#### Scenario: Existing trust integration tests pass unchanged

- **WHEN** the integration test suite under `tests/` runs
- **THEN** every test that exercised trust block / advisory / filter behaviour before the change passes without modification

### Requirement: Gate owns integrity advisory rendering

The Trust gate SHALL own rendering of trust-store integrity advisories (the "Trust store corrupted" and "Trust store integrity failure" boxes whose content is defined in `trust-advisory-boxes`). CLI subcommands SHALL NOT call `trust_advisory::write_integrity_advisories` (or its successor) directly. The gate SHALL render integrity advisories during the same invocation as it consults the trust store, before producing its allow/block outcome.

#### Scenario: Integrity advisory and warning advisory render in stable order

- **WHEN** a single invocation has both an integrity issue (e.g. corrupt store) and an untrusted-program warning
- **THEN** the gate renders the integrity advisory first, then the warning advisory, to stderr — matching today's ordering in `cmd_eval` and `cmd_check`

#### Scenario: Subcommand bypass forbidden

- **WHEN** a CLI subcommand is added or modified
- **THEN** it SHALL NOT call `write_integrity_advisories` or any other integrity-advisory routine outside the Trust gate; the gate is the sole call site

### Requirement: Migration-driven rehash routes through the trust module

The trust module SHALL expose `rehash_after_migration() -> miette::Result<usize>` that loads the trust store, recomputes the canonical form for each entry, and saves the store. `cmd_migrate` SHALL call this function after applying migrations rather than calling `TrustStore::load` directly. The return value reports the number of entries whose hash changed.

The carve-out for `cmd_trust` calling `TrustStore::load` directly (see `Trust store loading is internal to the gate`) remains; `cmd_migrate` is not added to that carve-out — it routes through the new entry point instead.

#### Scenario: cmd_migrate does not load the trust store directly

- **WHEN** scanning `src/cmd_migrate.rs` for `TrustStore::load` references
- **THEN** zero references appear
- **AND** the post-migration rehash is implemented by a call to `crate::trust::rehash_after_migration`

#### Scenario: Rehash preserves approval status

- **WHEN** the trust store has an approved entry whose canonical form is recomputed identically (no change) during migration
- **THEN** `rehash_after_migration` leaves the entry untouched and does not count it as rehashed

#### Scenario: Rehash updates entries whose canonical form changed

- **WHEN** a migration changes the canonical form of an approved rule (so its old hash no longer matches the recomputed form)
- **THEN** `rehash_after_migration` replaces the entry's hash with the recomputed hash, preserves the approval status, and increments the rehashed-count return value
