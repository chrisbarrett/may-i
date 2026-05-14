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

The system SHALL expose a single `trust_gate::evaluate` function that CLI commands consult before evaluating a shell command. The function SHALL accept the loaded `Config`, the command string, and a `GateMode` discriminating text output, JSON output, and Claude Code hook contexts. It SHALL return either `Proceed` (with a Trust-filtered config and an optional pre-built advisory `Layout`) or `Block` (with a reason, source files, and an `:ask` decision).

#### Scenario: Text mode with no untrusted programs

- **WHEN** `trust_gate::evaluate` is called in `GateMode::Text` against a config whose loaded rules are all trusted
- **THEN** the gate returns `Proceed` with the original config unchanged and `advisory: None`

#### Scenario: Text mode with untrusted programs not invoked by the command

- **WHEN** the config contains untrusted loaded rules for `git`, but the command is `echo hi`
- **THEN** the gate returns `Proceed` with untrusted rules filtered out
- **AND** `advisory: Some(layout)` whose rendered text names the affected programs and source files (current `trust_warning_note` shape preserved)

#### Scenario: JSON mode with command invoking an untrusted program

- **WHEN** `GateMode::Json` is used and the command's program has untrusted rules
- **THEN** the gate returns `Block { decision: Ask, reason, files }` where `reason` matches the current `"Untrusted rules for X. Run: may-i trust"` format and `files` is the list of source paths

#### Scenario: Hook mode block reason includes file paths

- **WHEN** `GateMode::Hook` is used and the program has untrusted rules from `~/rules/basics.lisp`
- **THEN** the gate returns `Block` whose `reason` contains the file path, matching `cmd_claude_code_hook`'s current message format

#### Scenario: Filtering applies before Proceed

- **WHEN** the gate returns `Proceed`
- **THEN** the returned `Config` contains no Loaded rules whose hash is un-approved in the trust store

### Requirement: Program-name extraction is internal to the gate

The gate SHALL extract the invoked program name from the command string using the same rules currently duplicated in `cmd_eval.rs` and `cmd_claude_code_hook.rs` (first whitespace-separated token, then last component after `/`). Callers SHALL NOT perform program-name extraction for Trust purposes outside the gate.

#### Scenario: Path-prefixed program

- **WHEN** the command is `/usr/local/bin/git status`
- **THEN** the program considered for Trust is `git`

#### Scenario: Compound command first segment

- **WHEN** the command is `git push && echo done`
- **THEN** Trust evaluation considers the program of the first segment for block decisions, matching today's behaviour

### Requirement: Trust store loading is internal to the gate

The gate SHALL load the trust store from `default_trust_store_path()`. CLI commands other than `cmd_trust` SHALL NOT call `TrustStore::load` directly.

#### Scenario: Trust store missing or unreadable

- **WHEN** the trust store cannot be loaded (path missing, IO error)
- **THEN** the gate behaves as today's call sites do: `Proceed` with the original config (no filtering) and no advisory; failure does not propagate as an error to the caller

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
