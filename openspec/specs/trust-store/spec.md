# trust-store Specification

## Purpose

Persistent on-disk storage of approved trust hashes, plus the evaluation block behaviour when a stored hash does not match the current computed hash. Trust-relevant: yes — see `trust-hashing` for hash computation, `trust-command` for the approval UI, `trust-gate` for the runtime check.

## Requirements

### Requirement: Trust hashes are stored persistently

The system SHALL store trust hashes in a persistent file at a platform-appropriate data directory (e.g. `~/.local/share/may-i/trust.json`).

#### Scenario: Approved hash is persisted

- **WHEN** the user approves trust for program `"git"`
- **THEN** the hash is written to the trust store and survives process restart

### Requirement: Evaluation blocks on trust mismatch

When a program's computed trust hash does not match the stored hash, the system SHALL block evaluation for that program, returning `ask` with a reason indicating trust approval is needed.

#### Scenario: Hash mismatch blocks evaluation

- **WHEN** evaluating `"git commit"` and the trust hash for `"git"` has changed since last approved
- **THEN** the system returns decision `ask` with a reason mentioning trust approval

#### Scenario: Hash match allows evaluation

- **WHEN** evaluating `"git commit"` and the trust hash for `"git"` matches the stored value
- **THEN** evaluation proceeds normally

### Requirement: First load of a program requires approval

When a program has `Loaded` content and no entry exists in the trust store, the system SHALL treat it as a trust mismatch (no TOFU).

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
