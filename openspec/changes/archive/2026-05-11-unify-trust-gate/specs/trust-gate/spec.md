## ADDED Requirements

### Requirement: Single Trust gate entry-point
The system SHALL expose a single `trust_gate::evaluate` function that CLI
commands consult before evaluating a shell command. The function SHALL accept
the loaded `Config`, the command string, and a `GateMode` discriminating text
output, JSON output, and Claude Code hook contexts. It SHALL return either
`Proceed` (with a Trust-filtered config and an optional pre-built advisory
`Layout`) or `Block` (with a reason, source files, and an `:ask` decision).

#### Scenario: Text mode with no untrusted programs
- **WHEN** `trust_gate::evaluate` is called in `GateMode::Text` against a config
  whose loaded rules are all trusted
- **THEN** the gate returns `Proceed` with the original config unchanged and
  `advisory: None`

#### Scenario: Text mode with untrusted programs not invoked by the command
- **WHEN** the config contains untrusted loaded rules for `git`, but the
  command is `echo hi`
- **THEN** the gate returns `Proceed` with untrusted rules filtered out
- **AND** `advisory: Some(layout)` whose rendered text names the affected
  programs and source files (current `trust_warning_note` shape preserved)

#### Scenario: JSON mode with command invoking an untrusted program
- **WHEN** `GateMode::Json` is used and the command's program has untrusted
  rules
- **THEN** the gate returns `Block { decision: Ask, reason, files }` where
  `reason` matches the current `"Untrusted rules for X. Run: may-i trust"`
  format and `files` is the list of source paths

#### Scenario: Hook mode block reason includes file paths
- **WHEN** `GateMode::Hook` is used and the program has untrusted rules from
  `~/rules/basics.lisp`
- **THEN** the gate returns `Block` whose `reason` contains the file path,
  matching `cmd_claude_code_hook`'s current message format

#### Scenario: Filtering applies before Proceed
- **WHEN** the gate returns `Proceed`
- **THEN** the returned `Config` contains no Loaded rules whose hash is
  un-approved in the trust store

### Requirement: Program-name extraction is internal to the gate
The gate SHALL extract the invoked program name from the command string using
the same rules currently duplicated in `cmd_eval.rs` and
`cmd_claude_code_hook.rs` (first whitespace-separated token, then last
component after `/`). Callers SHALL NOT perform program-name extraction for
Trust purposes outside the gate.

#### Scenario: Path-prefixed program
- **WHEN** the command is `/usr/local/bin/git status`
- **THEN** the program considered for Trust is `git`

#### Scenario: Compound command first segment
- **WHEN** the command is `git push && echo done`
- **THEN** Trust evaluation considers the program of the first segment for
  block decisions, matching today's behaviour

### Requirement: Trust store loading is internal to the gate
The gate SHALL load the trust store from `default_trust_store_path()`. CLI
commands other than `cmd_trust` SHALL NOT call `TrustStore::load` directly.

#### Scenario: Trust store missing or unreadable
- **WHEN** the trust store cannot be loaded (path missing, IO error)
- **THEN** the gate behaves as today's call sites do: `Proceed` with the
  original config (no filtering) and no advisory; failure does not propagate
  as an error to the caller

### Requirement: External Trust behaviour preserved
The user-visible output of `eval`, `check`, and the hook SHALL be byte-for-byte
identical before and after the gate is introduced for any input that does not
exercise the duplicated program-name extraction inconsistency. This is a
refactor; existing specs (`trust-block-context`, `trust-advisory-boxes`,
`trust-provenance`, `per-rule-trust`) remain authoritative for what the gate
must produce.

#### Scenario: Existing trust integration tests pass unchanged
- **WHEN** the integration test suite under `tests/` runs
- **THEN** every test that exercised trust block / advisory / filter behaviour
  before the change passes without modification
