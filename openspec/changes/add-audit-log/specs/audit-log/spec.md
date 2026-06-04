---
audience: user
bucket: tracing-and-output
---
# audit-log Specification

## Purpose

The Audit log: a persisted, append-only JSONL trail of evaluation outcomes,
one audit record per evaluation, for after-the-fact forensics — which commands
failed to parse, asked, or were denied. Covers the primary-config-only
`(audit …)` form, the `(threshold …)` selector, precedence across config / env /
CLI, the audit record schema, which commands write, the file location and
permissions, the append-only write discipline, and the best-effort
failure-isolation guarantee. The Audit log is distinct from a Trace (rendered
and ephemeral) and an Advisory (a notice about config health). See
`trust-hashing` for the canonical-form rule hashes the record carries,
`command-pipeline` for the eval/hook terminal points where records are emitted,
and `shell-command-security-model` for why the trail is a sensitive on-disk
surface.

## ADDED Requirements

### Requirement: The `(audit …)` form configures the Audit log

The system SHALL accept a top-level `(audit …)` form carrying an optional
`(threshold …)` sub-form and an optional `(file …)` sub-form, following the
head-keyed sub-form convention of `(define-arg-style …)` (not a keyword plist).
The threshold value SHALL be one of the keywords `:off`, `:deny`, `:ask`, or
`:all` (a closed-set enumerated value, spelled as a keyword like `(pun :allow)`).
When the form is absent, or `(threshold …)` is absent, the threshold
SHALL default to `:off` (the Audit log is disabled). There SHALL be no separate
enable/disable knob — `off` is the disabled state.

#### Scenario: Form sets the threshold

- **WHEN** the primary config contains `(audit (threshold :ask))`
- **THEN** the effective audit threshold is `:ask`

#### Scenario: Absent form disables the log

- **WHEN** the primary config contains no `(audit …)` form and no audit flag or
  environment variable is set
- **THEN** the effective audit threshold is `off` and no audit record is written
  for any evaluation

#### Scenario: Invalid threshold value is a load error

- **WHEN** the primary config contains `(audit (threshold :loud))`
- **THEN** loading fails with an error naming the valid values
  `:off`, `:deny`, `:ask`, `:all`

### Requirement: The `(audit …)` form is honoured only from the primary config

An `(audit …)` form SHALL be accepted only when it originates from the primary
config. An `(audit …)` form appearing in any loaded source — pulled in via
`(load …)` or discovered as repo-local config — SHALL be a hard load error that
refuses the offending file. A loaded source MUST NOT be able to enable,
disable, or redirect the Audit log.

#### Scenario: Audit form in a loaded file is rejected

- **WHEN** a file pulled in via `(load …)` contains `(audit (threshold :off))`
- **THEN** loading fails with an error stating that `(audit …)` is permitted
  only in the primary config
- **AND** no command is evaluated

#### Scenario: Audit form in repo-local config is rejected

- **WHEN** a discovered repo-local config file (e.g. `.may-i.lisp`) contains an
  `(audit …)` form
- **THEN** loading fails with the same primary-config-only error

### Requirement: The threshold selects which outcomes are recorded

The threshold SHALL select which evaluation outcomes produce an audit record,
ordered by strictness: `off` records nothing; `deny` records denials; `ask`
records asks and denials; `all` records allows, asks, and denials. Regardless
of threshold (at any non-`off` setting), an evaluation whose command failed to
parse SHALL always be recorded.

#### Scenario: `deny` threshold omits asks and allows

- **GIVEN** the threshold is `deny`
- **WHEN** a command evaluates to `ask`
- **THEN** no audit record is written
- **WHEN** a command evaluates to `deny`
- **THEN** one audit record is written

#### Scenario: `ask` threshold records asks and denials

- **GIVEN** the threshold is `ask`
- **WHEN** a command evaluates to `ask` and another to `deny`
- **THEN** an audit record is written for each
- **AND** a command evaluating to `allow` produces no record

#### Scenario: Parse failures are always recorded

- **GIVEN** the threshold is `deny`
- **WHEN** a command fails to parse (its decision floors to `ask`)
- **THEN** one audit record is written even though `ask` is below the `deny`
  threshold

### Requirement: Audit settings resolve per-field across config, environment, and CLI

Each audit setting (`threshold`, `file`) SHALL resolve independently with the
precedence flag > environment variable > config form > built-in default. The
CLI flags SHALL be `--audit-threshold` and `--audit-file`; the environment
variables SHALL be `MAYI_AUDIT_THRESHOLD` and `MAYI_AUDIT_FILE`. Overriding one
field MUST NOT reset another to its default. Threshold values supplied on the
CLI or in the environment SHALL be bare strings (`ask`, `all`) — the keyword
spelling (`:ask`) is the `(audit …)` form's value syntax only.

#### Scenario: Flag overrides the config threshold but not the file

- **GIVEN** the primary config contains `(audit (threshold :ask) (file "/var/x.jsonl"))`
- **WHEN** `may-i eval` is run with `--audit-threshold all`
- **THEN** the effective threshold is `all`
- **AND** the effective file remains `/var/x.jsonl`

#### Scenario: Environment variable overrides config and is overridden by flag

- **GIVEN** the config threshold is `off` and `MAYI_AUDIT_THRESHOLD=ask` is set
- **WHEN** no `--audit-threshold` flag is given
- **THEN** the effective threshold is `ask`
- **WHEN** `--audit-threshold deny` is also given
- **THEN** the effective threshold is `deny`

#### Scenario: Hook mode is configurable without flags

- **GIVEN** hook mode is invoked with JSON on stdin and no CLI flags
- **WHEN** `MAYI_AUDIT_THRESHOLD=deny` is set in the environment
- **THEN** denials in hook mode are recorded

### Requirement: An audit record captures the evaluation outcome

Each audit record SHALL be a single JSON object on one line carrying: a schema
version; a timestamp; the originating command (`eval` or `hook`); the harness
when known; the evaluated command string; the decision (`allow`, `ask`, or
`deny`); the reason when present; the outcome source (`rule`, `trust-block`, or
`parse-floor`); whether the command parsed; the parse diagnostic when it did
not; the canonical-form hashes of the deciding rules; the config path; and the
working directory when known. The schema version SHALL be present so the format
can evolve.

#### Scenario: A denial records its deciding rules

- **WHEN** a command is denied by a matching rule
- **THEN** the record's decision is `deny`, its source is `rule`, and its rule
  list contains the canonical-form hash of each rule that carried the winning
  decision

#### Scenario: A parse failure records the diagnostic

- **WHEN** a command fails to parse
- **THEN** the record's parse status indicates failure, its source is
  `parse-floor`, and the parse diagnostic message is present

#### Scenario: The schema version is present

- **WHEN** any audit record is written
- **THEN** the record carries a schema version field

### Requirement: Trust-block outcomes are recorded

The system SHALL write an audit record with source `trust-block` when an
evaluation is short-circuited by the Trust gate (a command blocked because a
loaded rule awaits approval) and the threshold would record a denial. The trail
MUST NOT silently omit commands blocked for want of approval.

#### Scenario: A trust block is recorded distinctly from a rule denial

- **GIVEN** the threshold records denials
- **WHEN** a command is blocked by the Trust gate before any rule is applied
- **THEN** one audit record is written with source `trust-block`, distinguishing
  it from a `rule` denial

### Requirement: Only the eval and hook commands write audit records

Audit records SHALL be written only by the `eval` and `hook` evaluation paths.
The `check` command SHALL NOT write audit records, because it replays synthetic
test commands and never blocks.

#### Scenario: Check writes nothing

- **GIVEN** any threshold and a config whose embedded checks include denied
  commands
- **WHEN** `may-i check` runs
- **THEN** no audit record is written

#### Scenario: Eval and hook both write

- **GIVEN** the threshold records denials
- **WHEN** the same denied command is evaluated once via `may-i eval` and once
  via the hook path
- **THEN** an audit record is written in each case, distinguished by the
  command field

### Requirement: Default file location and permissions

The default audit file SHALL be `$XDG_STATE_HOME/may-i/audit.jsonl`, falling
back to `~/.local/state/may-i/audit.jsonl` when `XDG_STATE_HOME` is unset. The
containing directory SHALL be created with mode `0700` and the file with mode
`0600`, because it records verbatim commands. A configured file path SHALL
override this default.

#### Scenario: Default path under XDG_STATE_HOME

- **GIVEN** `XDG_STATE_HOME` is set and no audit file is configured
- **WHEN** an audit record is written
- **THEN** it is appended to `$XDG_STATE_HOME/may-i/audit.jsonl` with the file
  mode `0600`

#### Scenario: Configured path overrides the default

- **WHEN** the effective file is `/dev/null`
- **THEN** records are written there and the default location is not created

### Requirement: Records are appended atomically and writing is best-effort

Each audit record SHALL be appended as one complete line in a single append
write, so that concurrent evaluations (such as parallel hook invocations) do not
interleave partial lines on a local filesystem. A failure to open or write the
audit file SHALL NOT alter the decision, the rendered output, or the process
exit code; the audit attempt SHALL be abandoned silently.

#### Scenario: Concurrent writes do not interleave

- **WHEN** multiple hook invocations write audit records concurrently to the
  same local file
- **THEN** each record appears as one intact JSON line, none torn or interleaved

#### Scenario: A write failure does not change the decision

- **GIVEN** the audit file path cannot be written (e.g. its directory is not
  writable)
- **WHEN** a command is denied
- **THEN** the deny decision and its exit code are unchanged and no error is
  raised for the failed audit write
