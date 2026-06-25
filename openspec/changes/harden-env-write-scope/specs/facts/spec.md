## ADDED Requirements

### Requirement: The entry environment is a names-only runtime input

`may-i` SHALL model an **entry environment**: the set of environment-variable
*names* exported into the process at the start of an invocation. It is a kind of
runtime context — observed per invocation, like a fact — but it SHALL be
distinct from a fact: a fact is asserted policy context consumed by
`(fact? …)`, whereas the entry environment is observed ground truth consumed
structurally by the env-write floor (see `shell-command-security-model`). The
entry environment SHALL NOT be exposed through the `(fact? …)` namespace.

The entry environment SHALL carry **names only** — never values. No requirement
may consult an entry-environment *value*; "present" / "absent" is the only
observable. This invariant lets the entry environment participate in decisions
without ever exposing a secret value to a trace, an audit record, or an error
message.

The entry environment SHALL be immutable for the duration of an invocation: it
is the inherited exported set observed at one instant, not a running model of
the shell's variable state. Writes performed *within* the evaluated command
(an `export`, a prefix, a bare assignment) SHALL NOT mutate it; those are
classified structurally, independently of the snapshot.

#### Scenario: Snapshot exposes presence, not value

- **WHEN** the entry environment is captured with `AWS_SECRET_ACCESS_KEY` set
- **THEN** the snapshot SHALL record the name `AWS_SECRET_ACCESS_KEY` as present
- **AND** SHALL NOT retain its value
- **AND** no trace, audit record, or error message SHALL be able to render the
  value from the snapshot

#### Scenario: Intra-command writes do not mutate the snapshot

- **GIVEN** an entry environment in which `FOO` is absent
- **WHEN** evaluating `export FOO=bar; cmd`
- **THEN** `FOO` SHALL remain absent from the entry environment for the whole
  evaluation
- **AND** the `export FOO=bar` write SHALL be classified as reaching a child by
  its syntax, not by the snapshot

#### Scenario: Not reachable as a fact

- **GIVEN** an entry environment in which `PATH` is present
- **WHEN** a rule body evaluates `(fact? :PATH)`
- **THEN** the predicate SHALL NOT match on the strength of the entry
  environment — entry-environment presence is not a fact

### Requirement: The entry environment is sourced per invocation mode

The source of the entry environment SHALL depend on the invocation mode, so live
enforcement reflects reality while the explanation and test modes stay
reproducible.

- `may-i hook` SHALL capture the entry environment from the live process
  environment as its first action, before any internal environment mutation
  (including the git-environment scrubbing performed before spawning
  subprocesses).
- `may-i eval` SHALL default to an **empty** entry environment. It SHALL accept
  a repeatable `--env NAME` flag that adds `NAME` to a hypothetical entry
  environment, and a `--inherit-env` flag that captures the real process
  environment for reproducing a live hook decision locally. The two SHALL be
  combinable; `--inherit-env` with `--env` adds names to the inherited set.
- `may-i check` SHALL be hermetic: it SHALL NOT read the process environment,
  and SHALL evaluate each case against only the entry environment the case
  declares (see `testing-strategy`), defaulting to empty.

#### Scenario: Hook captures before scrubbing

- **WHEN** `may-i hook` runs with `GIT_DIR` exported
- **THEN** `GIT_DIR` SHALL appear in the entry environment
- **AND** the later git-environment scrubbing SHALL NOT remove it from the
  snapshot

#### Scenario: Eval defaults to empty, opts into names

- **WHEN** `may-i eval 'PATH=/evil ls'` runs with no env flags
- **THEN** `PATH` SHALL be treated as absent from the entry environment
- **WHEN** `may-i eval --env PATH 'PATH=/evil ls'` runs
- **THEN** `PATH` SHALL be treated as present

#### Scenario: Check ignores the host environment

- **GIVEN** a check case that declares no entry environment
- **WHEN** `may-i check` runs on a machine where `PATH` is exported
- **THEN** the case SHALL evaluate as if `PATH` were absent, regardless of the
  host environment
