---
audience: user
bucket: facts
---
# facts Specification

## Purpose

Facts are keyed runtime context used by rules and predicates: each fact is a
key (e.g. `:via`, `:ssh/host`) mapped to a set of string values. Rules query
facts through `(fact? …)` predicates over the `FactPattern` surface
(Literal, Wildcard, Regex, And, Or, Not) and the `FactQuery` surface
(Presence, Value). Users supply facts via the `--fact` CLI surface;
recursive evaluation also pushes one automatic fact, `:via`, recording the
chain of `(authorise …)` carriers under which an inner command runs. Every
other fact (e.g. `:ssh/host`) must be declared explicitly via a
parser-side `#var` binding paired with a rule-side `(with-facts …)` form.

## Requirements

### Requirement: FactPattern enum available in predicates module

The `FactPattern` enum (Literal, Wildcard, Regex, And, Or, Not) SHALL be defined in `crates/core/src/predicates.rs` and re-exported from `may_i_core`.

#### Scenario: FactPattern can match literal values

- **WHEN** `FactPattern::Literal("prod")` is matched against "prod"
- **THEN** it returns true

#### Scenario: FactPattern supports boolean Pattern composition

- **WHEN** `FactPattern::And(vec![p1, p2])` is matched
- **THEN** it returns true only if both patterns match

### Requirement: FactQuery enum available in predicates module

The `FactQuery` enum (Presence, Value) SHALL be defined in `crates/core/src/predicates.rs` and re-exported from `may_i_core`. `FactQuery::Presence` SHALL carry only the `key` field — no `vector_syntax` field.

#### Scenario: FactQuery can check key presence

- **WHEN** `FactQuery::Presence { key }` is evaluated
- **THEN** it checks if the key exists in context

#### Scenario: FactQuery can check key value

- **WHEN** `FactQuery::Value { key, pattern }` is evaluated
- **THEN** it checks if the key's value matches the pattern

#### Scenario: No vector_syntax in domain model

- **WHEN** constructing a `FactQuery::Presence`
- **THEN** only the `key` field SHALL be required

### Requirement: FactQuery::Presence evaluates against stored facts

`FactQuery::Presence` SHALL return Match when the queried key exists in the fact store (the set may be empty or populated). Fact store is set-based; presence checks key existence regardless of set contents.

#### Scenario: Key present with values

- **GIVEN** fact store contains `:via` = `{"sudo", "ssh"}`
- **WHEN** evaluating `FactQuery::Presence { key: ":via" }`
- **THEN** it SHALL return Match

#### Scenario: Key present with empty set

- **GIVEN** fact store contains `:client/claude-code` with empty set
- **WHEN** evaluating `FactQuery::Presence { key: ":client/claude-code" }`
- **THEN** it SHALL return Match

#### Scenario: Key absent

- **GIVEN** fact store does not contain `:via`
- **WHEN** evaluating `FactQuery::Presence { key: ":via" }`
- **THEN** it SHALL return NoMatch

### Requirement: FactQuery::Value evaluates as set-membership test

`FactQuery::Value` SHALL return Match when the queried key exists and the pattern matches any member of the set at that key.

#### Scenario: Literal matches a set member

- **GIVEN** fact store contains `:via` = `{"sudo", "ssh"}`
- **WHEN** evaluating `FactQuery::Value { key: ":via", pattern: Literal("ssh") }`
- **THEN** it SHALL return Match

#### Scenario: Literal does not match any member

- **GIVEN** fact store contains `:via` = `{"sudo"}`
- **WHEN** evaluating `FactQuery::Value { key: ":via", pattern: Literal("ssh") }`
- **THEN** it SHALL return NoMatch

#### Scenario: Regex matches any set member

- **GIVEN** fact store contains `:ssh/host` = `{"prod-server-01"}`
- **WHEN** evaluating `FactQuery::Value { key: ":ssh/host", pattern: Regex("^prod-") }`
- **THEN** it SHALL return Match

#### Scenario: Wildcard matches if set is non-empty

- **GIVEN** fact store contains `:ssh/host` = `{"prod-1"}`
- **WHEN** evaluating `FactQuery::Value { key: ":ssh/host", pattern: Wildcard }`
- **THEN** it SHALL return Match

#### Scenario: Wildcard does not match empty set

- **GIVEN** fact store contains `:client/claude-code` with empty set
- **WHEN** evaluating `FactQuery::Value { key: ":client/claude-code", pattern: Wildcard }`
- **THEN** it SHALL return NoMatch

#### Scenario: Missing key returns NoMatch

- **GIVEN** fact store does not contain `:ssh/host`
- **WHEN** evaluating `FactQuery::Value { key: ":ssh/host", pattern: Literal("prod") }`
- **THEN** it SHALL return NoMatch

### Requirement: `(authorise …)` pushes carrier command name onto :via set

When `(authorise #var)` (or any other `(authorise …)`-shaped recursion entry — `(parameter NAME (authorise))` single-token capture, `(tail (authorise))`) triggers recursive evaluation, the evaluator SHALL automatically push the current command name onto the `:via` fact set before evaluating the inner command. The push SHALL apply to every evaluation unit produced by the recursion (one push per `(authorise …)` call, not per inner unit).

#### Scenario: Single carrier

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))` and `(rule "sudo" (authorise #cmd))` and `(rule "rm" (deny))`
- **WHEN** evaluating `sudo rm -rf /`
- **THEN** the inner evaluation of `rm -rf /` SHALL have `:via` = `{"sudo"}`.

#### Scenario: Nested carriers accumulate

- **GIVEN** `(parser "sudo" (style gnu) (flags posix) (rest #cmd))`, `(parser "ssh" (style gnu) (flags posix) (positional #host (regex "^[^-].*")) (rest #cmd))`, `(rule "sudo" (authorise #cmd))`, and `(rule "ssh" (authorise #cmd))`
- **WHEN** evaluating `sudo ssh prod-1 rm -rf /`
- **THEN** the inner evaluation of `rm` SHALL have `:via` = `{"sudo", "ssh"}`.

#### Scenario: Order does not matter for set membership

- **GIVEN** `:via` = `{"sudo", "ssh"}` from nested carrier recursion
- **WHEN** evaluating `(fact? [:via "ssh"])`
- **THEN** it SHALL return Match regardless of carrier order.

### Requirement: :via is the only automatically pushed fact

Only the `:via` key SHALL be automatically populated by an `(authorise …)` recursion. All other facts (e.g., `:ssh/host`) require explicit declaration: a parser-side `#var` binding (`(positional #host …)`, `(parameter "k" #v)`, `(rest #cmd)`) combined with a rule-side `(with-facts [[:k #var]] …)` form, or — for set-membership tests only — a direct `(fact? …)` predicate.

#### Scenario: Parser bindings are not automatic facts

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (positional #host (regex "^[^-].*")) (rest #cmd))` and `(rule "ssh" (authorise #cmd))`
- **WHEN** evaluating `ssh prod-1 ls`
- **THEN** the inner evaluation SHALL have `:via` = `{"ssh"}`
- **AND** the inner evaluation SHALL NOT have a `:ssh/host` fact (no `(with-facts …)` lifted `#host` into facts).

#### Scenario: `(with-facts …)` lifts a binding alongside automatic via

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (positional #host (regex "^[^-].*")) (rest #cmd))` and `(rule "ssh" (with-facts [[:ssh/host #host]] (authorise #cmd)))`
- **WHEN** evaluating `ssh prod-1 ls`
- **THEN** the inner evaluation SHALL have `:via` = `{"ssh"}` and `:ssh/host` = `{"prod-1"}`.

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
