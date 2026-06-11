## ADDED Requirements

### Requirement: Command-evaluation pipeline is not duplicated

The engine SHALL contain exactly one core function implementing the *parse →
decompose → evaluate units → strictest-wins aggregate → parse-error floor*
pipeline. `evaluate_command_inner` and `evaluate_authorised_string` SHALL both be
thin adapters over that core; neither SHALL re-implement the unit loop, the
`:allow < :ask < :deny` aggregation, or the Error-severity parse-error floor.
Segment/offset collection SHALL be an optional injected concern of the core, so
the top-level path collects segments and the authorise path does not, without a
second loop.

#### Scenario: One unit-loop-and-floor implementation

- **WHEN** inspecting `crates/engine/src/eval/command.rs` for the
  decompose-loop-aggregate-floor sequence
- **THEN** exactly one function SHALL contain it, and `evaluate_command_inner`
  and `evaluate_authorised_string` SHALL delegate to it

#### Scenario: Top-level and authorise paths agree on decisions

- **WHEN** the same shell input is evaluated through `evaluate_command` and
  through `evaluate_authorised_string`
- **THEN** the two SHALL return the same decision for every input (modulo the
  `:via` fact the authorise path injects)

### Requirement: Substitution termination is reported by the parser

The shell parser SHALL report, per embedded substitution it extracts, whether
that substitution is terminated. The engine SHALL decide whether to recurse
into a substitution from that reported flag and SHALL NOT re-derive termination
by correlating substitution body spans against `ParseDiagnostic` spans. No
byte-offset correlation between substitution spans and diagnostic spans SHALL
exist in the engine.

#### Scenario: Engine reads a termination flag, not diagnostic spans

- **WHEN** inspecting `crates/engine/src/eval/decompose.rs`
- **THEN** it SHALL skip unterminated substitutions by reading the parser's
  per-substitution termination flag, and no function correlating substitution
  spans against diagnostic spans SHALL remain

#### Scenario: Unterminated substitution is still not recursed into

- **WHEN** the input is `grep -n "x$(y" file` and `grep` is allowed
- **THEN** the decision SHALL be `:ask` with a reason starting
  `parse error: unterminated command substitution`, and the reason SHALL NOT
  contain `No rule for command`

#### Scenario: Well-formed substitution still recurses

- **WHEN** the input is `echo $(rm -rf /)`, `echo` is allowed and `rm` is denied
- **THEN** the decision SHALL be `:deny`

### Requirement: Parser-aware positional tokenisation uses single implementation

The engine SHALL have exactly one implementation of the style-aware
positional/tail tokenisation (the outer/tail split, positional residual
extraction, and first-positional-index scan). Code needing owned results SHALL clone at the
call site rather than maintaining a parallel owned copy of the state machine.

#### Scenario: One positional-tokenisation state machine

- **WHEN** scanning the engine for positional-residual / first-positional-index
  / outer-tail-split logic
- **THEN** exactly one implementation of each SHALL exist, and the binding
  environment SHALL obtain owned values by cloning the borrowed result rather
  than re-implementing the scan
