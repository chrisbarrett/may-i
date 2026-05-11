## ADDED Requirements

### Requirement: Check evaluation propagates errors

The check evaluation system SHALL propagate evaluation errors as diagnostic results rather than panicking. When `evaluate()` returns an error (e.g., UnresolvedPredicate), the check system SHALL report it as a check failure with a descriptive message.

#### Scenario: Unresolved predicate during check

- **WHEN** a check rule references an undefined predicate
- **THEN** the check system SHALL report a diagnostic failure instead of panicking

### Requirement: EvalResult exposes per-segment decisions

`EvalResult` SHALL include a `segment_decisions` field that lists each
evaluated unit of the input command with its byte range in the original
input string and the `Decision` reached for that unit. The aggregate
`decision` and `reason` fields SHALL retain their current semantics
(strictest decision over all units; reason from the contributing unit).

#### Scenario: Single command produces one segment

- **WHEN** `evaluate_command("echo hi", config, facts)` is called and `echo` is allowed
- **THEN** `result.segment_decisions` is one entry covering the byte range `0..7` with decision `Allow`
- **AND** `result.decision` is `Allow`

#### Scenario: Compound `&&` produces one entry per command

- **WHEN** `evaluate_command("echo a && rm -rf /", config, facts)` is called, `echo` is allowed, `rm` is unmatched
- **THEN** `result.segment_decisions` contains two entries: `(0..6, Allow)` for `echo a` and `(10..18, Ask)` for `rm -rf /` (operator `&&` is not a segment)
- **AND** `result.decision` is `Ask`

#### Scenario: Embedded substitution becomes its own segment

- **WHEN** `evaluate_command("echo $(rm)", config, facts)` is called
- **THEN** `result.segment_decisions` contains an entry covering the inner `rm` range with the decision reached for `rm`
- **AND** the outer `echo` segment is also present

#### Scenario: Dynamic command segments report Ask

- **WHEN** the input contains `$EDITOR file.txt`
- **THEN** the corresponding `segment_decisions` entry has decision `Ask`, matching the engine's existing `EvalUnit::DynamicCommand` behaviour

#### Scenario: Empty or malformed input yields no segments

- **WHEN** the input is empty, whitespace-only, or fails parsing such that no `EvalUnit` is produced
- **THEN** `segment_decisions` is empty
- **AND** `decision` is `Ask` with a reason as today

### Requirement: Segment decisions describe non-overlapping byte ranges

Within a single `EvalResult`, segment byte ranges SHALL NOT overlap, except that an embedded-command segment MAY be contained within its enclosing segment's range. Display code SHALL be able to walk the input top-to-bottom mapping segments to their decisions without ambiguity for top-level units.

#### Scenario: Top-level segments are disjoint

- **WHEN** the input is `a; b; c` with three simple commands
- **THEN** the three top-level entries' byte ranges are pairwise disjoint

### Requirement: Display does not re-evaluate to colourise

CLI display SHALL derive per-segment colours from `EvalResult.segment_decisions` without invoking the engine a second time. The eval pipeline is the single source of truth for any segment's decision.

#### Scenario: cmd_eval colourises from the result

- **WHEN** `cmd_eval` renders the coloured command line for the Result block
- **THEN** it reads colours from `result.segment_decisions` only; no call to `engine::eval::evaluate_command` originates from the display path

### Requirement: Aggregate decision unchanged

The aggregate `decision` and `reason` returned for any input SHALL be byte-identical before and after this change. `segment_decisions` is additive information; existing callers ignore it without semantic change.

#### Scenario: All existing engine tests pass unchanged

- **WHEN** the engine test suite runs against the post-change implementation
- **THEN** every assertion that compares `result.decision` or `result.reason` passes without modification
