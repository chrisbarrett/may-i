# Rule-Decisions Specification

## Purpose

Describes the user-level model for how a command resolves to a Decision. Given a parsed command and the loaded set of Rules, the engine selects the Rules whose command name matches the program being evaluated, derives a Decision for each, and combines them into a single Decision and aggregate reason. The resolution is order-independent: shuffling the Rule list (across files or `(load …)` boundaries) MUST yield the same Decision and reason. This spec covers Decision semantics only; the trust closure that determines which Rules are eligible is described in `trust-hashing`. Per-segment decisions on `EvalResult` and check-evaluation error propagation are also documented here.

Trust-relevant: no.

## Requirements

### Requirement: Program name selects the applicable rule set

When evaluating a command, the engine SHALL identify the *applicable set*
of rules: every rule whose command effect matches the program name being
evaluated. Rules whose command effect does not match SHALL be excluded.

#### Scenario: Rule for unrelated program is excluded

- **GIVEN** `(rule "rm" (effect :deny "no rm"))` and `(rule "ls" (effect
  :allow))`
- **WHEN** evaluating `ls -la`
- **THEN** the applicable set SHALL be the `ls` rule only
- **AND** the result SHALL be `:allow`

#### Scenario: Multiple rules for the same program all enter the set

- **GIVEN** two `(rule "git" …)` declarations
- **WHEN** evaluating `git push`
- **THEN** the applicable set SHALL contain both rules

### Requirement: All applicable rules run; strictest non-Nil decision wins

The engine SHALL evaluate every rule in the applicable set, collect each
rule's outcome, discard outcomes whose effect resolved to Nil, and return
the *strictest* of the remaining decisions. Strictness is ordered
`Deny > Ask > Allow`.

#### Scenario: Allow and Deny coexist; Deny wins

- **GIVEN** `(rule "rm" (effect :allow))` and `(rule "rm" (when (flag
  ["r" "recursive"]) (effect :deny "recursive")))`
- **WHEN** evaluating `rm -rf /tmp/foo`
- **THEN** the result SHALL be `:deny "recursive"`

#### Scenario: Allow and Ask coexist; Ask wins

- **GIVEN** `(rule "scp" (effect :allow))` and `(rule "scp" (when
  (fact? :prod) (effect :ask "prod")))`
- **WHEN** evaluating `scp host:foo .` with fact `:prod`
- **THEN** the result SHALL be `:ask "prod"`

#### Scenario: A non-matching rule body returns Nil and does not contribute

- **GIVEN** `(rule "rm" (when (flag "r") (effect :deny)))` and
  `(rule "rm" (effect :allow))`
- **WHEN** evaluating `rm foo` (no `-r`)
- **THEN** the first rule's body SHALL produce Nil
- **AND** the result SHALL be `:allow` from the second rule

### Requirement: Order of rules in the config SHALL not affect the decision

Shuffling the rule list MUST yield the same decision and the same
aggregate reason as the original ordering, for any input (including
across files and `(load …)` order).

#### Scenario: Reordering deny and allow rules

- **GIVEN** `(rule "rm" (effect :deny "X"))` followed by
  `(rule "rm" (effect :allow))`
- **AND** the same two rules in the reverse order
- **WHEN** evaluating any `rm …` command
- **THEN** both configurations SHALL produce the same decision and
  reason

#### Scenario: Reordering across `(load …)` boundaries

- **GIVEN** rule A in `rules/a.lisp` and rule B in `rules/b.lisp`
- **AND** the root config loads them in either order
- **WHEN** evaluating any command those rules cover
- **THEN** both load orders SHALL produce the same decision

### Requirement: Tie-breaking among equally-strict decisions is order-free

The engine SHALL produce a deterministic aggregate reason when two or
more rules return the strictest decision (e.g. two `Deny`s); the
aggregate SHALL NOT depend on rule order. Distinct reasons SHALL be
sorted lexically and joined with `"; "`. Identical reasons SHALL be
deduplicated.

#### Scenario: Two distinct deny reasons combine deterministically

- **GIVEN** `(rule "rm" (when (flag "r") (effect :deny "B")))` and
  `(rule "rm" (when (flag "f") (effect :deny "A")))`
- **WHEN** evaluating `rm -rf /tmp/foo`
- **THEN** the result SHALL be `:deny "A; B"`
- **AND** the same result SHALL hold if the two rules are reversed

#### Scenario: Identical deny reasons are deduplicated

- **GIVEN** two `(rule "rm" (effect :deny "no rm"))` declarations
- **WHEN** evaluating any `rm` command
- **THEN** the result SHALL be `:deny "no rm"` (single reason, not duplicated)

### Requirement: Default decision when no applicable rule produces a decision

When the applicable set is empty, the engine SHALL return `:ask` with a
reason that names the missing program. When the applicable set is
non-empty but every rule body produces Nil, the engine SHALL return
`:ask` with a reason explaining that rules exist but no patterns
matched. The choice between these reasons MUST depend only on whether
the applicable set is empty, not on rule order.

#### Scenario: No rule for the program

- **GIVEN** a config with no rule for `kubectl`
- **WHEN** evaluating `kubectl get pods`
- **THEN** the result SHALL be `:ask`
- **AND** the reason SHALL mention "No rule for command `kubectl`"

#### Scenario: Rules exist but no body matches

- **GIVEN** `(rule "rm" (when (flag "r") (effect :deny)))` only
- **WHEN** evaluating `rm foo` (no `-r`)
- **THEN** the result SHALL be `:ask`
- **AND** the reason SHALL mention that rules exist but no patterns matched

### Requirement: Compound-command aggregation composes with per-program aggregation

Per-segment per-program aggregation SHALL run first for compound shell
commands (`cmd1 && cmd2`, embedded substitution, etc.), and the existing
across-segment "strictest wins" aggregation SHALL combine the
per-segment results unchanged. The two layers use the same strictness
ordering.

#### Scenario: Two segments with different decisions

- **GIVEN** `ls` is allowed and `rm -rf /` is denied
- **WHEN** evaluating `ls && rm -rf /`
- **THEN** the result SHALL be `:deny` from the `rm` segment

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
- **WHEN** `evaluate_command("echo hi", config, facts)` is called and `echo` is
  allowed
- **THEN** `result.segment_decisions` is one entry covering the byte range
  `0..7` with decision `Allow`
- **AND** `result.decision` is `Allow`

#### Scenario: Compound `&&` produces one entry per command
- **WHEN** `evaluate_command("echo a && rm -rf /", config, facts)` is called,
  `echo` is allowed, `rm` is unmatched
- **THEN** `result.segment_decisions` contains two entries: `(0..6, Allow)`
  for `echo a` and `(10..18, Ask)` for `rm -rf /` (operator `&&` is not a
  segment)
- **AND** `result.decision` is `Ask`

#### Scenario: Embedded substitution becomes its own segment
- **WHEN** `evaluate_command("echo $(rm)", config, facts)` is called
- **THEN** `result.segment_decisions` contains an entry covering the inner
  `rm` range with the decision reached for `rm`
- **AND** the outer `echo` segment is also present

#### Scenario: Dynamic command segments report Ask
- **WHEN** the input contains `$EDITOR file.txt`
- **THEN** the corresponding `segment_decisions` entry has decision `Ask`,
  matching the engine's existing `EvalUnit::DynamicCommand` behaviour

#### Scenario: Empty or malformed input yields no segments
- **WHEN** the input is empty, whitespace-only, or fails parsing such that no
  `EvalUnit` is produced
- **THEN** `segment_decisions` is empty
- **AND** `decision` is `Ask` with a reason as today

### Requirement: Segment decisions describe non-overlapping byte ranges
Within a single `EvalResult`, segment byte ranges SHALL NOT overlap, except
that an embedded-command segment MAY be contained within its enclosing
segment's range. Display code SHALL be able to walk the input top-to-bottom
mapping segments to their decisions without ambiguity for top-level units.

#### Scenario: Top-level segments are disjoint
- **WHEN** the input is `a; b; c` with three simple commands
- **THEN** the three top-level entries' byte ranges are pairwise disjoint

### Requirement: Display does not re-evaluate to colourise
CLI display SHALL derive per-segment colours from `EvalResult.segment_decisions`
without invoking the engine a second time. The eval pipeline is the single
source of truth for any segment's decision.

#### Scenario: cmd_eval colourises from the result
- **WHEN** `cmd_eval` renders the coloured command line for the Result block
- **THEN** it reads colours from `result.segment_decisions` only; no call to
  `engine::eval::evaluate_command` originates from the display path

### Requirement: Aggregate decision unchanged
The aggregate `decision` and `reason` returned for any input SHALL be
byte-identical before and after this change. `segment_decisions` is additive
information; existing callers ignore it without semantic change.

#### Scenario: All existing engine tests pass unchanged
- **WHEN** the engine test suite runs against the post-change implementation
- **THEN** every assertion that compares `result.decision` or `result.reason`
  passes without modification
