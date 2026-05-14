---
audience: user
bucket: rules-and-evaluation
---
# rule-decisions Specification

## Purpose

Describes the user-level model for how a command resolves to a Decision. Given a parsed command and the loaded set of Rules, the engine selects the Rules whose command name matches the program being evaluated, derives a Decision for each, and combines them into a single Decision and aggregate reason under the **most-strict-wins lattice** `:allow < :ask < :deny` (so loaded or repo-local rules cannot widen the policy established by an existing matching primary rule). The resolution is order-independent: shuffling the Rule list (across files or `(load …)` boundaries) MUST yield the same Decision and reason. This spec covers Decision semantics only; the trust closure that determines which Rules are eligible is described in `trust-hashing`. Check-evaluation error propagation is also documented here.

## Requirements

### Requirement: Program name selects the applicable rule set

When evaluating a command, the engine SHALL identify the *applicable set*
of rules: every rule whose command effect matches the program name being
evaluated. Rules whose command effect does not match SHALL be excluded.

#### Scenario: Rule for unrelated program is excluded

- **GIVEN** `(rule "rm" (deny "no rm"))` and `(rule "ls" (allow))`
- **WHEN** evaluating `ls -la`
- **THEN** the applicable set SHALL be the `ls` rule only
- **AND** the result SHALL be `:allow`

#### Scenario: Multiple rules for the same program all enter the set

- **GIVEN** two `(rule "git" …)` declarations
- **WHEN** evaluating `git push`
- **THEN** the applicable set SHALL contain both rules

### Requirement: All applicable rules run; strictest decision wins

The engine SHALL evaluate every rule in the applicable set, collect each
rule's outcome, discard rules whose body did not produce a decision, and
combine the remaining decisions by taking the *strictest* under the lattice
`:allow < :ask < :deny`.

#### Scenario: Allow and Deny coexist; Deny wins

- **GIVEN** `(rule "rm" (allow))` and `(rule "rm" (when (flag
  ["r" "recursive"]) (deny "recursive")))`
- **WHEN** evaluating `rm -rf /tmp/foo`
- **THEN** the result SHALL be `:deny "recursive"`

#### Scenario: Allow and Ask coexist; Ask wins

- **GIVEN** `(rule "scp" (allow))` and `(rule "scp" (when
  (fact? :prod) (ask "prod")))`
- **WHEN** evaluating `scp host:foo .` with fact `:prod`
- **THEN** the result SHALL be `:ask "prod"`

#### Scenario: Ask and Deny coexist; Deny wins

- **GIVEN** `(rule "rm" (ask))` and
  `(rule "rm" (positional "-rf") (deny "danger"))` in any order
- **WHEN** evaluating `rm -rf /tmp`
- **THEN** the result SHALL be `:deny`

#### Scenario: Multiple rules at the same decision collapse

- **GIVEN** three rules all matching `echo` and all yielding `:allow`
- **WHEN** evaluating `echo hi`
- **THEN** the result SHALL be `:allow`

#### Scenario: A non-matching rule body produces no decision and does not contribute

- **GIVEN** `(rule "rm" (when (flag "r") (deny)))` and
  `(rule "rm" (allow))`
- **WHEN** evaluating `rm foo` (no `-r`)
- **THEN** the first rule's body SHALL produce no decision
- **AND** the result SHALL be `:allow` from the second rule

#### Scenario: Loaded rule contributes the strictest decision

- **GIVEN** primary config `(rule "git" (allow))`
  and loaded file `(rule "git" (positional "push") (deny "no push"))`
- **WHEN** evaluating `git push`
- **THEN** the result SHALL be `:deny "no push"` (the only rule
  contributing the strictest decision)

### Requirement: Order of rules in the config SHALL not affect the decision

Shuffling the rule list MUST yield the same decision and the same
aggregate reason as the original ordering, for any input (including
across files and `(load …)` order).

#### Scenario: Reordering deny and allow rules

- **GIVEN** `(rule "rm" (deny "X"))` followed by
  `(rule "rm" (allow))`
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
more rules return the strictest decision (e.g. two `:deny`s); the
aggregate SHALL NOT depend on rule order. Distinct reasons SHALL be
sorted lexically and joined with `"; "`. Identical reasons SHALL be
deduplicated.

#### Scenario: Two distinct deny reasons combine deterministically

- **GIVEN** `(rule "rm" (when (flag "r") (deny "B")))` and
  `(rule "rm" (when (flag "f") (deny "A")))`
- **WHEN** evaluating `rm -rf /tmp/foo`
- **THEN** the result SHALL be `:deny "A; B"`
- **AND** the same result SHALL hold if the two rules are reversed

#### Scenario: Identical deny reasons are deduplicated

- **GIVEN** two `(rule "rm" (deny "no rm"))` declarations
- **WHEN** evaluating any `rm` command
- **THEN** the result SHALL be `:deny "no rm"` (single reason, not duplicated)

### Requirement: Default decision when no applicable rule produces a decision

When the applicable set is empty, the engine SHALL return `:ask` with a
reason that names the missing program. When the applicable set is
non-empty but no rule body produces a decision, the engine SHALL return
`:ask` with a reason explaining that rules exist but no patterns
matched. The choice between these reasons MUST depend only on whether
the applicable set is empty, not on rule order.

#### Scenario: No rule for the program

- **GIVEN** a config with no rule for `kubectl`
- **WHEN** evaluating `kubectl get pods`
- **THEN** the result SHALL be `:ask`
- **AND** the reason SHALL mention "No rule for command `kubectl`"

#### Scenario: Rules exist but no body matches

- **GIVEN** `(rule "rm" (when (flag "r") (deny)))` only
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
The check evaluation system SHALL propagate evaluation errors as diagnostic results rather than panicking. When evaluation fails (for example, a rule references an undefined predicate), the check system SHALL report it as a check failure with a descriptive message.

#### Scenario: Unresolved predicate during check
- **WHEN** a check rule references an undefined predicate
- **THEN** the check system SHALL report a diagnostic failure instead of panicking

### Requirement: Trace surfaces all tied entries

The engine SHALL include every rule that contributed the most-strict decision in the trace output for an evaluation. Among the tied rules, the one carrying a `reason` that is earliest in source order SHALL be marked as the reason source; the remaining tied rules SHALL be presented as also-matched siblings at the same decision. (The aggregate result `reason` is the order-free sorted join of all distinct tied reasons — see "Tie-breaking among equally-strict decisions is order-free"; the reason-source marking affects only trace presentation.)

#### Scenario: Two rules tied at Deny — both appear in trace
- **GIVEN** two rules both matching `rm` and both yielding
  `:deny`, the first with reason `"primary"` and the second
  with reason `"loaded"`
- **WHEN** the command `rm file` is evaluated with trace output
  enabled
- **THEN** the trace SHALL list both rules as evaluated entries
- **AND** the rule with reason `"primary"` SHALL be marked as the
  reason source
- **AND** the rule with reason `"loaded"` SHALL appear as a tied
  sibling at the same effect

#### Scenario: Single most-strict rule — no sibling annotation
- **GIVEN** a single matching rule yielding `:deny` and
  other matching rules yielding `:allow`
- **WHEN** trace output is rendered
- **THEN** the `:deny` rule SHALL appear as the reason source with no
  tied-sibling annotation

### Requirement: Adding a rule cannot relax the decision

The engine SHALL NOT produce a less-strict decision when a rule is added to a config in which at least one rule already matches the command. Formally, for any config `C`, command `cmd`, and additional rule `r`, if `C` already contains a rule whose command name matches `cmd`, then evaluating `C` with `r` appended SHALL yield a decision at least as strict as evaluating `C` alone, under the decision lattice `:allow < :ask < :deny`. This is the load-bearing security property: loaded rules — including those discovered via repo-local resolution — MUST NOT widen the policy established by an existing matching primary rule.

The no-match fallback (`:ask`) is excluded from this property: when no rule in `C` matches, appending the first matching rule replaces the fallback with that rule's decision, which may be `:allow`. Configs that wish to deny by default must encode that as an explicit catch-all rule.

#### Scenario: Adding an Allow rule to an Allow result is a no-op
- **GIVEN** a config that yields `:allow` for a command
- **WHEN** any rule yielding `:allow` is appended
- **THEN** the result SHALL still be `:allow`

#### Scenario: Adding an Allow rule to a Deny result does not widen
- **GIVEN** a config that yields `:deny` for a command
- **WHEN** a rule yielding `:allow` is appended
- **THEN** the result SHALL remain `:deny`

#### Scenario: Adding a Deny rule can tighten an Allow result
- **GIVEN** a config that yields `:allow` for a command
- **WHEN** a matching rule yielding `:deny` is appended
- **THEN** the result SHALL become `:deny`
