# Rule Evaluation Specification

## Purpose

Describes the user-level model for how a command resolves to a Decision. Given a parsed command and the loaded set of Rules, the engine selects the Rules whose command name matches the program being evaluated, evaluates each one, and combines the results into a single Decision and aggregate reason. The resolution is order-independent: shuffling the Rule list (across files or `(load …)` boundaries) MUST yield the same Decision and reason. This spec covers semantics only; the trust closure that determines which Rules are eligible is described in `trust-hashing`.

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

For any input, shuffling the rule list produced by config loading
(across files, including `(load …)` order) MUST yield the same
decision and the same aggregate reason as the original ordering.

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

When two or more rules return the strictest decision (e.g. two `Deny`s),
the engine SHALL produce a deterministic aggregate reason that does not
depend on rule order. Distinct reasons SHALL be sorted lexically and
joined with `"; "`. Identical reasons SHALL be deduplicated.

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

When the input is a compound shell command (`cmd1 && cmd2`, embedded
substitution, etc.), the per-segment per-program aggregation SHALL run
first, and the existing across-segment "strictest wins" aggregation SHALL
combine the per-segment results unchanged. The two layers use the same
strictness ordering.

#### Scenario: Two segments with different decisions

- **GIVEN** `ls` is allowed and `rm -rf /` is denied
- **WHEN** evaluating `ls && rm -rf /`
- **THEN** the result SHALL be `:deny` from the `rm` segment
