## ADDED Requirements

### Requirement: Positional matching terminates within a step budget

Positional pattern matching SHALL terminate for every input, including
Patterns containing nested sequence-group quantifiers. Termination SHALL be
guaranteed by two mechanisms:

1. **Nullable-iteration guard.** A `+` or `*` repetition whose sub-sequence
   consumes zero args in an iteration SHALL terminate that repetition rather
   than iterate again. This prevents a nullable group (e.g. `(* (? A))`)
   from looping without consuming input.
2. **Step budget.** The matcher SHALL track a step count against a
   configured budget. When the budget is exhausted the match attempt SHALL
   return no-match rather than continue. The budget SHALL be a
   config-structure value with a high default such that only pathological
   Patterns reach it; no surface syntax for setting it is exposed by this
   change.

When matching returns no-match due to budget exhaustion, the rule's decision
SHALL floor to `:ask` (per the tokenisation/engine flooring invariant), never
to `:allow`.

#### Scenario: Nullable group does not loop

- **WHEN** the matcher evaluates `(* (? "x"))` against any arg list
- **THEN** matching SHALL terminate
- **AND** SHALL NOT iterate the outer repetition on a zero-consuming inner match.

#### Scenario: Budget exhaustion floors to ask, not allow

- **WHEN** a Pattern's positional match exceeds the configured step budget
- **THEN** the match SHALL return no-match
- **AND** the rule decision SHALL NOT be `:allow`.

### Requirement: Constrained matches against expansion-bearing args stay unprovable under groups

The expansion-bearing-word soundness rule SHALL hold for every match path
introduced by sequence-group quantifiers, including each iteration of a
repeated group and each element of a nested group. That rule: a non-wildcard
Pattern element matching an expansion-bearing arg (a word whose runtime value
is unknown, e.g. `$VAR`) MUST NOT contribute to an `:allow` decision.

A successful positional match SHALL carry the provenance of every
constrained match it performed against an expansion-bearing arg along the
winning path. No group match path SHALL be able to report a successful match
without its accompanying provenance.

#### Scenario: Constrained match inside a repeated group floors the decision

- **WHEN** a repeated sequence group matches an expansion-bearing arg with a non-wildcard element along the winning path
- **THEN** the match's provenance SHALL include that arg
- **AND** the rule decision SHALL NOT be `:allow`.

#### Scenario: Wildcard match inside a group does not constrain

- **WHEN** a repeated sequence group matches an expansion-bearing arg with a bare wildcard element
- **THEN** the match SHALL NOT record that arg as unprovable
- **AND** the arg SHALL NOT block an otherwise-`:allow` decision.
