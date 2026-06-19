## ADDED Requirements

### Requirement: Statically-enumerable `for` loops resolve the loop variable

The evaluator SHALL treat a `for` loop variable as bound to a provable, finite
value set within the loop body when the loop is **statically enumerable**, and
evaluate the body once per value, combining the per-value decisions with the
existing strictest-wins meet across evaluation units.

A `for` loop is statically enumerable only when ALL of the following hold;
otherwise the loop variable SHALL remain unresolved in the body exactly as today:

- every word of the loop's list resolves to a static literal (no command
  substitution, no glob, no `$@`/`$*`, no variable that is not itself provably
  constant);
- the loop variable is not reassigned or `unset` in the body before the use;
- unrolling the body across the list values does not exceed the total
  evaluation-unit budget (nested enumerable loops multiply; over budget the loop
  variable stays unresolved).

Because every iteration executes, the combined decision SHALL be at least as
strict as the strictest per-value decision. Enumeration SHALL only narrow the set
of unresolved-expansion asks; it SHALL NOT change any decision that did not
previously rest on an unresolved loop-variable expansion.

#### Scenario: All list values match the allow pattern

- **WHEN** the input is `for k in a b c; do aws s3 cp "s3://bkt/$k" /tmp/x; done`
- **AND** a rule allows `aws s3 cp` whose source matches `s3://bkt/a`, `s3://bkt/b`,
  and `s3://bkt/c`
- **THEN** the decision SHALL be `:allow` without an unresolved-expansion floor

#### Scenario: One list value fails the allow pattern

- **WHEN** the input is `for k in ok danger; do aws s3 cp "s3://bkt/$k" /tmp/x; done`
- **AND** a rule allows `aws s3 cp` only when the source matches `s3://bkt/ok`
- **THEN** the decision SHALL be at least `:ask` (the `danger` iteration is not
  covered by the allow, and the meet over iterations takes the stricter outcome)

#### Scenario: A non-literal list keeps the loop variable unresolved

- **WHEN** the input is `for k in $(ls); do rm "$k"; done`
- **THEN** the loop variable SHALL remain unresolved in the body and an `:allow`
  resting on `"$k"` SHALL floor exactly as before (the list is not statically
  enumerable)

#### Scenario: Reassignment in the body keeps the loop variable unresolved

- **WHEN** the input is `for k in a b; do k=$(date); rm "$k"; done`
- **THEN** the loop variable SHALL remain unresolved at the `rm "$k"` use (it is
  reassigned in the body before the use)

#### Scenario: Nested enumerable loops over budget fall back

- **WHEN** two nested enumerable `for` loops would unroll to more evaluation
  units than the budget allows
- **THEN** the evaluator SHALL NOT unroll beyond the budget and the affected loop
  variable SHALL remain unresolved, flooring an `:allow` as before — never
  under-asking
