## ADDED Requirements

### Requirement: Quantifiers accept a sequence of sub-patterns

A quantifier head (`?`, `+`, `*`) SHALL accept one **or more** sub-patterns.
With a single sub-pattern the meaning is unchanged. With more than one
sub-pattern the sub-patterns form an **implicit sequence**: the quantified
unit is the whole sub-sequence, matched left to right against consecutive
positional args. A sub-pattern MAY itself be a quantifier form, so groups
nest.

`(? A B …)` SHALL match either zero args (the group is skipped) or the
full sub-sequence `A B …` in order. `(+ A B …)` and `(* A B …)` SHALL
repeat the whole sub-sequence (see the one-or-more and zero-or-more
requirements).

#### Scenario: Optional sequence group skipped

- **WHEN** matching the positional patterns `(? "run" (? "--")) *` against the args `state`
- **THEN** matching SHALL succeed with the group consuming zero args.

#### Scenario: Optional sequence group, partial inner

- **WHEN** matching the positional patterns `(? "run" (? "--")) *` against the args `run state`
- **THEN** matching SHALL succeed with the group consuming `run`.

#### Scenario: Optional sequence group, full inner

- **WHEN** matching the positional patterns `(? "run" (? "--")) *` against the args `run -- state`
- **THEN** matching SHALL succeed with the group consuming `run --`.

#### Scenario: Sequence group requires its leading element

- **WHEN** matching the positional patterns `(? "run" (? "--")) *` against the args `-- state`
- **THEN** the group SHALL NOT match `--` (its leading `run` is absent), and the group SHALL consume zero args.

## MODIFIED Requirements

### Requirement: Pattern serialization roundtrips through the parser
A Pattern serialized to its s-expression form SHALL parse back to a structurally equivalent Pattern. This SHALL hold for quantifier Patterns carrying a sequence of sub-patterns, including nested groups.

#### Scenario: Arbitrary pattern roundtrip
- **WHEN** a randomly generated Pattern is converted to an s-expression string and parsed back
- **THEN** the result SHALL be structurally equivalent to the original Pattern

#### Scenario: Nested sequence-group roundtrip
- **WHEN** the Pattern `(? "run" (? "--"))` is converted to an s-expression string and parsed back
- **THEN** the result SHALL be structurally equivalent to the original Pattern

### Requirement: Optional quantifier matches with or without arg

A Pattern wrapped in `(? PAT …)` (the optional quantifier) SHALL match even when the arg at that position is absent. When matched, the sub-sequence `PAT …` MUST match consecutive args in order. A single-sub-pattern `(? PAT)` is the special case of a one-element sequence.

#### Scenario: Optional positional present

- **WHEN** matching the positional patterns `"branch" (? "branch")` against the args `branch branch`
- **THEN** matching SHALL succeed.

#### Scenario: Optional positional absent

- **WHEN** matching the positional patterns `"push" (? "origin")` against the args `push`
- **THEN** matching SHALL succeed.

#### Scenario: Optional positional present but value mismatch

- **WHEN** matching the positional patterns `"branch" (? "branch")` against the args `branch tag`
- **THEN** matching SHALL NOT succeed.

### Requirement: One-or-more quantifier requires at least one match

A Pattern wrapped in `(+ PAT …)` (the one-or-more quantifier) SHALL require at least one full occurrence of the sub-sequence `PAT …` at the pattern's position, and SHALL match as many consecutive occurrences as possible, backtracking so that following patterns can match. With a single sub-pattern this reduces to the historical "one or more args each matching `PAT`" behaviour.

#### Scenario: One-or-more wildcard with one arg

- **WHEN** matching the positional pattern `(+ *)` against the args `file1`
- **THEN** matching SHALL succeed.

#### Scenario: One-or-more wildcard with multiple args

- **WHEN** matching the positional pattern `(+ *)` against the args `file1 file2 file3`
- **THEN** matching SHALL succeed.

#### Scenario: One-or-more with no args

- **WHEN** matching the positional patterns `"cmd" (+ *)` against the args `cmd`
- **THEN** matching SHALL NOT succeed.

#### Scenario: One-or-more sequence group repeats

- **WHEN** matching the positional pattern `(+ "--opt" *)` against the args `--opt a --opt b`
- **THEN** matching SHALL succeed, consuming two occurrences of the sub-sequence.

### Requirement: Zero-or-more quantifier matches any count

A Pattern wrapped in `(* PAT …)` (the zero-or-more quantifier) SHALL match zero or more consecutive occurrences of the sub-sequence `PAT …` from that position, backtracking so that following patterns can match. With a single sub-pattern this reduces to the historical "zero or more args each matching `PAT`" behaviour.

#### Scenario: Zero-or-more wildcard with no args

- **WHEN** matching the positional patterns `"cmd" (* *)` against the args `cmd`
- **THEN** matching SHALL succeed.

#### Scenario: Zero-or-more wildcard with multiple args

- **WHEN** matching the positional pattern `(* *)` against the args `a b c`
- **THEN** matching SHALL succeed.

#### Scenario: Zero-or-more sequence group repeats

- **WHEN** matching the positional pattern `(* "--opt" *)` against the args `--opt a --opt b`
- **THEN** matching SHALL succeed, consuming two occurrences of the sub-sequence.
