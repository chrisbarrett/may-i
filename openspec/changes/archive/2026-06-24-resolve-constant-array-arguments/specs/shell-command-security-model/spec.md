## ADDED Requirements

### Requirement: Provably-constant arrays are resolved in arguments

The evaluator SHALL resolve a subscripted parameter expansion against a
provably-constant array when the array's value is statically known, using the
same provability discipline as scalar resolution. An array is provably constant
only when ALL of the following hold; otherwise its expansions SHALL remain
unresolved and floor an `:allow` exactly as today:

- the array has a single array-literal assignment whose elements are all static
  literals (no command substitution, no glob, no unresolved variable);
- it is never mutated by element assignment (`arr[i]=…`), append (`arr+=(…)`),
  `unset 'arr[i]'`, or a sparse/dynamic index;
- the assignment executes unconditionally before the use (the straight-line,
  use-order discipline that governs scalars).

For a provably-constant array the evaluator SHALL resolve:

- `${arr[i]}` with a literal index `i` → the single element literal at `i`;
- a quoted `"${arr[@]}"` → **one resolved argument word per element**, each a
  provable literal, expanding the argv the matcher sees;
- `${#arr[@]}` → the element count as a literal.

`${arr[*]}` and **unquoted** `${arr[@]}` SHALL remain unresolved (their joining
and splitting depend on `IFS` and globbing). Resolution is all-or-nothing per
expansion: if any element is not a provable literal, the whole expansion stays
unresolved. Resolution SHALL only narrow the set of unresolved-expansion asks.

This requirement applies to **indexed** arrays only. An **associative** array
(declared `declare -A`, distinguished by `model-bash-arrays`) has unspecified
element order in bash, so the evaluator SHALL NOT resolve an associative
`"${m[@]}"`, `${m[*]}`, or `${#m[@]}` — they remain unresolved and floor an
`:allow` as before. Associative single-key reads and value modelling are out of
scope for this change.

#### Scenario: Quoted `[@]` expands to one argument per element

- **WHEN** the input is `parts=(s3://bkt/a s3://bkt/b); aws s3 cp "${parts[@]}" /tmp/x`
- **AND** a rule allows `aws s3 cp` whose sources match `s3://bkt/a` and `s3://bkt/b`
- **THEN** matchers SHALL see the arguments `s3://bkt/a`, `s3://bkt/b`, `/tmp/x`
- **AND** the decision SHALL be `:allow` without an unresolved-expansion floor

#### Scenario: Literal index resolves a single element

- **WHEN** the input is `zones=(z-a z-b z-c); echo "${zones[1]}"`
- **THEN** the argument SHALL resolve to `z-b`

#### Scenario: Length form resolves to the count

- **WHEN** the input is `arr=(a b c); echo "${#arr[@]}"`
- **THEN** the argument SHALL resolve to `3`

#### Scenario: Star form stays unresolved

- **WHEN** the input is `arr=(a b); cmd "${arr[*]}"`
- **THEN** the expansion SHALL remain unresolved and floor an `:allow` as before
  (the join depends on `IFS`)

#### Scenario: A mutated array stays unresolved

- **WHEN** the input is `arr=(a b); arr+=(c); cmd "${arr[@]}"`
- **THEN** the array SHALL NOT be provably constant and the expansion SHALL floor
  an `:allow` as before

#### Scenario: A non-literal element keeps the whole expansion unresolved

- **WHEN** the input is `arr=(a $(hostname) c); cmd "${arr[@]}"`
- **THEN** the expansion SHALL remain unresolved (an element is not a provable
  literal)

#### Scenario: An associative `[@]` stays unresolved

- **WHEN** the input is `declare -A m=([a]=1 [b]=2); cmd "${m[@]}"`
- **THEN** the expansion SHALL remain unresolved and floor an `:allow` as before
  (associative element order is unspecified in bash)
