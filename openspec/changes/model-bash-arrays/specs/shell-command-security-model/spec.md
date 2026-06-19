## ADDED Requirements

### Requirement: Array-literal assignments are parsed without discarding the command

The parser SHALL parse an array-literal assignment of the form `name=(word…)`
(including the `declare -a` / `local -a` / `export -a` and append `name+=(word…)`
forms) into a representation that preserves each element word. It SHALL NOT emit
an Error-severity diagnostic solely because of the array literal, and it SHALL
continue parsing the remainder of the command — no command following an array
literal SHALL be discarded from evaluation.

#### Scenario: Array literal preserves the following command

- **WHEN** the input is `arr=(a b c); echo done`
- **THEN** the parser SHALL parse both the array assignment and the `echo done`
  command
- **AND** no Error-severity diagnostic SHALL be emitted for the array literal
- **AND** `echo done` SHALL be present in the evaluated command

#### Scenario: Array element words are preserved

- **WHEN** the input is `arr=(one "two three" four)`
- **THEN** the parsed array SHALL preserve three element words, with
  `two three` as a single element

#### Scenario: Append and indexed assignment do not truncate

- **WHEN** the input is `arr=(a); arr+=(b); arr[5]=c; echo end`
- **THEN** no portion of the command SHALL be silently discarded, and `echo end`
  SHALL be present in the evaluated command

### Requirement: Subscripted parameter expansions are parsed as array references

The parser SHALL represent a subscripted parameter expansion — `${name[index]}`,
`${name[@]}`, `${name[*]}`, and the length form `${#name[@]}` — with the array
name and the subscript distinguished, rather than folding the subscript into the
parameter name. Until a later change resolves array values, such an expansion
SHALL be treated as expansion-bearing (unresolved) and floor an `:allow` exactly
as an unknown scalar expansion does.

#### Scenario: Subscript is separated from the name

- **WHEN** the input is `echo "${arr[@]}" "${arr[0]}"`
- **THEN** each expansion SHALL be parsed as a reference to the array `arr` with a
  distinguished subscript (`@`, `0`), not as a parameter named `arr[@]` / `arr[0]`

#### Scenario: Unresolved subscript still floors an allow

- **WHEN** the input is `aws s3 cp "${parts[@]}" /tmp/x`
- **AND** a rule would allow `aws s3 cp` only for a constrained source
- **THEN** the subscripted expansion SHALL be treated as unresolved and the
  `:allow` SHALL floor to `:ask` (no value resolution in this change)

### Requirement: Array kind is recorded in the parsed representation

The parser SHALL record whether an array is **indexed** (`declare -a`, `local -a`,
or a bare `name=(…)` assignment) or **associative** (`declare -A`). Associative
arrays have unspecified element order in bash, so a later resolver must
distinguish the two kinds to avoid resolving an order-dependent expansion
unsoundly. This change records the kind; it does not resolve associative values.

#### Scenario: Indexed and associative declarations are distinguished

- **WHEN** the input declares `declare -a idx=(a b c)` and
  `declare -A assoc=([k]=v)`
- **THEN** the parsed representation SHALL mark `idx` as indexed and `assoc` as
  associative

#### Scenario: Bare assignment is indexed

- **WHEN** the input is `arr=(a b c)`
- **THEN** the parsed array SHALL be marked indexed
