## Requirements

### Requirement: CST serialization roundtrip consistency
The CST parser SHALL produce output that can be re-parsed identically.
`pretty_serialize` output MAY differ in whitespace from the original input
(due to reformatting) but SHALL re-parse to a structurally equivalent CST.

For nodes containing children with source trivia, `pretty_serialize` MAY
produce output closer to the original input than before (since preserved
children retain their source whitespace).

#### Scenario: Simple atom roundtrip
- **WHEN** parsing `"foo"` into CST and serializing back
- **THEN** the output SHALL be `"foo"`
- **AND** re-parsing the output SHALL produce an equivalent CST

#### Scenario: List roundtrip
- **WHEN** parsing `"(foo bar)"` into CST and serializing back
- **THEN** the output SHALL be `"(foo bar)"`
- **AND** re-parsing the output SHALL produce an equivalent CST

#### Scenario: Nested structure roundtrip
- **WHEN** parsing `"(foo (bar baz))"` into CST and serializing back
- **THEN** the output SHALL be `"(foo (bar baz))"`
- **AND** re-parsing the output SHALL produce an equivalent CST

#### Scenario: String literal roundtrip
- **WHEN** parsing `'(foo "hello world")'` into CST and serializing back
- **THEN** the output SHALL preserve the string literal
- **AND** re-parsing the output SHALL produce an equivalent CST

#### Scenario: Vector roundtrip
- **WHEN** parsing `"[foo bar]"` into CST and serializing back
- **THEN** the output SHALL be `"[foo bar]"`
- **AND** re-parsing the output SHALL produce an equivalent CST

#### Scenario: Pretty-serialize roundtrip
- **WHEN** pretty-serializing a CST node and re-parsing the output
- **THEN** the re-parsed CST SHALL be structurally equivalent to the original
- **AND** whitespace MAY differ from the original input

### Requirement: CST to Sexpr conversion preserves structure
Converting CST to Sexpr SHALL preserve all structural information.

#### Scenario: Atom conversion
- **WHEN** converting a CST atom node to Sexpr
- **THEN** the Sexpr SHALL be an Atom with the same value

#### Scenario: List conversion
- **WHEN** converting a CST list node to Sexpr
- **THEN** the Sexpr SHALL be a List with the same children

#### Scenario: Vector conversion
- **WHEN** converting a CST vector node to Sexpr
- **THEN** the Sexpr SHALL be a Vector with the same children

### Requirement: Sexpr parse uses CST internally
The `may_i_sexpr::parse()` function SHALL use the CST parser internally.

#### Scenario: parse function delegates to CST
- **WHEN** calling `may_i_sexpr::parse(input)`
- **THEN** the implementation SHALL use `parse_cst()` internally
- **AND** convert the result to Sexpr via `to_sexpr()`
