## MODIFIED Requirements

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
