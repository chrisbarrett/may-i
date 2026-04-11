## ADDED Requirements

### Requirement: Config parse roundtrip property
A property test SHALL verify that parsing a valid config, serializing it, and parsing again produces an equivalent result.

#### Scenario: Arbitrary valid config roundtrips
- **WHEN** a randomly generated valid config is serialized and re-parsed
- **THEN** the parsed result SHALL be structurally equivalent to the original

### Requirement: CST pretty_serialize roundtrip property
A property test SHALL verify that pretty-printing a CST and re-parsing it preserves structure.

#### Scenario: Pretty-printed CST roundtrips
- **WHEN** a parsed CST is pretty-serialized at a random width and re-parsed
- **THEN** the structural skeleton (atoms, lists) SHALL be preserved

### Requirement: Positional backtracking correctness property
A property test SHALL verify that positional pattern matching is correct.

#### Scenario: Matched plus unconsumed equals original
- **WHEN** positional matching runs on random args with random patterns
- **THEN** matched args concatenated with unconsumed args SHALL equal the original args

### Requirement: Cycle detection soundness property
A property test SHALL verify that define-graph cycle detection is correct.

#### Scenario: Acyclic graphs pass
- **WHEN** a randomly generated acyclic define graph is validated
- **THEN** validation SHALL succeed

#### Scenario: Cyclic graphs are rejected
- **WHEN** a randomly generated graph with a cycle is validated
- **THEN** validation SHALL report an error

### Requirement: Expression parser roundtrip property
A property test SHALL verify that expressions roundtrip through serialization and parsing.

#### Scenario: Arbitrary expressions roundtrip
- **WHEN** a randomly generated Expr is serialized and re-parsed
- **THEN** the result SHALL be structurally equivalent

### Requirement: render_annotated_rule never panics
A property test SHALL verify that the rendering pipeline does not panic on arbitrary inputs.

#### Scenario: Random annotated configs
- **WHEN** a randomly generated config is evaluated and rendered
- **THEN** the rendering pipeline SHALL complete without panicking
