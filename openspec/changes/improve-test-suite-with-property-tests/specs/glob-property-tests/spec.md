## ADDED Requirements

### Requirement: Glob matching satisfies algebraic properties
The glob matching system SHALL satisfy algebraic properties that ensure consistent behavior across all valid patterns and inputs.

#### Scenario: Roundtrip equivalence with reference implementation
- **WHEN** any valid glob pattern and input string are generated
- **THEN** glob_match(pattern, input) SHALL equal reference_backtrack_match(pattern, input)

#### Scenario: Empty string handling
- **WHEN** any glob pattern is tested against an empty string
- **THEN** the result SHALL be deterministic based on pattern structure

#### Scenario: Negation is complement
- **WHEN** a character class `[abc]` matches a character
- **THEN** the negated class `[!abc]` SHALL NOT match that character
- **AND** when `[abc]` does not match, `[!abc]` SHALL match

### Requirement: Glob strip operations are inverse
The glob strip prefix and suffix operations SHALL be inverse operations when the pattern matches.

#### Scenario: Strip prefix preserves remainder
- **WHEN** glob_strip_prefix(pattern, text, longest) successfully matches
- **THEN** concatenating the matched portion with the result SHALL equal the original text

#### Scenario: Strip suffix preserves prefix
- **WHEN** glob_strip_suffix(pattern, text, longest) successfully matches
- **THEN** concatenating the result with the matched portion SHALL equal the original text

### Requirement: Glob replacement is consistent
The glob replace operation SHALL replace the expected number of occurrences based on the `all` parameter.

#### Scenario: Replace all occurrences
- **WHEN** glob_replace(pattern, text, replacement, true) is called
- **THEN** ALL occurrences of pattern in text SHALL be replaced

#### Scenario: Replace first occurrence only
- **WHEN** glob_replace(pattern, text, replacement, false) is called
- **THEN** ONLY the first occurrence SHALL be replaced

#### Scenario: No match returns original
- **WHEN** glob_replace is called with a pattern that doesn't match
- **THEN** the original text SHALL be returned unchanged
