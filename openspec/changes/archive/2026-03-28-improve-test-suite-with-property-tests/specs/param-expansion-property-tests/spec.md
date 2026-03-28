## ADDED Requirements

### Requirement: Parameter expansion default values work correctly
The parameter expansion default operators SHALL substitute the default value only when the variable is unset or empty (depending on colon modifier).

#### Scenario: Colon-default with empty variable
- **WHEN** ${VAR:-default} is resolved and VAR is empty
- **THEN** the result SHALL be "default"

#### Scenario: Colon-default with set variable
- **WHEN** ${VAR:-default} is resolved and VAR has a value
- **THEN** the result SHALL be VAR's value

#### Scenario: No-colon default only checks unset
- **WHEN** ${VAR-default} is resolved and VAR is set but empty
- **THEN** the result SHALL be empty (not "default")

### Requirement: Parameter expansion strip operations work correctly
The parameter expansion strip operators SHALL remove the matched prefix or suffix pattern.

#### Scenario: Shortest prefix strip
- **WHEN** ${VAR#pattern} is resolved and pattern matches the beginning
- **THEN** the shortest match SHALL be removed

#### Scenario: Longest prefix strip
- **WHEN** ${VAR##pattern} is resolved and pattern matches the beginning
- **THEN** the longest match SHALL be removed

#### Scenario: Shortest suffix strip
- **WHEN** ${VAR%pattern} is resolved and pattern matches the end
- **THEN** the shortest match SHALL be removed

#### Scenario: Longest suffix strip
- **WHEN** ${VAR%%pattern} is resolved and pattern matches the end
- **THEN** the longest match SHALL be removed

### Requirement: Parameter expansion replacement works correctly
The parameter expansion replace operators SHALL substitute text based on the `all` parameter.

#### Scenario: Replace first occurrence
- **WHEN** ${VAR/pattern/replacement} is resolved
- **THEN** only the first occurrence of pattern SHALL be replaced

#### Scenario: Replace all occurrences
- **WHEN** ${VAR//pattern/replacement} is resolved
- **THEN** all occurrences of pattern SHALL be replaced

### Requirement: Parameter expansion substring works correctly
The parameter expansion substring operators SHALL extract a portion of the variable value.

#### Scenario: Substring with positive offset
- **WHEN** ${VAR:offset} is resolved with positive offset
- **THEN** the substring SHALL start at that offset (0-indexed)

#### Scenario: Substring with negative offset
- **WHEN** ${VAR:offset} is resolved with negative offset
- **THEN** the offset SHALL count from the end of the string

#### Scenario: Substring with length
- **WHEN** ${VAR:offset:length} is resolved
- **THEN** at most `length` characters SHALL be returned

### Requirement: Parameter expansion case conversion works correctly
The parameter expansion case conversion operators SHALL convert the case of the variable value.

#### Scenario: Uppercase first character
- **WHEN** ${VAR^} is resolved
- **THEN** only the first character SHALL be uppercased

#### Scenario: Uppercase all characters
- **WHEN** ${VAR^^} is resolved
- **THEN** all characters SHALL be uppercased

#### Scenario: Lowercase first character
- **WHEN** ${VAR,} is resolved
- **THEN** only the first character SHALL be lowercased

#### Scenario: Lowercase all characters
- **WHEN** ${VAR,,} is resolved
- **THEN** all characters SHALL be lowercased

#### Scenario: Case conversion roundtrip
- **WHEN** ${VAR^^} is lowercased with ${VAR,,}
- **THEN** for ASCII strings, the result SHALL equal the original (modulo case)
