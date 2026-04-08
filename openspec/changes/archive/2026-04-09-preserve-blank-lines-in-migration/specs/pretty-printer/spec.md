## ADDED Requirements

### Requirement: Whitespace trivia preserves blank lines
The pretty printer SHALL preserve blank lines from whitespace-only trivia when rendering child elements.

#### Scenario: Single blank line between forms is preserved
- **WHEN** a source form has a single blank line (one extra newline) before it in the source
- **THEN** the pretty printer output SHALL include that blank line before the form

#### Scenario: Multiple blank lines between forms are preserved
- **WHEN** a source form has multiple blank lines (two or more extra newlines) before it in the source
- **THEN** the pretty printer output SHALL include those blank lines before the form

#### Scenario: No extra blank lines results in single newline
- **WHEN** a source form has only standard spacing (single newline) before it in the source
- **THEN** the pretty printer output SHALL include only a single newline before the form

#### Scenario: Blank lines within check forms are preserved
- **WHEN** a `check` form contains multiple test cases separated by blank lines
- **THEN** the pretty printer output SHALL preserve those blank lines between test cases
