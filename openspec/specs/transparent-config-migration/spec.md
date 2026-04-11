## MODIFIED Requirements

### Requirement: Comment and trivia preservation through migration
The migration pipeline SHALL preserve comments and trivia from the original v1 config in the migrated output.

#### Scenario: Comments between top-level forms
- **WHEN** a v1 config has comments between defcontext/rule forms
- **THEN** the migrated output SHALL retain those comments in their relative positions

#### Scenario: Inline comments inside forms
- **WHEN** a v1 wrapper form contains inline comments
- **THEN** the migrated rule SHALL retain the comments

#### Scenario: Multi-line comment blocks above rules
- **WHEN** a multi-line comment block precedes a v1 rule
- **THEN** the comment block SHALL appear before the migrated rule
