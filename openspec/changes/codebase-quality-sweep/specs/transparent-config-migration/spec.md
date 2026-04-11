## MODIFIED Requirements

### Requirement: Span preservation through migration
Error messages SHALL report source locations from the original config file, not the migrated text. The migration module SHALL use `may_i_core::Span` instead of a local duplicate.

#### Scenario: Error in migrated config reports original location
- **GIVEN** a legacy config with 147 lines containing `(wrapper ...)` at line 147
- **AND** the migration transforms the wrapper to canonical syntax
- **WHEN** a semantic error occurs (e.g., undefined reference)
- **THEN** the error message SHALL reference line 147
- **AND** the error context SHALL show the original `(wrapper ...)` syntax

#### Scenario: Migration module uses core Span
- **WHEN** the migrate module needs a source span
- **THEN** it SHALL use `may_i_core::Span`, not a locally defined Span struct

## ADDED Requirements

### Requirement: Migration rewrite helpers reduce boilerplate
Shared helper functions SHALL exist for common migration rewrite patterns: checking for tagged lists and rebuilding list nodes.

#### Scenario: tagged_list helper
- **WHEN** a rewrite rule needs to check if a CST node is a list tagged with a specific keyword
- **THEN** it SHALL use the `tagged_list` helper (or equivalent) instead of inline `is_tagged` + `as_list` + length validation

#### Scenario: rebuild_list helper
- **WHEN** a rewrite rule needs to construct a new list node preserving annotations
- **THEN** it SHALL use the `rebuild_list` helper (or equivalent) instead of inline `CstNode::list` construction
