## MODIFIED Requirements

### Requirement: Check evaluation propagates errors
The check evaluation system SHALL propagate evaluation errors as diagnostic results rather than panicking. When `evaluate()` returns an error (e.g., UnresolvedPredicate), the check system SHALL report it as a check failure with a descriptive message.

#### Scenario: Unresolved predicate during check
- **WHEN** a check rule references an undefined predicate
- **THEN** the check system SHALL report a diagnostic failure instead of panicking
