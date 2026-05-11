# evaluator-error-handling Specification

## Purpose

Contributor-only. The check pipeline propagates evaluator errors (e.g. `UnresolvedPredicate`) as diagnostic results rather than panicking; user invocation of `may-i check` against a broken config surfaces a per-case failure with a descriptive message.

## Requirements

### Requirement: Check evaluation propagates errors
The check evaluation system SHALL propagate evaluation errors as diagnostic results rather than panicking. When `evaluate()` returns an error (e.g., UnresolvedPredicate), the check system SHALL report it as a check failure with a descriptive message.

#### Scenario: Unresolved predicate during check
- **WHEN** a check rule references an undefined predicate
- **THEN** the check system SHALL report a diagnostic failure instead of panicking
