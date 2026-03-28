## REMOVED Requirements

### Requirement: At effect matches by 1-based position
**Reason**: The `At`/`(= N PATTERN)` matcher is redundant — `positional` with wildcards covers the same cases (e.g., `(= 3 "deploy")` is equivalent to `(positional * * "deploy")`)
**Migration**: Replace `(= N PATTERN)` with `(positional)` using wildcards to skip positions

### Requirement: At predicate matches by 1-based position
**Reason**: Removed alongside the At effect — same redundancy applies in predicate position
**Migration**: Replace with `(positional)` using wildcards
