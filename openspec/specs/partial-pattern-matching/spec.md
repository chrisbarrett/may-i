## REMOVED Requirements

### Requirement: At patterns match by position
**Reason**: The `At` matcher is redundant — `positional` with wildcards covers the same cases
**Migration**: Replace `(= N PATTERN)` with `(positional)` using wildcards to skip positions
