## ADDED Requirements

### Requirement: No bare unwrap in production code paths
Production code (non-test, non-debug) SHALL NOT use bare `.unwrap()`. Use `.expect("reason")` for safe invariants or proper error propagation for fallible operations.

#### Scenario: Hardcoded keyword construction
- **WHEN** a Keyword is constructed from a hardcoded valid string
- **THEN** `.expect("hardcoded keyword is valid")` SHALL be used instead of `.unwrap()`

### Requirement: Rewrite convergence is bounded
The `rewrite_until_convergence` function SHALL terminate after a maximum number of iterations to prevent infinite loops from oscillating rules.

#### Scenario: Oscillating rules
- **WHEN** rewrite rules would cause infinite oscillation
- **THEN** the function SHALL terminate after at most 100 iterations
