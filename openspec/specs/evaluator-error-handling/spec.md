## ADDED Requirements

### Requirement: Evaluator returns Result for unresolved named predicates

The `evaluate` function and related evaluation functions SHALL return
`Result<T, EvalError>` instead of panicking when encountering an unresolved
`Named` predicate. `EvalError` SHALL have at minimum an
`UnresolvedPredicate { name: String }` variant.

#### Scenario: Unresolved predicate produces error

- **GIVEN** a config containing `(rule "git" (when unresolved-name (effect :allow)) :effect (effect :deny))`
- **AND** predicate resolution has NOT been run
- **WHEN** `evaluate` is called
- **THEN** it SHALL return `Err(EvalError::UnresolvedPredicate { name: "unresolved-name" })`

#### Scenario: Resolved config evaluates successfully

- **GIVEN** a config where all named predicates have been resolved via `validate_and_resolve`
- **WHEN** `evaluate` is called
- **THEN** it SHALL return `Ok(EvalResult { .. })` with no error

### Requirement: EvalError implements standard error traits

`EvalError` SHALL implement `std::fmt::Display` and `std::error::Error` so it
can be used with `?` in functions returning `miette::Result` or
`anyhow::Result`.

#### Scenario: Error displays human-readable message

- **GIVEN** an `EvalError::UnresolvedPredicate { name: "my-pred" }`
- **WHEN** formatted with `Display`
- **THEN** the message SHALL contain `my-pred` and indicate it is unresolved
