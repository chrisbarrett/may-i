## MODIFIED Requirements

### Requirement: Evaluator returns Result for unresolved named predicates

The `evaluate` function and related evaluation functions SHALL return
`Result<T, EvalError>` instead of panicking when encountering an unresolved
`Named` predicate. `EvalError` SHALL have at minimum an
`UnresolvedPredicate { name: String }` variant. (CHANGED: rule evaluation now dispatches on a single effect instead of looping over a Vec)

#### Scenario: Unresolved predicate produces error

- **GIVEN** a config containing `(rule "git" (when unresolved-name (effect :allow)))`
- **AND** predicate resolution has NOT been run
- **WHEN** `evaluate` is called
- **THEN** it SHALL return `Err(EvalError::UnresolvedPredicate { name: "unresolved-name" })`

#### Scenario: Resolved config evaluates successfully

- **GIVEN** a config where all named predicates have been resolved via `validate_and_resolve`
- **WHEN** `evaluate` is called
- **THEN** it SHALL return `Ok(EvalResult { .. })` with no error
