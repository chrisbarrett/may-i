## ADDED Requirements

### Requirement: Prefer property tests
New tests SHALL prefer property-based testing with proptest and Arbitrary implementations on core AST types. Targeted unit tests SHALL be used as a fallback for hard-to-hit branches or specific regression cases.

#### Scenario: New invariant uses property test
- **WHEN** adding a test for a general evaluation invariant (e.g., boolean algebra law)
- **THEN** it SHALL be implemented as a property test generating random inputs

#### Scenario: Edge case uses unit test
- **WHEN** adding a test for a specific parser error path
- **THEN** it MAY use a targeted unit test with a crafted input

### Requirement: Key invariants are verified
Property tests SHALL cover these invariant classes:
- **No panics**: Evaluation functions never panic on valid inputs
- **Boolean algebra**: And/Or/Not obey standard laws including De Morgan's
- **Determinism**: Same input always produces same output
- **Recursion limits**: Depth limits are respected and produce Ask
- **Type safety**: Predicates return Match/NoMatch, effects return Decision/Nil

#### Scenario: Evaluation does not panic
- **WHEN** evaluating any valid Effect against any valid EvalContext
- **THEN** the evaluator SHALL return a result without panicking

#### Scenario: Boolean algebra holds for predicates
- **WHEN** evaluating `(not (and A B))` and `(or (not A) (not B))` with the same context
- **THEN** both SHALL produce the same Match/NoMatch result

#### Scenario: Evaluation is deterministic
- **WHEN** evaluating the same command against the same config and facts twice
- **THEN** both evaluations SHALL return identical results

### Requirement: Arbitrary implementations cover AST types
Core AST types (Effect, Predicate, ArgPattern, CommandPattern, Expr, FactQuery, FactPattern, ContextFacts) SHALL implement proptest's Arbitrary trait for use in property tests.

#### Scenario: Generated values are valid
- **WHEN** proptest generates an arbitrary Effect tree
- **THEN** the tree SHALL satisfy type invariants (e.g., Keywords start with `:`, regexes compile)
