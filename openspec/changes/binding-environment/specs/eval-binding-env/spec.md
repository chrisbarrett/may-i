## ADDED Requirements

### Requirement: EvalContext carries a binding environment

The evaluator SHALL carry a binding environment mapping define names to their
predicate bodies. The environment SHALL be built from the config's `Define` list
before evaluation begins.

#### Scenario: Environment is available during evaluation

- **WHEN** a config contains `(define safe (has :safe))` and
  `(rule "git" (when safe (allow)))`
- **THEN** the evaluator resolves `safe` at eval time via the binding
  environment and produces the correct decision

### Requirement: Predicate::Named resolves via env lookup

When the evaluator encounters a `Predicate::Named` reference, it SHALL look up
the name in the binding environment and evaluate the referenced predicate body.

#### Scenario: Named predicate matches

- **WHEN** the env contains `safe → (has :safe)` and the context has fact
  `:safe`
- **THEN** evaluating `Predicate::Named("safe")` returns `Match`

#### Scenario: Named predicate does not match

- **WHEN** the env contains `safe → (has :safe)` and the context lacks fact
  `:safe`
- **THEN** evaluating `Predicate::Named("safe")` returns `NoMatch`

#### Scenario: Transitive named references

- **WHEN** the env contains `a → (has :x)` and `b → a` (Named reference to a)
- **THEN** evaluating `Predicate::Named("b")` resolves transitively and returns
  based on fact `:x`

### Requirement: Undefined named predicate is an eval error

If a `Predicate::Named` reference has no entry in the binding environment, the
evaluator SHALL return an error.

#### Scenario: Missing define

- **WHEN** a rule references `Predicate::Named("missing")` and no define
  exists for `"missing"`
- **THEN** the evaluator returns `EvalError::UnresolvedPredicate`

### Requirement: Inlining step is removed from validate_and_resolve

`validate_and_resolve` SHALL return rules with `Predicate::Named` references
intact. The function SHALL NOT inline define bodies into rule predicates.

#### Scenario: Rules retain Named references after validation

- **WHEN** a config with defines and rules is validated via
  `validate_and_resolve`
- **THEN** the returned rules still contain `Predicate::Named` nodes (not
  inlined `Predicate::Fact` nodes)

#### Scenario: Validation still detects duplicates

- **WHEN** a config contains two defines with the same name
- **THEN** `validate_and_resolve` returns an error

#### Scenario: Validation still detects undefined refs

- **WHEN** a rule references a define that does not exist
- **THEN** `validate_and_resolve` returns an error

#### Scenario: Validation still detects cycles

- **WHEN** define `a` references define `b` and `b` references `a`
- **THEN** `validate_and_resolve` returns an error

### Requirement: Evaluation results are identical to inlining

For any config and input, the evaluator with binding environment SHALL produce
the same decision and reason as the previous inlining-based approach.

#### Scenario: Equivalence on simple config

- **WHEN** evaluating `"git commit"` against a config with defines
- **THEN** the decision is identical whether defines were inlined or resolved
  at eval time

### Requirement: The fold predicate_named callback is invoked

When evaluating a `Predicate::Named`, the evaluator SHALL call
`fold.predicate_named(name, child_out, result)` where `child_out` is the fold
output from evaluating the define body.

#### Scenario: Fold receives named predicate

- **WHEN** a rule with `Predicate::Named("safe")` is evaluated using a custom
  fold
- **THEN** the fold's `predicate_named` method is called with name `"safe"`,
  the child result from evaluating the body, and the final predicate result
