## ADDED Requirements

### Requirement: Evaluator is generic over a fold trait
The evaluator functions (`evaluate`, `evaluate_effect`, `evaluate_predicate`)
SHALL accept a generic `F: EvalFold` parameter that determines the output type
at each node. The engine drives traversal and short-circuiting; the fold
observes each step.

#### Scenario: Pure evaluation produces EffectResult
- **WHEN** the evaluator is called with `PureFold`
- **THEN** it SHALL return `EffectResult` values identical to the current
  monomorphic evaluator

#### Scenario: Custom fold produces custom output
- **WHEN** the evaluator is called with a fold where `EffectOut = (EffectResult, String)`
- **THEN** it SHALL return pairs at each node without affecting evaluation logic

### Requirement: EvalFold has projection methods for control flow
The `EvalFold` trait SHALL provide `effect_result` and `predicate_result`
projection methods that extract the decision from the fold output. The engine
uses these projections for short-circuiting (`And`/`Or`) and branching
(`When`/`Unless`/`If`/`Cond`).

#### Scenario: And short-circuits on Nil using projection
- **GIVEN** an `And` effect with three children
- **WHEN** the first child's fold output projects to `Nil`
- **THEN** the engine SHALL stop evaluation and call `skipped` for remaining
  children
- **AND** the fold's `effect_and` method receives one `Evaluated` and two
  `Skipped` children

#### Scenario: Or short-circuits on non-Nil using projection
- **GIVEN** an `Or` effect with three children
- **WHEN** the second child's fold output projects to a Decision
- **THEN** the engine SHALL stop evaluation
- **AND** the fold's `effect_or` method receives two `Evaluated` and one
  `Skipped` children

#### Scenario: When branches on predicate projection
- **GIVEN** a `When` effect with a predicate and body
- **WHEN** the predicate's fold output projects to `NoMatch`
- **THEN** the fold's `effect_when` method receives a `Skipped` body

### Requirement: EvalFold covers all Effect variants
The `EvalFold` trait SHALL have a method for every `Effect` variant: terminal
decisions, command pattern match, argument pattern match, `And`, `Or`, `Not`,
`When`, `Unless`, `If`, `Cond`, and `MayI`.

#### Scenario: Terminal effect calls effect_terminal
- **WHEN** evaluating `Effect::Allow(Some("reason"))`
- **THEN** the fold's `effect_terminal` method is called with the effect and
  `EffectResult::Decision(Allow, Some("reason"))`

#### Scenario: MayI calls effect_may_i with inner result
- **GIVEN** a `MayI` effect whose pattern matches the args
- **WHEN** the inner command is recursively evaluated
- **THEN** the fold's `effect_may_i` method receives the inner command, args,
  and the inner evaluation's fold output

#### Scenario: MayI no-match calls effect_may_i_no_match
- **GIVEN** a `MayI` effect whose pattern does not match
- **THEN** the fold's `effect_may_i_no_match` method is called

### Requirement: EvalFold covers all Predicate variants
The `EvalFold` trait SHALL have a method for every `Predicate` variant: fact
queries, argument patterns, `And`, `Or`, `Not`, and named predicates.

#### Scenario: Fact query calls predicate_fact with detail
- **WHEN** evaluating `Predicate::Fact(FactQuery::Presence { key: ":via/ssh" })`
- **THEN** the fold's `predicate_fact` method is called with the query, the
  result, and a `FactDetail` carrying observed values

#### Scenario: Predicate And short-circuits on NoMatch
- **GIVEN** a `Predicate::And` with three sub-predicates
- **WHEN** the second projects to `NoMatch`
- **THEN** the fold's `predicate_and` receives two `Evaluated` and one `Skipped`

### Requirement: EvalFold has rule-level methods
The `EvalFold` trait SHALL have methods for the rule-level loop: `rule_matched`
when a rule produces a non-Nil result, `rule_skipped` when a rule's command
effect returns Nil, and `default_ask` when no rule matches.

#### Scenario: Matching rule calls rule_matched
- **GIVEN** a rule whose command pattern matches and effects produce Allow
- **WHEN** the rule loop processes this rule
- **THEN** `rule_matched` is called with the rule, its source line, and the
  effect fold output

#### Scenario: Non-matching rule calls rule_skipped
- **GIVEN** a rule whose command pattern does not match
- **WHEN** the rule loop processes this rule
- **THEN** `rule_skipped` is called with the rule

#### Scenario: No rules match calls default_ask
- **WHEN** no rule in the config produces a non-Nil result
- **THEN** `default_ask` is called with a reason string

### Requirement: PureFold is zero-overhead
`PureFold` SHALL implement `EvalFold` with `EffectOut = EffectResult` and
`PredicateOut = PredicateResult`. All methods SHALL trivially return the result
argument, ignoring detail parameters.

#### Scenario: PureFold produces identical results to monomorphic evaluator
- **GIVEN** any config and command
- **WHEN** evaluated with `PureFold`
- **THEN** the decision and reason SHALL match the current evaluator output

### Requirement: EvalResult has no trace field
`EvalResult` SHALL contain only `decision: Decision` and
`reason: Option<String>`. The `trace` field SHALL be removed.

#### Scenario: EvalResult is decision and reason only
- **WHEN** constructing an `EvalResult`
- **THEN** it has exactly two fields: `decision` and `reason`

### Requirement: ChildResult distinguishes evaluated and skipped children
The `ChildResult<T>` enum SHALL have variants `Evaluated(T)` and `Skipped` to
represent whether a child was visited or short-circuited.

#### Scenario: Evaluated child carries fold output
- **WHEN** a child effect is evaluated
- **THEN** its `ChildResult` is `Evaluated(out)` where `out` is the fold output

#### Scenario: Skipped child carries no data
- **WHEN** a child effect is skipped due to short-circuiting
- **THEN** its `ChildResult` is `Skipped`
