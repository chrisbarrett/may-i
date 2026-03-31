## ADDED Requirements

### Requirement: TracingFold produces annotated Doc trees alongside results
`TracingFold` SHALL implement `EvalFold` with
`EffectOut = (EffectResult, Doc<Option<Ann>>)` and
`PredicateOut = (PredicateResult, Doc<Option<Ann>>)`. Each fold method SHALL
build an annotated Doc node that mirrors the s-expression structure of the
evaluated AST node.

#### Scenario: Terminal effect produces annotated doc
- **WHEN** evaluating `Effect::Allow(Some("safe"))`
- **THEN** the fold output contains `EffectResult::Decision(Allow, Some("safe"))`
- **AND** a `Doc` representing `(effect :allow "safe")` with an `Ann` recording
  the decision

#### Scenario: Command match produces annotated doc
- **WHEN** evaluating `Effect::CommandPattern(Literal("git"))` against command
  `"git"`
- **THEN** the `Doc` represents `"git"` with an `Ann::CommandMatch { matched: true }`

#### Scenario: Short-circuited children appear dimmed
- **GIVEN** an `And` effect where the first child returns Nil
- **WHEN** the fold builds the doc for the And node
- **THEN** unevaluated children's docs SHALL have `dimmed = true`

### Requirement: Ann enum covers all annotation kinds
The `Ann` enum SHALL have variants for: command match (with matched flag),
argument match (with args and evidence), fact query result (with observed values
and failure reasons), effect decision (with decision and reason), and
quantifier match (with count). These correspond to the evidence needed for
the right column in two-column trace output.

#### Scenario: Arg match annotation includes evidence
- **WHEN** `(anywhere "-r")` is evaluated against args `["-r", "-f", "/"]`
- **THEN** the `Ann` records the search tokens, the full arg set, and whether
  each token was found

#### Scenario: Fact query annotation includes observed values
- **WHEN** `(fact? [:opencode/agent "build"])` is evaluated and context has
  `opencode/agent = {"plan"}`
- **THEN** the `Ann` records the expected value `"build"`, observed set
  `{"plan"}`, and `matched: false`

### Requirement: TracingFold lives outside the engine crate
The `TracingFold` struct, `Ann` enum, and all `Doc`-related types SHALL be
defined in the CLI binary (`src/`), not in the engine crate. The engine crate
SHALL NOT depend on `may-i-core::doc` for trace purposes.

#### Scenario: Engine crate compiles without Doc dependency for traces
- **WHEN** the engine crate is compiled
- **THEN** no trace-related code in the engine imports `Doc` or `Ann`

### Requirement: TracingFold handles MayI recursion
When the evaluator processes a `MayI` effect, it SHALL call `evaluate`
recursively with the same `TracingFold` instance. The inner evaluation produces
its own `(EffectResult, Doc<Option<Ann>>)`. The outer `effect_may_i` method
SHALL incorporate the inner doc as a nested trace.

#### Scenario: Wrapper command shows inner trace
- **GIVEN** a wrapper rule for `nohup` and an inner command `git push`
- **WHEN** `may-i eval 'nohup git push'` is evaluated with `TracingFold`
- **THEN** the trace shows the inner `git push` evaluation with full annotations
