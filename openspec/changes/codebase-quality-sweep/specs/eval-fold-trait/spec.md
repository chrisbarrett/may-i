## MODIFIED Requirements

### Requirement: EvalFold covers all Effect variants
The `EvalFold` trait SHALL have a method for every `Effect` variant: `Terminal` (replacing separate Allow/Ask/Deny), command pattern match, argument pattern match, `And`, `Or`, `Not`, `When`, `Unless`, `If`, `Cond`, and `MayI`.

#### Scenario: Terminal effect calls effect_terminal
- **WHEN** evaluating `Effect::Terminal { decision: Decision::Allow, reason: Some("reason") }`
- **THEN** the fold's `effect_terminal` method is called with the effect and `EffectResult::Decision(Allow, Some("reason"))`

#### Scenario: MayI calls effect_may_i with inner result
- **GIVEN** a `MayI` effect whose pattern matches the args
- **WHEN** the inner command is recursively evaluated
- **THEN** the fold's `effect_may_i` method receives the inner command, args, and the inner evaluation's fold output

#### Scenario: MayI no-match calls effect_may_i_no_match
- **GIVEN** a `MayI` effect whose pattern does not match
- **THEN** the fold's `effect_may_i_no_match` method is called

### Requirement: Fold detail types use precise enums
`PositionalElementDetail` SHALL use a `PositionalMatchKind` enum. `BindDetail.key` SHALL be `Keyword`. `ArgMatchDetail` SHALL use a constructor for common defaults.

#### Scenario: PositionalElementDetail kind field
- **WHEN** inspecting a `PositionalElementDetail` from a fold callback
- **THEN** the `kind` field SHALL be a `PositionalMatchKind` enum variant

#### Scenario: BindDetail key is Keyword
- **WHEN** a fold callback receives a `BindDetail`
- **THEN** the `key` field SHALL be of type `Keyword`

### Requirement: Arg pattern fold uses unified Ordered variant
The fold's argument pattern methods SHALL handle `ArgPattern::Ordered { mode, .. }` instead of separate `Positional` and `Exact` variants.

#### Scenario: Ordered positional fold
- **WHEN** evaluating `ArgPattern::Ordered { mode: Positional, .. }`
- **THEN** the fold receives an `ArgMatchDetail` indicating positional mode

#### Scenario: Ordered exact fold
- **WHEN** evaluating `ArgPattern::Ordered { mode: Exact, .. }`
- **THEN** the fold receives an `ArgMatchDetail` indicating exact mode
