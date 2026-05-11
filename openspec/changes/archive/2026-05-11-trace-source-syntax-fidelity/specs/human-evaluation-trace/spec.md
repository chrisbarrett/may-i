## ADDED Requirements

### Requirement: Trace renders `ArgPattern::Tail` using source syntax
The human-readable evaluation trace SHALL render `ArgPattern::Tail` as the s-expression `(tail (authorise))` in the annotated rule body.

#### Scenario: Tail authorise predicate appears in source form
- **GIVEN** a rule containing `(tail (authorise))`
- **WHEN** the trace renders the rule body
- **THEN** the corresponding line reads `(tail (authorise))`
- **AND** the trace does not contain the literal string `<unknown-arg-pattern>`

### Requirement: Trace renders `ParameterForm::MayI` as `(authorise)`
The human-readable evaluation trace SHALL render `ParameterForm::MayI` inside a `(parameter …)` predicate as `(authorise)` in the annotated rule body.

#### Scenario: Parameter authorise predicate appears in source form
- **GIVEN** a rule containing `(parameter "c" (authorise))`
- **WHEN** the trace renders the rule body
- **THEN** the corresponding line reads `(parameter "c" (authorise))`
- **AND** the rendered text does not contain `(may-i *)`

### Requirement: Trace renders terminal effects using `(allow|ask|deny "reason"?)` form
The human-readable evaluation trace SHALL render `Effect::Terminal` nodes using their canonical source syntax — `(allow)`, `(ask)`, `(deny)`, or any of the three with a quoted reason — in the annotated rule body. The legacy `(effect :allow|:ask|:deny "reason"?)` form SHALL NOT appear in the rendered rule body.

The right-column decision annotation produced from `Ann::EffectDecision` SHALL continue to use the colon-prefixed keyword form (e.g. `→ :allow "reason"`).

#### Scenario: Allow with reason
- **GIVEN** a rule whose terminal effect is `Effect::Terminal { decision: Allow, reason: Some("safe") }`
- **WHEN** the trace renders the rule body
- **THEN** the corresponding line reads `(allow "safe")`
- **AND** the right column for that line reads `→ :allow "safe"`

#### Scenario: Bare ask
- **GIVEN** a rule whose terminal effect is `Effect::Terminal { decision: Ask, reason: None }`
- **WHEN** the trace renders the rule body
- **THEN** the corresponding line reads `(ask)`
- **AND** the right column for that line reads `→ :ask`

#### Scenario: Deny with reason
- **GIVEN** a rule whose terminal effect is `Effect::Terminal { decision: Deny, reason: Some("blocked in prod") }`
- **WHEN** the trace renders the rule body
- **THEN** the corresponding line reads `(deny "blocked in prod")`
- **AND** the right column for that line reads `→ :deny "blocked in prod"`

### Requirement: Trace annotates `(tail (authorise))` with the tail slice
When `ArgPattern::Tail` matches, the human-readable evaluation trace SHALL render a right-column annotation on the `(tail (authorise))` line of the form `tail = "<value>"` where `<value>` is the captured tail slice's tokens joined by single ASCII spaces and surrounded by double-quote delimiters. The previous full-argv `(authorise) ∈ { … } → yes` form SHALL NOT appear.

#### Scenario: Single-token tail slice
- **GIVEN** evaluating `direnv exec true` against a rule containing `(tail (authorise))`, with `direnv`'s `(positional "exec")` consuming `exec`
- **WHEN** the trace renders the rule body
- **THEN** the right column for the `(tail (authorise))` line reads `tail = "true"`

#### Scenario: Multi-token tail slice
- **GIVEN** evaluating `direnv exec echo hi there` against a rule containing `(tail (authorise))`
- **WHEN** the trace renders the rule body
- **THEN** the right column for the `(tail (authorise))` line reads `tail = "echo hi there"`

#### Scenario: Tail slice is not the full argv
- **WHEN** rendering a trace whose tail slice is `["true"]` and full argv is `["exec", "true"]`
- **THEN** the right column for the `(tail (authorise))` line reads `tail = "true"`
- **AND** the rendered annotation does not contain `"exec"`

### Requirement: Trace annotates `(parameter NAME (authorise))` with the captured value
When `ArgPattern::Parameter` with `ParameterForm::MayI` captures a value, the human-readable evaluation trace SHALL render a right-column annotation on the `(parameter …)` line of the form `value = "<captured>"` where `<captured>` is the captured single-token parameter value, surrounded by double-quote delimiters. The inner recursion trace SHALL still render beneath the rule.

#### Scenario: Bash -c captures a quoted command
- **GIVEN** evaluating `bash -c "echo hi"` against a rule containing `(parameter "c" (authorise))`
- **WHEN** the trace renders the rule body
- **THEN** the right column for the `(parameter "c" (authorise))` line reads `value = "echo hi"`
- **AND** the trace also includes a child block showing the recursive evaluation of `echo hi`

#### Scenario: Multi-token captured value
- **GIVEN** evaluating `bash -c "echo hi there"` against a rule containing `(parameter "c" (authorise))`
- **WHEN** the trace renders the rule body
- **THEN** the right column for the `(parameter "c" (authorise))` line reads `value = "echo hi there"`

### Requirement: ArgPattern display rendering is exhaustive
The trace renderer's `ArgPattern → Doc` conversion SHALL match every `ArgPattern` variant explicitly. A wildcard fallthrough that produces a placeholder atom (e.g. `<unknown-arg-pattern>`) SHALL NOT appear in this conversion. Adding a new `ArgPattern` variant in the workspace SHALL produce a compile error in the trace renderer until an explicit display arm is added.

#### Scenario: Compile-time exhaustiveness
- **WHEN** a developer adds a new `ArgPattern` variant in `crates/core/src/pattern.rs`
- **AND** runs `cargo build`
- **THEN** the build fails with a non-exhaustive-match error pointing at the trace renderer's `ArgPattern` match
- **AND** no rendered output contains the literal string `<unknown-arg-pattern>`
