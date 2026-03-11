## MODIFIED Requirements

### Requirement: Rules can query namespaced context facts
The configuration DSL SHALL allow a rule to include a `(context EXPR)` clause whose expression is evaluated against a namespaced context fact set alongside command and argument matching. Context expressions SHALL support alias references plus explicit boolean composition with `(and ...)`, `(or ...)`, and `(not ...)`, and primitive fact queries via `(has QUERY)`. `QUERY` SHALL support bare-key presence forms `:key` and `[:key]`, exact scalar forms `[:key "value"]`, and restricted scalar value patterns `[:key PATTERN]` where `PATTERN` may be a string literal, `*`, `(regex "...")`, `(and ...)`, `(or ...)`, or `(not ...)`.

#### Scenario: Presence fact gates a rule
- **WHEN** a rule includes `(context (has :via/ssh))` and the evaluated command context contains `:via/ssh`
- **THEN** the rule's context clause matches

#### Scenario: Vector presence query is equivalent to bare-key syntax
- **WHEN** a rule includes `(context (has [:via/ssh]))` and the evaluated command context contains `:via/ssh`
- **THEN** the rule's context clause matches

#### Scenario: Scalar fact matches by exact value
- **WHEN** a rule includes `(context (has [:claude-code/permission-mode "acceptEdits"]))` and the evaluated context contains that exact scalar fact value
- **THEN** the rule's context clause matches

#### Scenario: Scalar fact matches by regex
- **WHEN** a rule includes `(context (has [:ssh/host (regex "^prod-")]))` and the evaluated context contains `:ssh/host = "prod-1"`
- **THEN** the rule's context clause matches

#### Scenario: Scalar wildcard requires a scalar value
- **WHEN** a rule includes `(context (has [:ssh/host *]))` and the evaluated context contains `:ssh/host = "prod-1"`
- **THEN** the rule's context clause matches

#### Scenario: Composed scalar pattern can match mixed matcher kinds
- **WHEN** a rule includes `(context (has [:opencode/agent (or "build" (regex "^plan-"))]))` and the evaluated context contains `:opencode/agent = "plan-review"`
- **THEN** the rule's context clause matches

### Requirement: Context aliases can be defined and composed
The configuration DSL SHALL allow top-level `(defcontext NAME EXPR)` forms that define reusable context expressions. A defined alias SHALL be usable anywhere another context expression can appear, including inside boolean compositions. Unknown aliases and cyclic alias definitions MUST cause configuration errors.

#### Scenario: Alias used directly in a rule
- **WHEN** the config defines `(defcontext remote-prod (and (has :via/ssh) (has [:ssh/host (regex "^prod-")])))` and a rule includes `(context remote-prod)`
- **THEN** the rule evaluates the aliased context expression

#### Scenario: Alias composes inside a boolean expression
- **WHEN** the config defines `my-ctx-a` and `my-ctx-b` and a rule includes `(context (or my-ctx-a my-ctx-b))`
- **THEN** the rule matches when either aliased context expression matches

#### Scenario: Cyclic aliases are rejected
- **WHEN** context aliases reference each other recursively
- **THEN** configuration loading fails with an error describing the cycle

### Requirement: Context facts remain conservative when values are missing or dynamic
The evaluator MUST treat missing context facts as absent rather than synthesizing defaults. Wrapper-derived scalar facts MUST only be attached when the matched value is statically known as a single scalar. If a wrapper match is known but the extracted value is dynamic or opaque, the evaluator MUST keep the inferred `:via/...` fact and omit the derived scalar fact.

#### Scenario: Dynamic wrapper value omits scalar fact
- **WHEN** an `ssh` wrapper matches but the host value cannot be statically resolved
- **THEN** the evaluated context includes `:via/ssh` and does not include `:ssh/host`

#### Scenario: Missing runtime metadata does not fabricate facts
- **WHEN** a runtime integration does not provide a field such as `permission_mode`
- **THEN** the evaluated context does not include a corresponding namespaced fact for that field

#### Scenario: Context-sensitive rule falls back conservatively
- **WHEN** a rule depends on `(has [:ssh/host "prod-1"])` and the command context lacks `:ssh/host`
- **THEN** that rule does not match and evaluation continues using the remaining rules
