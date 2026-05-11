# Human-Evaluation-Trace Specification

## Purpose

Defines how the human-readable evaluation trace renders to the terminal: which signals are surfaced, how multi-line queries are annotated, and what the JSON counterpart preserves for machine consumers.
## Requirements
### Requirement: Human trace renders compact evidence for context fact queries
The human-readable evaluation trace SHALL preserve the written `fact?` query on the left and summarize context-fact evidence on the right using a single compact annotation. Presence queries MUST render only `yes` or `no`. Exact scalar queries MUST render `yes` on success, the observed scalar value on mismatch, and `no` when no scalar value is available. Pattern-based scalar queries MUST render the observed scalar value with the final verdict whenever a scalar value is available, and `no` otherwise. (CHANGED: annotation data now carried via `Ann` enum produced by `TracingFold` instead of `EvalAnn` produced by `annotate.rs`)

#### Scenario: Presence query renders only the verdict
- **WHEN** a rendered trace includes `(fact? :via/ssh)` and the context contains `:via/ssh`
- **THEN** the right column for that query is `yes`

#### Scenario: Exact scalar mismatch renders the observed value
- **WHEN** a rendered trace includes `(fact? [:opencode/agent "build"])` and the context contains `:opencode/agent` = `{"plan"}`
- **THEN** the right column for that query is `"plan" -> no`

#### Scenario: Pattern-based scalar query renders the observed value on success
- **WHEN** a rendered trace includes `(fact? [:ssh/host (regex "^prod-")])` and the context contains `:ssh/host` = `{"prod-1"}`
- **THEN** the right column for that query is `"prod-1" -> yes`

#### Scenario: Missing scalar value renders plain no
- **WHEN** a rendered trace includes `(fact? [:ssh/host (regex "^prod-")])` and the context does not include `:ssh/host`
- **THEN** the right column for that query is `no`

### Requirement: Human trace places fact evidence on the decisive query line
When a `fact?` query wraps across multiple rendered lines, the human-readable trace SHALL place the single right-column annotation on the line containing the decisive leaf that finalized the query result. Unevaluated branches from short-circuited value patterns MUST remain visible and dimmed. (CHANGED: annotation placement logic now operates on `Doc<Option<Ann>>` trees from `TracingFold` instead of `Doc<Option<EvalAnn>>` from `annotate.rs`)

#### Scenario: Wrapped regex query annotates the regex line
- **WHEN** `(fact? [:ssh/host (regex "^prod-")])` wraps across multiple rendered lines and the context contains `:ssh/host` = `{"prod-1"}`
- **THEN** the annotation `"prod-1" -> yes` appears on the rendered line containing `(regex "^prod-")`

#### Scenario: Short-circuited composed pattern annotates the decisive leaf
- **WHEN** `(fact? [:opencode/agent (or "build" (regex "^plan-"))])` wraps across multiple rendered lines and the context contains `:opencode/agent` = `{"build"}`
- **THEN** the annotation `"build" -> yes` appears on the rendered line containing `"build"`
- **AND** the rendered line containing `(regex "^plan-")` is dimmed as unevaluated

#### Scenario: Missing scalar value annotates the key-value portion of the query
- **WHEN** `(fact? [:ssh/host (regex "^prod-")])` wraps across multiple rendered lines and the context does not include `:ssh/host`
- **THEN** the annotation `no` appears on the rendered line nearest the key/value part of the query rather than on the closing delimiter line

### Requirement: JSON trace remains explicit for context fact queries
Machine-readable trace output SHALL preserve full detail for `fact?` evaluation even when the human-readable trace is compressed. JSON annotations MUST distinguish presence, exact scalar, and pattern-based `fact?` queries; include canonicalized query source strings; and record explicit failure reasons such as `absent`, `no_matching_member`, and `pattern_mismatch`. Pattern-based JSON annotations MUST include both a structured pattern AST and a nested evaluation tree containing unevaluated children marked with `evaluated: false`. (CHANGED: JSON annotations now serialised from `Ann` enum instead of `EvalAnn`)

#### Scenario: Exact scalar absence records an explicit failure reason
- **WHEN** JSON trace output includes evaluation for `(fact? [:opencode/agent "build"])` and the context does not include `:opencode/agent`
- **THEN** the corresponding annotation reports a failed exact-scalar `fact?` query with failure reason `absent`

#### Scenario: Pattern evaluation records unevaluated children
- **WHEN** JSON trace output includes evaluation for `(fact? [:opencode/agent (or "build" (regex "^plan-"))])` and the context contains `:opencode/agent` = `{"build"}`
- **THEN** the corresponding annotation includes the canonical source for the full query
- **AND** its nested pattern evaluation marks the `"build"` child as evaluated and matched
- **AND** its nested pattern evaluation includes the `(regex "^plan-")` child with `evaluated: false`

### Requirement: Human trace renders the resolved parser as a kv row beneath the command row
The human-readable evaluation trace SHALL render the resolved parser for the evaluated command as a key-value row using the same two-column geometry as the `command` row, with label `parser` on the left and the parser description on the right. The `parser` row SHALL appear immediately beneath the `command` row, with no intervening blank line. The right column SHALL contain the resolved style name; when the parser declares parameter spellings, they SHALL follow as ` parameters (<token> <token> …)`; when the parser declares a tail boundary, it SHALL follow as ` tail (after <spec>)`.

#### Scenario: Default gnu parser with no parameters or tail
- **WHEN** rendering a failure trace whose resolved parser has style `gnu`, no parameter spellings, and no tail
- **THEN** the trace contains a `command │ <command-string>` row
- **AND** the next rendered row is `parser │ gnu`
- **AND** there is no blank line between the `command` row and the `parser` row

#### Scenario: Parser with parameter spellings
- **WHEN** rendering a failure trace whose resolved parser has style `gnu` and parameter spellings `-X` and `--request`
- **THEN** the `parser` row's right column reads `gnu  parameters (-X --request)`

#### Scenario: Parser with a tail boundary
- **WHEN** rendering a failure trace whose resolved parser has style `gnu` and tail `Tail::AfterFlags`
- **THEN** the `parser` row's right column reads `gnu  tail (after :flags)`

#### Scenario: Parser with both parameters and a tail boundary
- **WHEN** rendering a failure trace whose resolved parser has style `gnu`, parameter spellings `-c`, and tail `Tail::AfterToken(["--"])`
- **THEN** the `parser` row's right column reads `gnu  parameters (-c)  tail (after "--")`

### Requirement: Standalone right-aligned parser banner is removed
The human-readable evaluation trace SHALL NOT render the parser as a standalone right-aligned banner row above the `command` row. The previously emitted blank line that followed the standalone banner SHALL also be removed.

#### Scenario: No top-of-trace parser banner
- **WHEN** rendering any failure trace
- **THEN** the trace does not contain a row whose left column is the entire width and whose visible text begins with `parser:` followed by the style name
- **AND** the first rendered content row of the trace is the `command` row

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

