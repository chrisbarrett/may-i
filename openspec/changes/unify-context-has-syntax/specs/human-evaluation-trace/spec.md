## ADDED Requirements

### Requirement: Human trace renders compact evidence for context has queries
The human-readable evaluation trace SHALL preserve the written `has` query on the left and summarize context-fact evidence on the right using a single compact annotation. Presence queries MUST render only `yes` or `no`. Exact scalar queries MUST render `yes` on success, the observed scalar value on mismatch, and `no` when no scalar value is available. Pattern-based scalar queries MUST render the observed scalar value with the final verdict whenever a scalar value is available, and `no` otherwise.

#### Scenario: Presence query renders only the verdict
- **WHEN** a rendered trace includes `(has :via/ssh)` and the context contains `:via/ssh`
- **THEN** the right column for that query is `yes`

#### Scenario: Exact scalar mismatch renders the observed value
- **WHEN** a rendered trace includes `(has [:opencode/agent "build"])` and the context contains `:opencode/agent = "plan"`
- **THEN** the right column for that query is `"plan" -> no`

#### Scenario: Pattern-based scalar query renders the observed value on success
- **WHEN** a rendered trace includes `(has [:ssh/host (regex "^prod-")])` and the context contains `:ssh/host = "prod-1"`
- **THEN** the right column for that query is `"prod-1" -> yes`

#### Scenario: Missing scalar value renders plain no
- **WHEN** a rendered trace includes `(has [:ssh/host (regex "^prod-")])` and the context does not include a scalar `:ssh/host` fact
- **THEN** the right column for that query is `no`

### Requirement: Human trace places fact evidence on the decisive query line
When a `has` query wraps across multiple rendered lines, the human-readable trace SHALL place the single right-column annotation on the line containing the decisive leaf that finalized the query result. Unevaluated branches from short-circuited value patterns MUST remain visible and dimmed.

#### Scenario: Wrapped regex query annotates the regex line
- **WHEN** `(has [:ssh/host (regex "^prod-")])` wraps across multiple rendered lines and the context contains `:ssh/host = "prod-1"`
- **THEN** the annotation `"prod-1" -> yes` appears on the rendered line containing `(regex "^prod-")`

#### Scenario: Short-circuited composed pattern annotates the decisive leaf
- **WHEN** `(has [:opencode/agent (or "build" (regex "^plan-"))])` wraps across multiple rendered lines and the context contains `:opencode/agent = "build"`
- **THEN** the annotation `"build" -> yes` appears on the rendered line containing `"build"`
- **AND** the rendered line containing `(regex "^plan-")` is dimmed as unevaluated

#### Scenario: Missing scalar value annotates the key-value portion of the query
- **WHEN** `(has [:ssh/host (regex "^prod-")])` wraps across multiple rendered lines and the context does not include a scalar `:ssh/host` fact
- **THEN** the annotation `no` appears on the rendered line nearest the key/value part of the query rather than on the closing delimiter line

### Requirement: JSON trace remains explicit for context has queries
Machine-readable trace output SHALL preserve full detail for `has` evaluation even when the human-readable trace is compressed. JSON annotations MUST distinguish presence, exact scalar, and pattern-based `has` queries; include canonicalized query source strings; and record explicit failure reasons such as `absent`, `present_without_scalar`, `value_mismatch`, and `pattern_mismatch`. Pattern-based JSON annotations MUST include both a structured pattern AST and a nested evaluation tree containing unevaluated children marked with `evaluated: false`.

#### Scenario: Exact scalar absence records an explicit failure reason
- **WHEN** JSON trace output includes evaluation for `(has [:opencode/agent "build"])` and the context does not include `:opencode/agent`
- **THEN** the corresponding annotation reports a failed exact-scalar `has` query with failure reason `absent`

#### Scenario: Presence-only fact records present-without-scalar distinctly
- **WHEN** JSON trace output includes evaluation for `(has [:ssh/host (regex "^prod-")])` and the context includes bare presence `:ssh/host` without a scalar value
- **THEN** the corresponding annotation reports a failed pattern-based `has` query with failure reason `present_without_scalar`

#### Scenario: Pattern evaluation records unevaluated children
- **WHEN** JSON trace output includes evaluation for `(has [:opencode/agent (or "build" (regex "^plan-"))])` and the context contains `:opencode/agent = "build"`
- **THEN** the corresponding annotation includes the canonical source for the full query
- **AND** its nested pattern evaluation marks the `"build"` child as evaluated and matched
- **AND** its nested pattern evaluation includes the `(regex "^plan-")` child with `evaluated: false`
