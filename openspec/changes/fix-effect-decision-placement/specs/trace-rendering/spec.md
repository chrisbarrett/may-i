## ADDED Requirements

### Requirement: Dimmed nodes produce no right-column annotations
When a Doc node is dimmed (representing an unevaluated branch), the renderer
SHALL NOT produce any right-column annotation for that node or its children.

#### Scenario: Dimmed effect branch has no annotation
- **WHEN** a `(effect :deny)` node is dimmed because an earlier branch matched
- **THEN** no `→ :deny` annotation appears in the right column for that line

#### Scenario: Dimmed anywhere pattern has no annotation
- **WHEN** an `(anywhere "token")` node is dimmed
- **THEN** no `"token" ∈ {...} → yes/no` annotation appears

### Requirement: Structural annotation placement via AnnotatedLineBuilder
The renderer SHALL use `AnnotatedLineBuilder` to collect annotations
structurally during pretty-printing, rather than string-matching rendered output
with `find_line`.

#### Scenario: EffectDecision placed on correct line
- **WHEN** `(effect :allow "reason")` is rendered in broken layout across
  multiple lines
- **THEN** the `→ :allow "reason"` annotation appears on the line containing
  `(effect`, not on the `:allow` line

#### Scenario: Per-token anywhere annotations
- **WHEN** `(anywhere "t1" "t2")` with a parent ArgMatch is rendered
- **THEN** each token atom gets its own `"t" ∈ {args} → yes/no` annotation on
  its rendered line

### Requirement: Multiple annotations per line use priority ordering
When multiple annotations exist on a single rendered line, the renderer SHALL
display only the highest-priority annotation.

#### Scenario: EffectDecision takes priority over ArgMatch
- **WHEN** a line contains both an `EffectDecision` and an `ArgMatch` annotation
- **THEN** only the `EffectDecision` annotation is shown in the right column
