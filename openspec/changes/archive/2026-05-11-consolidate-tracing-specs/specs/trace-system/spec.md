## ADDED Requirements

### Requirement: Heading and label widths use visible character width

The layout renderer SHALL compute visible character width (not byte length) for NoteHeading text and ColRow label text. This ensures correct column alignment when headings or labels contain multi-byte Unicode characters or ANSI escape codes.

#### Scenario: Unicode heading alignment

- **WHEN** a NoteHeading is created from a string containing Unicode characters (e.g., "ℹ Info")
- **THEN** the visible_width field SHALL equal the number of visible characters, not the byte length

#### Scenario: ColRow label with Unicode

- **WHEN** a ColRow::kv is created with a label containing Unicode characters
- **THEN** the width used for column arithmetic SHALL equal the visible character width

### Requirement: Trace shows define name at point of use

When a rule's trace includes a `Predicate::Named` reference, the trace SHALL display the define name (not the expanded body) at the point of use in the rule structure.

#### Scenario: Human-readable trace shows name

- **WHEN** evaluating `"git push"` against a rule `(rule "git" (when build-mode (allow)))` where `build-mode` is a define
- **THEN** the human-readable trace shows `build-mode` in the rule's predicate position, not the expanded body

#### Scenario: JSON trace shows name

- **WHEN** evaluating the same rule with `--json`
- **THEN** the trace includes an annotation with `"type": "var_ref"` and `"name": "build-mode"`

### Requirement: Trace includes a breakout section for the define body

When a `Predicate::Named` is evaluated, the trace SHALL include a nested breakout section showing the define's body with its own evaluation annotations.

#### Scenario: Breakout shows expanded body with annotations

- **WHEN** `build-mode` is defined as `(or (has [:client "claude-code"]) (has [:agent "build"]))` and the context has fact `[:agent "build"]`
- **THEN** the trace breakout for `build-mode` shows the `(or ...)` body with annotations indicating which branch matched

#### Scenario: Human-readable breakout is visually distinct

- **WHEN** a rule trace includes a var breakout
- **THEN** the breakout is rendered as an indented, labelled section beneath the var reference — visually distinct from the rule's own trace

#### Scenario: JSON breakout is nested

- **WHEN** a rule trace includes a var breakout in JSON mode
- **THEN** the var annotation contains a `"body"` field with the child predicate's annotations as a nested array

### Requirement: Unmatched var breakout is still shown

When a `Predicate::Named` reference evaluates to `NoMatch`, the trace SHALL still show the breakout with annotations indicating why it did not match.

#### Scenario: Breakout shows non-matching body

- **WHEN** `build-mode` does not match the current context
- **THEN** the trace breakout shows the body with annotations indicating no branch matched
