## ADDED Requirements

### Requirement: Pretty-printer accepts a generic output trait
The `may_i_pp` crate SHALL define a `PrettyOutput<A>` trait that receives
structured rendering events from the pretty-printer. Render functions SHALL
accept `&mut impl PrettyOutput<A>` instead of returning `String` directly.

#### Scenario: Trait defines required event methods
- **WHEN** a consumer implements `PrettyOutput<A>`
- **THEN** it must provide `begin_line(indent)`, `emit_space()`,
  `emit_delim(ch, dimmed)`, and `emit_atom(text, ann, dimmed)` methods

#### Scenario: Entry point accepts any PrettyOutput implementation
- **WHEN** calling `pretty_into(doc, indent, fmt, &mut output)`
- **THEN** the pretty-printer drives the output builder with the same layout
  decisions (flat/broken/all-drop) as the existing `pretty()` function

### Requirement: StringBuilder reproduces existing pretty() output
A `StringBuilder` implementation of `PrettyOutput<A>` SHALL produce output
identical to the existing `pretty()` function for all inputs.

#### Scenario: Backward-compatible pretty() wrapper
- **WHEN** calling `pretty(doc, indent, fmt)` (the existing API)
- **THEN** it internally uses `StringBuilder` and returns the same `String`
  output as before the refactor

#### Scenario: Colorized atoms match existing rendering
- **WHEN** `StringBuilder` receives `emit_atom("rm", ann, false)` with color
  enabled
- **THEN** the output matches `colorize_atom("rm", true)`

### Requirement: AnnotatedLineBuilder produces lines with annotations
An `AnnotatedLineBuilder<A>` implementation of `PrettyOutput<A>` SHALL produce
a `Vec<AnnotatedLine<A>>` where each rendered line carries the annotations from
Doc nodes that produced content on that line.

#### Scenario: Single-line atom carries its annotation
- **WHEN** a `Doc<Option<Ann>>` with a single annotated atom is pretty-printed
  via `AnnotatedLineBuilder`
- **THEN** the resulting `AnnotatedLine` carries that annotation and the
  rendered text matches the `StringBuilder` output

#### Scenario: Multi-line broken layout preserves per-line annotations
- **WHEN** a list with annotated children renders in broken layout
- **THEN** each child's line carries its own annotation
- **AND** the concatenated text of all lines matches `StringBuilder` output

#### Scenario: Flat layout aggregates annotations on single line
- **WHEN** multiple annotated atoms render on a single flat line
- **THEN** the `AnnotatedLine` carries all annotations from atoms on that line

### Requirement: Flat-vs-broken decision uses event buffering
When the pretty-printer attempts flat rendering to check if output fits within
the width budget, it SHALL buffer output events and replay them to the real
output only if the flat form fits. If flat rendering exceeds the width, the
buffer SHALL be discarded and broken rendering SHALL emit directly.

#### Scenario: Flat rendering fits within width
- **WHEN** a list fits on one line within the width budget
- **THEN** the buffered events are replayed to the output builder
- **AND** the result is identical to current flat rendering

#### Scenario: Flat rendering exceeds width
- **WHEN** a list does not fit on one line
- **THEN** the buffer is discarded and broken rendering emits directly
- **AND** the result is identical to current broken rendering
