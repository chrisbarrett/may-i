## Context

The rendering pipeline has three clean layers: `Doc<A>` (s-expression trees with
annotations), the pretty-printer (`crates/pp`) which converts Doc to formatted
strings, and declarative `Layout` primitives (`crates/layout`) which handle
terminal column/indent rendering. Between these layers sits `src/output.rs`
(2310 lines) which:

1. Transforms Doc trees (truncate, dim) before pretty-printing
2. Pretty-prints to a `String` via `pretty()`
3. Independently walks the same Doc tree to extract `(needle, right_text)` pairs
4. Does substring matching (`find_line`) to correlate annotations with rendered
   lines
5. Colorizes right-column text by re-parsing formatted strings
6. Assembles `Layout` trees for terminal output

The core problem is step 2-4: pretty-printing discards structural information by
returning a flat `String`, forcing a second tree walk plus fragile string
matching to reconstruct which annotation belongs on which line.

## Goals / Non-Goals

**Goals:**

- Eliminate the `find_line` string-matching pipeline by threading annotations
  through the pretty-printer
- Make `output.rs` navigable by splitting into focused modules
- Preserve byte-identical terminal and JSON output (validated by oracle snapshots)
- Keep the `pretty()` -> `String` API for callers that don't need annotations

**Non-Goals:**

- Changing the `Layout` enum or `write_layout` interpreter
- Modifying how `TracingFold` produces `Doc<Option<Ann>>` trees
- Adding new output formats (HTML, Markdown) -- the trait enables this but we
  don't implement it now
- Changing the visual appearance of any trace output

## Decisions

### Decision 1: Modularize output.rs first (Phase 1)

Split `output.rs` into `src/output/{mod, transform, annotate, render_rule,
colorize, json, util}.rs` before introducing new abstractions.

**Rationale**: This is zero-risk mechanical extraction that makes each concern
independently readable. It also creates the clean module boundaries that Phase 2
needs -- specifically, `render_rule.rs` becomes the isolated target for replacing
the annotation pipeline.

**Alternative considered**: Skip modularization and go straight to the trait.
Rejected because modifying 2310-line monolith in-place is error-prone and makes
review difficult.

### Decision 2: Generic `PrettyOutput<A>` trait in pp crate (Phase 2)

Introduce a trait that receives structured events from the pretty-printer:

```rust
pub trait PrettyOutput<A> {
    fn begin_line(&mut self, indent: usize);
    fn emit_space(&mut self);
    fn emit_delim(&mut self, ch: char, dimmed: bool);
    fn emit_atom(&mut self, text: &str, ann: &A, dimmed: bool);
}
```

Render functions change from returning `String` to accepting
`&mut impl PrettyOutput<A>`.

**Rationale**: This eliminates the core problem -- annotations flow structurally
through rendering instead of being reconstructed via string matching. The trait
keeps the pp crate generic (no knowledge of `Ann`), and `StringBuilder`
preserves backward compatibility.

**Alternatives considered**:
- Annotated pretty-printer returning `Vec<AnnotatedLine>` (Strategy 3):
  requires duplicating all render functions or complex generics. The trait
  approach achieves the same result without duplication.
- Intermediate TraceDoc IR (Strategy 2): adds a new layer without eliminating
  the `find_line` fragility.
- Enriching the Layout enum (Strategy 1): pushes domain types into the generic
  layout crate.

### Decision 3: Event buffering for flat-vs-broken width measurement

The current `render_flat` returns a `String` and measures it to decide if the
flat form fits. With the trait approach, use an event buffer:

```rust
enum OutputEvent<'a, A> {
    BeginLine(usize),
    Space,
    Delim(char, bool),
    Atom(&'a str, &'a A, bool),
}
```

`render_flat` captures events into a `Vec<OutputEvent>`, measures total width,
and replays to the real output only if the flat form fits. Otherwise, switches to
broken layout emitting directly.

**Rationale**: This matches the current control flow closely and avoids
exposing measurement complexity to `PrettyOutput` implementations.

### Decision 4: Distribute `ArgMatch` annotations to child atoms

For `(anywhere "t1" "t2")` patterns, the parent node carries a single
`Ann::ArgMatch` with all search tokens. The current pipeline generates separate
`(needle, text)` pairs per token. With the trait approach, add a pre-processing
step that distributes the parent annotation down to individual token atoms, so
each atom's `AnnotatedLine` carries its specific match result.

**Rationale**: This keeps the `AnnotatedLineBuilder` simple (just collect
annotations per line) and moves the ArgMatch-specific logic to a single
well-defined transform.

## Risks / Trade-offs

- **[Render function complexity]** Render functions gain a type parameter
  (`PrettyOutput<A>`) increasing monomorphization. For a CLI tool this is
  negligible. Mitigation: `StringBuilder` is the common path; the
  `AnnotatedLineBuilder` is only used in trace rendering.

- **[Event buffer overhead]** Flat rendering now buffers events before deciding
  to emit. Mitigation: events are borrowed references; the buffer is small
  (typically < 20 events per flat attempt) and stack-allocated for common cases.

- **[Snapshot test sensitivity]** Any rendering change breaks oracle tests.
  Mitigation: run oracle snapshots after each commit; Phase 1 (modularization)
  changes zero behavior.

- **[ArgMatch annotation distribution]** The pre-processing step must handle
  nested patterns (forbidden = `(not (anywhere ...))`). Mitigation: the existing
  `truncate_matched_anywhere` already walks these patterns; the distribution
  transform follows the same structure.
