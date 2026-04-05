## Context

The codebase has two formatting engines that independently implement
s-expression layout:

**`pp` crate (pretty printer)**. Operates on `Doc<A>` — a trivia-free annotated
tree. Layout decisions use speculative rendering: an `EventBuffer` captures
output events from a candidate layout (flat, broken, all-drop), measures the
resulting line widths, and either commits or falls back. Form-specific strategies
handle `rule`, `cond`, `when`/`if`/`unless`. This is the higher-quality engine.

**`cst.rs` `pretty_serialize` (formatter)**. Operates on `CstNode<TriviaAnn>` —
a concrete syntax tree with preserved whitespace and comments. Uses `PrettyCtx`,
a single-pass imperative renderer. For children with source trivia it calls
`pretty_write` (emit trivia verbatim); for constructed children it calls
`pretty_write_no_whitespace` (compute layout from scratch using `estimate_width`
heuristic and cascading `has_broken` flag). Form-specific indent rules duplicate
those in `pp` but with a different special-form table.

The interleaved use case (migration rewrites) needs both: preserve source layout
for cloned subtrees, produce canonical layout for newly constructed nodes. The
CST formatter handles this dispatch but its constructed-node path is weaker than
`pp` — it can't back-track and uses rough width estimates.

## Goals / Non-Goals

**Goals:**

- One rendering engine for both pretty printing and formatting.
- Constructed nodes get speculative layout (the `EventBuffer` approach from
  `pp`), not single-pass heuristic layout.
- Preserved nodes keep the author's line breaks and comments.
- One special-form classification table shared by all rendering paths.
- Migration output quality improves (better layout for rewritten nodes).
- Trace output (`pp` current consumers) is unaffected.

**Non-Goals:**

- Changing the faithful `serialize()` method (verbatim CST roundtrip).
- Changing rewrite rules in `crates/config/src/migrate.rs`.
- Re-indenting the internal whitespace of preserved subtrees to match a new
  nesting depth (a known limitation; acceptable for now).
- Merging the `layout` crate (terminal layout with word-wrap) into this work.
  It serves a different purpose (2-column terminal output).

## Decisions

### 1. Trivia as a Doc annotation

Use the existing `Doc<A>` type parameter to carry optional trivia:

```rust
type FormattingDoc = Doc<Option<TriviaAnn>>;
```

- `Doc<()>` (current trace use case): no trivia, pure pretty printing. A trivial
  `Doc<()>` → `Doc<Option<TriviaAnn>>` conversion wraps each annotation in
  `None`.
- `Doc<Option<TriviaAnn>>` (formatting use case): source-parsed nodes carry
  `Some(trivia)`, constructed nodes carry `None`.

**Why not a new type?** `Doc<A>` already parameterizes the annotation. Using
`Option<TriviaAnn>` avoids a parallel type hierarchy and lets all rendering code
work on one tree type. The `PrettyOutput<A>` trait already threads `A` through,
so the renderer can inspect trivia at each node.

**Why not a `Doc` field?** Adding `trivia: Option<TriviaAnn>` as a dedicated
field alongside `ann: A` would decouple the two annotation concerns. This is a
viable alternative, but it means every `Doc` consumer must know about trivia even
when irrelevant. Using the type parameter keeps the unadorned `Doc<()>` clean.

### 2. Trivia-aware rendering in the `pp` renderer

Extend the `render` function to consult the annotation before choosing layout:

```
fn render<A>(doc: &Doc<A>, ...) where A: TriviaSource
```

Where `TriviaSource` is a trait:

```rust
trait TriviaSource {
    fn forced_break(&self) -> bool;
    fn leading_trivia(&self) -> &[Trivia];
    fn trailing_trivia(&self) -> &[Trivia];
}
```

Implemented for `()` (always returns false/empty) and `Option<TriviaAnn>`
(delegates to the trivia when `Some`).

When rendering children of a list:

1. If the child has `forced_break()` (its leading trivia contains a newline),
   emit a line break and indent, then emit the trivia (comments, blank lines),
   then render the child's content.
2. Otherwise, fall through to the existing speculative flat/broken/all-drop
   logic.

This preserves the existing pretty-printing behaviour for `Doc<()>` (the trait
methods are all no-ops) while adding trivia awareness for `Doc<Option<TriviaAnn>>`.

### 3. `CstNode::to_doc_with_trivia()`

Add a conversion method on `CstNode<TriviaAnn>`:

```rust
impl CstNode<TriviaAnn> {
    pub fn to_doc_with_trivia(&self) -> Doc<Option<TriviaAnn>> { ... }
}
```

This walks the CST tree and produces a `Doc` where:

- Each node's annotation is `Some(trivia_ann)` if the node has source trivia
  (`has_source_trivia()` returns true), or `None` if it was freshly constructed.
- `ShapeF::Atom` / `ShapeF::Str` → `DocF::Atom`.
- `ShapeF::List` / `ShapeF::Vector` → `DocF::List` / `DocF::Vector`.

The existing `to_doc()` (which discards all trivia) remains for the trace
use case.

### 4. Reimplement `pretty_serialize`

Replace the current implementation:

```rust
pub fn pretty_serialize(&self, width: usize) -> String {
    let doc = self.to_doc_with_trivia();
    may_i_pp::pretty(&doc, 0, &Format { width, ..Default::default() })
}
```

This eliminates `PrettyCtx`, `pretty_write`, `pretty_write_no_whitespace`,
`compute_child_indent`, `estimate_width`, and the `SPECIAL_FORMS` table in
`cst.rs`.

### 5. Unified special-form table

Move the special-form classification into the `pp` crate (or `core`) as the
single source of truth. The current tables:

- `pp`: `rule`, `command`, `args`, `effect`, `cond`, `if`, `when`, `unless`,
  `else`, `positional`, `exact`, `anywhere`
- `cst.rs`: `define`, `check`, `with-facts`, `when`, `unless`, `rule`, `cond`

The unified table should include the union, minus any that are no longer
relevant after migration rewrites remove them (e.g. `command`, `args`, `effect`
which are v1-only forms). The exact list:

- `rule`, `define`, `check`, `with-facts`, `when`, `unless`, `if`, `cond`,
  `case`, `and`, `or`

`and` and `or` are included because they are connectives that benefit from +2
body indent rather than function-call alignment when they have complex
sub-expressions. (This is a judgement call — revisit based on output quality.)

### 6. Trivia emission in `PrettyOutput`

Add methods to the `PrettyOutput` trait for emitting trivia:

```rust
fn emit_leading_trivia(&mut self, trivia: &[Trivia], indent: usize);
fn emit_trailing_trivia(&mut self, trivia: &[Trivia]);
```

Default implementations handle whitespace and comments with the same logic
currently in `pretty_write_no_whitespace` (comment-on-own-line at indent level,
blank line preservation, trailing comment gap preservation).

`EventBuffer` implements these by recording trivia events and accounting for
their width. `StringBuilder` emits them directly.

### 7. Cascade semantics for mixed trees

When a list contains a mix of preserved and constructed children:

- A preserved child with a forced break (newline in trivia) sets the cascade
  flag, just as the current `has_broken` mechanism does.
- Subsequent constructed children see the cascade and break accordingly.
- A constructed child that breaks (because it exceeds width) also sets the
  cascade for subsequent children.

This matches the current behaviour but moves the logic from `PrettyCtx` mutable
state into the `render` function's recursive flow.

## Risks / Trade-offs

- **Output changes**: `pretty_serialize` output will change for constructed nodes
  (they get better speculative layout instead of heuristic layout). Some may
  also change due to the unified special-form table. Test snapshots will need
  updating. → Acceptable; the new output is higher quality.

- **Preserved-node indentation mismatch**: When a rewrite changes nesting depth,
  preserved subtrees keep their original internal indentation, which may not
  match the new context. → Known limitation, same as today. Acceptable for
  migration; a future enhancement could re-indent trivia whitespace.

- **Trait complexity**: Adding `TriviaSource` introduces a trait bound on
  `render`. → Minimal complexity; the trait is small and has only two
  implementations. An alternative is to make `render` always take
  `Doc<Option<TriviaAnn>>` and have trace callers wrap with `None`, avoiding
  the trait entirely. Decide during implementation based on ergonomics.

- **Performance**: Speculative rendering (try flat, measure, possibly discard)
  is slightly more expensive than single-pass. → Negligible for config files
  (small inputs). The `EventBuffer` approach is already proven in production for
  trace output.

- **Migration of `and`/`or` to special-form indent**: Currently these use
  function-call indent (align under first arg). Changing to +2 body indent
  alters formatting for existing configs. → Evaluate by running against real
  configs before committing. If the change is too noisy, keep them as
  function-call forms.
