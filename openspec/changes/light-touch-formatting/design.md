## Context

The CST serializer has two rendering methods:

- `pretty_write`: emits the node's trivia verbatim (whitespace, comments), then
  delegates children to `pretty_write_no_whitespace`.
- `pretty_write_no_whitespace`: strips all whitespace trivia, re-derives line
  breaks via cascading reflow, and computes indentation from scratch.

This means even children that were **cloned intact from the source CST** (with
their original whitespace trivia preserved) get their whitespace discarded and
replaced by the formatter's reflow logic. A packed `(or "cat" "bat" "zat" ...)`
from the source becomes a one-per-line cascade in the output.

Rewrite rules already do the right thing: when extracting an inner node (e.g.
pulling `(or ...)` out of `(command (or ...))`), they clone it with its full
trivia tree. The rendering layer just ignores that preserved trivia.

## Goals / Non-Goals

**Goals:**

- Children with intact source trivia render via `pretty_write` (preserving the
  author's line breaks, packing, blank-line grouping).
- Children constructed by rewrite rules (default/empty trivia) render via
  `pretty_write_no_whitespace` (the existing reflow logic).
- Migration diffs shrink: only actual syntax changes appear, not reformatting
  noise from reflowed unchanged sub-expressions.

**Non-Goals:**

- Changing the Doc-based pretty-printer (`crates/pp`). It serves the
  tracing/display use case and should continue to cascade aggressively.
- Adding a configurable layout hint enum to `TriviaAnn`. If a simple detection
  heuristic works, avoid adding schema complexity.
- Changing rewrite rules. The fix is in the rendering layer, not in how rules
  construct nodes.

## Decisions

### 1. Detection: "has this node been through a rewrite?"

A node carries original trivia if it was cloned from the parsed CST. A node is
freshly constructed if it was built with `Default::default()` or
`CstNode::atom`/`CstNode::list` with explicit empty trivia.

**Heuristic**: a node has "source trivia" if its `TriviaAnn` has a non-zero
span. Parsed nodes get real spans from the parser; constructed nodes get
`Span::new(0, 0)` from `Default::default()`.

**Why span rather than trivia vec contents?** Trivia vecs can be empty for real
parsed nodes too (e.g. the first atom in a list has no leading whitespace). But
the span is always set by the parser and always zero for constructed nodes. It's
the most reliable signal.

**Why not a boolean flag?** Adding `is_preserved: bool` to `TriviaAnn` would
work but requires threading it through every rewrite rule and constructor. The
span check is zero-cost and requires no changes to existing code.

### 2. Dispatch in `pretty_write` list rendering

Currently `pretty_write` renders list children like this:

```rust
child.pretty_write_no_whitespace(ctx);
```

Change to:

```rust
if child.has_source_trivia() {
    child.pretty_write(ctx);
} else {
    child.pretty_write_no_whitespace(ctx);
}
```

When a child has source trivia, `pretty_write` will emit that child's whitespace
verbatim — including its original line breaks and spacing. The parent still
controls the indent level and the space/break *before* each child; the child
controls its own *internal* layout.

### 3. Indentation interaction

The elisp-style indentation rules (from the prior change) set `child_indent`
on the `PrettyCtx` indent stack. For preserved children rendered via
`pretty_write`, their internal trivia may use different indentation than what
the formatter would choose.

This is acceptable for now. The author's original indentation was presumably
correct for the original nesting depth. If a rewrite changes the nesting depth
(e.g. removing a wrapper layer), the internal indentation may be slightly off —
but this is a rare edge case and still produces correct, parseable output.

A future enhancement could adjust preserved trivia's leading whitespace to match
the current indent level, but this is out of scope.

### 4. `pretty_write_no_whitespace` remains unchanged

The whitespace-stripping path continues to work as-is for constructed nodes. No
changes to its cascading reflow or indentation logic.

## Risks / Trade-offs

- **Mixed indentation in output**: When a rewritten parent contains a preserved
  child, the parent's indentation is computed by the formatter but the child's
  internal indentation is from the source. If nesting depth changed, there may
  be a visual mismatch. → Acceptable for migration (correctness preserved, just
  cosmetic); revisit if users report issues.
- **Span heuristic could be wrong**: If a rewrite rule clones a node but
  manually sets its span to zero, the heuristic misclassifies it.
  → No current rewrite rule does this; the convention is clear.
- **Test churn**: Some `pretty_serialize` tests may produce different output for
  inputs containing nodes with source trivia. → Expected; the new output is
  closer to the original.
