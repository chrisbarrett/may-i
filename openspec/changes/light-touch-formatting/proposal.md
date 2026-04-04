## Why

`pretty_serialize` currently pretty-prints rewritten CST nodes: it strips all
original whitespace and imposes canonical line breaks with cascading reflow. This
is appropriate for tracing/display, but the migration command needs a
**formatter** — one that fixes indentation while preserving the author's
structural choices (packed vs cascaded line breaks, blank-line grouping). The
result is unnecessarily noisy migration diffs: long `or` lists that were packed
across a few lines explode into one-item-per-line, obscuring the actual syntax
changes.

## What Changes

- Separate the two use cases in `pretty_write_no_whitespace`:
  - **Preserved children** (cloned from the original CST with intact trivia):
    render via `pretty_write`, emitting their original whitespace verbatim. The
    author's line-break decisions flow through unchanged.
  - **Constructed children** (built by rewrite rules with default/empty trivia):
    render via `pretty_write_no_whitespace` with the existing reflow logic.
- Detection heuristic: a node is "preserved" if its trivia is non-default (e.g.
  non-empty leading/trailing trivia, or non-zero span). A node is "constructed"
  if it has `Default::default()` annotation.
- No changes to the Doc-based pretty-printer in `crates/pp` (used for
  tracing/display — it should continue to aggressively reflow).

## Capabilities

### New Capabilities

- `trivia-aware-rendering`: When rendering rewritten CST nodes, the serializer
  distinguishes between children that carry original trivia (preserved from
  source) and children that were freshly constructed, applying the appropriate
  rendering strategy to each.

### Modified Capabilities

- `elisp-style-indent`: The indentation rules remain unchanged; what changes is
  the line-break strategy for preserved children (they keep their original
  breaks instead of being reflowed).
- `cst-roundtrip`: `pretty_serialize` output may differ from current behaviour
  for nodes containing a mix of preserved and constructed children.

## Impact

- `crates/sexpr/src/cst.rs`: `pretty_write`, `pretty_write_no_whitespace`, and
  possibly `TriviaAnn` (needs a reliable "is this default?" check).
- `crates/config/src/migrate.rs`: No code changes expected, but migration output
  will change (diffs become smaller).
- `tests/migration_diff.rs`: Snapshot expectations may change.
- Existing `pretty_serialize` tests: Some assertions may need updating.
