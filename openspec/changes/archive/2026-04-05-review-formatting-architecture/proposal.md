## Why

The codebase has two independent formatting engines for s-expressions that need
to agree on layout rules but share no implementation:

1. **`pp` crate** — Pretty printer operating on `Doc` (trivia-free AST). Uses
   speculative rendering via `EventBuffer` (try flat, measure, fall back to
   broken/all-drop). Form-specific strategies for `rule`, `cond`,
   `when`/`if`/`unless`. Used for evaluator trace output.

2. **`cst.rs` `pretty_serialize`** — Formatter operating on `CstNode<TriviaAnn>`.
   Single-pass imperative approach via `PrettyCtx`. Dispatches between
   `pretty_write` (preserve trivia) and `pretty_write_no_whitespace` (compute
   layout) based on `has_source_trivia()`.

A new use case — migration with rewrite rules — interleaves the two concerns:
rewritten nodes need canonical pretty-printed layout, while moved/cloned nodes
should preserve their source formatting. The CST formatter already handles this
dispatch, but its "pretty print from scratch" path is weaker than the `pp` crate
(no speculative rendering, uses a rough `estimate_width` heuristic, single-pass
with no backtracking).

The two engines also have divergent special-form lists (`pp` includes `args`,
`effect`, `exact`, `positional`, `anywhere`; `cst.rs` includes `check`,
`with-facts`) and duplicated layout logic that will inevitably drift further.

## What Changes

Unify around a single rendering engine that handles both use cases:

- **Trivia-annotated Doc**: Introduce a `Doc` variant (or annotation) that can
  carry optional trivia from the source CST. Source-parsed nodes carry trivia;
  freshly constructed nodes carry none.
- **Trivia-aware renderer**: Extend the `pp` crate's `render` function to
  consult trivia when present. Trivia with newlines constitutes a forced break
  (preserving the author's layout). Absent trivia falls through to speculative
  flat/broken/all-drop rendering.
- **Single special-form table**: One source of truth for form classification,
  shared by all rendering paths.
- **Retire `PrettyCtx`**: Replace `pretty_serialize` with a
  `to_doc_with_trivia()` conversion on `CstNode` followed by the unified `pp`
  renderer. The faithful `serialize()` method (verbatim roundtrip) is unchanged.

## Capabilities

### New Capabilities

- `unified-renderer`: A single rendering engine that handles both pretty
  printing (canonical layout with width pressure) and formatting (preserving
  source layout with indentation correction). The engine operates on
  `Doc<Option<TriviaAnn>>` and dispatches per-node based on whether trivia is
  present.

### Modified Capabilities

- `elisp-style-indent`: Indentation rules move from `cst.rs` to the unified
  renderer. Behaviour is preserved.
- `trivia-aware-rendering`: The preserved-vs-constructed dispatch moves from
  `PrettyCtx` to the `pp` renderer. Same semantics, better layout quality for
  constructed nodes (speculative rendering replaces `estimate_width`).
- `cst-roundtrip`: `pretty_serialize` output may change for constructed nodes
  (they now get the better speculative layout). `serialize()` is unchanged.

### Removed Capabilities

- `PrettyCtx` and the imperative formatting path in `cst.rs` are retired.

## Impact

- `crates/pp/src/lib.rs`: Major changes — gains trivia-aware rendering, absorbs
  form classification from `cst.rs`, extends `render` to handle forced breaks
  from trivia.
- `crates/core/src/doc.rs`: `Doc` gains the ability to carry optional trivia
  annotations (either via the existing `A` type parameter or a dedicated field).
- `crates/sexpr/src/cst.rs`: `pretty_serialize` reimplemented as
  `to_doc_with_trivia()` + unified renderer. `PrettyCtx`, `pretty_write`,
  `pretty_write_no_whitespace`, `compute_child_indent`, and `estimate_width`
  are removed. `serialize()` is unchanged.
- `crates/config/src/migrate.rs`: No code changes expected (consumes
  `pretty_serialize`).
- Tests: Assertions on `pretty_serialize` output may change where constructed
  nodes get better layout. Migration diff snapshots may change.
