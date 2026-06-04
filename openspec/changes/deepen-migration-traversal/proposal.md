## Why

The migration pipeline is a deep module on the outside — `migrate(node) ->
node` — but a shallow sprawl on the inside. Each of the ~22 rewrite passes is a
bare `fn(&CstNode) -> Option<Box<CstNode>>`. Passes that must reach nested forms
hand-roll the same 13-line recurse-children-then-match block
(`effect_to_decision_verb`, `check_form`, `flatten_nested_if`, …), and every
pass that rebuilds a node hand-threads trivia (`strip_whitespace_trivia` plus
manual `ann.leading`/`ann.trailing` cloning). The catamorphism that would absorb
this — `ShapeF::map`, `CstNode::map`, `CstNode::fold` — already exists in
`crates/sexpr/src/cst.rs` but is gated behind `#[cfg(test)]`, so production
passes re-walk the tree by hand. Trivia-preservation bugs therefore have ~22
possible sites instead of one.

This is the cleanest deepening opportunity on the board: a small, well-tested
traversal seam that turns shallow, recursion-carrying passes into pure local
rewrites — without changing a single byte of migration output.

## What Changes

- Promote a CST rewrite-traversal seam in the `sexpr` crate out of
  `#[cfg(test)]` into the production surface: a post-order (bottom-up) rewrite
  combinator built on the existing `ShapeF`/`CstNode` functor, plus the
  convergence driver that already lives in `rewrite_until_convergence`.
- Centralise trivia preservation in the traversal layer: when a pass returns a
  rebuilt node, re-grafting/stripping of leading/trailing trivia is handled once
  behind the seam, not in each pass.
- Refactor the migration passes in `crates/config/src/migrate/` to pure local
  rewrites — each matches only the immediate shape and returns a replacement;
  none carries its own full-tree recursion or trivia bookkeeping.
- **Behaviour-preserving**: migration output (including comments, formatting,
  Class A/B classification, diffs) is byte-identical before and after. No
  user-facing DSL, decision, or trust-hash change. Not a **BREAKING** change.

## Capabilities

### New Capabilities
- `cst-rewrite-traversal`: contributor-facing capability defining the CST
  rewrite-traversal seam — the bottom-up traversal/convergence combinator over
  the `ShapeF`/`CstNode` functor and the invariant that trivia preservation and
  recursion live in the seam, so migration passes are authored as local rewrites
  only.

### Modified Capabilities
<!-- None. The migration-system requirements (sexpr-before-AST rewrites, discrete
     passes, comment/trivia preservation, Class A/B, diff display) are all
     preserved verbatim; only the internal authoring shape changes, which is an
     implementation detail under those requirements. -->

## Impact

- **Code**: `crates/sexpr/src/cst.rs` (promote/extend traversal primitives;
  `transform` is currently top-down/early-return — a post-order variant is
  added), `crates/config/src/migrate/*.rs` (passes simplified;
  `helpers.rs::strip_whitespace_trivia` usage folded into the seam where
  possible), `crates/config/src/migrate/mod.rs` (`RewriteFn` registry unchanged
  in shape; ordering constraints preserved).
- **Tests**: existing `migrate/property_tests.rs` and `regression_tests.rs` are
  the safety net for byte-identical output; new proptests target the traversal
  combinator itself (idempotence, trivia round-trip, post-order coverage).
- **No impact** on the engine, trust store, parser, or output crates. No
  dependency changes.
