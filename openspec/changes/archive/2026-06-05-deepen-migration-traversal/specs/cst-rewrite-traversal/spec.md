---
audience: contributor
bucket: contributor-internals
---
## ADDED Requirements

### Requirement: CST rewrite-traversal seam owns recursion

The CST rewrite-traversal seam in the `sexpr` crate SHALL provide a bottom-up
(post-order) traversal combinator over the `ShapeF` / `CstNode` functor that
visits every node and offers each registered rewrite the chance to replace it,
iterating to convergence. Individual migration passes SHALL NOT carry their own
full-tree recursion; a pass body SHALL match and rewrite only the node it is
given. (This is a contributor-facing capability; audience is declared in
frontmatter.)

#### Scenario: Nested occurrences rewritten by a local pass

- **WHEN** a config contains a rewritable form nested inside other forms
- **AND** a pass is registered that matches only that form's immediate shape
- **THEN** the traversal combinator SHALL apply the pass to every occurrence,
  nested or top-level, without the pass recursing itself

#### Scenario: Convergence over interacting passes

- **GIVEN** two passes where one pass produces a form the other rewrites
- **WHEN** the traversal combinator runs the registered passes
- **THEN** it SHALL iterate until no pass fires, producing the same fixed point
  the current `rewrite_until_convergence` driver produces

### Requirement: Trivia preservation lives in the traversal layer

When a pass returns a replacement node, the seam SHALL preserve the original
node's comment and whitespace trivia and `Span` semantics according to whether
the replacement is freshly constructed or carried over from source, so that a
pass body does not hand-thread `ann.leading` / `ann.trailing`. Comments present
in the source SHALL survive any rewrite.

#### Scenario: Comment survives a local rewrite

- **GIVEN** a source form carrying an inline comment in its trivia
- **WHEN** a pass rewrites that form via the seam
- **THEN** the comment SHALL appear in the serialized output

#### Scenario: Freshly constructed replacement reflows

- **WHEN** a pass returns a node built from default (zero-span) annotations
- **THEN** the seam SHALL treat it as constructed, so the pretty printer reflows
  it rather than locking it to stale source layout

### Requirement: Production traversal primitives are not test-gated

The functor and catamorphism primitives the seam is built on SHALL be part of
the production surface of the `sexpr` crate and SHALL NOT be gated behind
`#[cfg(test)]` — namely `ShapeF` map and `CstNode` map/fold — so migration
passes and the seam consume one shared traversal implementation.

#### Scenario: Seam and passes share one traversal

- **WHEN** the migration pipeline is built for release (non-test) compilation
- **THEN** the rewrite-traversal seam SHALL be available without any
  `#[cfg(test)]` primitive, and no production pass SHALL re-implement node
  recursion
