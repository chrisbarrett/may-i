## Context

The migration pipeline (`crates/config/src/migrate/`) converts older DSL syntax
to canonical form before AST parsing. Its public surface is one deep call —
`migrate(node) -> node` (`migrate/mod.rs:146`) — but internally it is ~22
free-function passes wired into a `Vec<RewriteFn>` (`migrate/mod.rs:100`) and run
by `rewrite_until_convergence` (`crates/sexpr/src/cst.rs:697`).

Two shapes of duplication live in the passes:

1. **Hand-rolled recursion.** `rewrite_until_convergence` drives recursion via
   `CstNode::transform` (`cst.rs:316`), which is *top-down* and *early-return*:
   `f(self)` is tried first, and on a match the replacement is returned without
   descending into it. Passes that must rewrite *every* nested occurrence in one
   shot therefore re-implement their own recurse-children-then-match block
   (`effect_to_decision_verb`, `check_form`, `flatten_nested_if`, …) — the same
   ~13 lines copied per pass.
2. **Hand-threaded trivia.** A pass that rebuilds a node must preserve comments
   and choose source-vs-constructed layout by calling
   `helpers::strip_whitespace_trivia` (`migrate/helpers.rs:40`) and manually
   cloning `ann.leading` / `ann.trailing`. Get it wrong and comments vanish or
   layout locks. ~22 possible sites for one class of bug.

The catamorphism that would absorb both already exists — `ShapeF::map`
(`cst.rs:40`) and `CstNode::map` / `CstNode::fold` (`cst.rs:367`) — but all three
are `#[cfg(test)]`-gated, so production passes cannot use them.

Constraint: migration output must be **byte-identical** before and after.
Comment/trivia preservation, Class A/B classification, and diff display are
locked by the `migration-system` spec and its property + regression suites.

## Goals / Non-Goals

**Goals:**

- A single deep traversal seam in the `sexpr` crate owns recursion, convergence,
  and trivia preservation for CST rewrites.
- Migration passes become pure local rewrites: match the given node, return a
  replacement, nothing else.
- `ShapeF` / `CstNode` traversal primitives move to the production surface.
- Byte-identical migration output, verified by characterization tests over the
  `examples/*.lisp` corpus plus the existing property suite.

**Non-Goals:**

- No change to user-facing DSL, decisions, trust hashes, or diff UX.
- No change to the `RewriteFn` registry *shape* or to pass ordering.
- Not touching the other deepening candidates (EvalFold width, combinator-engine
  unification) — separate changes.
- Not introducing a `Migration` trait (see Decisions).

## Decisions

### D1: Add a post-order rewrite combinator; keep `transform` for its current callers

The seam adds a *bottom-up* (post-order) rewrite: visit children first, rebuild,
then offer the node to the pass set. A single post-order sweep rewrites all
occurrences — including nested ones — so passes need no internal recursion.
Convergence is still driven outside (re-sweep until no pass fires), preserving
the existing fixed-point.

- *Alternative — keep top-down `transform` + convergence only (status quo).*
  Rejected: it is exactly what forces per-pass recursion and extra convergence
  iterations.
- *Alternative — replace `transform` outright.* Rejected: `transform` has other
  callers and a defined early-return contract; widening scope risks unrelated
  regressions. Add alongside; migrate `migrate` to the new combinator.

### D2: Trivia preservation moves into the seam

When a pass returns a replacement, the seam decides trivia/`Span` handling using
the existing `has_source_trivia` signal (`cst.rs:75`): carried-over source nodes
keep comments and re-graft the original node's leading/trailing trivia;
freshly-constructed (zero-span) nodes reflow. The per-pass
`strip_whitespace_trivia` dance is folded behind the seam.

- *Alternative — leave trivia in `helpers.rs`, call per pass.* Rejected: that is
  the sprawl being removed; locality is the whole point.

### D3: Keep `RewriteFn = Box<dyn Fn(&CstNode) -> Option<Box<CstNode>>>` unchanged

Passes stay drop-in functions with the same signature; only their *bodies*
shrink. The registry (`migration_rules()`) and its documented ordering
constraints are untouched.

- *Alternative — introduce a `Migration` trait with `fn apply`.* Rejected by the
  deletion test: a trait adds an interface without adding leverage — every pass
  is still one function, and the trait would just be ceremony over `Fn`. Depth
  belongs in the traversal seam, not in re-typing the passes.

### D4: Promote traversal primitives out of `#[cfg(test)]`

`ShapeF::map`, `CstNode::map`, `CstNode::fold` become part of the `sexpr` crate's
production API (narrowest visibility that compiles — `pub(crate)` or `pub` only
where the seam needs it), so the seam and any future CST consumer share one
traversal implementation.

## Risks / Trade-offs

- **Post-order changes which occurrence a pass sees first (innermost vs the
  current outermost-first).** A non-idempotent or shape-shifting pass could
  reach a different fixed point. → Mitigation: a characterization test snapshots
  `migrate()` serialized output over the full `examples/*.lisp` corpus *before*
  the refactor; parity is the green bar. The seam can expose both directions if
  a specific pass provably needs outermost-first.
- **Ordering-sensitive passes** (e.g. `or_leading_when_to_if` must precede
  `predicate_pushdown`, per `mod.rs:87`). → Mitigation: registry order and the
  convergence-with-restart discipline are preserved verbatim; only the within-
  sweep recursion direction changes, guarded by the existing
  evaluation-equivalence property tests.
- **Convergence iteration count / `MAX_ITERS` (`cst.rs:704`).** A post-order
  sweep that rewrites all occurrences per pass should *reduce* iterations, but a
  regression could spin. → Mitigation: assert convergence within the existing
  cap on the corpus; add a proptest that the combinator terminates.
- **Trivia edge cases** (sentinel `Span::new(0,1)` for comment-only nodes,
  `migrate/helpers.rs:62`). → Mitigation: port that exact rule into the seam and
  cover it with the existing `strip_whitespace_trivia` unit tests plus a
  round-trip proptest.

## Migration Plan

Behaviour-preserving internal refactor; no deploy/state migration.

1. **Red:** add a characterization test capturing current `migrate()` output for
   every `examples/*.lisp` form (and a generated v1 corpus) — the parity oracle.
2. Add the post-order rewrite combinator + trivia handling to `sexpr` (D1, D2,
   D4) with its own proptests (idempotence, trivia round-trip, termination).
3. Point `migrate()` at the new combinator; confirm the corpus snapshot and the
   `migration-system` property/regression suites stay green.
4. Simplify passes one at a time, each change guarded by the snapshot, removing
   internal recursion and trivia threading.
5. Delete now-dead `helpers` paths and re-gate nothing back to `#[cfg(test)]`.

Rollback: revert the commits; the registry and signatures are unchanged, so the
refactor is fully self-contained.
