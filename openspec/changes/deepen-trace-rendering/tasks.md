## 1. Define TraceNode and the new renderer interface

- [ ] 1.1 Sketch `TraceNode`, `Role`, and `Evidence` in a new
  module (`src/trace/node.rs` or top of `src/annotation.rs`).
  Fields private; accessors for `label()`, `role()`,
  `evidence()`, `children()`, `dimmed()`.
- [ ] 1.2 Enumerate `Role` variants from a sweep of the
  existing `Ann::` matches across `src/output/transform.rs`,
  `src/output/render_rule.rs`, `src/output/json.rs`,
  `src/output/mod.rs`. Confirm coverage maps 1-to-1 onto
  current annotation kinds.
- [ ] 1.3 Enumerate `Evidence` variants — at minimum
  `Scalar`, `SetMembership`, `CapturedValue`,
  `FactAbsent`, `Presence`, `PatternBased`. Each carries
  the structural data the existing `Ann::` variant
  carries, minus any `ArgPattern`-shaped field name.
- [ ] 1.4 Write smart constructors on the producer side
  (`TraceNode::arg_match(…)`, `::fact_query(…)`, …) that
  admit only valid `(Role, Evidence)` combinations.
- [ ] 1.5 Confirm `TraceNode` carries no `ArgPattern`,
  `Predicate`, `Expr`, `MatchMode`, `Quantifier` field
  exposed publicly (`pub(super)` at most for producer
  helpers).

## 2. Move per-rewrite pass logic into the producer

- [ ] 2.1 Move long-`(or …)` truncation from the renderer
  ("20-alternative or-list truncates" scenario) into the
  producer. Producer emits a bounded prefix plus a
  `Role::CollapsedEllipsis` tail.
- [ ] 2.2 Move cond-branch collapse (the "5 branches, 2nd
  matches → branches 3-5 become a single `…`" scenario)
  from the renderer into the producer. Producer emits the
  collapsed tree directly.
- [ ] 2.3 Move dimming of unevaluated branches from the
  renderer-side `dimmed` flag on `Doc` to a producer-side
  `Role::Dimmed` (or a `dimmed()` accessor on `TraceNode`).
- [ ] 2.4 Move fact-query evidence compaction (presence vs
  exact scalar vs pattern-based; "Human trace renders
  compact evidence for context fact queries") into the
  producer. Producer emits the correct `Evidence` variant;
  renderer formats without re-classifying.
- [ ] 2.5 Move the `ArgPattern → Doc` exhaustiveness arm
  into the producer's `ArgPattern → TraceNode` conversion.
  Confirm `cargo build` still fails on an unhandled
  `ArgPattern` variant.

## 3. Port the text renderer

- [ ] 3.1 Add a `TraceNode → Layout` pass in `src/output/`
  (replacing `transform.rs`'s `Doc<Option<Ann>>` → `Layout`
  walk). Walk consumes `TraceNode` via accessors only.
- [ ] 3.2 Port `render_rule.rs` to attach right-column
  evidence via structural correspondence — for each
  rendered ColRow, the matching `TraceNode`'s
  `evidence()` populates the right column. Delete the
  `AnnotatedLineBuilder` collection / priority arbitration
  path.
- [ ] 3.3 Port `mod.rs` re-exports and any direct `Ann::`
  matches in shared helpers.
- [ ] 3.4 Verify the text-trace snapshots under `tests/`
  pass byte-for-byte (the `traces` spec pins their
  contents). Where a snapshot legitimately changed,
  inspect the diff against the spec scenarios before
  accepting.
- [ ] 3.5 Confirm `rg 'Ann::' src/output/` returns zero
  hits.
- [ ] 3.6 Confirm `rg 'may_i_core::pattern::(ArgPattern|CommandPattern|MatchMode|Quantifier)' src/output/`
  returns zero hits.

## 4. Port the JSON renderer

- [ ] 4.1 Port `src/output/json.rs` to consume `TraceNode`.
  JSON renderer maps `Role` to field names and `Evidence`
  to nested objects.
- [ ] 4.2 Preserve the user-observable JSON invariants
  from `traces`: `type` field present, `decision` field
  present, failure-reason fields, nested var-breakout
  (`"body"` field), unevaluated children marked
  `evaluated: false`, structural pattern AST for
  pattern-based fact queries.
- [ ] 4.3 Re-baseline JSON snapshots in `tests/snapshots/`
  (and any per-crate snapshots) where the field shape
  legitimately changes to drop `ArgPattern`-leaking
  fields. Review each diff against the preserved JSON
  invariants.

## 5. Delete the old surface

- [ ] 5.1 Delete the public `Ann` enum from
  `src/annotation.rs` (or its successor module).
- [ ] 5.2 Delete the `Doc<Option<Ann>>` type alias and
  any helpers (`ann_atom`, `ann_list`, …) that exist
  only to construct it.
- [ ] 5.3 Replace `TraceEntry::Rule { doc, … }` with
  `TraceEntry::Rule { node, … }` where `node:
  TraceNode`. `pre_migration_doc`, `facts`,
  `inner_command`, `combine_role` retain their current
  semantics.
- [ ] 5.4 Narrow visibility on `CapturedValue` and
  `FactFailure` (and any helper types) to
  `pub(crate)` if no spec or external consumer
  requires them public.
- [ ] 5.5 Confirm `rg '\bAnn\b' src/` returns zero hits
  outside comments / archived-change references.

## 6. Update snapshots and documentation

- [ ] 6.1 Run `cargo insta accept` only after each
  individual snapshot diff has been reviewed against the
  spec scenarios it covers.
- [ ] 6.2 Update any in-source doc comments that refer
  to `Ann` or `Doc<Option<Ann>>` to use `TraceNode`.
- [ ] 6.3 Run `may-i fmt examples/*.lisp` if any example
  configs changed (none expected — this change is
  internal).
- [ ] 6.4 Run `cargo fmt` before staging.

## 7. Verify

- [ ] 7.1 `cargo build` succeeds workspace-wide.
- [ ] 7.2 `cargo test --workspace` passes.
- [ ] 7.3 `cargo clippy --workspace` is clean
  (no new lints introduced).
- [ ] 7.4 `cargo tarpaulin` run; inspect `lcov.info`. For
  any uncovered branch in the new producer or renderer
  path, follow the `code-coverage` skill — prefer
  proptests for program properties, fall back to
  targeted unit tests for hard-to-hit branches.
- [ ] 7.5 `openspec validate deepen-trace-rendering`
  passes.
- [ ] 7.6 `rg 'Ann::|may_i_core::pattern::(ArgPattern|CommandPattern|MatchMode|Quantifier)' src/output/`
  returns zero hits (the contract from `output-rendering`).
- [ ] 7.7 `rg '<unknown-arg-pattern>' src/` returns zero
  hits (the contract from `traces`).
