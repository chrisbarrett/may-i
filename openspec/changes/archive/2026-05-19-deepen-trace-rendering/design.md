## Context

`src/annotation.rs` is the trace producer: it implements
`may_i_engine::fold::EvalFold` and emits, per evaluated node, an
`(EffectResult | PredicateResult, Doc<Option<Ann>>)` pair. The
top-level trace stream is `Vec<TraceEntry>`, where
`TraceEntry::Rule` carries the annotated `Doc` for one rule.

The renderers — `src/output/transform.rs` (the `Doc<Option<Ann>>`
→ `Layout` conversion used by the text path),
`src/output/render_rule.rs` (the two-column rule body renderer),
`src/output/json.rs` (the JSON serializer), and re-exports in
`src/output/mod.rs` — each pattern-match on `Ann` to decide:

1. *What text to put in the right column* (e.g.
   `"-r" ∈ {"-r", "-f", "/"} → yes` for `Ann::ArgMatch`).
2. *Which highlight* (green/yellow/red, dimmed, bold) belongs on
   the left-column atom.
3. *How to truncate or collapse* (long `(or …)` lists,
   short-circuited `cond` branches, skipped subtrees).
4. *Where the annotation attaches* (which rendered line, via
   `AnnotatedLineBuilder` priority ordering).

Today (1)–(4) are scattered across four files. Adding a new
trace concept — say, "show captured binding name on the left
column too" — requires:

- a new `Ann::` variant in `src/annotation.rs`,
- a producer arm in `TracingFold::predicate_*`,
- a renderer arm in `transform.rs`,
- a renderer arm in `render_rule.rs`,
- a renderer arm in `json.rs`,
- snapshot baselines updated.

The `traces` spec already pushes structural-data discipline on
the producer ("Trace producer records structural data, not
display strings", lines 440–483 of
`openspec/specs/traces/spec.md`), but the producer/renderer
contract is still the public `Ann` enum — variants of which name
*ArgPattern-internal fields*. CONTEXT.md warns against this
exact leak ("Resist the urge to surface this split in user docs,
error messages, or DSL forms; users see one kind of thing.",
lines 86–90), and `code-quality`'s "Advisory note builders are
pure functions owned by their data module" (lines 220–250 of
`openspec/specs/code-quality/spec.md`) sets the precedent: the
data module owns the layout decision, not the renderer.

## Goals / Non-Goals

**Goals:**

- Make the producer/renderer seam opaque: renderers do not
  pattern-match on `ArgPattern`, `Predicate`, or any
  pattern-internal shape.
- Put all structural rendering decisions (truncation, dimming,
  collapse, annotation priority, evidence compaction) in *one*
  place — the trace producer.
- Reduce "add a new trace concept" from a four-file edit to a
  one-file edit.
- Preserve the user-observable text-trace byte output where the
  `traces` spec pins it (parser kv row geometry, decisive-line
  annotation placement, dimmed unevaluated branches, var
  breakout shape).

**Non-Goals:**

- Changing what gets traced. The set of evaluator events the
  producer subscribes to is unchanged.
- Moving the trace producer out of the CLI binary. The
  "TracingFold lives outside the engine crate" requirement in
  `traces` is preserved.
- Carving `TraceNode` into a separate crate. It stays in
  `src/annotation.rs` (or a sibling module), private to the
  binary.
- Touching the engine `EvalFold` trait or `EffectResult` /
  `PredicateResult` types.

## Decisions

### TraceNode is opaque; renderers receive a pre-decided layout

The new producer/renderer contract is a `TraceNode` ADT whose
public surface is what a *renderer* needs to know:

- a label (the s-expression text to display, or a structured
  source-token reference the renderer can pretty-print);
- a `Role` enum (effect-decision, match-evidence, dimmed,
  collapsed-ellipsis, var-breakout, parser-kv, …) that the
  renderer maps to colour / dimming / two-column placement;
- evidence (a small `Evidence` enum: scalar, set-membership,
  captured-value, fact-key-absent, …) the renderer formats
  into the right column;
- ordered children.

Fields are private. Smart constructors on the producer side
admit only valid shapes. Renderers consume via accessors —
they do not match on internal enum variants.

**Alternative considered: keep `Ann` but make it `pub(crate)`.**
Visibility narrowing alone doesn't fix the leak: the renderers
still pattern-match 130+ times on variants whose fields name
`ArgPattern` internals. Rejected.

**Alternative considered: visitor-pattern callback (renderer
passes a closure per node kind).** Pushes the renderer logic
back across the seam; the producer would still need to know
which node kinds the renderer cares about. Rejected.

### Structural decisions move into the producer

The producer pre-computes:

- **Truncation** of long `(or …)` lists. Producer emits a
  `TraceNode` with N children plus a `Role::CollapsedEllipsis`
  tail when the list exceeds the cap. Renderers render
  whatever children they get.
- **Dimming** of unevaluated branches (existing producer logic
  in `TracingFold` already marks `dimmed`; the spec language
  shifts from a `dimmed` flag on `Doc` to a `Role::Dimmed`
  marker on `TraceNode`).
- **Cond-branch collapse** (the "5 branches, 2nd matches →
  branches 3–5 become a single `…`" scenario in `traces`).
  Producer emits the collapsed shape; renderers do not need a
  "skip the rest" pass.
- **Evidence compaction** for fact queries ("Human trace renders
  compact evidence for context fact queries" in `traces`).
  Producer emits `Evidence::Scalar`, `Evidence::Absent`,
  `Evidence::PresenceOnly` etc.; renderers map each to bytes
  without re-deciding which case applies.
- **Annotation placement / priority**. Today
  `AnnotatedLineBuilder` collects annotations during
  pretty-printing and resolves priority at render time. The
  producer pre-computes which `TraceNode` carries the
  right-column evidence; the renderer attaches it to the
  matching rendered line by structural correspondence
  (TraceNode → ColRow) rather than by line-index priority
  arbitration.

**Alternative considered: leave evidence compaction in the
renderer.** Loses the single-place-to-add-a-concept benefit;
the renderer would still match on fact-query subvariants.
Rejected.

### ArgPattern → TraceNode exhaustiveness moves to the producer

The `traces` spec today requires the renderer's
`ArgPattern → Doc` conversion to be exhaustive at compile time
("ArgPattern display rendering is exhaustive", lines 485–492).
After this change, the renderer no longer sees `ArgPattern`;
the producer is the only call site that destructures
`ArgPattern` for trace purposes, and the exhaustiveness
obligation moves with it.

The compile-time guarantee — adding an `ArgPattern` variant in
`crates/core/src/pattern.rs` breaks `cargo build` until the
trace path adds an explicit arm — is preserved. Only the
*location* of the obligation changes.

### Text and JSON renderers share a Layout pass

Today `transform.rs` builds a `Layout` for text and `json.rs`
walks `Doc<Option<Ann>>` independently for JSON, with each
renderer making its own truncation / dimming / evidence
decisions. After this change, both consume the same
`TraceNode` tree; each maps `Role` and `Evidence` to its own
output format (terminal bytes via `Layout`; JSON via
`serde_json::Value`). The shared `TraceNode` shape is the
single source of truth for what the trace contains; the two
renderers diverge only in *how* they encode it.

**Alternative considered: render JSON from the text Layout
post-hoc.** Loses structural information (JSON wants nested
arrays for var breakouts, not flat ColRows). Rejected.

### Snapshots: text byte-for-byte; JSON allowed to drift

The `traces` spec pins text-output bytes via scenarios with
specific rendered strings (e.g. `"-r" ∈ {"-r", "-f", "/"} →
yes`). The port preserves these byte sequences — they are part
of the contract. Where the spec leaves room
("structured representation of the s-expression", JSON
trace serialises Doc<Ann> tree"), JSON field shapes MAY
change to drop `ArgPattern`-leaking fields
(`search_tokens` + `arg_set` collapse into a single
`evidence` object keyed by `Role`).

The user-observable JSON invariants in `traces` are preserved:
`type`, `decision`, failure-reason fields, nested var
breakout (`"body"` field), unevaluated children marked
`evaluated: false`, structural pattern AST for pattern-based
fact queries.

## Risks / Trade-offs

- **[Risk]** Snapshot churn obscures real regressions during the
  port. **Mitigation:** port text renderer first while the
  spec-pinned scenarios still pass byte-for-byte (text
  snapshots unchanged → high signal). Port JSON renderer
  second; re-baseline only the JSON snapshots, and review the
  diff against the `traces` JSON requirements.

- **[Risk]** A `TraceNode` shape that's too narrow forces a
  follow-up widening when a future trace concept doesn't fit.
  **Mitigation:** the `Role` and `Evidence` enums are
  contributor-internals (private to the binary) and can grow
  variants without spec change. The seam discipline — no
  `ArgPattern`-shaped fields, no pattern matching on engine
  internals across the renderer boundary — is the invariant;
  the enums are implementation.

- **[Risk]** Moving annotation placement out of
  `AnnotatedLineBuilder` regresses the "decisive line" scenario
  ("Wrapped regex query annotates the regex line", `traces`
  spec). **Mitigation:** the producer already knows which AST
  node is decisive (it called the predicate); structural
  correspondence — TraceNode → ColRow — preserves the link
  without string matching. Verify with the spec's three
  decisive-line scenarios on the ported renderer before
  deleting `AnnotatedLineBuilder`.

- **[Risk]** Tarpaulin coverage drops because the per-rewrite
  pass logic moves and tests still target old call sites.
  **Mitigation:** task 7.x runs `cargo tarpaulin` and the
  coverage skill; uncovered branches in the new producer
  become explicit follow-up tests.

- **[Risk]** The compile-time `ArgPattern` exhaustiveness
  obligation moves but is silently weakened (e.g. a wildcard
  arm is introduced in the producer). **Mitigation:** the
  modified `traces` requirement keeps the explicit prohibition
  on wildcard fallthroughs, just relocated to the producer.

## Migration Plan

Single change, multiple commits. No user-facing migration: no
config syntax change, no trust-hash change, no DSL change. No
`may-i migrate` step.

Implementation order (mirrored in `tasks.md`):

1. Define `TraceNode`, `Role`, `Evidence` with their accessor
   surface. New module or rewritten `src/annotation.rs`.
2. Move per-rewrite pass logic (truncation, dimming,
   ellipsis, evidence compaction) from renderers into the
   producer.
3. Port text renderer (`transform.rs`, `render_rule.rs`,
   `mod.rs`) to consume `TraceNode`. Text snapshot bytes
   unchanged.
4. Port JSON renderer (`json.rs`) to consume `TraceNode`.
   Re-baseline JSON snapshots.
5. Delete `Ann`, `Doc<Option<Ann>>` alias, and any
   now-unused producer helpers.
6. Verify with `cargo test` and `cargo tarpaulin`.

## Open Questions

- Should `TraceNode` live in its own module
  (`src/trace/node.rs`) given `src/annotation.rs` is at 1938
  lines and the rewrite shrinks it? Deferred to
  implementation; a `src/trace/` directory may emerge
  naturally as `annotation.rs` thins out.
- Whether `Evidence` carries the source-tokens for argv
  matches as `Vec<String>` (current shape) or as
  `Vec<&Word>` references into the input. The latter would
  let the renderer reuse `Word::to_str()`
  (`code-quality`'s single-conversion-path requirement)
  without an intermediate allocation. Deferred.
