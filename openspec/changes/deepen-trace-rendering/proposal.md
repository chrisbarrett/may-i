## Why

`src/annotation.rs` (1938 lines) defines a public `Ann` enum whose
variants (`ArgMatch`, `FactQuery`, `RegexMatch`, `PositionalMatch`,
`BindMatch`, `Combinator`, `VarRef`, …) embed `ArgPattern`-internal
shape (`search_tokens`, `arg_set`, regex pattern strings,
positional match-mode booleans) straight into the rendering seam.
Every renderer — `src/output/transform.rs` (34 `Ann::` matches),
`src/output/render_rule.rs` (38), `src/output/json.rs` (30),
`src/output/mod.rs` (8) — pattern-matches the same variants. Adding
a trace concept means touching four files in lockstep, and the
public `Ann` surface forces the contributor-only `ArgPattern` /
`Predicate` vocabulary across the producer/renderer boundary. This
is the "Pattern internals leak" warning in CONTEXT.md, materialised
at the rendering seam.

## What Changes

- Introduce a `TraceNode` ADT in `src/annotation.rs` whose
  interface is *what to render* (label, highlight role, child
  spans, captured evidence as a small enum). `TraceNode` SHALL
  have private fields and a constructor surface that admits only
  shapes the renderers can reach today.
- Move structural decisions currently spread across renderers —
  truncation of long `(or …)` lists, dimming of unevaluated
  branches, collapsing of skipped `cond` branches into `…`,
  per-line annotation priority, evidence compaction for fact
  queries — into the trace producer. The producer emits a
  pre-decided `TraceNode` tree; renderers translate node shapes
  to bytes.
- Define a single renderer interface (`Layout` in trace
  terminology: per-node label, role, evidence, children) that
  both `transform.rs` (text) and `json.rs` (JSON) consume. The
  text renderer maps roles to colour/dimming/two-column
  placement; the JSON renderer maps roles to field names.
- Delete the public `Ann` enum and its variant-specific carriers
  (`CapturedValue`, `FactFailure` stay if needed internally;
  visibility narrows). `TraceEntry` continues to exist as the
  top-level trace stream, but its `Rule` variant carries a
  `TraceNode` tree, not `Doc<Option<Ann>>`.
- Renderers stop importing `may_i_core::pattern::{ArgPattern,
  CommandPattern, MatchMode, Quantifier}` for annotation
  purposes. The compile-time exhaustiveness check on
  `ArgPattern → Doc` (from the `traces` spec) moves into the
  trace producer.
- **BREAKING (internal)**: `Ann`, `TraceEntry::Rule { doc, … }`,
  and the `Doc<Option<Ann>>` type alias are removed from the
  CLI binary's surface. No external consumer; pre-1.0.
- **BREAKING (JSON)**: JSON trace field shapes MAY change where
  the current shape leaks pattern internals (e.g.
  `search_tokens` + `arg_set` arrays). The user-observable
  invariants in the `traces` spec (presence of `type`,
  `decision`, failure-reason fields; nested var breakout shape;
  unevaluated children marked `evaluated: false`) are preserved.

## Capabilities

### New Capabilities

_None._

### Modified Capabilities

- `output-rendering`: adds a requirement that `crate::output`'s
  trace renderers consume an opaque `TraceNode` tree and SHALL
  NOT pattern-match on engine-internal annotation variants. This
  pins the new seam so a future refactor doesn't quietly
  re-expose pattern internals at the rendering boundary.
- `traces`: modifies the existing "Ann enum covers all
  annotation kinds" requirement to talk about `TraceNode` roles
  rather than `Ann` variants; modifies "Trace producer records
  structural data, not display strings" to additionally
  prohibit the producer from exposing `ArgPattern`-shaped
  fields across the producer/renderer seam; modifies
  "ArgPattern display rendering is exhaustive" to relocate the
  exhaustiveness obligation from the renderer to the producer
  (the new seam is `ArgPattern → TraceNode`, and the renderer
  never sees `ArgPattern`); removes "Structural annotation
  placement via AnnotatedLineBuilder" and "Multiple annotations
  per line use priority ordering" because the producer
  pre-computes node placement and priority, leaving the
  renderer with no choice to make.

## Impact

- **Code (CLI binary):** `src/annotation.rs` rewritten;
  `src/output/transform.rs`, `src/output/render_rule.rs`,
  `src/output/json.rs`, `src/output/mod.rs` ported to the new
  `TraceNode` surface; `src/output/annotate.rs` likely
  collapses or shrinks substantially.
- **Engine / core crates:** unaffected. The producer continues
  to consume `may_i_engine::fold::EvalFold` and
  `may_i_core::pattern::ArgPattern`; only the *output* of the
  producer changes shape.
- **Snapshots:** insta snapshots under `tests/snapshots/` and
  `crates/may-i-output/src/snapshots/` re-baseline only where
  byte output legitimately changes (JSON shape; text output
  bytes SHOULD be unchanged where the spec preserves them).
- **External consumers:** none (pre-1.0, single workspace).
- **Build/CI:** `cargo build`, `cargo test`,
  `cargo tarpaulin`, and `prek` hooks all run unchanged.
