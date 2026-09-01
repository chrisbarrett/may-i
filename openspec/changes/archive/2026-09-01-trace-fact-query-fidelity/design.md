## Context

See `proposal.md` — Why. The mechanics both defects turn on, verified against
v0.12.0 (`cbf9dd8`):

`Evidence::FactValues { expected, observed, matched }` (`src/trace/node.rs:66`)
carries the rendered query source, the whole observed value set, and the verdict
— but not which member produced the verdict. It cannot, because
`evaluate_fact_query` tests with `set.iter().any(…)`
(`crates/engine/src/eval/predicates.rs:303`) and discards the match position.

The renderer therefore guesses: `observed.iter().next()`
(`src/output/render_rule.rs:116`) takes the first member in `BTreeSet` order,
which is lexicographic and unrelated to the query.

Separately, `fact_query_to_doc` (`src/annotation.rs:237`) builds the left column
as `Doc::atom("has")`, overriding `Predicate::to_doc`, which already renders
`fact?` (`crates/core/src/ast.rs:439`).

## Goals / Non-Goals

**Goals:**

- The Trace's left column shows what the author wrote and could paste back.
- The Trace's right column names evidence that actually decided the query.
- A rule that cannot be explained honestly renders a bare verdict rather than a
  misleading one.

**Non-Goals:**

- The JSON Trace. It emits the full observed set and picks no witness
  (`src/output/json.rs:219`), so it is already accurate. (Its `structure`
  field mirrors the human trace's Doc and shared the `has` spelling; the
  producer-side spelling fix corrects both surfaces at once. Verified
  byte-identical apart from that correction.)
- Fact storage, query semantics, or any Decision. Both defects are
  explanation-only; the Decisions are correct today.
- Rendering more than one witness when several members match. One suffices to
  explain a match, and the compact-annotation contract is a single line.

## Decisions

### Record the witness at evaluation, do not reconstruct it at render

`evaluate_fact_query` changes from `any` to a search that keeps the matching
member, and `Evidence::FactValues` gains a witness field the renderer consumes.

*Alternative — re-test at render time.* The renderer would need the pattern, but
`expected` is a rendered `String`, not a `FactPattern`. Threading the pattern AST
into the trace layer to re-run matching duplicates evaluation logic in the
renderer and risks the two disagreeing — which is the class of bug being fixed.

*Alternative — render the whole observed set.* Honest but defeats the compact
single-line annotation the requirement mandates, and reads poorly for `:via`
under deep Carrier nesting.

### Render a bare `no` for a multi-member mismatch

No single member explains a mismatch — every member failed — so naming one
implies a test that did not decide anything. This also follows the existing
requirement's own fallback ("`no` otherwise"), now that "scalar value available"
is pinned to `ContextFacts::get_scalar`'s single-member definition
(`crates/core/src/context.rs:46-51`).

*Alternative — keep showing an arbitrary member with `no`.* Rejected for the
same reason as the match case: it attributes the verdict to a value that did not
produce it.

### Fix the spelling at the producer, not the renderer

`fact_query_to_doc` should defer to the same rendering the AST already performs
rather than carrying its own copy of the surface syntax. The duplication is what
let the two drift across the `has` → `fact?` migration.

## Risks / Trade-offs

- **Snapshot churn** in trace tests that encode `has` → expected; the migration
  corpus under `crates/config/src/migrate/snapshots` is CST-level and should be
  unaffected, but needs checking.
- **Evidence gains a field, and `Evidence` is matched exhaustively in several
  renderers** (`src/output/render_rule.rs`, `src/output/json.rs`,
  `src/annotation.rs`) → compile errors will locate every site; no silent
  fallthrough.
- **A witness is arbitrary runtime text** — it can carry quotes, newlines, or
  great length → render it through the existing `render_observed_value`
  (`src/output/annotate.rs:9`), which already escapes and truncates at 40
  characters. No new display surface; the witness replaces the value that
  function is already given.

## Migration Plan

No user-config migration. The Trace is output, not input; no stored artefact
encodes the `has` spelling. Configurations that were written against the old
Trace output continue to evaluate identically.

Rollback is per-commit: the spelling fix and the witness fix are independent and
can land in either order.
