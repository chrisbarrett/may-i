## Why

Two defects make the human Trace misreport `fact?` queries. Both were found while
probing Fact behaviour for `explicit-fact-binder`; neither is caused by it, and
neither depends on it.

**The Trace prints a retired spelling.** A rule written `(fact? …)` renders as
`(has …)`. `has` was migrated away by `rename_has_to_fact`, so the Trace shows a
form the DSL no longer accepts — a reader copying it back into a config gets a
load error. This violates an existing requirement: the Trace "SHALL preserve the
written `fact?` query on the left" (`openspec/specs/traces/spec.md:352`).

**The Trace names the wrong witness.** A query against a Fact holding several
values reports an arbitrary member as the evidence. Querying
`[:o/all "a=1"]` against `:o/all` = `{"BAD", "a=1"}` renders `"BAD" → yes`,
naming a value that had nothing to do with the verdict. The existing requirement
is written entirely in terms of a *scalar* observed value and does not say what a
multi-member Fact should render — while `ContextFacts::get_scalar` defines a
scalar as a single-member set, and the renderer ignores that and takes the
set's first member.

The second is the more serious of the two: a Trace exists to explain a Decision,
and this one attributes it to the wrong evidence. `:via` is multi-member under
any nested Carrier, so it is reachable from ordinary configurations.

## What Changes

- **Render the query as written.** `(fact? …)` in the Trace, matching the source
  and the DSL. The JSON Trace surface is unaffected — it never emitted `has`.
- **Name the witness that decided the query.** On a match, the Trace SHALL report
  the Fact value that satisfied the query, not an arbitrary member.
- **Define multi-member rendering.** Extend the compact-evidence requirement,
  which currently only describes scalar Facts, to say what a Fact holding several
  values renders in each of the match and no-match cases.

Not in scope: the JSON Trace, which already emits the full observed set and needs
no witness selection; and any change to Fact storage or query semantics — the
Decision is correct in both defects, only its explanation is wrong.

## Capabilities

Bucket: **tracing-and-output**.

### New Capabilities

None.

### Modified Capabilities

- `traces`: extend "Human trace renders compact evidence for context fact
  queries" to cover multi-member Facts and to require the witness be the value
  that decided the query. The `fact?` spelling is already required by that same
  requirement and needs a scenario to lock it, not a new rule.

## Impact

**Code.** `src/annotation.rs:237` hardcodes `Doc::atom("has")` in
`fact_query_to_doc`, while `crates/core/src/ast.rs:439` renders `fact?`
correctly — the annotation producer overrides the AST's own spelling.
`src/output/render_rule.rs:116` selects the witness with
`observed.iter().next()`, taking the first member in `BTreeSet` order.

The witness is not currently recorded anywhere: `evaluate_fact_query` tests with
`set.iter().any(…)` (`crates/engine/src/eval/predicates.rs:303`) and discards
which member matched, so `Evidence::FactValues` (`src/trace/node.rs:66`) has no
witness field to render. Producing it means threading the matching value out of
evaluation into the evidence.

**Surfaces.** Human Trace only. `src/output/json.rs:219` emits `observed` in full
alongside `matched` and selects no witness.

**Tests.** `format_line_annotation_fact_query_with_observed`
(`src/output/render_rule.rs:248`) asserts the current single-member behaviour and
stays valid; multi-member cases are uncovered.

**Docs.** No REFERENCE.md surface change expected — the Trace format is
illustrated there, so examples showing `has` need checking.
