## Context

The canonicaliser (`crates/config/src/canonicalise.rs`) dispatches body
forms to per-head sort routines. `(check …)` currently routes to
`sort_check_body`, which alphabetises cases by their first string
literal. Trivia (comments, blank lines) is attached to neighbouring
forms during CST construction and is moved alongside whichever form it
attaches to, so sorting cases re-locates their nearby comments — section
headers end up beside the wrong cases.

Trust-hash construction (`crates/engine/src/trust.rs:122`,
`canonical_rule`) explicitly omits `(check …)` from the hashed
representation; the `canonical_rule_excludes_checks` test pins this.
Check-case order has therefore never participated in trust
determinism — sorting them was a pure formatter convention.

CONTEXT.md (§ Canonical-form ordering) now states the principle that
governs this change: sort a body form only when it is **both**
engine-order-independent **and** not human-curated. `(check …)` fails
the second test (cases carry user-authored section comments) even
though it passes the first (cases are independent assertions).

## Goals / Non-Goals

**Goals:**
- Stop `may-i fmt` from reordering `(check …)` cases.
- Keep all other canonicaliser behaviour unchanged — parser bodies,
  `define-arg-style` plists, flag/parameter name vectors continue to
  sort.
- Keep the pretty-printer's whitespace and indentation normalisation
  for check forms.
- Update the `pretty-printing` spec so the new behaviour is the
  authoritative requirement.

**Non-Goals:**
- No migration tool to un-scramble check cases in configs that were
  already alphabetised by previous `fmt` runs.
- No change to trust hashing (already excludes checks).
- No change to how `may-i check` executes test cases.
- No change to the legacy plist-form `check` fallback (the
  `fmt-command` spec's "legacy syntax" path is unrelated and stays
  pretty-print-only).

## Decisions

**Drop the dispatch arm, delete the dead sort routine.** Removing
`Some("check") => sort_check_body` from the match in
`canonicalise_node` is sufficient: recursion still walks each
child via `children.into_iter().map(canonicalise_node).collect()`,
so nested forms inside check cases (`with-facts`, decision verbs)
continue to receive canonical treatment. The `sort_check_body`
function and its helper `check_case_sort_key` then have no callers
and can be removed entirely. Keeping them as dead code would be
misleading.

Alternative considered: leave `sort_check_body` as a callable
function with the sort step removed but recursion preserved. Rejected
— recursion already happens before the match arm runs, so the
function would do nothing.

**Keep the idempotence proptest.** `canonicalise_is_idempotent_on_check`
becomes vacuous (any function is idempotent if it's the identity), but
the test still guards against a future regression that reintroduces
sorting or any other non-idempotent rewrite to check bodies. Cost is
near zero; signal is non-trivial.

Alternative considered: delete the proptest along with the sort.
Rejected — the property is cheap to keep and protects against the
exact regression this change is fixing.

**Invert the existing unit test.** `check_cases_alphabetised_by_command`
currently asserts the sort. The test is renamed to
`check_cases_preserve_source_order` and rewritten to assert that an
out-of-order input renders unchanged. The test stays in the same
module — it documents the same canonicaliser contract, just with the
new behaviour.

**Migration: no tool.** Configs that were previously alphabetised by
`fmt` will not auto-rearrange. Users who care about section comments
re-cluster cases manually once, and `fmt` thereafter preserves their
order. A regrouper tool would have to either prompt per case or guess
from header text — both produce surprising results, and the bug
(scrambling) is fixed without one.

## Risks / Trade-offs

- **Two configs differing only in check-case order now diff visibly
  under `fmt`** → acceptable: check cases are a sequence of test
  assertions, and authored grouping is the property the user actually
  wants preserved. The "canonical form is unique per semantic content"
  property already does not hold for `(check …)` — duplicate cases
  with different reasons, or `with-facts` permutations, are all
  observably distinct.
- **`sort_check_body` helper removal is a minor public-surface
  reduction inside `crates/config`** → safe: the symbol is
  `pub(crate)`-scoped via its module being non-public, no external
  consumer.
- **CONTEXT.md and REFERENCE.md drift from code if the spec delta
  ships but the code change doesn't** → mitigated by bundling the
  spec, code, and docs changes in the same change set (see tasks.md).
