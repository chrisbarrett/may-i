## Context

Named predicates are defined via `(define name body)` in config and referenced
as `Predicate::Named(name)` in the AST. Today, `validate_and_resolve` in
`resolve.rs` inlines all Named references before evaluation — replacing them
with the define body. The evaluator treats `Predicate::Named` as an error
(`EvalError::UnresolvedPredicate`).

The fold trait already has a `predicate_named` callback that accepts a resolved
child, but it is never invoked in production — only exercised in test folds.

The annotation fold (`src/annotation.rs`) currently renders Named as a plain
atom followed by the resolved child doc, but this code path is also dead in
production.

## Goals / Non-Goals

**Goals:**

- `Predicate::Named` survives into the evaluator and is resolved at eval time
  via a binding environment
- Trace output preserves the user's define names and shows a breakout with the
  expanded body and its evaluation annotations
- All existing validation (duplicates, undefined refs, cycles) remains at load
  time
- The fold trait's existing `predicate_named` callback becomes the live
  integration point

**Non-Goals:**

- Provenance tracking on defines (deferred to load-trust change)
- Scoping or shadowing — the env is flat, matching current semantics
- Changes to the config parser or `Define` AST type
- Changes to the sexpr layer

## Decisions

### 1. Binding env on EvalContext

Add a `bindings: &'a [Define]` field (or a pre-built `HashMap<&'a str,
&'a Predicate>`) to `EvalContext`. Built once from `Config.defines` before
evaluation begins.

**Why:** `EvalContext` already carries all evaluation state (command, args,
facts, recursion depth). The env is read-only and shared across all rule
evaluations, so a reference to the config's defines list is sufficient.

**Alternative:** Pass the env as a separate parameter through evaluate calls.
Rejected — adds a parameter to every function in the eval chain for no benefit.

### 2. Resolve Named in evaluate_predicate_fold

Replace the `Predicate::Named` error arm in `evaluate_predicate_fold` with:
look up the name in `ctx.bindings`, evaluate the body recursively, wrap the
result with `fold.predicate_named(name, child_out, result)`.

**Why:** This is the minimal change. The fold callback already exists and has
the right signature. `PureFold` already passes through the result. The
annotation fold already has a partial implementation.

**Alternative:** A separate resolution pass that wraps Named nodes. Rejected —
unnecessary indirection when the evaluator can resolve directly.

### 3. Remove inlining from validate_and_resolve

`validate_and_resolve` currently returns `Vec<Rule>` with all predicates
inlined. Change it to return validated-but-unresolved rules. The return type
stays the same — callers receive the original rules with `Named` references
intact.

**Why:** The inlining step (`resolve_predicates`) is the one being replaced by
runtime resolution. Validation (steps 1-3 of the pipeline) is unchanged.

**Impact:** Callers that previously received inlined rules now receive rules
with Named references. This is safe because the evaluator will resolve them.
Tests that assert on specific inlined predicate shapes will need updating.

### 4. Trace breakout for var references

When the annotation fold hits `predicate_named`, it produces a doc node that:

1. Shows the define name as a token at the point of use (in the rule's doc tree)
2. Includes the child predicate's annotated doc as a nested sub-tree

The output renderer displays the name inline in the rule trace and renders the
child doc as a visually distinct "breakout" section — indented and labelled with
the define name.

In JSON output, the annotation becomes a node with `type: "var_ref"`, `name`,
`matched`, and a `body` array containing the child annotations.

**Why:** Users need to see both the name they wrote (for orientation) and the
expanded body (for debugging). The breakout mirrors how `may-i` already renders
inner commands in `(may-i ...)` traces — a nested section with its own
annotation column.

## Risks / Trade-offs

- **[Risk] Existing test breakage** — Tests in `resolve.rs` assert on inlined
  predicate structure. These need updating to assert on Named references
  instead. The validation tests are unaffected. Mitigation: update tests as part
  of the inlining removal task.
- **[Risk] Performance** — HashMap lookup per Named reference vs zero-cost
  inlined predicates. Mitigation: negligible for config-sized workloads (tens of
  defines, not millions). No action needed.
- **[Trade-off] Annotation fold complexity** — The breakout rendering adds
  complexity to the output layer. Accepted because it directly improves the user
  experience and mirrors the existing `may-i` inner-command pattern.
