## Context

The trace renderer in `src/annotation.rs:657-705` (`build_rule_children`) synthesises a fixed three-shell shape around every rule:

```
(rule
  (command <pattern>)         ← synthetic
  [(context <pred>)]          ← synthetic; lifted from when/unless predicate
  [(args <body>)]             ← synthetic
  [<terminal-decision>])
```

The `extract_context_and_effect` helper (L707) pulls the predicate out of a top-level `when`/`unless` into the synthetic `(context …)` sibling, and moves the body up next to it. These wrappers correspond to the v1 DSL surface that was retired in the redesign that introduced bare command-name atoms and `(allow)/(ask)/(deny)` decision verbs (see `parser-bindings/spec.md:11`).

Current surface DSL (per `crates/config/src/starter_config.lisp`, `examples/`, and `rule-decisions` spec) is:

```
(rule "X" <body…>)
(rule (or "X" "Y" …) <body…>)
```

Body forms (`when`, `unless`, `if`, `cond`, `and`/`or`/`not`, predicate atoms, terminal verbs) sit directly under the `(rule …)` list with no shell.

The decision-verb half of this divergence was fixed previously (see `traces/spec.md` §"Trace renders terminal effects using `(allow|ask|deny "reason"?)` form" — L373). The wrapper half was not.

## Goals / Non-Goals

**Goals:**

- Trace output for a rule reproduces the *shape* the user wrote (modulo annotations and pretty-print breaks).
- Eliminate `(command …)` / `(args …)` / `(context …)` synthetic wrappers from rendered output.
- Stop the `when`/`unless` → `(context …)` lift.
- Bring `traces/spec.md` requirements in line with current DSL surface.

**Non-Goals:**

- Changing JSON trace output structure. JSON serialises the structural `Doc<Ann>` tree, which never contained these synthetic wrappers — only the text renderer constructs them. Verify the JSON path doesn't depend on them, but don't redesign the JSON shape here.
- Changing the column geometry / two-column layout / annotation placement logic.
- Touching the `migration-system` spec's references to v1 `(command …)`/`(args …)`/`(context …)` — those describe v1 *inputs* to migration, not live output, and remain correct.
- Adding new functionality to traces (var breakouts, evidence display, dimming, etc. all unchanged).

## Decisions

### D1: Drop wrappers in the producer, not the renderer

`build_rule_children` lives in the trace producer (`src/annotation.rs`), not the renderer. The `traces` spec assigns *structural layout decisions* to the producer (L428-434); the wrappers are exactly such a decision. So the fix lands in the producer: emit a `TraceNode` for the rule whose children are `[<command-pattern-node>, <body-node…>]` directly. The renderer is unchanged.

**Alternative considered:** synthesise the wrappers in the producer but strip them in the renderer. Rejected — strip-on-output is the wrong direction (producer already records what the renderer should print, per `traces/spec.md` L428) and adds renderer complexity.

### D2: `when`/`unless` predicates stay in place

Today's `extract_context_and_effect` (L707) lifts the predicate of a top-level `when`/`unless` into a synthetic `(context …)` sibling because rendering `(when <pred> <body>)` as one form makes the per-line annotation placement awkward — the predicate's match annotations sit on its lines, the body's decision annotation sits on a later line, and the whole thing reads top-to-bottom. The lift produced two visually separate blocks, which read more naturally in v1 output.

**Decision:** drop the lift. The annotations still attach to the lines they describe (predicate match annotations on the predicate's lines, body decision on the body's line) — the two-column layout already handles multi-line forms. The single-form `(when …)` rendering is closer to source. Per `traces/spec.md` (existing requirement at L428), the producer owns structural layout decisions, including this one.

**Alternative considered:** keep the lift but rename the synthetic head to something non-colliding (e.g. `(predicate …)`). Rejected — still synthetic, still divergent from source, still confusing.

### D3: Renderer call sites that pattern-match on the wrapper heads

Any code in `src/output/` or `src/trace/` that branches on `head == "command"` / `head == "args"` / `head == "context"` must be updated or removed. The seam exposes `TraceNode` accessors (per `traces/spec.md` L436) — pattern matching by head string is brittle but does occur (e.g. `annotate_positional_elements` in `src/annotation.rs` matches on `"positional"`/`"exact"`, which is fine — those heads survive). Audit pass:

```
rg '"command"|"args"|"context"' src/output/ src/trace/ src/annotation.rs
```

Treat each hit individually. Anything pattern-matching on the wrapper heads is dead with this change.

### D4: Snapshot regeneration strategy

All `migrated_v1_trace__*` stripped + raw snapshots regenerate. Strategy: `cargo insta test --review` after the code change, manually inspect the diff for the first few cases to verify the new shape is sane, then `cargo insta accept` the batch. Re-grep for any remaining `(rule (command` / `(args ` / `(context ` strings in snapshot files post-accept — should be zero outside of `migration-system`-tagged tests that explicitly assert v1 input shape.

### D5: Spec edits

Two MODIFIED requirements in `traces/spec.md`:

1. **"Long or-lists are truncated with elision"** — reword to key off the rule head's command-pattern slot rather than `(command (or …))`.
2. **"Trace producer records structural data, …"** — its `(command (or …))` scenario reworded to refer to the rule's command-pattern.

One ADDED requirement: **"Trace rule shape matches source DSL surface"** — parallels the existing L373 decision-verb requirement. Scenarios cover literal command, or-alternation, `when` body, `unless` body, and terminal-under-rule.

## Risks / Trade-offs

- **Visual density** — the synthetic `(context …)` sibling visually separates predicate from body. Dropping it means predicates and bodies share the `(when …)` form's nesting level. → Mitigation: the pretty-printer already breaks `(when <pred> <body>)` across lines for non-trivial predicates (see `pretty-printing` spec); the resulting shape is what `cargo expand` of the source produces and matches user expectation.
- **Annotation placement on `when`** — the right-column annotation for the body's decision sits on the body's line, which is now nested one level deeper inside the `(when …)`. The renderer's annotation-on-line logic is line-based, not form-based; verify by visual inspection of the regenerated snapshots that decision arrows still land on the right line.
- **Hidden coupling in `src/output/`** — pattern-matching on the wrapper heads. Audit pass mandatory (D3). → Mitigation: covered by snapshot tests; anything that breaks shows up as a snapshot diff or a rendering regression.
- **Spec divergence at archive time** — the `MODIFIED` requirement copies must match heading text exactly. → Mitigation: openspec validator catches mismatch; run `openspec validate trace-faithful-rule-shape` before declaring tasks done.

## Migration Plan

Pre-1.0; no user migration. Snapshot diff is the only externally observable change.
