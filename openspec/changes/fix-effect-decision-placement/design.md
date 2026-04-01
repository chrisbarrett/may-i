## Context

The `declarative-rendering-pipeline` change introduced `PrettyOutput<A>` trait,
`AnnotatedLineBuilder`, and `distribute_arg_annotations` (Phases 2–5), but Phase
6 integration stalled because `AnnotatedLineBuilder` captures annotations from
dimmed (unevaluated) branches, producing duplicates and wrong placements for
`EffectDecision` annotations.

Currently `render_annotated_rule` uses:
1. `pretty()` → string output
2. `collect_annotations()` → `Vec<(needle, right_text)>` from tree walk
3. `find_line()` → sequential string search to place annotations on rendered lines
4. `extract_outcome()` → separate EffectDecision extraction with `(effect` string match

The `find_line` approach is fragile (depends on string matching and sequential
ordering) but accidentally handles dimmed branches correctly because
`collect_annotations` generates `(needle, text)` pairs where the needle is a
rendered text fragment — dimmed and non-dimmed branches produce the same needles,
and sequential search happens to place them on the right lines.

## Goals / Non-Goals

**Goals:**
- Replace `find_line` pipeline with `AnnotatedLineBuilder` for structural
  annotation placement
- Suppress annotations from dimmed nodes so unevaluated branches don't produce
  right-column text
- Maintain byte-identical oracle snapshot output
- Remove dead code (`find_line`, `collect_annotations`, `node_text`)

**Non-Goals:**
- Changing the tracing fold's annotation placement (EffectDecision stays on
  `(effect ...)` list nodes)
- Changing any user-visible output format
- Modifying JSON trace output

## Decisions

### 1. Suppress `emit_node_ann` for dimmed nodes

`render()` in the pp crate calls `emit_node_ann(&doc.ann)` for every non-empty
List/Vector. Gate this on `!dimmed`:

```rust
if !dimmed {
    out.emit_node_ann(&doc.ann);
}
```

**Rationale**: Dimmed nodes represent unevaluated branches. Their annotations
(e.g. static `EffectDecision` from `effect_to_static_ann_doc`) should not appear
in the right column. The current pipeline achieves this implicitly; the
structural approach needs it explicit.

**Alternative**: Filter dimmed annotations in `format_line_annotation`. Rejected
because `AnnotatedLineBuilder` doesn't track dimmed state per annotation — it
only receives `A` values via `emit_node_ann`/`emit_atom`. Adding dimmed tracking
to the annotation type would complicate the generic `PrettyOutput<A>` trait.

### 2. Also suppress `emit_atom` annotations for dimmed atoms

Similarly, `emit_atom(text, ann, dimmed)` already receives the dimmed flag. The
`AnnotatedLineBuilder` should only collect annotations where `!dimmed`:

```rust
fn emit_atom(&mut self, text: &str, ann: &A, dimmed: bool) {
    // ... append text ...
    if !dimmed {
        self.current_annotations.push(ann.clone());
    }
}
```

### 3. `format_line_annotation` maps `Vec<Ann>` → right-column text

A new function takes all annotations for a line and produces the right-column
string (or empty). Priority order:

1. `EffectDecision` → `"→ :keyword"` or `"→ :keyword \"reason\""`
2. `MayI` → `` "`cmd` → :keyword"``
3. `BindMatch` → `"facts += :key \"value\""`
4. `RegexMatch` → `"\"actual\" ~ (regex \"pattern\") → yes/no"`
5. `FactQuery` → observed value + verdict
6. `CommandMatch { matched: false }` → `"no"`
7. `ArgMatch` (per-token from `distribute_arg_annotations`) → `"token" ∈ {set} → yes/no`
8. `PositionalMatch` → `"actual" = "pattern" → yes/no`

When multiple annotations exist on one line, show the highest-priority one. This
replaces both `collect_annotations` and `format_annotation`.

### 4. Keep `extract_outcome` + `(effect` placement as fallback

The existing `extract_outcome` logic that finds `EffectDecision` on top-level
children and places it on lines containing `(effect` handles the case where the
`AnnotatedLineBuilder` line for an `EffectDecision` doesn't match the
`(effect` opening line (e.g., if the annotation is captured on a different line
due to flat layout). Run this only when `AnnotatedLineBuilder` didn't already
place the decision.

**Rationale**: Belt-and-suspenders approach for the trickiest annotation. Can be
removed once structural placement is verified across all oracle cases.

## Risks / Trade-offs

- **[Risk] Dimmed suppression changes annotation count** → Mitigated by oracle
  snapshot tests catching any output difference.
- **[Risk] Multiple annotations per line** → `format_line_annotation` uses
  priority ordering; only one annotation shown per line (matching current
  behavior).
- **[Risk] `distribute_arg_annotations` changes tree structure** → It clears
  parent annotations and adds per-child annotations, so the overall annotation
  count changes. Tests verify per-token annotations render identically.
