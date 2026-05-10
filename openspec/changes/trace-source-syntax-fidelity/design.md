## Context

`TracingFold` (`src/annotation.rs`) builds an annotated `Doc` tree alongside evaluation, used by the human-readable trace renderer. Three call sites construct display Docs by hand instead of routing through the canonical `to_doc` pipeline, and they have drifted from source syntax over successive migrations:

- `arg_pattern_to_doc` (line 248-294) handles the common `ArgPattern` variants explicitly and falls through to `_ => Doc::atom("<unknown-arg-pattern>")`. `ArgPattern::Tail` (added with the wrapper-tail recursion feature) is unhandled and hits the fallthrough.
- `arg_pattern_to_doc`'s `ParameterForm::MayI` arm (line 286-288) renders `(may-i *)` — the pre-canonicalisation spelling. The current source syntax is `(authorise)`.
- `TracingFold::effect_terminal` (line 561-583) builds `[plain_atom("effect"), plain_atom(":ask"), …]` by hand. `Effect::to_doc` in `crates/core/src/ast.rs:996-1023` already produces the correct `(ask "reason")` form.

Two annotation issues compound the rendering bugs:

- `ArgPattern::Tail` evaluation in `crates/engine/src/eval/effects.rs:394-432` populates `ArgMatchDetail` with `arg_set: ctx.args.to_vec()` (full argv, not the tail slice) and `search_tokens: vec!["(authorise)"]`. The renderer then formats this as `(authorise) ∈ {full-argv} → yes`, which misrepresents the operation.
- `ArgPattern::Parameter` with `ParameterForm::MayI` (line 655-661) goes straight to `recurse_into_inner_command` without emitting an `effect_arg_match`. The captured value is invisible at the `(parameter …)` line — only the inner trace block reveals it.

## Goals / Non-Goals

**Goals:**
- Trace's annotated rule body uses source syntax: `(tail (authorise))`, `(parameter X (authorise))`, `(ask "…")`/`(allow "…")`/`(deny "…")`.
- Compiler enforces variant exhaustiveness on `ArgPattern` rendering — adding a future variant must produce a build error, not a placeholder.
- `(tail (authorise))` annotation shows the tail slice as a whitespace-joined quoted string: `tail = "echo hi there"`.
- `(parameter NAME (authorise))` annotation shows the captured value as a quoted string: `value = "echo hi there"`.

**Non-Goals:**
- No change to JSON trace structure beyond a new `captured_value` field on the parameter-authorise arg-match annotation.
- No change to `Effect::to_doc` or `ArgPattern::Tail` evaluation semantics — only the display path and `ArgMatchDetail` payload.
- No change to the inner-trace plumbing for either tail or parameter recursion.

## Decisions

### Exhaustive match on `ArgPattern`

Replace the `_ =>` fallthrough in `arg_pattern_to_doc` with explicit arms for every `ArgPattern` variant, including `Tail`. The `ArgPattern` enum is `#[non_exhaustive]` (`crates/core/src/pattern.rs:266`); inside this crate the compiler still enforces exhaustiveness, so a new variant added in `crates/core` will fail the workspace build until its display arm exists.

**Alternative considered**: keep the fallthrough, add a `Tail` arm above it. Rejected — the user wants compile-time guarantee that future variants get rendered correctly, not silent placeholders.

### Render terminal effects via `Effect::to_doc`

In `TracingFold::effect_terminal`, replace the hand-built `[plain_atom("effect"), plain_atom(":ask"), …]` construction with `unannotated_to_ann(effect.to_doc())`, then attach the `Ann::EffectDecision` annotation to the resulting Doc node. The terminal verb (`allow`/`ask`/`deny`) and reason already round-trip through `Effect::to_doc`.

The right-column annotation (`→ :allow "…"`) is produced separately by the renderer from the `EffectDecision` ann; that path is untouched. The colon-prefixed `:allow`/`:ask`/`:deny` only appear in the right column going forward, where they convey "decision keyword", consistent with `colorize_decision_keyword` usage elsewhere.

**Alternative considered**: leave `effect_terminal` as-is and only fix the `:effect` head atom. Rejected — the canonical form is `(allow "reason")`, not `(effect :allow "reason")`. Half-fixing leaves the wrapping `effect` atom in place.

### `(tail (authorise))` annotation: whitespace-joined tail slice

Modify `evaluate_tail_authorise_fold` to populate `ArgMatchDetail` with:
- `search_tokens: vec![]` (no longer `["(authorise)"]`)
- A new field carrying the captured tail slice value as one whitespace-joined string

Two implementation options for the new field:

**A. Reuse `ArgMatchDetail` with a new optional field**
Add `captured_value: Option<String>` to `ArgMatchDetail` (`crates/engine/src/eval/effects.rs`). Renderer prefers `captured_value` over the existing `search_tokens` / `arg_set` rendering when present.
- Pro: single carrier struct, minimal new types.
- Con: widens `ArgMatchDetail` for two callers (tail, parameter-authorise) — JSON shape gains an optional field.

**B. New `Ann` variant**
Introduce `Ann::AuthoriseValue { kind: AuthoriseKind, value: String }` distinct from `Ann::ArgMatch`. Tail and parameter-authorise emit this variant; renderer formats it as `<kind> = "<value>"` where kind is `tail` or `value`.
- Pro: cleaner separation, exhaustive match on `Ann` catches missing render arms.
- Con: more code; Ann surface area grows.

**Choosing A.** Both tail and parameter-authorise are still arg-match conceptually (the predicate matched something in argv); the captured-value field is just additional evidence on the same annotation. It also keeps the two new annotations symmetric, since both render in the same `value = "…"` style with only the label differing (`tail` vs `value`).

### `(parameter NAME (authorise))` emits arg-match before recursion

In `evaluate_parameter_fold`, before delegating to `recurse_into_inner_command`, emit an `effect_arg_match` carrying the captured `value` in `ArgMatchDetail::captured_value`. The recursion still runs and still produces its child trace. The new arg-match annotation lands on the `(parameter …)` rule line.

The renderer treats `(parameter X (authorise))` similarly to `(tail (authorise))`: when `captured_value` is present, format the right column as `value = "<captured>"`.

### Annotation labels

| Predicate                        | Right-column shape          |
|----------------------------------|-----------------------------|
| `(tail (authorise))`             | `tail = "echo hi there"`    |
| `(parameter X (authorise))`      | `value = "echo hi there"`   |

The whitespace-join uses literal space — no shell-quoting reconstruction. The intent is readability, not faithful round-trip; the inner trace shows the parsed command-line representation.

## Risks / Trade-offs

- [Snapshot churn] → Update insta snapshots and oracle traces under `crates/engine/src/test_generators/`, `src/snapshots/`, `tests/check_integration.rs`. Diff should show only the syntax-fidelity changes and the new annotation strings.
- [`#[non_exhaustive]` interaction] → Inside the defining crate's workspace, exhaustiveness is enforced; downstream consumers (none today) would still see the wildcard requirement. Acceptable.
- [JSON consumers see new `captured_value` field] → Optional field; existing consumers ignore unknown fields. Document in the trace-system spec.
- [Whitespace-joining loses shell-quote fidelity] → Acceptable per the user's request; the inner trace surfaces the parsed form.
