## Why

The `may-i check` failure trace renders parts of the rule using stale or placeholder syntax that no longer matches what users wrote in source. This makes traces harder to scan and undermines the trace's job of pointing at the offending rule.

Three concrete divergences:
- `(tail (authorise))` renders as the literal placeholder `<unknown-arg-pattern>` because `arg_pattern_to_doc` has no arm for `ArgPattern::Tail`.
- `(parameter X (authorise))` renders as `(parameter X (may-i *))` — the pre-canonicalisation spelling.
- Terminal effects render as `(effect :ask "reason")` — the legacy `:effect` keyword form retired in favour of `(ask "reason")`/`(allow "reason")`/`(deny "reason")`.

Two adjacent annotation bugs make the same failures harder to read:
- `(tail (authorise))` annotates with the full argv on the right (`(authorise) ∈ {"exec", "true"} → yes`), implying a search across all arguments. The relevant value is the tail slice that gets recursed on.
- `(parameter X (authorise))` emits no arg-match annotation at all — the captured value never appears alongside the predicate; it only surfaces as an inner trace.

## What Changes

- Render `ArgPattern::Tail` as `(tail (authorise))` in the trace's annotated rule body.
- Render `ParameterForm::MayI` as `(authorise)` so `(parameter X (authorise))` round-trips its source spelling.
- Replace `arg_pattern_to_doc`'s `_ => Doc::atom("<unknown-arg-pattern>")` fallthrough with an exhaustive match over `ArgPattern` variants. A future variant SHALL produce a compile error rather than a placeholder. **BREAKING** for anyone forking the trace renderer (no external impact).
- Render terminal effects through `Effect::to_doc` so the trace shows `(ask "reason")`, `(allow "reason")`, `(deny "reason")` to match source syntax. The right-column decision annotation is unaffected.
- For `(tail (authorise))`, set the right-column annotation to `tail = "<whitespace-joined tail tokens>"` — e.g. `tail = "true"` for `direnv exec true`, `tail = "echo hi there"` for a multi-token tail. The full-argv `∈ { … }` form is replaced.
- For `(parameter NAME (authorise))`, emit an arg-match annotation carrying the captured value, rendered as `value = "<captured>"`. The inner trace still appears beneath, surfaced by the existing recursion plumbing.

## Capabilities

### New Capabilities
*(none)*

### Modified Capabilities
- `human-evaluation-trace`: trace renderer SHALL emit source-canonical syntax for `ArgPattern::Tail`, `ParameterForm::MayI`, and `Effect::Terminal`; SHALL annotate `(tail (authorise))` with the tail slice and `(parameter X (authorise))` with the captured value.

## Impact

- Affected code:
  - `src/annotation.rs`: `arg_pattern_to_doc` (Tail arm + exhaustive match), `effect_terminal` (route via `Effect::to_doc`).
  - `crates/engine/src/eval/effects.rs`: `evaluate_tail_authorise_fold` (pass tail slice + whitespace-joined string in `ArgMatchDetail`); `evaluate_parameter_fold`'s `ParameterForm::MayI` branch (emit arg-match before recursion with captured value).
  - `src/output/render_rule.rs`: render the new annotation shapes for tail and parameter-authorise.
- Affected output: text-mode `may-i check` failure traces and any other surface that consumes `TracingFold` output (currently only `cmd_check`).
- Snapshot tests under `crates/engine/src/test_generators/`, `src/snapshots/`, and `tests/check_integration.rs` will need updating.
- No API, config-syntax, or wire-format changes. JSON trace output gains the captured-value field for parameter-authorise but otherwise unchanged.
