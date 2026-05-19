## Why

The trace renderer wraps every rule in `(command …)` / `(args …)` / `(context …)` synthetic shells and lifts `when` / `unless` predicates into a synthetic `(context …)` form. These shapes match the retired pre-redesign DSL, not the current surface syntax (where a rule is `(rule "X" <body>)` with the command as a string atom and body forms directly under the rule). The mismatch confuses users — the trace claims to show "their" rules but renders shapes that no longer exist in the language. The `(effect …)` half of this divergence was already fixed (traces/spec.md §"Trace decision verbs match source syntax"); the wrapper half remains.

## What Changes

- Render the trace rule node as `(rule <command-pattern> <body…>)` — drop the synthetic `(command …)`, `(args …)`, and `(context …)` wrappers in `build_rule_children`.
- Stop lifting `when` / `unless` predicates into a synthetic `(context …)` sibling. Render `(when <pred> <body>)` / `(unless <pred> <body>)` literally, the same shape the user wrote.
- Update the `traces` spec: reword the truncation requirement that currently keys off `(command (or …))` to key off the command-pattern alternation slot, and add a positive requirement that the rendered rule shape matches the source DSL shape (parallel to the existing decision-verb requirement).
- **BREAKING** (trace output): all migrated-v1 trace snapshots and any current-DSL trace snapshots that include rule headers will regenerate. Output is human-facing only — no programmatic consumers via the text channel. JSON trace output structure is unaffected (it already serialises the `Doc<Ann>` tree, not the synthetic wrappers).

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `traces`: requirements that pin the legacy `(command …)` / `(args …)` wrapper shape are removed; a new requirement pins the rendered rule shape to the current source DSL surface (command as string atom or `(or …)` pattern at the head, body forms directly under `(rule …)`). Truncation-of-long-or-list requirement is reworded to apply to the command-pattern slot regardless of wrapper.

## Impact

- Code: `src/annotation.rs` — `build_rule_children` (synthetic wrapper construction) and `extract_context_and_effect` (when/unless lift). Knock-on: any caller that pattern-matches on `head == "command"` / `head == "args"` / `head == "context"` (search `src/output/` and `src/trace/`).
- Specs: `openspec/specs/traces/spec.md` — delta in this change. No other stable spec references the wrappers as live output (the `migration-system` spec references them only as v1 inputs to migration, which is correct).
- Tests: snapshots under `tests/snapshots/migrated_v1_trace__*` (all migrated-v1 cases) and any `src/snapshots/may_i__cmd_eval__*` that include rule headers; insta review pass.
- No runtime, parsing, evaluation, or trust impact. Pre-1.0; no migration needed.
