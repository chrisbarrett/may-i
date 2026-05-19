## 1. Audit current wrapper coupling

- [x] 1.1 `rg '"command"|"args"|"context"' src/annotation.rs src/output/ src/trace/` and list call sites that branch on these head labels. Outcome: a checklist of code paths that must be updated or removed.
- [x] 1.2 Confirm JSON trace path (`src/output/json.rs`) does not depend on the synthetic wrappers — read `trace_to_json` and walk its `TraceNode` traversal. Note finding in design.md if anything is unexpected.

## 2. Drop synthetic wrappers in the producer

- [x] 2.1 Rewrite `build_rule_children` in `src/annotation.rs` to emit `(rule <command-pattern-node> <body-node…>)` directly: drop the `plain_atom("command")` wrapping, drop the `(args …)` shell, drop the call to `extract_context_and_effect`. Keep the terminal-decision-as-direct-child path as the only path.
- [x] 2.2 Delete `extract_context_and_effect` (no other callers — confirm via grep).
- [x] 2.3 Update any call sites surfaced in 1.1 — remove pattern matches on `"command"` / `"args"` / `"context"` head labels. Delete dead branches.
- [x] 2.4 `cargo build` clean; `cargo clippy --workspace --all-targets`.

## 3. Update the traces spec

- [x] 3.1 Apply the delta at `openspec/changes/trace-faithful-rule-shape/specs/traces/spec.md` — MODIFIED "Long or-lists are truncated with elision", MODIFIED "Trace producer records structural data…", ADDED "Trace rule shape matches source DSL surface".
- [x] 3.2 `openspec validate trace-faithful-rule-shape` — both heading matches and scenario counts pass.

## 4. Regenerate snapshots

- [x] 4.1 `cargo insta test --workspace --review` — walk through the first 3 `migrated_v1_trace__*` cases manually, confirm the new shape matches the user's source form (no `(command …)` / `(args …)` / `(context …)`).
- [x] 4.2 Accept the remaining snapshot diffs (`cargo insta accept`).
- [x] 4.3 `rg '\(rule \(command|\(args \(|\(context ' tests/snapshots/ src/snapshots/` — should match only snapshot files that explicitly assert v1 input shape (e.g. `migration-system`-tagged tests). Any other match indicates a missed wrapper site or a leftover snapshot — investigate.

## 5. Add a regression test for the rule shape

- [x] 5.1 Add an integration test that evaluates a fixture containing `(rule "X" (when <pred> <body>))` and `(rule (or "a" "b") (allow))`, captures the trace output, and asserts that the output contains `(rule "X" (when ` and `(rule (or "a" "b")` and does NOT contain `(command "X")`, `(args `, or a synthetic `(context (` lift. Location: alongside `tests/migrated_v1_trace.rs` or a new `tests/trace_rule_shape.rs`.
- [x] 5.2 Run only this test (`cargo test --test trace_rule_shape`) and confirm green.

## 6. Verification

- [x] 6.1 `cargo test --workspace` green; `cargo fmt`; `cargo clippy --workspace --all-targets -- -D warnings`.
- [x] 6.2 Eyeball one real trace via `cargo run -- eval 'rm -rf /'` against the starter config — confirm the rendered shape matches the source `(rule "rm" (if (and …) (deny …)))`.
- [x] 6.3 `openspec validate trace-faithful-rule-shape --strict`.
