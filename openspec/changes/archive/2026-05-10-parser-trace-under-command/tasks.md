## 1. Failing tests for new layout

- [x] 1.1 Add a unit test in `src/output/mod.rs` (`tests` mod) that builds a trace containing a `TraceEntry::Parser` (style `gnu`, no parameters, no tail) and a subsequent rule entry, then asserts the rendered text places `parser │ gnu` immediately after the `command │ <cmd>` row with no blank line between them.
- [x] 1.2 Add a unit test for `TraceEntry::Parser` with non-empty `parameter_tokens` asserting the right column reads `gnu  parameters (-X --request)`.
- [x] 1.3 Add a unit test for `TraceEntry::Parser` with `tail = Some("(after :flags)")` asserting the right column reads `gnu  tail (after :flags)`.
- [x] 1.4 Add a unit test for `TraceEntry::Parser` with both parameters and tail asserting both segments appear in the right column.
- [x] 1.5 Add a regression unit test asserting no rendered row has the entire-width left-aligned `parser:` banner format.

## 2. Implementation

- [x] 2.1 In `src/output/mod.rs`, change the `TraceEntry::Parser` arm of `trace_to_layout` so it pushes a `ColRow::kv("parser", <value>)` instead of a right-aligned full-width row. Build `<value>` from `style`, optional ` parameters (...)`, and optional ` tail (...)`.
- [x] 2.2 Confirm the `TraceEntry::Parser` row is grouped into the same `current_rows` block as the `command` row so they render adjacent without an intervening flush. Adjust grouping logic if a flush boundary currently sits between them.
- [x] 2.3 Run the new unit tests added in step 1; verify they pass.

## 3. Snapshot + integration test updates

- [x] 3.1 Run `cargo test --workspace`. Identify all snapshot tests whose output captures the standalone `parser:` banner (likely under `src/snapshots/`, `crates/engine/src/test_generators/`, and `tests/check_integration.rs`).
- [x] 3.2 Re-run `cargo insta review` (or hand-edit non-insta snapshots) to accept the new layout for each affected snapshot.
- [x] 3.3 Spot-check at least one snapshot diff to confirm the only change is row position and the removal of the trailing blank line.

## 4. Manual verification

- [x] 4.1 Run `cargo run --quiet --bin may-i -- check --config /tmp/test_check.lisp` against a sample config that produces a failing check; confirm the rendered trace shows `parser │ gnu` directly under `command │ …`.
- [x] 4.2 Re-run with a config that exercises a parser declaring parameters (e.g. `curl -X` rule) and confirm the right column reads `gnu  parameters (-X --request)`.
- [x] 4.3 Re-run with a config that declares a wrapper-tail parser (e.g. the prelude `nix` parser) and confirm the right column includes the `tail (after …)` segment.

## 5. Coverage check

- [x] 5.1 Run `cargo tarpaulin` and inspect `lcov.info` for the modified arm in `src/output/mod.rs`; add targeted tests if any branch (e.g. the both-parameters-and-tail case) is uncovered.
