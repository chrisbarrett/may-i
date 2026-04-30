## 1. Snapshot existing CLI output

- [ ] 1.1 Capture stdout for representative `cmd_eval` inputs covering single command, `&&`/`;`/`|`, embedded `$(...)`, dynamic `$EDITOR`, malformed input. Commit fixtures under `tests/fixtures/segment_decisions/` for byte-equality replay.

## 2. Engine API additions

- [ ] 2.1 Add `SegmentDecision { start, end, decision }` to `crates/engine/src/lib.rs`.
- [ ] 2.2 Add `segment_decisions: Vec<SegmentDecision>` to `EvalResult`; default empty in `EvalResult::new`.
- [ ] 2.3 Add `span: (usize, usize)` (or `may_i_core::Span`) to each `EvalUnit` variant in `crates/engine/src/eval/decompose.rs`.
- [ ] 2.4 Update `decompose()` to emit byte-ranges referencing the outermost original input (track an offset when stepping into embedded sources).

## 3. Populate segment decisions

- [ ] 3.1 In `evaluate_command_inner`, push a `SegmentDecision` per unit using its span and the decision returned from `evaluate_with_fold` / inner recursion.
- [ ] 3.2 Ensure the recursion-depth, parse-error, and empty-input paths still return well-formed `segment_decisions` (empty or single placeholder per spec).
- [ ] 3.3 Verify nested embedded commands produce both an outer top-level entry and inner entries; ranges of inner entries are fully contained in their parent's range.

## 4. Engine tests

- [ ] 4.1 Unit tests in `command.rs` for each scenario in the spec (single command, compound `&&`, embedded `$(...)`, `$EDITOR`, empty input).
- [ ] 4.2 Property test: top-level (non-contained) segment ranges are pairwise disjoint.
- [ ] 4.3 Property test: aggregate `decision` equals the strictest decision across all top-level `segment_decisions`.

## 5. CLI display refactor

- [ ] 5.1 Rewrite `cmd_eval::colorize_segments` to consume `result.segment_decisions` directly. Filter to top-level entries (those not contained in another) so the rendered string stays at parser-segment granularity.
- [ ] 5.2 Delete the per-segment `engine::eval::evaluate_command` call.
- [ ] 5.3 Verify `evaluate_with_colorization` still returns `(EvalResult, Vec<TraceEntry>, String)` with no behaviour change for the trace path.

## 6. Verify

- [ ] 6.1 `cargo fmt`, `cargo clippy --all-targets`.
- [ ] 6.2 Full test suite + `cargo tarpaulin`; no coverage regression for the engine.
- [ ] 6.3 Replay step-1 snapshots: confirm byte-equal CLI output across all inputs.
- [ ] 6.4 Confirm hook-mode and JSON-mode output unaffected (those modes ignore `segment_decisions`).
