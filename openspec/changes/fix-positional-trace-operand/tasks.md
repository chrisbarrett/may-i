# Tasks

- [x] 1. RED: assert a multi-element positional `(positional "source-file" (or
  "a" "b"))` against `["source-file", "b"]` annotates the `or` branches with
  `actual == "b"`.
- [x] 2. Engine: `match_positional_patterns` records a per-element trace
  (`ElementMatch { tested, consumed, matched }`) along its winning backtracking
  path; `build_positional_element_details` maps over it and emits `tested_arg`.
  Tests: `(* "a") "a"` vs `["a"]` records the required element tested at arg 0;
  a failed match records the prefix up to the failing element.
- [x] 3. Thread the detail to both fold paths: `EvalFold::predicate_arg` gains
  `Vec<PositionalElementDetail>`; the predicate evaluator builds it from the
  single match. Updated `PureFold`, `audit_fold` (×2), and test fold impls.
- [x] 4. Renderer: `annotate_positional_elements` annotates each element against
  its `tested_arg`; deleted `tested_args_for`, `extract_positional_args`, and
  `distribute_positional_at_top`. Effect + predicate paths share the pass.
- [x] 5. Tests: optional-skip cursor, backtracked `(* "a") "a"`, all-`One`
  proptest. Updated `traces` spec scenarios. Regenerated/audited
  `migrated_v1_trace` snapshots (no change from the committed correct values).
- [x] 6. `cargo fmt`, `cargo clippy`, `cargo test`, `openspec validate` clean.
