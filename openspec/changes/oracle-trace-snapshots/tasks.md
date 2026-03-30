## 1. Integration test harness

- [x] 1.1 Write `tests/oracle_trace_v1.rs` with a test-case loader that parses `tests/fixtures/v1/cases.toml` into (name, command, facts) tuples
- [x] 1.2 Implement output capture: call `may_i_config::load` + `evaluate_with_fold` + `print_trace` rendering into a `String` buffer with `COLUMNS=80` and `colored::control::set_override(true)`
- [x] 1.3 Implement config path normalisation — replace the `config: ...` line in both actual and expected output with `config: <config-path>`
- [x] 1.4 Implement stripped comparison: strip ANSI from captured output, compare against `.txt` snapshot, produce a clear diff on failure
- [x] 1.5 Implement raw comparison: compare captured output byte-for-byte against `.raw` snapshot, produce a clear diff on failure
- [x] 1.6 Verify the test harness compiles and runs (all 24 cases execute, failures are expected at this stage)

## 2. Expose rendering internals for testability

- [x] 2.1 Extract the trace + result rendering from `cmd_eval.rs` into a function that writes to `impl Write` instead of `println!` directly, so the test can capture output without subprocess spawning
- [x] 2.2 Ensure `output::print_trace` and the result footer can write to a buffer — may need `write!` variants alongside `println!`

## 3. Trace rendering improvements

- [x] 3.1 `rule_not_matched` fold method: show command-matching rules even when args/context fail
- [x] 3.2 `build_rule_doc_children`: decompose When/Unless wrapping terminals into (context) + (args) + (effect) siblings
- [x] 3.3 Forbidden pattern rendering: `(not (anywhere ...))` with correct inner annotation inversion
- [x] 3.4 `truncate_matched_anywhere`: truncate to first matching token for anywhere/forbidden patterns
- [x] 3.5 Per-token annotations for anywhere/forbidden: `"token" ∈ {args} → yes/no`
- [x] 3.6 Dynamic default ask reasons: "No rule for command" vs "Rules exist but did not match"
- [x] 3.7 Fix `evaluate_segments` reason propagation (>= instead of >)

## 4. Oracle snapshot parity

- [x] 4.1 Regenerate oracle snapshots from dev build (V2 semantics)
- [x] 4.2 All 24 stripped snapshot tests pass
- [x] 4.3 All 24 raw ANSI snapshot tests pass
- [x] 4.4 Fix prop test: `pure_fold_agrees_with_evaluate` uses flag expansion consistently
