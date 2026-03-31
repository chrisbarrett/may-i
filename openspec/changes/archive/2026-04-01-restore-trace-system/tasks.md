## 1. Clean up EvalResult and delete old trace types

- [x] 1.1 Remove `trace` field from `EvalResult` in `crates/engine/src/lib.rs`
- [x] 1.2 Remove `trace` field from `CheckResult` in `crates/engine/src/check.rs`
- [x] 1.3 Delete `crates/engine/src/trace.rs` and remove `pub mod trace` from `lib.rs`
- [x] 1.4 Fix all compilation errors from removed trace types (eval.rs references, TraceBuilder export, etc.)

## 2. Define EvalFold trait and ChildResult

- [x] 2.1 Create `crates/engine/src/fold.rs` with `EvalFold` trait, `ChildResult` enum, and detail types (`ArgMatchDetail`, `FactDetail`)
- [x] 2.2 Implement `PureFold` (EffectOut = EffectResult, PredicateOut = PredicateResult) with trivial pass-through methods

## 3. Parameterise evaluator over EvalFold

- [x] 3.1 Make `evaluate_effect` generic over `F: EvalFold`, calling fold methods at each Effect node and passing detail data
- [x] 3.2 Make `evaluate_predicate` generic over `F: EvalFold`, calling fold methods at each Predicate node with FactDetail
- [x] 3.3 Make `Evaluator::evaluate` and `evaluate_rule_with_trace` generic over `F: EvalFold`, calling rule-level fold methods
- [x] 3.4 Update top-level `evaluate()` function to use PureFold by default, add `evaluate_with_fold()` that accepts a fold
- [x] 3.5 Verify all existing engine tests pass with PureFold (no behaviour change)

## 4. Define Ann enum and TracingFold

- [x] 4.1 Create `src/annotation.rs` with `Ann` enum covering all annotation kinds (command match, arg match, fact query, effect decision, quantifier)
- [x] 4.2 Implement `TracingFold` struct with `EvalFold` impl producing `(EffectResult, Doc<Option<Ann>>)` and `(PredicateResult, Doc<Option<Ann>>)`
- [x] 4.3 Implement Doc construction for each effect fold method (building s-expression tree with annotations)
- [x] 4.4 Implement Doc construction for each predicate fold method (fact evidence, arg match evidence)
- [x] 4.5 Handle short-circuited children (set `dimmed = true` on skipped nodes)

## 5. Recover and adapt renderer

- [x] 5.1 Recover `output.rs` from v0.0.3 git history into `src/output.rs`
- [x] 5.2 Replace `EvalAnn` references with new `Ann` enum throughout
- [x] 5.3 Replace old `TraceEntry` references with new structure (Doc<Option<Ann>> + line number)
- [x] 5.4 Adapt `format_annotation` to handle all `Ann` variants for right-column rendering
- [x] 5.5 Adapt `trace_to_json` and `collect_json_annotations` for new Ann types
- [x] 5.6 Verify two-column layout, truncation, elision, dimming, and colorisation work

## 6. Restore cmd_eval

- [x] 6.1 Rewrite `src/cmd_eval.rs` to use `TracingFold` via `evaluate_with_fold`
- [x] 6.2 Restore per-segment evaluation for compound commands with colorised output
- [x] 6.3 Restore trace section printing (rule traces with two-column annotations)
- [x] 6.4 Restore result section (colorised command, decision arrow, config path)
- [x] 6.5 Restore JSON mode with trace array from Doc<Ann> serialisation

## 7. Restore cmd_check

- [x] 7.1 Update check runner to use `TracingFold` when invoked from CLI (for trace-on-failure)
- [x] 7.2 Restore verbose mode listing all checks with PASS/FAIL status
- [x] 7.3 Restore failure detail output (location, expected/actual, context, trace)
- [x] 7.4 Restore summary line (✓ N passed, M failed)
- [x] 7.5 Restore JSON mode with structured results including traces

## 8. Integration testing

- [x] 8.1 Test `may-i eval` against the user's real config and compare trace output quality with v0.0.3
- [x] 8.2 Test `may-i check` against the user's real config and verify all checks pass
- [x] 8.3 Test compound command tracing (e.g., `echo hello && rm -rf /`)
- [x] 8.4 Test fact-aware tracing (e.g., `--fact ':opencode/agent=build' 'rm -r /tmp/foo'`)
- [x] 8.5 Test JSON output mode for both eval and check
