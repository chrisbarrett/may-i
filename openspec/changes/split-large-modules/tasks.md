## 1. Split pp crate

- [x] 1.1 Create `crates/pp/src/output.rs` with `PrettyOutput` trait and `OutputEvent` enum; add `mod output` to `lib.rs`
- [x] 1.2 Create `crates/pp/src/buffer.rs` with `StringBuilder`, `EventBuffer`, `AnnotatedLine`, `AnnotatedLineBuilder` and their impls; add `mod buffer`
- [x] 1.3 Create `crates/pp/src/color.rs` with `colorize_atom` and `visible_len`; add `mod color`
- [x] 1.4 Create `crates/pp/src/render.rs` with `pretty`, `pretty_into`, `line_prefix_width` and all rendering logic (lines ~700–1466); add `mod render`
- [x] 1.5 Update `lib.rs` to re-export all public symbols from submodules; remove moved code
- [x] 1.6 Extract `#[cfg(test)]` blocks from the original `lib.rs` into test files under the appropriate submodules
- [x] 1.7 Run `cargo test -p may-i-pp` and `cargo check` — verify all pass, no file exceeds 600 prod / 1200 test lines

## 2. Split engine eval module

- [x] 2.1 Create `crates/engine/src/eval/` directory; move `eval.rs` to `eval/mod.rs`
- [x] 2.2 Extract `context.rs` with `EvalContext`, `PredicateResult`, `DEFAULT_RECURSION_LIMIT`
- [x] 2.3 Extract `predicates.rs` with `evaluate_predicate` and `evaluate_predicate_fold`
- [x] 2.4 Extract `positional.rs` with `match_positional_patterns` and surrounding pattern-matching logic
- [x] 2.5 Extract `effects.rs` with `evaluate_effect` and `evaluate_effect_fold`
- [x] 2.6 Extract `entry.rs` with `evaluate`, `evaluate_with_fold`, `expand_combined_flags`, `positional_args`, `Evaluator`
- [x] 2.7 Update `mod.rs` to re-export all previously-public symbols; fix `use` paths in the rest of the engine crate
- [x] 2.8 Extract `#[cfg(test)]` blocks into test files under `eval/tests/`
- [x] 2.9 Run `cargo test -p may-i-engine` and `cargo check` — verify all pass, no file exceeds limits

## 3. Extract test_generators test modules

- [x] 3.1 Identify each `#[cfg(test)]` module in `test_generators.rs` and its line ranges
- [x] 3.2 Move each test module to a separate file (e.g. `tests/predicate_properties.rs`, `tests/eval_properties.rs`, etc.) and wire with `mod` declarations
- [x] 3.3 Trim `test_generators.rs` to generators only; verify it is under 600 lines
- [x] 3.4 Run `cargo test -p may-i-engine` — verify all property tests pass
