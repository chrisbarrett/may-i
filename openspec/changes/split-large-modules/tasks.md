## 1. Split pp crate

- [ ] 1.1 Create `crates/pp/src/output.rs` with `PrettyOutput` trait and `OutputEvent` enum; add `mod output` to `lib.rs`
- [ ] 1.2 Create `crates/pp/src/buffer.rs` with `StringBuilder`, `EventBuffer`, `AnnotatedLine`, `AnnotatedLineBuilder` and their impls; add `mod buffer`
- [ ] 1.3 Create `crates/pp/src/color.rs` with `colorize_atom` and `visible_len`; add `mod color`
- [ ] 1.4 Create `crates/pp/src/render.rs` with `pretty`, `pretty_into`, `line_prefix_width` and all rendering logic (lines ~700–1466); add `mod render`
- [ ] 1.5 Update `lib.rs` to re-export all public symbols from submodules; remove moved code
- [ ] 1.6 Extract `#[cfg(test)]` blocks from the original `lib.rs` into test files under the appropriate submodules
- [ ] 1.7 Run `cargo test -p may-i-pp` and `cargo check` — verify all pass, no file exceeds 600 prod / 1200 test lines

## 2. Split engine eval module

- [ ] 2.1 Create `crates/engine/src/eval/` directory; move `eval.rs` to `eval/mod.rs`
- [ ] 2.2 Extract `context.rs` with `EvalContext`, `PredicateResult`, `DEFAULT_RECURSION_LIMIT`
- [ ] 2.3 Extract `predicates.rs` with `evaluate_predicate` and `evaluate_predicate_fold`
- [ ] 2.4 Extract `positional.rs` with `match_positional_patterns` and surrounding pattern-matching logic
- [ ] 2.5 Extract `effects.rs` with `evaluate_effect` and `evaluate_effect_fold`
- [ ] 2.6 Extract `entry.rs` with `evaluate`, `evaluate_with_fold`, `expand_combined_flags`, `positional_args`, `Evaluator`
- [ ] 2.7 Update `mod.rs` to re-export all previously-public symbols; fix `use` paths in the rest of the engine crate
- [ ] 2.8 Extract `#[cfg(test)]` blocks into test files under `eval/tests/`
- [ ] 2.9 Run `cargo test -p may-i-engine` and `cargo check` — verify all pass, no file exceeds limits

## 3. Extract test_generators test modules

- [ ] 3.1 Identify each `#[cfg(test)]` module in `test_generators.rs` and its line ranges
- [ ] 3.2 Move each test module to a separate file (e.g. `tests/predicate_properties.rs`, `tests/eval_properties.rs`, etc.) and wire with `mod` declarations
- [ ] 3.3 Trim `test_generators.rs` to generators only; verify it is under 600 lines
- [ ] 3.4 Run `cargo test -p may-i-engine` — verify all property tests pass
