## 1. Parser reports substitution termination (D3)

- [x] 1.1 Write a failing `shell-parser` test: a terminated `$(date)` extracts with `terminated == true`; an unterminated `$(date` extracts with `terminated == false` (same for backtick and process substitution).
- [x] 1.2 In `crates/shell-parser/src/ast/word.rs`, change the embedded-extraction result to carry a `terminated: bool` (introduce an `Embedded` struct or extend the returned tuple). Set the flag in the lexer (`lexer/word_parts.rs`, `lexer/mod.rs`) at the points that already emit the unterminated diagnostics; terminated substitutions get `true`.
- [x] 1.3 Confirm the AST nodes and the `ParseResult.diagnostics` list are byte-identical to before (only the extraction result gains a field) — assert via an existing AST-stability/snapshot test or add one.
- [x] 1.4 In `crates/engine/src/eval/decompose.rs`, skip a substitution when its reported `terminated` is false; delete `substitution_is_unterminated` and stop threading `diagnostics` into `decompose` solely for correlation (drop the parameter if it has no other use).
- [x] 1.5 Confirm the engine guard tests still pass unchanged: `unterminated_command_substitution_not_recursed`, `well_formed_substitution_still_recurses`, `unterminated_parameter_and_arithmetic_floor_without_fabrication`.
- [x] 1.6 Grep the engine for any remaining substitution-span ↔ diagnostic-span correlation; confirm none remains.

## 2. Single positional tokeniser (D4)

- [x] 2.1 Confirm `entry::parser_positional_args` (`pub(crate)`) and `entry::split_outer_tail` (`pub(super)`) are reachable from `bindings.rs`.
- [x] 2.2 In `bindings::parse_argv`, route the outer/tail split through `entry::split_outer_tail`, and reduce `positional_args_owned` to a clone-adapter over `entry::parser_positional_args`.
- [x] 2.3 Delete the duplicated state machine from `bindings`: `first_positional_index`, `split_after_flags`, `split_after_token`, and the hand-ported body of `positional_args_owned` (now a 4-line delegating clone).
- [x] 2.4 Run the binding/positional tests and `prop_tokens_match_string_when_metafree`; confirm green (behaviour identical by construction).

## 3. One evaluation core (D1, D2)

- [x] 3.1 Relied on the existing `prop_authorised_matches_top_level` proptest — it asserts `evaluate_command` and `evaluate_authorised_string` agree on decisions for arbitrary input, the equivalence the collapse must preserve.
- [x] 3.2 Introduced a private `eval_units` core in `command.rs` owning the unit loop, strictest-wins aggregate, embedded-reason annotation, fold events, and the parse-error floor (aggregate always; per-segment only when collecting). Threads `depth` and `via: Option<&str>`; the `:via` push happens inside the core. The segment sink is `segments: Option<usize>` — `Some(outer_offset)` collects, `None` skips.
- [x] 3.3 Re-expressed `evaluate_command_with_fold` as `eval_units(.., via = None, segments = Some(0))` and `evaluate_authorised_string` as `eval_units(.., via, segments = None)`. Embedded recursion re-enters the core with `via = None` and the offset re-based to the substitution.
- [x] 3.4 Evaluate each `SimpleCommand` unit via `evaluate_at_depth(.., depth)` uniformly (top-level enters at depth 0). Reconciliation verified by `recursion_depth_limit`, `authorised_string_depth_limit_at_boundary`, and `prop_line_continuation_preserves_span_bounds`.
- [x] 3.5 All `command.rs` segment/decision/reason scenarios and proptests stay green (`segment_decisions_*`, `prop_top_level_segments_disjoint`, `prop_aggregate_matches_strictest_top_level`, `prop_reason_is_single_line`, `unclosed_process_substitution_segments_nest`).
- [x] 3.6 `evaluate_authorised_tokens` unchanged; its `len == 1` arm still delegates to `evaluate_authorised_string`.

## 4. Verification

- [x] 4.1 `cargo fmt`; full workspace `cargo test` green; `cargo clippy` clean on touched crates.
- [x] 4.2 `cargo tarpaulin` on `may-i-engine` + `may-i-shell-parser`; the only uncovered lines in touched files are pre-existing defensive guards in `evaluate_authorised_tokens` and the assignment-only embedded branch — `eval_units` and `extract_embedded` are covered. Net −0.07% (duplicate covered lines deleted).
- [x] 4.3 Reproductions (`! kill -0 %1` → deny; `grep -n "x$(y" file` → parse-error ask; `echo $(rm -rf /)` → deny with annotation) unchanged; authorise path validated via `binding_recursion`/`wrapper_tail_scoping` (26 tests) and `prop_authorised_matches_top_level`.
- [x] 4.4 No new `proptest-regressions/` files produced.
