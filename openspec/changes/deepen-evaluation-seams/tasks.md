## 1. Parser reports substitution termination (D3)

- [ ] 1.1 Write a failing `shell-parser` test: a terminated `$(date)` extracts with `terminated == true`; an unterminated `$(date` extracts with `terminated == false` (same for backtick and process substitution).
- [ ] 1.2 In `crates/shell-parser/src/ast/word.rs`, change the embedded-extraction result to carry a `terminated: bool` (introduce an `Embedded` struct or extend the returned tuple). Set the flag in the lexer (`lexer/word_parts.rs`, `lexer/mod.rs`) at the points that already emit the unterminated diagnostics; terminated substitutions get `true`.
- [ ] 1.3 Confirm the AST nodes and the `ParseResult.diagnostics` list are byte-identical to before (only the extraction result gains a field) — assert via an existing AST-stability/snapshot test or add one.
- [ ] 1.4 In `crates/engine/src/eval/decompose.rs`, skip a substitution when its reported `terminated` is false; delete `substitution_is_unterminated` and stop threading `diagnostics` into `decompose` solely for correlation (drop the parameter if it has no other use).
- [ ] 1.5 Confirm the engine guard tests still pass unchanged: `unterminated_command_substitution_not_recursed`, `well_formed_substitution_still_recurses`, `unterminated_parameter_and_arithmetic_floor_without_fabrication`.
- [ ] 1.6 Grep the engine for any remaining substitution-span ↔ diagnostic-span correlation; confirm none remains.

## 2. Single positional tokeniser (D4)

- [ ] 2.1 Confirm `entry::parser_positional_args` and `entry::first_positional_index` are `pub(crate)` and reachable from `bindings.rs`.
- [ ] 2.2 In `bindings::parse_argv`, obtain owned positionals by calling `entry::parser_positional_args(..).iter().map(str::to_string)`, and route the outer/tail split through `entry::split_outer_tail`.
- [ ] 2.3 Delete `bindings::positional_args_owned`, `bindings::first_positional_index`, `bindings::split_after_flags`, and `bindings::split_after_token`.
- [ ] 2.4 Run the binding/positional tests and `prop_tokens_match_string_when_metafree`; confirm green (behaviour identical by construction).

## 3. One evaluation core (D1, D2)

- [ ] 3.1 Write a failing/guard proptest asserting `evaluate_command` and `evaluate_authorised_string` agree on decisions for arbitrary input (extend or rely on `prop_authorised_matches_top_level`) — this is the equivalence the collapse must preserve.
- [ ] 3.2 Introduce a `SegmentSink` (byte-offset base + `SegmentDecision` accumulator; `None` = do not collect) and a private `eval_units` core in `command.rs` owning the unit loop, strictest-wins aggregate, embedded-reason annotation, and the parse-error floor (aggregate always; per-segment only when the sink is present). Thread `depth` and `via: Option<&str>`; perform the `:via` push inside the core.
- [ ] 3.3 Re-express `evaluate_command_inner` as `eval_units(.., via = None, segments = Some(sink @ outer_offset))` and `evaluate_authorised_string` as `eval_units(.., via, segments = None)`. Embedded recursion re-enters the core with `via = None` and the sink re-based to the substitution offset.
- [ ] 3.4 Evaluate each `SimpleCommand` unit via `evaluate_at_depth(.., depth)` uniformly (top-level enters at depth 0). Verify the reconciliation point with `recursion_depth_limit` and `prop_line_continuation_preserves_span_bounds`.
- [ ] 3.5 Confirm all `command.rs` segment/decision/reason scenarios and proptests stay green (`segment_decisions_*`, `prop_top_level_segments_disjoint`, `prop_aggregate_matches_strictest_top_level`, `prop_reason_is_single_line`, `unclosed_process_substitution_segments_nest`).
- [ ] 3.6 Confirm `evaluate_authorise_tokens` is unchanged and still delegates its `len == 1` arm to `evaluate_authorised_string`.

## 4. Verification

- [ ] 4.1 `cargo fmt`; full workspace `cargo test` green.
- [ ] 4.2 `cargo tarpaulin` on `may-i-engine` + `may-i-shell-parser`; confirm no new uncovered branches in the touched code.
- [ ] 4.3 Run the reproduction commands (`! kill -0 %1`; `grep -n "x$(y" file`) end-to-end; confirm decisions/reasons are unchanged from before this refactor.
- [ ] 4.4 Check in any new `proptest-regressions/` files.
