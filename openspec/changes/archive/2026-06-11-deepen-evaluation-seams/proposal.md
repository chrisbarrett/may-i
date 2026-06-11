## Why

Three pieces of evaluation machinery carry duplicated logic or leak implicit
cross-crate knowledge. All three surfaced while implementing
`harden-shell-parse-fidelity`, where the cost was concrete:

1. **Two copies of the command-evaluation pipeline.** `evaluate_command_inner`
   and `evaluate_authorised_string` (`crates/engine/src/eval/command.rs`) both
   run *parse → decompose → loop units → strictest-wins → parse-error floor*.
   The `harden-shell-parse-fidelity` change had to edit both `decompose` call
   sites and reason about both floor implementations. The single shared
   evaluator was the explicit, accepted decision in
   `may-i-recurse-compound-inner` (Decision 1, which rejected "keep paths
   separate and duplicate decompose logic"); the duplication is drift from that
   decision, kept alive only because `engine-segment-decisions` scoped segment
   *population* to the top-level path.

2. **The unterminated-substitution contract lives in the wrong crate.** The
   engine (`decompose`) re-derives, by byte-offset arithmetic, a fact the
   parser already knows at lex time: that a `$( … )` / `` ` … ` `` ran off the
   end. The "diagnostic span covers the substitution body span" correlation is
   documented nowhere in `shell-parser`; it is so implicit that the
   `harden-shell-parse-fidelity` design doc stated the span inclusion
   backwards.

3. **Two copies of the parser-aware tokenisation state machine.**
   `entry::parser_positional_args` / `entry::first_positional_index` and
   `bindings::positional_args_owned` / `bindings::first_positional_index` are
   byte-identical except `.as_str()` vs `.clone()`. A comment at
   `bindings.rs:457` already admits the body is "a straight port".

## What Changes

- **Collapse the two evaluation pipelines onto one core.** Extract a single
  private `eval_units` in `command.rs` owning the unit loop, the
  `:allow < :ask < :deny` lattice, embedded-reason annotation, and the
  parse-error floor. Thread `depth` and `via: Option<&str>` uniformly;
  segment/offset collection becomes an *injected optional sink* (top-level
  supplies it, the authorise path passes `None`), honouring
  `engine-segment-decisions`' opt-in-population constraint.
  `evaluate_authorise_tokens` stays a separate adapter.
- **Move the unterminated-substitution determination into the parser.**
  `Word`'s embedded-substitution extraction reports a `terminated` flag per
  substitution, set where the lexer already emits the unterminated diagnostic.
  The engine reads the flag; its `substitution_is_unterminated` helper and the
  diagnostic-span correlation are deleted. The AST stays byte-identical.
- **Delete the duplicated tokeniser copy.** Keep the borrowed
  `entry::parser_positional_args` / `entry::first_positional_index` as the
  single source; `parse_argv` clones at the call site. Remove the owned copies
  and `bindings::split_after_*`, routing through `entry::split_outer_tail`.

No user-facing behaviour changes; this is a contributor-internal deepening.

## Capabilities

### New Capabilities

<!-- none -->

### Modified Capabilities

- `code-quality`: add requirements that the command-evaluation pipeline is not
  duplicated, that substitution termination is reported by the parser rather
  than re-derived by the engine, and that parser-aware positional/tail
  tokenisation has a single implementation.

## Impact

- `crates/engine/src/eval/command.rs` — new `eval_units` core; `evaluate_command_inner` and `evaluate_authorised_string` become thin adapters.
- `crates/shell-parser/src/ast/word.rs` — embedded extraction reports `terminated`; `crates/shell-parser/src/lexer/word_parts.rs` + `lexer/mod.rs` set it.
- `crates/engine/src/eval/decompose.rs` — read `terminated`; delete `substitution_is_unterminated` and the diagnostic correlation.
- `crates/engine/src/eval/entry.rs` / `bindings.rs` — single tokeniser; delete owned duplicates.
- Tests: existing engine + parser suites must stay green; one reconciliation point (uniform depth threading) is gated by the recursion-limit tests.
- No DSL, config, trust-hash, or migration surface change.
