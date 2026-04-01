## Why

`src/output.rs` (2310 lines) is a monolithic bridge between the evaluation
engine and the terminal. Its most fragile component is the annotation pipeline:
`collect_annotations` walks the `Doc<Option<Ann>>` tree to extract
`(needle, right_text)` pairs, then `find_line` does substring matching against
pretty-printed output to correlate annotations with rendered lines. This
string-based round-trip is lossy -- annotations can land on the wrong line or
overflow when needle text appears multiple times or fails to match after
truncation. The file's size and tangled concerns make it difficult to modify
trace rendering with confidence.

## What Changes

- Decompose `src/output.rs` into focused submodules (`output/transform`,
  `output/annotate`, `output/render_rule`, `output/colorize`, `output/json`)
  with clear interfaces between them.
- Introduce a `PrettyOutput<A>` trait in the `may_i_pp` crate so the
  pretty-printer emits structured events (`emit_atom`, `begin_line`, etc.)
  instead of returning a flat `String`.
- Implement an `AnnotatedLineBuilder` that carries `Doc<A>` annotations through
  pretty-printing, producing `Vec<AnnotatedLine<A>>` where each rendered line
  knows its annotation.
- Replace the `collect_annotations` + `find_line` pipeline in `render_rule` with
  direct iteration over annotated lines.
- Preserve a `StringBuilder` implementation so the existing `pretty()` API
  remains backward-compatible.

## Capabilities

### New Capabilities

- `pretty-output-trait`: Generic output trait for the s-expression
  pretty-printer, enabling structured output without duplicating render logic.
- `output-module-structure`: Decomposition of the monolithic output.rs into
  focused submodules with clear data-flow boundaries.

### Modified Capabilities

- `trace-rendering`: The annotation-to-line correlation mechanism changes from
  string-based needle matching to structural annotation threading. Rendered
  output must remain identical.

## Impact

- `crates/pp/src/lib.rs` -- render functions refactored to emit via
  `PrettyOutput<A>` trait; new `StringBuilder` and `AnnotatedLineBuilder` types.
- `src/output.rs` -- split into `src/output/` module directory; `find_line` and
  `collect_annotations` eliminated in favour of annotated line iteration.
- `src/cmd_eval.rs`, `src/cmd_check.rs` -- unchanged public API; callers
  continue using `output::write_trace`, `output::trace_to_json`, etc.
- `crates/layout/src/lib.rs` -- unchanged.
- `tests/oracle_trace_v1.rs` -- snapshot tests must produce byte-identical
  output throughout.
