## Why

Migrated configs come out of `may-i migrate` with indentation that diverges sharply from hand-formatted Lisp. Two specific failures surface as soon as the diff is reviewed: `(cond …)` clauses indent at `+2` (defun-style) when convention says `+1`, and forms broken across lines drift right by aligning under the *last* inline argument instead of the *first*. Drift compounds in deeply nested forms — observed as 50+ columns of leading whitespace on a single config — making migration diffs unreadable and the formatter unsafe to point at user code. Without a written contract for indentation, the renderer's behaviour drifts whenever someone touches the layout pass.

## What Changes

- **NEW** Written indentation contract distinguishing two layout regimes: function-call (default) and body-indent (forms with declared `indent N`). Specifies the alignment column for breaks, the cascade discipline (fixed under first arg, no drift), and the special case for `(cond …)`.
- **BREAKING (output-only)** `(cond …)` clauses indent at `+1` (under first clause) instead of `+2`. The cond body is conventionally aligned with its first clause, not indented as a function-call body.
- **BREAKING (output-only)** Trivia-guided cascade no longer drifts. When a form's children fit inline on the head line, the cascade column is fixed at the start of the *first* inline arg and never updates as more children attach. Subsequent breaks land under the first arg, matching `render_broken_delim`'s already-correct behaviour.
- **NEW** Pretty-printer snapshot suite refreshed against the new contract. Hand-formatted configs round-trip stable.

## Capabilities

### New Capabilities

(none — this is a refinement of an existing capability)

### Modified Capabilities

- `pretty-printing`: tighten the indent-spec contract; change the cascade discipline from "drift to last inline arg" to "fixed at first inline arg"; change `cond` from N=0 (defun-style `+2`) to a dedicated renderer with `+1` clause indent.

## Impact

- **`crates/pp/src/render/layout.rs`**: `render_cond` (clause column) and `render_trivia_guided_delim` (cascade discipline). Two surgical edits.
- **`crates/pp/src/lib.rs`**: `INDENT_SPECS` table — keep `cond` listed but document that the renderer overrides the body-indent computation.
- **`tests/snapshots/oracle_trace_v1__*.snap`**: snapshots that contain pretty-printed rule sources will shift indent. Reviewed and accepted as part of this change, not a casual `INSTA_UPDATE=always`.
- **`crates/pp/src/tests/rendering.rs`**: a few cascade-related tests will move from drift-aware assertions to fixed-cascade assertions.
- **No breaking change to evaluation behaviour**. Pretty-printing affects `may-i fmt`, `may-i migrate` diff output, and trust-hash canonical form. Trust hashes only cover semantic content, not whitespace, so existing approvals are preserved.
