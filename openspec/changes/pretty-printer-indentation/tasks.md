## 1. Cond clause indent

- [x] 1.1 Change `render_cond` body_indent from `indent + 2` to `indent + 1` in `crates/pp/src/render/layout.rs`.
- [x] 1.2 Update body_col arithmetic so clause body parts indent at clause column `+1` (matching the spec's "body parts at clause + 1" rule).
- [x] 1.3 Add unit test in `crates/pp/src/tests/rendering.rs` asserting `(cond ((p) (allow)) (else (deny)))` renders with clauses at parent paren `+1`.

## 2. Trivia-guided cascade fix

- [x] 2.1 In `render_trivia_guided_delim`, change the cascade-update guard to fire only on the *first* inline child. Use a sentinel comparison (`cascade_col == initial_cascade`) or an explicit flag.
- [x] 2.2 Add unit test asserting `(positional A B C D)` at width forcing `D` to wrap puts `D` under start of `A`, not under start of `C`.
- [x] 2.3 Add unit test for the deeply-nested case: `(when (or (positional X (or "a" "b" "c" "d")) …) …)` with width that wraps the inner `or` — wrapped atoms align under the inner `or`'s first argument.
- [x] 2.4 Add unit test for the head-alone case: when source has a newline immediately after the head atom, cascade column is `paren_col + 1`.

## 3. Existing test fallout

- [x] 3.1 Run `cargo test -p may-i-pp`. Identify cascade-related tests that asserted drift behaviour. Update assertions to reflect fixed-cascade. (No fallout — all 106 pp tests pass; no existing test asserted drift behaviour.)
- [x] 3.2 For each updated test, verify the new assertion describes Emacs / Common-Lisp convention (under first arg), not just whatever the new code does. (Vacuous — no tests required updating.)

## 4. Snapshot review

- [x] 4.1 Run `INSTA_UPDATE=always cargo test --test oracle_trace_v1`. (Also updated `pretty_print_snapshots`.)
- [x] 4.2 For each `.snap` change, inspect the diff. Confirm the new layout is genuinely better (indent shifted left, drift removed) and not a regression elsewhere. (cond clauses shifted left by 1 col; parser cascade no longer drifts to under last inline arg.)
- [ ] 4.3 Stage and commit snapshot updates as a single commit, distinct from the renderer fixes.

## 5. End-to-end verification

- [x] 5.1 Run `cargo run -- migrate --dry-run --config ~/.config/may-i/config.lisp`. Verify the diff is readable: cond clauses at `+1`, no deep cascade drift in nested `(or …)` / `(positional …)` forms.
- [x] 5.2 Verify all tests still pass after the merge: `cargo test --no-fail-fast`.

## 6. Spec hygiene

- [x] 6.1 After implementation, review the modified spec text against the implemented behaviour. Adjust spec wording if any scenario doesn't match what the code actually does. (Change spec scenarios match implementation; lib.rs INDENT_SPECS doc comment updated for N=0 reserved-renderer semantics.)
- [x] 6.2 Ensure `pretty-printing` spec entries that refer to legacy `+2` cond layout are updated. (Change spec.md MODIFIED Requirements correctly state `+1`; persistent spec gets the diff applied on archive.)
