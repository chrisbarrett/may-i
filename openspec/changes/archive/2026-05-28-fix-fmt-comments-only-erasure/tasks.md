## 1. Failing tests (red)

- [x] 1.1 Add integration test in `tests/` covering file mode: write a comments-only `.lisp` to a tempfile, run `may-i fmt PATH`, assert exit `0` and on-disk bytes unchanged.
- [x] 1.2 Add integration test covering stdin filter mode: pipe a comments-only stream to `may-i fmt`, assert stdout is byte-identical and exit `0`.
- [x] 1.3 Add integration test covering `--check`: run `may-i fmt --check` against a comments-only file, assert exit `0` and empty stdout.
- [x] 1.4 Add integration test covering whitespace-only input (no comments) — same expectations.
- [x] 1.5 Add a proptest (placement: alongside existing `cmd_fmt` tests, or `crates/sexpr/` if the property targets `parse_cst`) that generates inputs composed solely of comments + whitespace and asserts a formless round-trip is byte-identical and parses with zero errors.
- [x] 1.6 Run the test suite; confirm the new tests fail in the way the proposal describes (file shrinks to 1 byte / canonical differs from source).

## 2. Implementation (green)

- [x] 2.1 In `src/cmd_fmt.rs::canonical_text`, after parsing, short-circuit when `forms.is_empty() && parse_errors.is_empty()`: return the source verbatim with `legacy = false`.
- [x] 2.2 Confirm `process_file` and `run_stdin_text` already do the right thing once `canonical == source` (no rewrite in file mode, `print!("{canonical}")` in stdin mode, `Severity::Clean` in `--check`). Adjust only if a code path still triggers a write.
- [x] 2.3 Re-run the suite; all new tests pass and no existing tests regress.

## 3. Refactor & polish

- [x] 3.1 Run `cargo fmt`.
- [x] 3.2 Run `cargo clippy --all-targets` and address findings introduced by this change.
- [x] 3.3 Run `cargo tarpaulin`; inspect `lcov.info` for uncovered branches in the new short-circuit and either add a targeted unit test or extend the proptest to cover them.

## 4. Verification

- [x] 4.1 Manual repro: write a comments-only file, run `may-i fmt` on it, confirm the file is unchanged on disk and exits `0`.
- [x] 4.2 Manual repro of the stdin path: `printf ';; x\n' | may-i fmt` produces `;; x\n` on stdout, exit `0`.
- [x] 4.3 Run `openspec validate fix-fmt-comments-only-erasure --strict`.
