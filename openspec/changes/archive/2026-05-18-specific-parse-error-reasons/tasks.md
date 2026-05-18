## 1. Formatter in shell-parser

- [x] 1.1 Write a failing unit test in `crates/shell-parser/src/diagnostic.rs` that calls `ParseDiagnostic::format_with_source(&self, src)` and asserts the `"<kind message> at line L, column C: '<excerpt>'"` shape on a multi-line input with an unterminated single quote on line 3.
- [x] 1.2 Add a property test: for any input + valid `Span`, the returned string is a single line (no embedded newlines), contains the diagnostic's `message()`, and contains the substring `at line L, column C:` with 1-based L, C derived from `span.start`.
- [x] 1.3 Implement `ParseDiagnostic::format_with_source(&self, src: &str) -> String`. Line/column computed by linear scan of `src[..span.start]`. Excerpt: up to 20 chars before `span.start` and up to 30 chars from `span.start`; replace control characters with their escape sequences (`\n`, `\t`, `\r`, etc.); ellipsise either side if truncated; wrap in single quotes.
- [x] 1.4 Add a unit test covering multibyte-safe slicing (non-ASCII content like `│` in the excerpt window must not panic and must produce a valid UTF-8 string).
- [x] 1.5 Run `cargo test -p may-i-shell-parser`.

## 2. Engine call sites

- [x] 2.1 Write a failing test in `crates/engine/src/eval/command.rs` (or a sibling test module) that evaluates an input with an unterminated single quote and asserts the resulting `EvalResult.reason` starts with `"parse error: unterminated single quote at line "`.
- [x] 2.2 Add a sibling test for `evaluate_authorised_string` (the second aggregate site) covering the same shape.
- [x] 2.3 Replace the literal `"parse error: ambiguous command boundary"` at the first call site with a helper that picks the first `Severity::Error` diagnostic and formats it via `format_with_source(input)`, falling back to the current literal when no error-severity entry is present.
- [x] 2.4 Apply the same change at the second call site (`evaluate_authorised_string`).
- [x] 2.5 Verify cascading-diagnostic behaviour with a targeted test: input with a stray `'` followed by content that yields additional unterminated backtick / cmd-sub diagnostics. Assert `reason` describes only the first diagnostic; assert `parse_diagnostics.len() >= 2`.
- [x] 2.6 Run `cargo test -p may-i-engine`.

## 3. Update existing tests pinned to old reason

- [x] 3.1 Grep for the literal `"parse error: ambiguous command boundary"` and `"ambiguous command boundary"` across the workspace; update each assertion or snapshot to the new shape (or relax to a `starts_with` / regex match where the exact excerpt would be fragile).
- [x] 3.2 Run `cargo test --workspace`.

## 4. Verification

- [x] 4.1 Run `cargo fmt --check`.
- [x] 4.2 Run `cargo clippy --workspace --all-targets -- -D warnings`.
- [x] 4.3 Run `cargo tarpaulin` and confirm `format_with_source` and the two engine call sites are covered.
- [x] 4.4 Run `openspec validate specific-parse-error-reasons --strict`.
