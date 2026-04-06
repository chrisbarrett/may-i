## 1. Implementation

- [ ] 1.1 Modify `emit_trivia_or_line` function in `crates/pp/src/lib.rs` to count newlines in whitespace trivia
- [ ] 1.2 Emit blank lines before calling `begin_line(indent)` when multiple newlines are detected
- [ ] 1.3 Ensure the fix handles both top-level forms and nested forms correctly

## 2. Testing

- [ ] 2.1 Add unit test for single blank line preservation
- [ ] 2.2 Add unit test for multiple blank lines preservation
- [ ] 2.3 Add unit test for check form with blank lines between test cases
- [ ] 2.4 Run migration on sample config and verify blank lines are preserved
- [ ] 2.5 Run existing test suite to ensure no regressions

## 3. Verification

- [ ] 3.1 Run `cargo test` in `crates/pp` to verify pp tests pass
- [ ] 3.2 Run `cargo test` at workspace level to verify all tests pass
- [ ] 3.3 Run `cargo run -- migrate` on a test config file to verify end-to-end behavior
