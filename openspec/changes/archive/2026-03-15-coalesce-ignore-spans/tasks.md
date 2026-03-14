## 1. Implement coalesce_spans function

- [x] 1.1 Add `coalesce_spans(spans: Vec<PermissionSpan>) -> Vec<PermissionSpan>` function to `src/cmd_eval.rs`
- [x] 1.2 Implement logic to merge consecutive spans with `"ignore"` permission
- [x] 1.3 Preserve non-ignore spans (allow/ask/deny) as separate entries

## 2. Integrate coalescing into JSON output pipeline

- [x] 2.1 Call `coalesce_spans()` after `build_spans()` in `evaluate_segments_json()`
- [x] 2.2 Ensure coalescing happens before JSON serialization
- [x] 2.3 Verify the coalesced spans can reconstruct the original command exactly

## 3. Add unit tests for coalescing

- [x] 3.1 Test: Empty spans array returns empty array
- [x] 3.2 Test: Single span returns unchanged
- [x] 3.3 Test: Two consecutive ignore spans are merged
- [x] 3.4 Test: ignore + allow + ignore keeps allow separate
- [x] 3.5 Test: Multiple consecutive ignore spans merge into one
- [x] 3.6 Test: No ignore spans returns unchanged
- [x] 3.7 Test: Mixed permissions preserve boundaries (allow, ignore, ask, ignore, deny)

## 4. Update integration tests

- [x] 4.1 Update existing span tests to expect coalesced output
- [x] 4.2 Add test verifying command reconstruction with coalesced spans
- [x] 4.3 Verify JSON output structure remains unchanged

## 5. Verify and finalize

- [x] 5.1 Run `cargo test` to ensure all tests pass
- [x] 5.2 Test manually: `may-i eval --json "true && curl || ls"` shows coalesced spans
- [x] 5.3 Verify backward compatibility: existing consumers still work
