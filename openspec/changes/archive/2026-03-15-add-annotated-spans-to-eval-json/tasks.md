# Tasks: Add Annotated Spans to eval --json Output

## Task 1: Add PermissionSpan struct and spans building logic

**File**: `src/cmd_eval.rs`

Add the data structure and helper function:

- [x] Add `PermissionSpan` struct with `text: String` and `permission: String` fields
- [x] Add `build_spans(command, segments, decisions) -> Vec<PermissionSpan>` function
- [x] Handle gaps between segments (whitespace as "ignore")
- [x] Handle leading/trailing whitespace
- [x] Map operator segments to "ignore" permission
- [x] Map command segments to their evaluated decision

## Task 2: Integrate spans into JSON output

**File**: `src/cmd_eval.rs`

Modify the JSON construction:

- [x] Capture segment decisions during `evaluate_segments()` evaluation
- [x] Call `build_spans()` in the JSON branch before constructing output
- [x] Add `spans` field to the JSON object
- [x] Ensure backward compatibility (spans is additive)

## Task 3: Add unit tests for span building

**File**: `src/cmd_eval.rs` (in `#[cfg(test)]` module)

- [x] Test: Empty command returns empty spans
- [x] Test: Single command "ls" returns single span with permission
- [x] Test: Command with operator "true && curl" returns 5 spans (command, whitespace, operator, whitespace, command)
- [x] Test: Leading/trailing whitespace preserved as "ignore" spans
- [x] Test: Multiple operators "a && b || c" returns correct span sequence
- [x] Test: Concatenating spans reproduces original command exactly

## Task 4: Add integration test

**File**: `tests/eval_e2e.rs`

- [x] Test: Full JSON output includes spans array
- [x] Test: Spans contain expected text and permissions
- [x] Test: Complex command with multiple segments

## Task 5: Verify and document

- [x] Run `cargo test` to ensure all tests pass
- [x] Verify example from design doc produces expected output
- [x] Update any relevant documentation if needed

## Acceptance Criteria

- [x] `may-i eval --json "true && curl example.com"` produces output with spans array
- [x] Each span has `text` and `permission` fields
- [x] Operators have "ignore" permission
- [x] Commands have their evaluated permission ("allow"/"ask"/"deny")
- [x] Concatenating all span texts reproduces the original command exactly
- [x] All tests pass
