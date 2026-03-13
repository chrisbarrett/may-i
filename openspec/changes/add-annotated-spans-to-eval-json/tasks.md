# Tasks: Add Annotated Spans to eval --json Output

## Task 1: Add PermissionSpan struct and spans building logic

**File**: `src/cmd_eval.rs`

Add the data structure and helper function:

- [ ] Add `PermissionSpan` struct with `text: String` and `permission: String` fields
- [ ] Add `build_spans(command, segments, decisions) -> Vec<PermissionSpan>` function
- [ ] Handle gaps between segments (whitespace as "ignore")
- [ ] Handle leading/trailing whitespace
- [ ] Map operator segments to "ignore" permission
- [ ] Map command segments to their evaluated decision

## Task 2: Integrate spans into JSON output

**File**: `src/cmd_eval.rs`

Modify the JSON construction:

- [ ] Capture segment decisions during `evaluate_segments()` evaluation
- [ ] Call `build_spans()` in the JSON branch before constructing output
- [ ] Add `spans` field to the JSON object
- [ ] Ensure backward compatibility (spans is additive)

## Task 3: Add unit tests for span building

**File**: `src/cmd_eval.rs` (in `#[cfg(test)]` module)

- [ ] Test: Empty command returns empty spans
- [ ] Test: Single command "ls" returns single span with permission
- [ ] Test: Command with operator "true && curl" returns 3 spans (command, operator, command)
- [ ] Test: Leading/trailing whitespace preserved as "ignore" spans
- [ ] Test: Multiple operators "a && b || c" returns correct span sequence
- [ ] Test: Concatenating spans reproduces original command exactly

## Task 4: Add integration test

**File**: `tests/eval_e2e.rs`

- [ ] Test: Full JSON output includes spans array
- [ ] Test: Spans contain expected text and permissions
- [ ] Test: Complex command with multiple segments

## Task 5: Verify and document

- [ ] Run `cargo test` to ensure all tests pass
- [ ] Verify example from design doc produces expected output
- [ ] Update any relevant documentation if needed

## Acceptance Criteria

- [ ] `may-i eval --json "true && curl example.com"` produces output with spans array
- [ ] Each span has `text` and `permission` fields
- [ ] Operators have "ignore" permission
- [ ] Commands have their evaluated permission ("allow"/"ask"/"deny")
- [ ] Concatenating all span texts reproduces the original command exactly
- [ ] All tests pass
