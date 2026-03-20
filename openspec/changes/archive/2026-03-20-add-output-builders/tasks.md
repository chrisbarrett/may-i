## 1. Create CheckReport Builder

- [x] 1.1 Define `CheckReport` struct with warnings, results, summary fields
- [x] 1.2 Define `CheckResultDisplay` struct for individual check results
- [x] 1.3 Implement `CheckReport::from_engine_results()` to extract data from `engine::CheckResult`
- [x] 1.4 Implement `CheckReport::render_text()` for human-readable output
- [x] 1.5 Implement `CheckReport::to_json()` for JSON output (rename `context` to `facts`)
- [x] 1.6 Implement `CheckReport::exit_code()` method returning 0 or 1
- [x] 1.7 Add `insta` snapshot tests for `render_text()` output (optional)
- [x] 1.8 Add `insta` snapshot tests for `to_json()` output (optional)

## 2. Refactor cmd_check

- [x] 2.1 Replace inline formatting logic with `CheckReport` builder usage
- [x] 2.2 Update `cmd_check()` to use builder for both JSON and text modes
- [x] 2.3 Move exit code handling to `cmd_check()` function (remove from builder)
- [x] 2.4 Verify text output matches existing format (manual check)
- [x] 2.5 Verify JSON structure with `context` → `facts` rename

## 3. Create EvalReport Builder

- [x] 3.1 Define `EvalReport` struct with segments, aggregate result, trace fields
- [x] 3.2 Define `EvalSegment` struct for command segments with decisions
- [x] 3.3 Implement `EvalReport::from_command()` to parse and evaluate command segments
- [x] 3.4 Implement `EvalReport::render_text()` with colored output
- [x] 3.5 Implement `EvalReport::to_json()` for JSON output
- [x] 3.6 Add `insta` snapshot tests for text output with colored spans (optional)
- [x] 3.7 Add `insta` snapshot tests for JSON output with permission spans (optional)

## 4. Refactor cmd_eval

- [x] 4.1 Replace `evaluate_segments()` and `evaluate_segments_json()` with builder
- [x] 4.2 Update `cmd_eval()` to use builder for both output modes
- [x] 4.3 Keep `PermissionSpan` and `coalesce_spans()` logic (used by builder)
- [x] 4.4 Verify colored command output matches existing format

## 5. Testing and Verification

- [x] 5.1 Run existing tests (`cargo test`) - **83 tests passing**
- [x] 5.2 Test `may-i check` with verbose flag
- [x] 5.3 Test `may-i check --json` and verify `facts` field name
- [x] 5.4 Test `may-i eval` with simple and compound commands
- [x] 5.5 Test `may-i eval --json` with span output
- [x] 5.6 Verify no regressions in `cmd_parse` or `cmd_hook`
