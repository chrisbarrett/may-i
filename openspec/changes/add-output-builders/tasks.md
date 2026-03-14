## 1. Create CheckReport Builder

- [ ] 1.1 Define `CheckReport` struct with warnings, results, summary fields
- [ ] 1.2 Define `CheckResultDisplay` struct for individual check results
- [ ] 1.3 Implement `CheckReport::from_engine_results()` to extract data from `engine::CheckResult`
- [ ] 1.4 Implement `CheckReport::render_text()` for human-readable output
- [ ] 1.5 Implement `CheckReport::to_json()` for JSON output (rename `context` to `facts`)
- [ ] 1.6 Implement `CheckReport::exit_code()` method returning 0 or 1
- [ ] 1.7 Add `insta` snapshot tests for `render_text()` output
- [ ] 1.8 Add `insta` snapshot tests for `to_json()` output (with redaction for paths)

## 2. Refactor cmd_check

- [ ] 2.1 Replace inline formatting logic with `CheckReport` builder usage
- [ ] 2.2 Update `cmd_check()` to use builder for both JSON and text modes
- [ ] 2.3 Move exit code handling to `cmd_check()` function (remove from builder)
- [ ] 2.4 Verify text output matches existing format (manual check)
- [ ] 2.5 Verify JSON structure with `context` → `facts` rename

## 3. Create EvalReport Builder

- [ ] 3.1 Define `EvalReport` struct with segments, aggregate result, trace fields
- [ ] 3.2 Define `EvalSegment` struct for command segments with decisions
- [ ] 3.3 Implement `EvalReport::from_command()` to parse and evaluate command segments
- [ ] 3.4 Implement `EvalReport::render_text()` with colored output
- [ ] 3.5 Implement `EvalReport::to_json()` for JSON output
- [ ] 3.6 Add `insta` snapshot tests for text output with colored spans
- [ ] 3.7 Add `insta` snapshot tests for JSON output with permission spans

## 4. Refactor cmd_eval

- [ ] 4.1 Replace `evaluate_segments()` and `evaluate_segments_json()` with builder
- [ ] 4.2 Update `cmd_eval()` to use builder for both output modes
- [ ] 4.3 Keep `PermissionSpan` and `coalesce_spans()` logic (used by builder)
- [ ] 4.4 Verify colored command output matches existing format

## 5. Testing and Verification

- [ ] 5.1 Run existing tests (`cargo test`)
- [ ] 5.2 Test `may-i check` with verbose flag
- [ ] 5.3 Test `may-i check --json` and verify `facts` field name
- [ ] 5.4 Test `may-i eval` with simple and compound commands
- [ ] 5.5 Test `may-i eval --json` with span output
- [ ] 5.6 Verify no regressions in `cmd_parse` or `cmd_hook`
