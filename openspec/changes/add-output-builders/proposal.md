## Why

The output formatting logic in `cmd_check.rs` and `cmd_eval.rs` interleaves data extraction, decision-making, and rendering. This makes the code harder to test and reason about. A builder pattern would separate these concerns, enabling property-based testing and making the output structure explicit.

## What Changes

- Add a `CheckReport` builder for `cmd_check` output that separates data extraction from rendering
- Add an `EvalReport` builder for `cmd_eval` output with similar separation
- Both builders support text and JSON output modes
- Normalize JSON field name: `context` → `facts` (minor breaking change)
- Keep existing output formats and visual appearance unchanged

## Capabilities

### New Capabilities
<!-- No new spec-level capabilities. This is an internal refactoring. -->

### Modified Capabilities
<!-- No spec-level requirement changes. Output formats preserved. -->

## Impact

- `src/cmd_check.rs` - Refactored to use builder pattern
- `src/cmd_eval.rs` - Refactored to use builder pattern
- JSON output in `check` command: `context` field renamed to `facts`
- No changes to `cmd_parse.rs` or `cmd_hook.rs` (simple enough already)
- New testable builder modules (optional, can remain in existing files)
