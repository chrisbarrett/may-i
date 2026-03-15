## 1. Rename and Restructure

- [x] 1.1 Rename `src/cmd_hook.rs` to `src/cmd_claude_code_hook.rs`
- [x] 1.2 Add private `extract_command()` function
- [x] 1.3 Add private `build_context()` function
- [x] 1.4 Add private `render_response()` function
- [x] 1.5 Update `cmd_claude_code_hook()` to use inline functions

## 2. Update main.rs

- [x] 2.1 Change `mod cmd_hook;` to `mod cmd_claude_code_hook;`
- [x] 2.2 Update the hook command dispatch in `run()`
- [x] 2.3 Remove `mod hook_harness;` declaration

## 3. Remove hook_harness Module

- [x] 3.1 Delete `src/hook_harness.rs` file

## 4. Testing and Verification

- [x] 4.1 Run `cargo build` to verify no compilation errors
- [x] 4.2 Run `cargo test` to verify no regressions
- [x] 4.3 Test with sample Claude Code hook payload (Bash tool)
- [x] 4.4 Test with non-Bash tool payload (should be silent)
- [x] 4.5 Verify output format matches previous implementation
