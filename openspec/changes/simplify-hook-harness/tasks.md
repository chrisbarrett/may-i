## 1. Rename and Restructure

- [ ] 1.1 Rename `src/cmd_hook.rs` to `src/cmd_claude_code_hook.rs`
- [ ] 1.2 Add private `extract_command()` function
- [ ] 1.3 Add private `build_context()` function
- [ ] 1.4 Add private `render_response()` function
- [ ] 1.5 Update `cmd_claude_code_hook()` to use inline functions

## 2. Update main.rs

- [ ] 2.1 Change `mod cmd_hook;` to `mod cmd_claude_code_hook;`
- [ ] 2.2 Update the hook command dispatch in `run()`
- [ ] 2.3 Remove `mod hook_harness;` declaration

## 3. Remove hook_harness Module

- [ ] 3.1 Delete `src/hook_harness.rs` file

## 4. Testing and Verification

- [ ] 4.1 Run `cargo build` to verify no compilation errors
- [ ] 4.2 Run `cargo test` to verify no regressions
- [ ] 4.3 Test with sample Claude Code hook payload (Bash tool)
- [ ] 4.4 Test with non-Bash tool payload (should be silent)
- [ ] 4.5 Verify output format matches previous implementation
