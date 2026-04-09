## Why

Code review identified duplicated logic, overly large functions, and minor quality issues that increase maintenance burden. Addressing these before release improves long-term code health without changing behavior.

## What Changes

### Duplicated code
- Unify `quote_string()` (cst.rs) and `quote_atom()` (sexpr.rs) into single function
- Extract shared config loading helper from cmd_eval, cmd_check, cmd_claude_code_hook (3 copies)
- Deduplicate CST `transform` and `write_to` logic for List vs Vector
- Deduplicate `strip_ansi` — co-locate with `visible_len` in pp crate
- Extract `is_capture_marker()` helper in migration (`:command+args` / `:command` / `:args` check repeated 3-4 times)

### Quality fixes
- Replace 5 bare `Keyword::new(...).unwrap()` in cmd_claude_code_hook.rs with `expect()` or const
- Replace `process::exit(1)` in cmd_check.rs with proper error return
- Add max-iteration guard to `rewrite_until_convergence` in cst.rs
- Replace `unwrap()` in resolve.rs:167 with `.expect()` documenting the invariant
- Fix unreachable branch ordering in `colorize_right` (~/∈ branch never fires)
- Remove empty `impl Format {}` block in pp
- Remove `let _ = effect;` / `let _ = args;` patterns — use `_effect` in signature
- Add `#[must_use]` to `evaluate()`, `EvalResult::new()`, key parse functions

### Factoring (optional, lower priority)
- Consider splitting `cst.rs` (2324 lines) into types/parser/tests submodules
- Consider splitting `annotation.rs` (1330 lines) into types/doc_builders/tracing_fold

## Capabilities

### New Capabilities

### Modified Capabilities

## Impact

- `crates/sexpr/src/` — dedup quote functions, optional cst.rs split
- `src/cmd_*.rs` — config loading dedup, process::exit fix
- `src/cmd_claude_code_hook.rs` — unwrap → expect
- `src/annotation.rs` — unused param cleanup, optional split
- `src/output/colorize.rs` — branch ordering fix
- `crates/pp/src/` — strip_ansi, empty impl, render_list cleanup
- `crates/config/src/migrate/` — capture marker helper
