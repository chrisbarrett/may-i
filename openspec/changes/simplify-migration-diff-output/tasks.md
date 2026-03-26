## 1. Add similar dependency

- [x] 1.1 Add `similar` crate to workspace Cargo.toml
- [x] 1.2 Verify dependency resolves with `cargo check`

## 2. Remove diff renderer

- [x] 2.1 Delete `crates/output/src/diff_renderer.rs`
- [x] 2.2 Remove `diff_renderer` module export from `crates/output/src/lib.rs`
- [x] 2.3 Remove `minus` and `unicode_width` from `crates/output/Cargo.toml`
- [x] 2.4 Run `cargo check -p may-i-output` to verify clean removal

## 3. Simplify diff module

- [x] 3.1 Remove `compute_diff()` function from `crates/sexpr/src/diff.rs`
- [x] 3.2 Remove `shapes_equal()` function from `crates/sexpr/src/diff.rs`
- [x] 3.3 Remove `annotate_child()` function from `crates/sexpr/src/diff.rs`
- [x] 3.4 Keep `ChangeType` enum and `DiffAnn` struct (may be used elsewhere)
- [x] 3.5 Update or remove tests in `diff.rs` that test removed functions
- [x] 3.6 Run `cargo test -p may-i-sexpr` to verify remaining tests pass

## 4. Update migrate command

- [x] 4.1 Remove imports of removed modules from `cmd_migrate.rs`
- [x] 4.2 Import `similar::TextDiff` and create text diff function
- [x] 4.3 Implement diff formatting with file path header (with ~ for HOME)
- [x] 4.4 Add 3 lines of context around changes
- [x] 4.5 Implement color support respecting `NO_COLOR` and TTY detection
- [x] 4.6 Update error message to "Config file would be modified. Use --yes to confirm non-interactive execution."
- [x] 4.7 Change prompt from `[Y/n]` to `[y/N]`
- [x] 4.8 Remove pager-related code

## 5. Update tests

- [x] 5.1 Update `tests/migration_diff.rs` to use snapshot testing with `insta`
- [x] 5.2 Create test snapshots for:
  - Simple migration with one change
  - Migration with multiple changes
  - Migration with no changes
- [x] 5.3 Update `cmd_migrate.rs` tests for new prompt behavior
- [x] 5.4 Remove tests for removed functionality (pager, two-column layout)
- [x] 5.5 Run `cargo test --test migration_diff` to verify

## 6. Verification

- [x] 6.1 Run `cargo fmt` to ensure consistent formatting
- [x] 6.2 Run `cargo clippy` to check for warnings
- [x] 6.3 Run full test suite `cargo test` to verify no regressions
- [x] 6.4 Manually test `may-i migrate` on a v1 config file
- [x] 6.5 Verify colors work in TTY: `may-i migrate` (should be colored)
- [x] 6.6 Verify no colors when piped: `may-i migrate | cat` (should be plain)
- [x] 6.7 Verify no colors with NO_COLOR: `NO_COLOR=1 may-i migrate` (should be plain)
- [x] 6.8 Verify prompt defaults to No: press Enter at prompt (should cancel)

## 7. Documentation

- [x] 7.1 Update help text if needed (check `cmd_help.rs`)
- [x] 7.2 Add example diff output to commit message
