## Why

The current migration diff display uses a custom CST-based renderer (`diff_renderer.rs` ~1040 lines) with complex two-column layout logic, terminal width detection, and ANSI color handling. This is error-prone and reinvents functionality that standard diff libraries provide. By switching to a simplified text-based diff using the `similar` crate, we can delete ~900 lines of finicky layout code while providing users with cleaner, more predictable diff output.

## What Changes

- **Remove** `crates/output/src/diff_renderer.rs` (~1040 lines of custom diff rendering)
- **Remove** `crates/sexpr/src/diff.rs` `compute_diff()` and structural diff logic (~300 lines)
- **Keep** `ChangeType` enum in `diff.rs` (may be used elsewhere)
- **Add** `similar` crate dependency for text-based diff generation
- **Modify** `cmd_migrate.rs` to generate unified text diff instead of CST diff
- **Update** error message from "Migration would modify N form(s)" to "Config file would be modified"
- **Change** interactive prompt from `[Y/n]` to `[y/N]` (safer default)
- **Update** tests to use snapshot testing with `insta` for diff output verification
- **Remove** dependencies: `minus` and `unicode_width` from `crates/output`

## Capabilities

### New Capabilities
- `simplified-migration-diff`: Text-based diff output with context lines for migration changes

### Modified Capabilities
- `migration-diff-display`: Changed from CST-based two-column rendering to text-based unified diff with file path header

## Impact

- **User-facing**: Migration diff output changes from two-column layout to simplified unified diff format with file path header
- **Dependencies**: Adds `similar` crate, removes `minus` and `unicode_width` from output crate
- **Code reduction**: ~900 lines deleted
- **Safety**: Interactive prompt now defaults to "no" (cancel) instead of "yes" (apply)
