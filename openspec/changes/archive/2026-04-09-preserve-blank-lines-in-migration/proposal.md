## Why

The `may-i migrate` command currently collapses blank lines between forms into single newlines, losing intentional formatting structure in user config files. Users expect empty lines between forms to be preserved during migration, as they serve as visual separators for logical groupings in their policy definitions.

## What Changes

- Modify the pretty printer's `emit_trivia_or_line` function to preserve blank lines from whitespace-only trivia
- When rendering children with only whitespace trivia (no comments), count the newlines in that whitespace and emit the appropriate number of blank lines before the form
- Ensure the fix works for both top-level forms and nested forms within lists (e.g., `check` forms)

## Capabilities

### New Capabilities
<!-- None - this is a bug fix to existing capability -->

### Modified Capabilities
- `pretty-printer`: The whitespace trivia handling behavior is changing to preserve blank lines between forms, not just comments.

## Impact

- Affects the `may-i-pp` crate's `lib.rs` file, specifically the `emit_trivia_or_line` function
- Migration output will preserve user-intended blank line spacing
- No breaking changes to public APIs or behavior beyond the intended fix
