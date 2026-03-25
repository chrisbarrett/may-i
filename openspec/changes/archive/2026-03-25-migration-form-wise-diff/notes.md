# Implementation Notes: Migration Form-Wise Diff

## Critical Implementation Details

### CST String Type Preservation

**Issue**: The original CST parsed `"~/.config/tmux/custom.conf"` as `Shape::Atom("~/.config/tmux/custom.conf")`, losing the distinction between string literals and bare atoms.

**Solution**: Added `Shape::Str(String)` variant. String literals are now parsed as `Shape::Str` and bare atoms as `Shape::Atom`. During serialization:
- `Shape::Str` is always quoted: `"content"`
- `Shape::Atom` is never quoted: `atom-name`

**Why this matters**: Without this distinction, valid v1 syntax with quoted paths produces invalid v2 output when the quotes are stripped during serialization.

### Error Context Strategy

When migration validation fails, the error is returned as a `ConfigError` (which implements `miette::Diagnostic`) with:
- The original source text for context
- Proper span information for line/column display
- The config file path as the source name

This allows `main()` to print rich error output with source context using the miette handler hook.

### Unhandled Cases Detection

Originally, `check_unhandled_cases()` only checked forms that failed to migrate. This missed legacy syntax nested inside successfully migrated forms.

**Fixed**: Now checks ALL top-level forms regardless of migration status. The `check_node_unhandled()` function recursively searches for legacy v1 constructs like `wrapper`, `defcontext`, and `context`.

### Visitor Pattern

Added `Visitor` trait to CST for future validation passes:

```rust
pub trait Visitor {
    fn visit(&mut self, node: &CstNode) -> bool;
}

impl CstNode {
    pub fn accept<V: Visitor>(&self, visitor: &mut V) {
        if !visitor.visit(self) { return; }
        // recurse into children...
    }
}
```

Currently unused but available for future validation needs.

### Migration Pipeline Flow

1. **Parse**: CST parses source, preserving trivia (comments/whitespace)
2. **Analyze**: Compare original vs migrated forms to create diff
3. **Migrate**: Apply rewrite rules until convergence
4. **Validate**: Parse output with v2 parser to ensure validity
5. **Report**: If validation fails, return error with source context

### Testing Mock Objects

`MockPromptHandler` enables testing interactive prompts:

```rust
let handler = MockPromptHandler::new(
    vec!["y".to_string()],  // Simulated user inputs
    true                     // is_tty
);
```

The handler implements the `PromptHandler` trait, allowing `cmd_migrate_with_handler()` to test prompt logic without actual terminal interaction.

### Terminal Width Detection

Used for choosing diff layout:
- ≥80 columns: Side-by-side layout
- <80 columns: Vertical layout

Falls back to 80 columns if `COLUMNS` env var or `terminal_size` crate fails.

## Known Limitations

- Migration doesn't handle all v1→v2 transformations (e.g., complex `cond` forms)
- Side-by-side diff layout truncates long lines to fit terminal width
- Validation only reports the first parse error in the output
