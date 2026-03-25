# Design: Migration Form-Wise Diff

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        cmd_migrate                               │
├─────────────────────────────────────────────────────────────────┤
│  1. Detect terminal width (or use --width override)             │
│  2. Parse input → CST forms                                      │
│  3. For each form:                                               │
│     - Serialize original                                         │
│     - Apply migration rules                                      │
│     - Serialize migrated                                         │
│     - If different: collect with context                         │
│  4. Render diff (side-by-side or vertical)                      │
│  5. If interactive: prompt for confirmation                     │
│  6. Apply or abort based on response                            │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow

```
Input File
    │
    ▼
┌──────────────┐
│ parse_cst()  │──→ Vec<CstNode> (with trivia)
└──────────────┘
    │
    ▼
┌────────────────────────────────────────┐
│ For each form:                         │
│   original = serialize(form)           │
│   migrated = migrate(form)             │
│   if original != migrated:             │
│     extract_context(form)              │
│     collect(MigrationDiff {            │
│       before, after, context_before,   │
│       context_after                    │
│     })                                 │
└────────────────────────────────────────┘
    │
    ▼
┌────────────────────────────────────────┐
│ Render:                                │
│   if term_width >= 80:                 │
│     side-by-side(columns / 2 - 2)      │
│   else:                                │
│     vertical(original, migrated)       │
└────────────────────────────────────────┘
    │
    ▼
┌────────────────────────────────────────┐
│ If TTY and not --yes:                  │
│   prompt("Apply migration? [Y/n] ")    │
│   if !confirmed: exit 0                │
│ write output                           │
└────────────────────────────────────────┘
```

## Key Data Structures

```rust
/// A single form that will be migrated
pub struct MigrationDiff {
    /// Original form text (with trivia)
    pub before: String,
    /// Migrated form text
    pub after: String,
    /// Up to 2 lines of trivia before the form
    pub context_before: Vec<String>,
    /// Up to 2 lines of trivia after the form
    pub context_after: Vec<String>,
    /// Span in original file (for error reporting)
    pub span: Span,
}

/// Result of analyzing a config for migration
pub struct MigrationAnalysis {
    /// Forms that will change
    pub diffs: Vec<MigrationDiff>,
    /// Forms that couldn't be parsed (with context)
    pub errors: Vec<MigrationError>,
    /// Forms that remained unchanged
    pub unchanged_count: usize,
}

/// Error with context for display
pub struct MigrationError {
    pub message: String,
    pub span: Span,
    pub context_before: Vec<String>,
    pub context_after: Vec<String>,
}
```

## Rendering Logic

### Side-by-Side Layout (≥80 columns)

```
Available width = term_width - separator(3) - padding(2)
Column width = available_width / 2

┌───────────────────────────┬───────────────────────────┐
│ ;; Wrappers               │ ;; Wrappers               │
│                           │                           │
│ (wrapper "nohup"          │ (rule "nohup"             │
│   :command+args)          │   . (may-i *)             │
│                           │   (effect :allow))        │
├───────────────────────────┼───────────────────────────┤
│ (defcontext write-ok ...) │ (define write-ok ...)     │
└───────────────────────────┴───────────────────────────┘
```

### Vertical Layout (<80 columns)

```
BEFORE:
  ;; Wrappers
  
  (wrapper "nohup"
    :command+args)

AFTER:
  ;; Wrappers
  
  (rule "nohup"
    . (may-i *)
    (effect :allow))
```

## Trivia Extraction

The CST preserves trivia (comments, whitespace) as annotations on nodes. To extract context:

1. For a given form, look at its `leading` trivia
2. Collect up to 2 lines worth of trivia (counting newlines in whitespace/comments)
3. Do the same for `trailing` trivia
4. Render these before/after the form in the diff

```rust
fn extract_context(form: &CstNode, lines: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut line_count = 0;
    
    for trivia in &form.annotation.leading {
        let text = trivia.as_str();
        result.push(text.to_string());
        line_count += text.matches('\n').count();
        if line_count >= lines {
            break;
        }
    }
    
    result
}
```

## Interactive Prompt

Abstract terminal interaction behind a trait for testability:

```rust
pub trait PromptHandler {
    fn is_tty(&self) -> bool;
    fn prompt(&self, message: &str) -> io::Result<String>;
}

pub struct RealPromptHandler;
pub struct MockPromptHandler {
    responses: Vec<String>,
}
```

## Error Display

Parse errors show the error location with surrounding context:

```
Error: unexpected character: '~'
  │
  │     (rule "rm" (args (regex "^/tmp/~")))
  │                             ^
  │
```

## Testing Strategy

1. **Unit tests**: Trivia extraction, terminal width calculation
2. **Integration tests**: Full migration flows with mock prompts
3. **Snapshot tests**: Diff output for sample configs

## Reuse of Existing Code

| Component | Source | Usage |
|-----------|--------|-------|
| Terminal width detection | `crates/output/src/lib.rs:16-22` | `term_width()` |
| Layout calculation | `crates/output/src/lib.rs:30-34` | `Layout { left_width }` |
| Table/Row/Cell | `crates/output/src/lib.rs:47-102` | Two-column layout |
| Pretty-printing | `crates/pp/src/lib.rs:224` | `pretty(doc, indent, &fmt)` |
| CST parsing | `crates/sexpr/src/cst.rs:264` | `parse()` with trivia |
| Migration rules | `crates/config/src/v2/migrate.rs` | `migrate_forms()` |
