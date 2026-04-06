## Context

The pretty printer in `crates/pp/src/lib.rs` currently has a function `emit_trivia_or_line` that handles rendering of leading trivia before child elements. The function has a bug: it only emits leading trivia when there are **comments** present. When there's only whitespace trivia (containing blank lines), it falls back to `begin_line(indent)` which emits only a single newline, collapsing multiple blank lines into one.

The relevant code is:
```rust
fn emit_trivia_or_line<A: TriviaSource>(...) {
    let leading = ann.leading_trivia();
    let has_comments = leading.iter().any(|t| matches!(t, Trivia::Comment { .. }));
    if has_comments {
        out.emit_leading_trivia(leading, indent);
    } else {
        out.begin_line(indent);  // Only emits ONE newline!
    }
}
```

The `emit_leading_trivia` function already knows how to handle blank lines from whitespace (see lines 283-293 in `lib.rs`), but it's only called when there are comments.

## Goals / Non-Goals

**Goals:**
- Preserve blank lines from whitespace-only trivia when rendering forms
- Ensure multiple consecutive blank lines between forms are maintained
- Keep the fix minimal and focused on the specific issue

**Non-Goals:**
- Rewriting the entire trivia handling system
- Changing how comments are handled (already working correctly)
- Modifying the output format beyond preserving blank lines

## Decisions

**Decision: Modify `emit_trivia_or_line` to check for blank lines in whitespace trivia**

Instead of just checking for comments, the function should:
1. Check if there's whitespace trivia containing multiple newlines
2. If so, emit those blank lines before calling `begin_line(indent)`
3. Fall back to the current behavior for simple single-newline cases

Rationale: This is the minimal change that fixes the issue without affecting other rendering paths. The `emit_leading_trivia` function already has logic to handle blank lines, but it's only invoked for comments.

## Risks / Trade-offs

**[Risk] Extra blank lines could accumulate in some edge cases** → Mitigation: Only emit blank lines from source-parsed nodes (nodes with `has_source_trivia()`), not from constructed nodes which have default/empty trivia.

**[Risk] Performance impact from additional whitespace scanning** → Mitigation: The scan is only done when there are no comments (rare case is simple whitespace), and the cost is minimal (just counting `\n` characters).
