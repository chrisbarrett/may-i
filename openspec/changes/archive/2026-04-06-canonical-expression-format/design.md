# Design: Canonical Expression Format

## Overview

The canonical expression format is defined by the interaction of several
mechanisms in the pretty-printer.

## Indent Specification System

Modeled after Emacs Lisp `(declare (indent N))`:

```rust
pub const INDENT_SPECS: &[(&str, u8)] = &[
    ("cond", 0),      // All children are body
    ("define", 1),    // Name special, rest body
    ("if", 2),        // Pred + then special, else body
    ("rule", 1),      // Pattern special, rest body
    ("unless", 1),    // Pred special, rest body
    ("when", 1),      // Pred special, rest body
    ("with-facts", 1), // Facts special, rest body
];
```

N=2 for `if` creates the asymmetric indentation:
- Pred: special-1 (stays on head line)
- Then: special-2 (+4 indent, aligns under pred)
- Else: body (+2 indent)

## Fill Layout

Trigger: `is_fill_eligible(children)` returns true when:
- Head is `"and"` or `"or"`
- All children after head are atoms

Algorithm (`render_fill`):
1. Render head: `(and `
2. First arg follows immediately
3. For each subsequent arg:
   - If fits on current line: space + arg
   - Else: newline + align under first arg + arg
4. Close paren

This packs many short atoms efficiently:
```
(and "foo" "bar" "baz"
     "qux" "quux")
```

## Dead Code Removal

`case` was renamed to `cond` before release. Remove:
1. `("case", 0)` from INDENT_SPECS (line ~641)
2. `"case"` from colored keywords list (line ~139)
3. `head == "case"` check in render path (line ~760)

## Function Rename

`args_cond_to_case` → `hoist_cond`

The function lifts cond expressions from `(args (cond ...))` position into rule
bodies. "Hoist" better describes this transformation than the old name which
implied creating a `case` form (it creates a `cond` form).

## Testing Strategy

1. Existing tests cover the formatting behavior:
   - `if_indent_spec_is_2`: Verifies asymmetric indent
   - `or_atoms_fill_layout`: Verifies fill layout
   - `and_atoms_fill_layout`: Verifies fill layout

2. After cleanup:
   - Run all pp tests
   - Run migration tests
   - Run `cargo run -- migrate` on sample config

## Files Modified

- `crates/pp/src/lib.rs`: Remove `case` references
- `crates/config/src/migrate.rs`: Rename function
