# Migration Diff Pretty-Print

## Problem Statement

The current `may-i migrate --diff` command has several rendering issues:

1. **No pretty-printing**: Shows raw serialized CST instead of nicely formatted s-expressions
2. **Broken output**: The wrapper→rule migration produces malformed output (missing parens)
3. **Line-based diff**: Hard to read for Lisp code where forms span multiple lines
4. **No interactive pager**: Output may scroll off screen in large configs

## Proposed Solution

Refactor the CST to a fixpoint-of-functor pattern (matching `Doc<A>`), then build a form-wise diff mechanism on top:

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. CST Refactor                                                  │
│    CstNode<A> with ShapeF<R> base functor                        │
│    → Functor map, Catamorphism fold                              │
├─────────────────────────────────────────────────────────────────┤
│ 2. Diff Annotation                                               │
│    DiffAnn { trivia, change: Unchanged|Modified|Deleted }         │
│    → CstNode<DiffAnn> carries diff status                        │
├─────────────────────────────────────────────────────────────────┤
│ 3. Diff Rendering                                                │
│    Two-column layout with line numbers (LHS only)                │
│    Fold markers (⋮) for unchanged sections                       │
│    Pretty-printed via pp crate                                   │
│    Paged via minus crate                                         │
└─────────────────────────────────────────────────────────────────┘
```

## Success Criteria

1. `may-i migrate --diff` shows pretty-printed before/after
2. Two-column layout for terminals ≥80 columns
3. Line numbers on left column (input file lines)
4. Centered ellipsis (⋮) as fold marker
5. Built-in pager (minus) for long output
6. Inline diff fallback for narrow terminals

## Out of Scope

- Typed AST refactor (separate change)
- External pager support (no env vars)
- Syntax highlighting in diff (use pp's colorization)

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| CST refactor breaks existing code | High | Comprehensive tests, gradual migration |
| Performance of diff computation | Low | O(n) tree walk, lazy evaluation |
| Pager dependency adds complexity | Medium | minus is lightweight, optional in tests |
