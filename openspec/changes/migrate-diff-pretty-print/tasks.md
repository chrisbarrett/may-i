# Tasks: Migration Diff Pretty-Print

## Phase 1: CST Refactor

- [x] Create `ShapeF<R>` base functor with `map`/`map_ref`
- [x] Refactor `CstNode` to `CstNode<A>` with generic annotation
- [x] Implement `map` (functor) for `CstNode<A>`
- [x] Implement `fold` (catamorphism) for `CstNode<A>`
- [x] Migrate existing CST code to new structure
- [x] Add tests for functor laws
- [x] Add tests for fold correctness

## Phase 2: Diff Module

- [x] Create `ChangeType` enum
- [x] Create `DiffAnn` struct
- [x] Define `PlainCst` and `DiffCst` type aliases
- [x] Implement `compute_diff` function
- [x] Add property tests for diff computation
- [x] Handle edge cases (insertions, deletions, moves)

## Phase 3: Diff Rendering

- [x] Create `DiffConfig` struct
- [x] Implement `render_diff` function
- [x] Add two-column layout logic
- [x] Add inline diff fallback (<80 cols)
- [x] Add fold markers for unchanged sections
- [x] Pretty-print via pp crate
- [x] Add tests for rendering

## Phase 4: Pager Integration

- [x] Add `minus` to Cargo.toml
- [x] Create `display_with_pager` function
- [x] Integrate into `cmd_migrate`
- [x] Handle TTY detection
- [x] Add tests with mock pager

## Phase 5: Migration Command Update

- [x] Update `cmd_migrate` to use new diff system
- [x] Remove old diff rendering code
- [x] Update CLI args if needed
- [x] Add integration tests
- [x] Update documentation

## Phase 6: Cleanup

- [x] Run clippy
- [x] Run tests
- [x] Check test coverage
- [x] Update README
- [x] Archive old change

## Notes

### Dependency Graph
```
CST Refactor
    ↓
Diff Module
    ↓
Diff Rendering
    ↓
Pager Integration
    ↓
Migration Update
```

### Estimated Effort
- Phase 1: 4 hours
- Phase 2: 3 hours
- Phase 3: 4 hours
- Phase 4: 2 hours
- Phase 5: 3 hours
- Phase 6: 2 hours
- **Total**: ~18 hours
