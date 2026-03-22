# Tasks: Migration Diff Pretty-Print

## Phase 1: CST Refactor

- [ ] Create `ShapeF<R>` base functor with `map`/`map_ref`
- [ ] Refactor `CstNode` to `CstNode<A>` with generic annotation
- [ ] Implement `map` (functor) for `CstNode<A>`
- [ ] Implement `fold` (catamorphism) for `CstNode<A>`
- [ ] Migrate existing CST code to new structure
- [ ] Add tests for functor laws
- [ ] Add tests for fold correctness

## Phase 2: Diff Module

- [ ] Create `ChangeType` enum
- [ ] Create `DiffAnn` struct
- [ ] Define `PlainCst` and `DiffCst` type aliases
- [ ] Implement `compute_diff` function
- [ ] Add property tests for diff computation
- [ ] Handle edge cases (insertions, deletions, moves)

## Phase 3: Diff Rendering

- [ ] Create `DiffConfig` struct
- [ ] Implement `render_diff` function
- [ ] Add two-column layout logic
- [ ] Add inline diff fallback (<80 cols)
- [ ] Add fold markers for unchanged sections
- [ ] Pretty-print via pp crate
- [ ] Add tests for rendering

## Phase 4: Pager Integration

- [ ] Add `minus` to Cargo.toml
- [ ] Create `display_with_pager` function
- [ ] Integrate into `cmd_migrate`
- [ ] Handle TTY detection
- [ ] Add tests with mock pager

## Phase 5: Migration Command Update

- [ ] Update `cmd_migrate` to use new diff system
- [ ] Remove old diff rendering code
- [ ] Update CLI args if needed
- [ ] Add integration tests
- [ ] Update documentation

## Phase 6: Cleanup

- [ ] Run clippy
- [ ] Run tests
- [ ] Check test coverage
- [ ] Update README
- [ ] Archive old change

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
