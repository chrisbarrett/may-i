## Why

The codebase currently maintains dual v1/v2 implementations with legacy code archived and duplicated. This creates maintenance overhead, confusion about which code paths are active, and prevents achieving comprehensive test coverage. We need to consolidate on v2 as the single implementation and remove all v1 artifacts to simplify the architecture and ensure complete test coverage.

## What Changes

- **BREAKING**: Remove all v1 code from `archive/v1/` directory (engine, core, config)
- **BREAKING**: Delete `crates/engine/src/lib_v1.rs` (legacy v1 engine re-export)
- Consolidate v2 as the sole implementation across all crates
- Audit and remove any v1 compatibility code paths from active codebase
- Write comprehensive tests to achieve 90% code coverage across all crates
- Update documentation to reflect v2-only architecture

## Capabilities

### New Capabilities
- `test-coverage-90`: Comprehensive test suite achieving 90% line coverage across all workspace crates

### Modified Capabilities
- `engine-v2-only`: Migrate from dual v1/v2 support to v2-only evaluation
- `config-v2-only`: Consolidate config parsing to v2 format only
- `codebase-cleanup`: Remove archived v1 code and legacy compatibility layers

## Impact

- **Code deletion**: Entire `archive/v1/` directory (~500KB of dead code)
- **Simplified engine**: Single v2 evaluator path in `crates/engine/src/lib.rs`
- **Config**: v2 format becomes the only supported format
- **Test coverage**: New test files and expanded test suites across all crates
- **Build time**: Faster compilation due to reduced code volume
- **Maintenance**: Eliminated dual-path complexity and confusion

## Acceptance Criteria

- [ ] All v1 code removed from archive and active codebase
- [ ] `cargo test` passes with zero v1-related code
- [ ] 90% line coverage achieved (measured via `cargo tarpaulin` or `cargo llvm-cov`)
- [ ] No breaking changes to v2 public APIs
- [ ] Documentation updated to remove v1 references
