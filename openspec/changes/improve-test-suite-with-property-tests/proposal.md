## Why

The test suite has grown to over 1,500 individual test cases, with the shell parser alone containing 3,800+ lines of example-based tests. This creates maintenance burden—tests break on refactors, edge cases are missed, and adding new features requires writing dozens of new test cases. Property-based testing has proven effective in the core types (Decision lattice, Expr boolean algebra) but is underutilized in the parser and glob matching modules. We need to consolidate redundant tests and add property tests to improve coverage while reducing maintenance overhead.

## What Changes

- **Add property tests for glob matching** - Replace ~50 individual glob pattern tests with 4-5 property tests covering roundtrip, equivalence, and edge cases
- **Add property tests for parameter expansion** - Replace ~100 individual operator tests with properties covering default values, strip operations, replacement, substring, and case conversion
- **Add property tests for word resolution** - Test that resolution is idempotent and concatenation distributes over resolution
- **Add visitor module tests** - The visitors/ directory currently has zero tests; add integration tests for code_execution, function_call, read_builtin, and wrapper_unwrap visitors
- **Consolidate shell parser tests** - Reduce 3,800+ lines of pattern-matching tests to focus on behavioral tests rather than structural assertions
- **Add error path coverage** - Add tests for invalid regex patterns, malformed configs, circular defines, and type errors

## Capabilities

### New Capabilities

- `glob-property-tests`: Property-based testing for glob matching operations ensuring algebraic properties hold
- `param-expansion-property-tests`: Property-based testing for parameter expansion operators
- `visitor-integration-tests`: Integration test suite for AST visitor modules
- `shell-parser-consolidation`: Consolidated behavioral tests for shell parser reducing structural coupling

### Modified Capabilities

- None (this is test infrastructure improvement only)

## Impact

- **Test maintenance**: Reduced from 1,500+ individual tests to ~1,200 with better coverage
- **Refactor resilience**: Property tests verify behavior, not structure, reducing breakage during refactoring
- **CI time**: May increase slightly due to property test iterations, but offset by reduced test count
- **Developer experience**: Fewer brittle tests to update when changing internal AST structures
- **Coverage**: Improved edge case detection through property-based generation
- **Dependencies**: No new runtime dependencies; proptest already used in core/, engine/, sexpr/, pp/ crates

## Success Criteria

- Glob matching: All existing test cases covered by properties
- Parameter expansion: 100+ individual tests replaced with <20 property/parameterized tests
- Visitor modules: Minimum 80% code coverage
- Shell parser: 3,800 lines reduced to <2,500 while maintaining equivalent coverage
- All existing CI checks pass
