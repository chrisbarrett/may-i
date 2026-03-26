## Context

The codebase currently has excellent property tests in `crates/core/src/types.rs` (Decision lattice, Expr boolean algebra) and `crates/engine/src/matcher.rs` (Matcher combinators). These use the `proptest` crate and test algebraic properties like commutativity, associativity, and De Morgan's laws.

However, other modules rely heavily on example-based testing:
- `crates/shell-parser/src/tests.rs`: 3,800+ lines of individual test cases
- `crates/shell-parser/src/tests.rs`: ~50 individual glob matching tests  
- `crates/shell-parser/src/tests.rs`: ~100 individual parameter expansion tests
- `crates/engine/src/visitors/`: Zero tests across all visitor modules

The pattern matching style used in many tests is brittle—tests break when internal AST structures change, even when behavior is preserved.

## Goals / Non-Goals

**Goals:**
- Add property tests for glob matching operations (roundtrip, equivalence, edge cases)
- Add property tests for parameter expansion operators (default, strip, replace, substring, case)
- Add property tests for word resolution (idempotence, distribution)
- Create integration tests for all visitor modules (minimum 80% coverage)
- Consolidate shell parser tests to focus on behavior, not structure
- Maintain or improve overall code coverage
- Ensure all existing CI checks pass

**Non-Goals:**
- No changes to production code behavior (tests only)
- No new runtime dependencies (proptest already available)
- No changes to public APIs
- No removal of test coverage (only consolidation)

## Decisions

### 1. Property Test Organization

**Decision**: Create `#[cfg(test)] mod prop_tests { ... }` submodules within existing test files rather than separate files.

**Rationale**: 
- Keeps related tests together
- Follows existing pattern in `crates/core/src/types.rs`
- Easier to find and maintain
- Allows sharing of test helpers

**Alternative considered**: Separate `tests/prop_*.rs` files. Rejected because it fragments test organization.

### 2. Glob Property Test Strategy

**Decision**: Test these properties:
- `∀ pattern, text: glob_match(pattern, text) == manual_backtrack(pattern, text)` - Reference implementation equivalence
- `∀ pattern: glob_match(pattern, "")` handles empty string correctly
- `∀ pattern with brackets: negation [!abc]` works as complement of `[abc]`
- `∀ pattern: strip_prefix(p, s) + remaining == s` when p matches prefix
- `∀ pattern: replace(pattern, text, replacement, all)` replaces correct number of occurrences

**Rationale**: These cover algebraic properties without requiring a formal specification.

### 3. Parameter Expansion Property Test Strategy

**Decision**: Test operators by their mathematical properties:
- **Default** `${VAR:-default}`: if var empty/unset, result equals default
- **Strip** `${VAR##pattern}`: result + matched_portion = original when pattern matches
- **Replace** `${VAR//old/new}`: all occurrences replaced when all=true
- **Substring** `${VAR:offset}`: negative offset counts from end
- **Case** `${VAR^^}` ∘ `${VAR,,}` ≈ identity for ASCII

**Rationale**: Each operator has a clear contract that can be expressed as a property.

### 4. Visitor Test Strategy

**Decision**: Integration tests that verify visitors correctly traverse AST structures.

**Test approach**:
- Parse known shell commands
- Run visitor over AST
- Verify visitor collected/transformed expected nodes
- Test edge cases: empty AST, deeply nested structures, mixed command types

**Rationale**: Visitors are inherently about tree traversal—integration tests capture this better than unit tests.

### 5. Shell Parser Test Consolidation

**Decision**: Replace structural pattern-matching tests with behavioral assertions.

**Before**:
```rust
match &cmd {
    Command::Simple(sc) => assert_eq!(sc.command_name(), Some("echo")),
    _ => panic!("..."),
}
```

**After**:
```rust
let words = extract_all_words(&cmd);
assert!(words.contains(&"echo".into()));
```

**Rationale**: Behavioral tests survive refactors; structural tests don't.

### 6. Test Helpers

**Decision**: Create shared test utilities in `crates/shell-parser/src/test_helpers.rs` (compile-gated with `#[cfg(test)]`).

**Helpers needed**:
- `parse_cmd(input: &str) -> Command` - Parse with panic on error
- `assert_words(cmd: &Command, expected: &[&str])` - Check words present
- `assert_no_dynamic(cmd: &Command)` - Verify no dynamic parts

## Risks / Trade-offs

**[Risk] Property tests may be slower than unit tests**
→ Mitigation: Use `proptest_config` to limit cases in CI (100 cases default, 1000 for release). Document in contributing guide.

**[Risk] Shrinking may produce confusing minimal cases**
→ Mitigation: Add clear failure messages showing original and shrunk input. Use `prop_assert!` with descriptive messages.

**[Risk] Property tests may miss specific regression cases**
→ Mitigation: Keep critical regression tests as example-based. Properties supplement, don't replace, where specific behavior matters.

**[Risk] Visitor tests may be flaky due to AST ordering**
→ Mitigation: Sort collections before comparison or use `HashSet` assertions.

**[Trade-off] Consolidation reduces test granularity**
→ Acceptance: Behavioral tests catch semantic bugs but may miss subtle structural issues. Acceptable trade-off for refactor resilience.

## Migration Plan

This change is test-only and requires no production migration.

**Rollout**:
1. Add property tests (new test modules, no impact on existing)
2. Consolidate shell parser tests (deletes tests, verified by CI)
3. Add visitor tests (new coverage)
4. Verify coverage report shows no regression

**Rollback**: 
- Revert individual commits if issues found
- No database or state migrations involved

## Open Questions

1. Should we use `proptest`'s `fork` feature for property tests to isolate failures?
2. What's the right balance of property vs example tests for glob edge cases (malformed brackets, etc.)?
3. Should visitor tests be in `tests/` directory (integration) or inline (unit)?
