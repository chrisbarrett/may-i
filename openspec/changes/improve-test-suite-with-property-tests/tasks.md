## 1. Setup and Infrastructure

- [x] 1.1 Add proptest dependency to shell-parser/Cargo.toml if not present
- [x] 1.2 Create test_helpers.rs module in shell-parser/src/ with shared utilities
- [x] 1.3 Implement parse_cmd helper function
- [x] 1.4 Implement assert_words helper function  
- [x] 1.5 Implement assert_no_dynamic helper function
- [x] 1.6 Run full test suite to establish baseline coverage metrics

## 2. Glob Property Tests

- [x] 2.1 Create prop_tests module in shell-parser/src/glob.rs or tests.rs
- [x] 2.2 Implement reference_backtrack_match function for comparison
- [x] 2.3 Add property: glob_match equivalence with reference implementation
- [x] 2.4 Add property: empty string handling for all patterns
- [x] 2.5 Add property: negation bracket is complement of positive bracket
- [x] 2.6 Add property: strip_prefix preserves remainder (inverse operation)
- [x] 2.7 Add property: strip_suffix preserves prefix (inverse operation)
- [x] 2.8 Add property: replace all vs first only behavior
- [x] 2.9 Add property: no-match returns original unchanged
- [ ] 2.10 Verify glob property tests cover all existing example test cases
- [ ] 2.11 Remove redundant example-based glob tests (keep edge cases)

## 3. Parameter Expansion Property Tests

- [x] 3.1 Create prop_tests module for parameter expansion operators
- [x] 3.2 Add property: default operator with colon uses empty check
- [x] 3.3 Add property: default operator without colon only checks unset
- [x] 3.4 Add property: shortest prefix strip removes minimal match
- [x] 3.5 Add property: longest prefix strip removes maximal match
- [x] 3.6 Add property: shortest suffix strip removes minimal match
- [x] 3.7 Add property: longest suffix strip removes maximal match
- [x] 3.8 Add property: replace first only affects first occurrence
- [x] 3.9 Add property: replace all affects all occurrences
- [x] 3.10 Add property: substring with positive offset
- [x] 3.11 Add property: substring with negative offset counts from end
- [x] 3.12 Add property: substring with length limits result
- [x] 3.13 Add property: case conversion roundtrip for ASCII
- [ ] 3.14 Verify param expansion property tests cover all existing example cases
- [ ] 3.15 Consolidate example-based param expansion tests (keep regressions)

## 4. Word Resolution Property Tests

- [x] 4.1 Create prop_tests module for word resolution
- [x] 4.2 Add property: resolution is idempotent (resolve(resolve(w)) == resolve(w))
- [x] 4.3 Add property: concatenation distributes over resolution
- [x] 4.4 Add property: words without dynamic parts resolve to themselves
- [x] 4.5 Add property: resolution preserves word count for static words
- [ ] 4.6 Verify word resolution tests cover existing cases

## 5. Visitor Integration Tests

- [x] 5.1 Create tests/visitors.rs integration test file
- [x] 5.2 Add test: code_execution visitor detects eval commands
- [x] 5.3 Add test: code_execution visitor detects command substitution
- [x] 5.4 Add test: code_execution visitor detects source/dot commands
- [x] 5.5 Add test: function_call visitor tracks function definitions
- [x] 5.6 Add test: function_call visitor tracks function invocations
- [x] 5.7 Add test: function_call visitor handles nested functions
- [x] 5.8 Add test: read_builtin visitor detects read commands
- [x] 5.9 Add test: read_builtin visitor extracts prompt and variable
- [x] 5.10 Add test: read_builtin visitor handles read -a array
- [x] 5.11 Add test: wrapper_unwrap visitor detects sudo wrapper
- [x] 5.12 Add test: wrapper_unwrap visitor detects ssh wrapper
- [x] 5.13 Add test: wrapper_unwrap visitor detects docker exec/run
- [x] 5.14 Add test: wrapper_unwrap visitor handles nested wrappers
- [x] 5.15 Add test: all visitors handle empty AST gracefully
- [x] 5.16 Add test: all visitors handle deeply nested structures
- [ ] 5.17 Verify visitor code coverage is at least 80%

## 6. Shell Parser Test Consolidation

- [ ] 6.1 Audit current 3,800+ lines of parser tests
- [ ] 6.2 Identify tests that verify behavior (keep these)
- [ ] 6.3 Identify tests that verify structure (migrate to behavioral)
- [ ] 6.4 Identify critical regression tests (preserve these)
- [ ] 6.5 Create behavioral equivalents using test helpers
- [ ] 6.6 Remove redundant structural pattern-matching tests
- [ ] 6.7 Verify all heredoc edge cases are preserved
- [ ] 6.8 Verify all quote handling edge cases are preserved
- [ ] 6.9 Verify all parameter expansion edge cases are preserved
- [ ] 6.10 Ensure parser test file is under 2,500 lines

## 7. Error Path Coverage

- [ ] 7.1 Add tests for invalid regex patterns in rules
- [ ] 7.2 Add tests for malformed config syntax recovery
- [ ] 7.3 Add tests for circular define references
- [ ] 7.4 Add tests for type errors in fact lookups
- [ ] 7.5 Add tests for unclosed quotes in shell parser
- [ ] 7.6 Add tests for unclosed substitutions

## 8. Verification and Cleanup

- [ ] 8.1 Run full test suite and verify all tests pass
- [ ] 8.2 Generate coverage report and verify no regression
- [ ] 8.3 Verify property tests complete in reasonable time (< 2x baseline)
- [ ] 8.4 Run cargo fmt on all modified files
- [ ] 8.5 Run cargo clippy and fix any warnings
- [ ] 8.6 Update any documentation referencing old test patterns
- [ ] 8.7 Verify test count reduced from 1,500+ to ~1,200
- [ ] 8.8 Final review of all changes
