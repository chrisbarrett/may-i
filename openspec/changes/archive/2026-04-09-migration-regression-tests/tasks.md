## 1. Evaluation equivalence test infrastructure

- [x] 1.1 Create crates/config/src/migrate/regression_tests.rs module
- [x] 1.2 Build eval-equivalence test helper: takes v1 config string, test commands/args/facts, verifies migrated config produces same decisions

## 2. Compound form eval-equivalence tests

- [x] 2.1 Write test: rule with (command) + (context) + (args) combined
- [x] 2.2 Write test: compound context with nested has key-value
- [x] 2.3 Write test: multi-clause cond inside args
- [x] 2.4 Write test: named predicate reference via defcontext

## 3. Wrapper migration tests

- [x] 3.1 Write test: timeout wrapper with positional regex + bare capture
- [x] 3.2 Write test: mise wrapper with positional + flag + -- separator + capture
- [x] 3.3 Write test: nix wrapper with positional or + flag with named option
- [x] 3.4 Write test: nix-shell wrapper with flag-only (no positional) + capture
- [x] 3.5 Write test: bash wrapper with single-char flag + capture

## 4. has → fact? with complex value patterns

- [x] 4.1 Write test: has with regex value pattern
- [x] 4.2 Write test: has with wildcard value
- [x] 4.3 Write test: has with or value pattern
- [ ] 4.4 Write test: has with compound value pattern (and + not)

## 5. Command patterns inside (command ...)

- [x] 5.1 Write test: (command (or "rm" "rmdir")) migration with eval equivalence
- [x] 5.2 Write test: (command (regex "^git-")) exact output verification
- [ ] 5.3 Write test: (command (or "cat" "head" "tail")) multi-element or

## 6. Comment/trivia preservation

- [x] 6.1 Write test: comments between top-level forms preserved
- [ ] 6.2 Write test: inline comments inside wrapper forms preserved
- [x] 6.3 Write test: multi-line comment blocks above rules preserved
- [x] 6.4 Write test: trailing comments on closing parens preserved

## 7. Mixed v1/v2 configs

- [x] 7.1 Write test: mixed syntax file — only v1 forms migrated
- [x] 7.2 Write test: idempotent on already-migrated config

## 8. Proptest generators for compound v1 forms

- [x] 8.1 Add any_v1_rule_with_context generator to property_tests.rs
- [x] 8.2 Add any_v1_rule_with_args generator
- [x] 8.3 Add any_v1_compound_rule generator (command + context + args)
- [ ] 8.4 Add any_v1_wrapper generator
- [ ] 8.5 Add any_v1_config generator mixing all form types
- [ ] 8.6 Add eval-equivalence property test for each new generator
