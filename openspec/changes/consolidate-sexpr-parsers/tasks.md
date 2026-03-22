## 1. Implement CST to Sexpr Conversion

- [ ] 1.1 Add `to_sexpr()` method to `CstNode<TriviaAnn>` in `crates/sexpr/src/cst.rs`
- [ ] 1.2 Handle `ShapeF::Atom` conversion to `Sexpr::Atom`
- [ ] 1.3 Handle `ShapeF::Str` conversion to `Sexpr::Atom` with quotes
- [ ] 1.4 Handle `ShapeF::List` conversion to `Sexpr::List` recursively
- [ ] 1.5 Handle `ShapeF::Vector` conversion to `Sexpr::Vector` recursively
- [ ] 1.6 Add unit tests for `to_sexpr()` method

## 2. Update Public API

- [ ] 2.1 Modify `may_i_sexpr::parse()` to use `parse_cst()` internally
- [ ] 2.2 Convert CST results to Sexpr using `to_sexpr()`
- [ ] 2.3 Ensure backward compatibility - all existing tests pass

## 3. Remove Sexpr Parser

- [ ] 3.1 Remove tokenization code from `sexpr.rs` (~300 lines)
- [ ] 3.2 Remove parsing logic from `sexpr.rs` (~400 lines)
- [ ] 3.3 Keep `Sexpr` enum definition and view methods (`as_atom()`, `as_list()`, etc.)
- [ ] 3.4 Keep `Display` implementation for `Sexpr`
- [ ] 3.5 Update `lib.rs` exports if needed

## 4. Add Generative Tests

- [ ] 4.1 Add `proptest` dependency to `crates/sexpr/Cargo.toml`
- [ ] 4.2 Create arbitrary s-expression generator for property testing
- [ ] 4.3 Implement roundtrip property: `parse(serialize(cst)) == cst`
- [ ] 4.4 Add edge case tests for multi-line expressions
- [ ] 4.5 Add edge case tests for deeply nested structures
- [ ] 4.6 Verify all existing tests still pass

## 5. Validation and Cleanup

- [ ] 5.1 Run full test suite: `cargo test --all`
- [ ] 5.2 Run clippy: `cargo clippy --all`
- [ ] 5.3 Run formatter: `cargo fmt`
- [ ] 5.4 Verify `may-i migrate` works on real config
- [ ] 5.5 Check code coverage improvement
- [ ] 5.6 Document any API changes in crate documentation
