## 1. Implement CST to Sexpr Conversion

- [x] 1.1 Add `to_sexpr()` method to `CstNode<TriviaAnn>` in `crates/sexpr/src/cst.rs`
- [x] 1.2 Handle `ShapeF::Atom` conversion to `Sexpr::Atom`
- [x] 1.3 Handle `ShapeF::Str` conversion to `Sexpr::Atom` with quotes
- [x] 1.4 Handle `ShapeF::List` conversion to `Sexpr::List` recursively
- [x] 1.5 Handle `ShapeF::Vector` conversion to `Sexpr::Vector` recursively
- [x] 1.6 Add unit tests for `to_sexpr()` method

## 2. Update Public API

- [x] 2.1 Modify `may_i_sexpr::parse()` to use `parse_cst()` internally
- [x] 2.2 Convert CST results to Sexpr using `to_sexpr()`
- [x] 2.3 Ensure backward compatibility - all existing tests pass

## 3. Remove Sexpr Parser

- [x] 3.1 Remove tokenization code from `sexpr.rs` (~300 lines)
- [x] 3.2 Remove parsing logic from `sexpr.rs` (~400 lines)
- [x] 3.3 Keep `Sexpr` enum definition and view methods (`as_atom()`, `as_list()`, etc.)
- [x] 3.4 Keep `Display` implementation for `Sexpr`
- [x] 3.5 Update `lib.rs` exports if needed

## 4. Add Generative Tests

- [x] 4.1 Add `proptest` dependency to `crates/sexpr/Cargo.toml`
- [x] 4.2 Create arbitrary s-expression generator for property testing
- [x] 4.3 Implement roundtrip property: `parse(serialize(cst)) == cst`
- [x] 4.4 Add edge case tests for multi-line expressions
- [x] 4.5 Add edge case tests for deeply nested structures
- [x] 4.6 Verify all existing tests still pass

## 5. Validation and Cleanup

- [x] 5.1 Run full test suite: `cargo test --all`
- [x] 5.2 Run clippy: `cargo clippy --all`
- [x] 5.3 Run formatter: `cargo fmt`
- [x] 5.4 Verify `may-i migrate` works on real config
- [x] 5.5 Check code coverage improvement
- [x] 5.6 Document any API changes in crate documentation
