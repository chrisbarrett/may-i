## 1. Refactor parse_config for reuse

- [x] 1.1 Extract `parse_config_from_sexprs(forms: &[Sexpr])` function from `parse_config()` in `crates/config/src/config.rs`
- [x] 1.2 Update `parse_config(input: &str)` to call `parse()` then `parse_config_from_sexprs()`
- [x] 1.3 Verify all existing tests pass after refactoring

## 2. Implement transparent migration in load()

- [x] 2.1 Modify `load()` in `crates/config/src/io.rs` to attempt normal parsing first
- [x] 2.2 On parse failure: parse CST, migrate forms, convert to Sexpr, retry parsing
- [x] 2.3 Add warning message to stderr when migration is applied
- [x] 2.4 Return original error if both normal parse and migration fail
- [x] 2.5 Add unit test: legacy config with wrapper forms loads successfully
- [x] 2.6 Add unit test: already migrated config skips migration (no warning)
- [x] 2.7 Add unit test: invalid config returns original error

## 3. Verify span preservation

- [x] 3.1 Add integration test: error in migrated config reports correct line number
- [x] 3.2 Add integration test: parse error in unmodified section shows correct context
- [x] 3.3 Verify spans flow through: CST → migrate → Sexpr → AST

## 4. Integration verification

- [x] 4.1 Test `may-i eval` with legacy config (should work with warning)
- [x] 4.2 Test `may-i check` with legacy config (should work with warning)
- [x] 4.3 Test `may-i migrate` still works correctly
- [x] 4.4 Run full test suite (`cargo test`)
- [x] 4.5 Run lint and format checks
