## 1. Core Types

- [ ] 1.1 Add `checks: Vec<Check>` field to `Config` struct in `crates/core/src/types.rs`
- [ ] 1.2 Update `Config::default()` to initialize empty checks vector

## 2. Parser

- [ ] 2.1 Add `"check"` case to top-level form match in `parse_raw()` in `crates/config/src/parse/mod.rs`
- [ ] 2.2 Call `parse_check_items()` for top-level check forms, passing `ContextFacts::default()`
- [ ] 2.3 Accumulate parsed checks into a local vector and add to `Config`
- [ ] 2.4 Update error message for unknown top-level forms to include `check`

## 3. Check Execution

- [ ] 3.1 Update `run_checks()` in `crates/engine/src/check.rs` to iterate `config.checks` after embedded checks
- [ ] 3.2 Ensure top-level checks get proper `location` info from `source_info`

## 4. Testing

- [ ] 4.1 Add parser test: simple top-level check parses
- [ ] 4.2 Add parser test: top-level check with `with-facts` parses
- [ ] 4.3 Add parser test: multiple top-level checks
- [ ] 4.4 Add integration test: top-level check evaluates against rules
- [ ] 4.5 Add integration test: top-level and embedded checks coexist

## 5. Documentation

- [ ] 5.1 Update config format documentation with top-level check examples
