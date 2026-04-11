## 1. Fix Unicode width in layout crate

- [x] 1.1 Write failing test: NoteHeading::from with Unicode string has correct visible_width
- [x] 1.2 Fix NoteHeading::from to use may_i_pp::visible_len instead of s.len()
- [x] 1.3 Write failing test: ColRow::kv with Unicode label has correct width
- [x] 1.4 Fix ColRow::kv to use visible_len for label width
- [x] 1.5 Run full test suite and update any affected snapshots

## 2. Fix production unwrap in check evaluation

- [ ] 2.1 Write failing test: check with unresolved predicate returns diagnostic instead of panicking
- [ ] 2.2 Replace unwrap() at check.rs:67 with error propagation into CheckResult
- [ ] 2.3 Verify existing check tests still pass

## 3. Remove debug print in pp renderer

- [x] 3.1 Remove the entire #[cfg(debug_assertions)] block at crates/pp/src/render/mod.rs:166-167
- [x] 3.2 Verify pp tests pass
