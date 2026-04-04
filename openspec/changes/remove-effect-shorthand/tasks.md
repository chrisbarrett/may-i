## 1. Migration Pipeline Fixes

- [ ] 1.1 Delete `rule_convert_effect_to_keyword` from `migrate.rs` and remove it from `migration_rules()` vec
- [ ] 1.2 Fix `rule_inline_context` to keep the whole `(effect ...)` node when building `(when PRED EFFECT)` instead of extracting the inner keyword/vector
- [ ] 1.3 Fix `rule_add_default_effect` to emit `(effect :ask)` list node instead of `:effect :ask` atoms, and detect existing effects by checking for `(effect ...)` tagged lists instead of `:effect` atoms
- [ ] 1.4 Clean up `args_cond_to_case` — remove the dead `!child.is_tagged(":effect")` guard at line 810

## 2. Parser Removals

- [ ] 2.1 Remove bare keyword shorthand handling (`:allow`/`:ask`/`:deny` as standalone effects) from `parse_effect()` in `effect.rs`
- [ ] 2.2 Remove vector shorthand handling (`[:ask "reason"]`) from `parse_effect()` in `effect.rs`
- [ ] 2.3 Remove `:effect` keyword skip from `parse_rule()` in `rule.rs` (lines 44-49)
- [ ] 2.4 Delete `parse_shorthand_effect()` function from `rule.rs`

## 3. Starter Config Update

- [ ] 3.1 Update `starter_config.lisp` to remove `:effect` keyword prefixes (e.g., `:effect (effect :allow)` becomes `(effect :allow)`)

## 4. Test Updates

- [ ] 4.1 Update migration tests in `migrate.rs` and `migration_tests.rs` that assert `:effect` keyword output to expect `(effect ...)` forms
- [ ] 4.2 Remove effect shorthand parser tests from `effect.rs` and `rule.rs` (shorthand keyword tests, vector shorthand tests, parse_shorthand_effect tests)
- [ ] 4.3 Update rule parser tests that use `:effect` keyword syntax
- [ ] 4.4 Run full test suite (`cargo test`) and fix any remaining failures
- [ ] 4.5 Verify all 202 `may-i check` assertions pass
