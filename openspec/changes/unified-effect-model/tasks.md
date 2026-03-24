## 1. AST Redesign (may_i_core::v2::ast)

- [x] 1.1 Redesign Effect enum with Nil support
  - Remove separate Predicate/Effect split
  - Add Allow, Ask, Deny, Nil variants
  - Add CommandPattern, ArgPattern as Effect variants
  - Add And, Or, Not combinators
  - Add When, Unless, If, Cond conditionals
  - Add MayI for recursion
- [x] 1.2 Update Rule struct
  - Change from (command, predicates, effect) to (command_effect, effects, default_effect)
- [x] 1.3 Add Predicate enum for use in conditionals
  - Keep predicates for when/unless/if/cond predicate position
  - Rename Has to FactPredicate
- [x] 1.4 Update Spanned wrapper if needed

## 2. Parser Rewrite (may_i_config::v2)

- [x] 2.1 Rewrite effect parser
  - Parse all effect forms returning unified Effect enum
  - Handle terminal effects: (effect :allow), (effect :ask), (effect :deny)
  - Handle pattern effects: command strings, (positional ...), (anywhere ...), (forbidden ...)
  - Handle combinators: (and ...), (or ...), (not ...)
  - Handle conditionals: (when ...), (unless ...), (if ...), (cond ...)
  - Handle recursion: (may-i ...)
- [x] 2.2 Add predicate parser for conditional contexts
  - Parse predicates for use in when/unless/if/cond
  - Rename has to fact?
- [x] 2.3 Rewrite rule parser
  - Parse (rule COMMAND-EFFECT EFFECT* :effect DEFAULT)
  - Support shorthand :effect :keyword
  - Support shorthand :effect [:keyword "reason"]
- [x] 2.4 Add improper list (dot notation) parsing
  - Parse (positional A B . EFFECT)
  - Store continuation effect in ArgPattern
  - Evaluate continuation with remaining args
- [ ] 2.5 Update error messages for new syntax

## 3. Evaluator Rewrite (may_i_engine::v2::eval)

- [x] 3.1 Implement unified effect evaluation
  - evaluate_effect returns Decision | Nil
  - Terminal effects return decision
  - Pattern effects return Allow on match, Nil otherwise
- [x] 3.2 Implement effect combinators
  - And: return first Nil or last effect
  - Or: return first non-Nil or Nil
  - Not: invert Allow/Nil, pass through Ask/Deny
- [x] 3.3 Implement conditionals
  - When: evaluate effect if predicate matches
  - Unless: evaluate effect if predicate doesn't match
  - If: choose branch based on predicate
  - Cond: first matching branch wins
- [x] 3.4 Implement MayI recursion
  - Pattern must match for recursion to happen
  - Return Nil if pattern doesn't match
  - Return inner decision if it does
- [x] 3.5 Implement rule evaluation with :effect default
  - Evaluate command effect first
  - If non-Nil, evaluate subsequent effects until non-Nil
  - Use :effect default if all Nil
- [ ] 3.6 Update trace generation for new effect types
  - Add And, Or, Not traces
  - Update existing traces for Nil handling

## 4. Update v1 Migration Tool

- [x] 4.1 Update migration rules for new syntax
  - Migrate (rule (command X) ...) to (rule X ...)
  - Migrate (effect :allow) to :effect :allow shorthand
  - Handle old-style rule structures
- [x] 4.2 Add migration for has → fact?
- [x] 4.3 Update validation to target new parser
- [x] 4.4 Add tests for complex migration cases

## 5. Update Tests

- [x] 5.1 Update parser tests for new syntax
- [x] 5.2 Update evaluator tests for unified effects
- [x] 5.3 Add tests for Nil handling in combinators
- [x] 5.4 Add tests for dot notation
  - Parser tests for dot notation
  - Integration tests for simple dot notation
  - Integration tests for dot notation with may-i
  - Integration tests for exact with dot notation
- [x] 5.5 Add tests for shorthand :effect syntax
- [x] 5.6 Update integration tests

## 6. Documentation

- [x] 6.1 Update README with new syntax
- [x] 6.2 Update starter config with new syntax
- [x] 6.3 Add `may-i reference` command for detailed DSL help
- [x] 6.4 Document dot notation usage
  - Documented in `may-i reference` command
  - Example: (positional [:host *] . (may-i *))

## 7. Cleanup

- [x] 7.1 Remove old v2 AST types
  - Deleted crates/core/src/v2/predicate.rs
- [x] 7.2 Remove old v2 parser code
  - All parser code updated to unified model
- [x] 7.3 Remove old v2 evaluator code
  - All evaluator code updated to unified model
- [x] 7.4 Run full test suite
  - All 1402 tests passing
- [x] 7.5 Verify migration works on example configs
  - Migration tests all passing
  - Validation confirms migrated output parses correctly
