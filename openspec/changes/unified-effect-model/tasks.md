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
- [ ] 2.4 Add improper list (dot notation) parsing
  - Parse (positional A B . EFFECT)
  - Transform to internal representation
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

- [ ] 4.1 Update migration rules for new syntax
  - Migrate (rule (command X) ...) to (rule X ...)
  - Migrate (args (cond ...)) to proper case form
  - Handle (args (and ... (if ...))) extraction
- [ ] 4.2 Add migration for has → fact?
- [ ] 4.3 Update validation to target new parser
- [ ] 4.4 Add tests for complex migration cases

## 5. Update Tests

- [ ] 5.1 Update parser tests for new syntax
- [ ] 5.2 Update evaluator tests for unified effects
- [ ] 5.3 Add tests for Nil handling in combinators
- [ ] 5.4 Add tests for dot notation
- [ ] 5.5 Add tests for shorthand :effect syntax
- [ ] 5.6 Update integration tests

## 6. Documentation

- [ ] 6.1 Update README with new syntax
- [ ] 6.2 Update config examples
- [ ] 6.3 Document effect evaluation semantics
- [ ] 6.4 Document dot notation usage

## 7. Cleanup

- [ ] 7.1 Remove old v2 AST types
- [ ] 7.2 Remove old v2 parser code
- [ ] 7.3 Remove old v2 evaluator code
- [ ] 7.4 Run full test suite
- [ ] 7.5 Verify migration works on example configs
