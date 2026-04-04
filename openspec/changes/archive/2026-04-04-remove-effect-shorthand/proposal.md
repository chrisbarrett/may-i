# Proposal: Remove Effect Shorthand Syntax

## Problem

The v2 parser accepts three redundant ways to express terminal effects:

1. **Explicit form**: `(effect :allow)`, `(effect :ask "reason")` — the canonical syntax
2. **Bare keyword shorthand**: `:allow`, `:ask`, `:deny` — anywhere an effect is expected
3. **Vector shorthand**: `[:ask "reason"]` — keyword + reason in a vector

Additionally, the `rule` parser silently skips a `:effect` keyword marker:
```lisp
(rule "git" :effect :allow)
```

This `:effect` keyword syntax is an artefact of the v1 migration pipeline — `rule_convert_effect_to_keyword` actively *destroys* valid `(effect ...)` forms to produce it.

The shorthand forms add parser complexity without adding expressiveness, and they make the grammar harder to reason about.

## Proposed Change

1. **Remove shorthand support from the v2 parser** — only `(effect ...)` and `(may-i ...)` are valid effect forms.
2. **Fix the v1 migration pipeline** to emit `(effect ...)` forms instead of bare keywords/vectors.
3. **Remove the `:effect` keyword marker** from both the rule parser and migration output.

## Scope

### Parser changes (removals)

- `effect.rs:parse_effect()` — remove bare keyword handling (`:allow`/`:ask`/`:deny` as standalone effects)
- `effect.rs:parse_effect()` — remove vector shorthand handling (`[:ask "reason"]`)
- `rule.rs:parse_rule()` — remove `:effect` keyword skip (lines 44-49)
- `rule.rs:parse_shorthand_effect()` — delete (becomes dead code)

### Migration changes

- **Delete** `rule_convert_effect_to_keyword` — it destroys valid `(effect ...)` forms; without it, `(effect :allow)` survives migration unchanged.
- **Fix** `rule_inline_context` — keep the whole `(effect ...)` node when building `(when PRED EFFECT)` instead of extracting just the keyword.
- **Fix** `rule_add_default_effect` — emit `(effect :ask)` instead of `:effect :ask`.
- **Fix** `args_cond_to_case` — update `:effect` atom handling now that the keyword marker is gone.

### Tests

- Remove tests that assert shorthand parsing works.
- Update migration tests that assert `:effect` keyword output.
- All 202 existing `may-i check` assertions must continue to pass (migration correctness).

## What Doesn't Change

- `(effect :allow)`, `(effect :ask "reason")`, `(effect :deny)` — unchanged
- `(may-i PATTERN)` — unchanged
- All conditional forms (`when`, `unless`, `if`, `cond`) — unchanged
- v1 config files — still load transparently via migration

## Risk

Low. The v1 config already uses `(effect ...)` everywhere. The migration pipeline mostly just needs to *stop destroying* those forms. Parser changes are pure removals.
