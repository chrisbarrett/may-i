## Context

The v2 parser currently accepts three redundant syntaxes for terminal effects:

1. **Canonical**: `(effect :allow)`, `(effect :ask "reason")`, `(effect :deny)`
2. **Bare keyword shorthand**: `:allow`, `:ask`, `:deny` as standalone atoms
3. **Vector shorthand**: `[:ask "reason"]`

The migration pipeline also produces a `:effect` keyword marker — an artefact of
`rule_convert_effect_to_keyword`, which *destructively* transforms
`(effect :allow)` into `:effect :allow`. The rule parser then skips the `:effect`
atom for backward compatibility.

The starter config and migrated configs use `(rule CMD :effect (effect :allow))`
— the `:effect` marker and `(effect ...)` form together, which is redundant.

## Goals / Non-Goals

**Goals:**

- Remove bare keyword and vector shorthand from the v2 effect parser
- Remove the `:effect` keyword marker from the migration pipeline and rule parser
- Ensure migration emits `(effect ...)` forms directly
- Keep all 202 `may-i check` assertions passing

**Non-Goals:**

- Changing the semantics of any effect evaluation
- Modifying conditional forms (`when`, `unless`, `if`, `cond`)
- Changing the `(may-i PATTERN)` recursion form
- Altering how v1 configs are loaded (they still migrate transparently)

## Decisions

### 1. Remove shorthand from parse_effect, not from the AST

The `Effect` enum (`Allow`, `Ask`, `Deny`) is unchanged. Only the parser entry
points that accept shorthand syntax are removed. This keeps the change surgical:
downstream evaluator code is unaffected.

**Alternative**: Deprecation warnings first, remove later. Rejected — no
external users depend on shorthand syntax since it was only reachable via
migration output.

### 2. Delete rule_convert_effect_to_keyword entirely

This rule converts `(effect :allow)` → `:effect :allow`. Without it, `(effect ...)`
forms produced by other migration rules survive unchanged into the output. The
canonical parser already handles `(effect ...)`, so no further conversion is needed.

**Alternative**: Make it a no-op. Rejected — dead code is worse than deleted code.

### 3. Fix rule_inline_context to preserve the whole (effect ...) node

Currently `rule_inline_context` extracts the *inner content* of `(effect ...)`:
`(effect :keyword)` becomes just `:keyword` in the `(when PRED ...)` form. After
removing shorthand, these bare keywords would fail to parse.

Fix: keep the entire `(effect ...)` node when building `(when PRED EFFECT)`:
- `(rule CMD (context PRED) (effect :allow))` → `(rule CMD (when PRED (effect :allow)))`
- `(rule CMD (context PRED) (effect :ask "reason"))` → `(rule CMD (when PRED (effect :ask "reason")))`

### 4. Fix rule_add_default_effect to emit (effect :ask)

Currently emits two atoms: `:effect :ask`. Change to emit a single list node:
`(effect :ask)`. The detection logic also changes: instead of scanning for a
`:effect` atom, scan for a child tagged `"effect"` or for conditional forms that
contain effects.

### 5. Fix args_cond_to_case: remove dead :effect guard

Line 810 has `!child.is_tagged(":effect")` which is always true for atoms
(`is_tagged` only matches lists). This was meant to skip `:effect` keyword atoms
but never worked. Since `:effect` atoms won't be produced anymore, remove this
dead guard. The atom check should just skip atoms that are the `:effect` keyword
by value.

Actually, since `rule_convert_effect_to_keyword` is deleted and
`rule_add_default_effect` no longer emits `:effect` atoms, no `:effect` atoms
will ever appear in the pipeline. The guard is dead code — remove it entirely.

### 6. Remove :effect skip from rule parser

`rule.rs:44-49` skips `:effect` atoms during parsing. Since migration no longer
produces them and users never write them, remove this compatibility shim.

### 7. Delete parse_shorthand_effect function

`rule.rs:parse_shorthand_effect()` becomes dead code once shorthand is removed
from the effect parser. Delete it along with its tests.

## Risks / Trade-offs

**[Existing v1 configs produce different migration output]** → The serialised
form changes (e.g., `(rule git :effect :allow)` becomes `(rule git (effect :ask))`),
but the semantic evaluation is identical. Validated by the 202 `may-i check`
assertions which test evaluation outcomes, not serialised syntax.

**[Starter config uses :effect keyword]** → The starter config at
`starter_config.lisp` uses `:effect (effect :allow)` syntax. It must be updated
to drop the `:effect` prefix, becoming just `(effect :allow)`.

**[Third-party configs using shorthand]** → Low risk. The shorthand syntax was
an implementation detail of migration output, not a documented user-facing
feature.
