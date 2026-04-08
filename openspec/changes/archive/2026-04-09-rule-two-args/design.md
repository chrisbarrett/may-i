## Context

Rules currently accept `(rule COMMAND EFFECT...)` with any number of body effects. The evaluator processes these sequentially: each effect is evaluated, and if any returns Nil the rule is considered "not matched" — remaining effects are never tried. This creates a trap: `(rule CMD (when PRED EFF1) EFF2)` looks like it should fall through to EFF2 when the predicate is false, but instead the rule fails to match entirely.

The `Rule` AST stores `effects: Vec<Spanned<Effect>>` and the evaluator has a loop with Nil/Allow/Decision branching. The migration pipeline can produce multi-effect output (e.g., `rule_inline_context` produces context-predicate + effect, and `rule_add_default_effect` appends a default).

## Goals / Non-Goals

**Goals:**

- Restrict rule syntax to exactly `(rule COMMAND EFFECT)` — two arguments
- Produce clear parse errors when rules have wrong arity
- Simplify the Rule AST to a single `effect` field
- Simplify the evaluator to single-effect dispatch
- Update the migration pipeline to wrap multi-child output in combinators
- Keep all 202 `may-i check` assertions passing

**Non-Goals:**

- Changing effect semantics (`and`, `or`, `when`, `cond`, etc. — all unchanged)
- Changing check syntax (checks remain alongside the two args)
- Introducing new combinator forms

## Decisions

### 1. Rule syntax is `(rule COMMAND EFFECT [CHECK...])`

The rule takes exactly two positional forms (command and effect), plus optional `(check ...)` forms. Parse error on zero or 2+ non-check body forms.

**Alternative**: Allow 0 body effects and implicitly use `(effect :ask)`. Rejected — explicit is better; a bare `(rule CMD)` with no effect is likely a mistake.

**Alternative**: Allow N effects with `or` semantics. Rejected — implicit `or` is the root cause of confusion. Users should write `(or ...)` explicitly.

### 2. Rule AST: `effects: Vec` → `effect: Spanned<Effect>`

The `Rule` struct changes from:
```rust
pub effects: Vec<Spanned<Effect>>,
```
to:
```rust
pub effect: Spanned<Effect>,
```

This is a breaking AST change that will require updates across the evaluator, fold trait, annotation, and output modules. The `command_effect` field is unchanged.

### 3. Evaluator: single-effect dispatch replaces loop

The `evaluate_rule` method currently loops over `rule.effects` with complex Nil/Allow/Decision branching. With a single effect, this becomes:

```
evaluate command_effect → if Nil, skip rule
evaluate effect → return result (with implicit :ask default wrapping at top level)
```

The existing top-level `(or ... (effect :ask))` wrapping continues to provide the default :ask when effects return Nil.

### 4. Migration: wrap multi-child output with combinators

Migration rules that currently produce multiple children in a rule must be updated:

- **`rule_inline_context`**: Currently produces `(rule CMD (when PRED EFFECT))` — already single-effect, no change needed.
- **`rule_add_default_effect`**: Currently appends `(effect :ask)`. After this change, it should NOT add a separate default — the evaluator's implicit `(or ... (effect :ask))` wrapping handles it. Delete this migration rule entirely.
- **`args_cond_to_case`**: Currently produces `(rule CMD COND_FORM)` — already single-effect, no change needed.

For v1 rules that produced `(rule CMD PATTERN EFFECT)` after migration (e.g., inlined args + effect), the migration must wrap them: `(rule CMD (and PATTERN EFFECT))`.

### 5. Fold trait: simplify effect output signatures

Methods like `rule_matched` and `rule_not_matched` currently take `Vec<F::EffectOut>`. These change to take a single `F::EffectOut`. This ripples through `TracingFold`, `PureFold`, and annotation/output code.

## Risks / Trade-offs

**[Large blast radius across modules]** → The `Rule` struct is used everywhere. Mitigate by making the AST change first and letting the compiler guide all call sites.

**[Migration output changes]** → Validated by the 202 `may-i check` oracle assertions which test evaluation outcomes.

**[Fold trait changes ripple through output/annotation]** → These are mechanical (Vec → single value). The compiler enforces completeness.
