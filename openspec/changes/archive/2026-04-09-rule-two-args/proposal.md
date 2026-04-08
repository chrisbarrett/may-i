## Why

The rule parser currently accepts `(rule COMMAND EFFECT...)` with an unbounded number of effects. The evaluator processes these effects sequentially with short-circuit-on-Nil semantics — if any effect returns Nil, the entire rule is "not matched". This is confusing and unspecified: users naturally expect `(rule CMD (when PRED EFF1) EFF2)` to fall through to EFF2 when the predicate is false, but instead the rule silently fails to match. Restricting rules to exactly two arguments — command and a single body effect — forces users to be explicit about control flow using combinators (`cond`, `if`, `or`), eliminating an entire class of surprising behavior.

## What Changes

- **BREAKING**: `(rule COMMAND EFFECT)` becomes the only valid rule syntax. Rules with zero or more than one body effect (excluding checks) produce a parse error.
- Rules that previously had multiple effects must be rewritten using combinators:
  - `(rule CMD EFF1 EFF2)` → `(rule CMD (or EFF1 EFF2))` (if fallthrough was intended)
  - `(rule CMD PAT EFF)` → `(rule CMD (and PAT EFF))` (if gating was intended)
- The `Rule` AST struct changes from `effects: Vec<Spanned<Effect>>` to `effect: Spanned<Effect>` (singular).
- The evaluator simplifies: instead of a sequential loop over effects, it evaluates a single effect and uses `or ... (effect :ask)` wrapping for the default.
- The migration pipeline must produce single-effect rules (wrapping in `or`/`and` as needed).
- `REFERENCE.txt` and `starter_config.lisp` must be updated.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `configuration-language`: Rule syntax changes from `(rule COMMAND EFFECT...)` to `(rule COMMAND EFFECT)`. Parse error on wrong arity.
- `transparent-config-migration`: Migration must emit single-effect rules, wrapping multi-effect v1 output in combinators.
- `evaluator-error-handling`: Rule evaluation simplifies to single-effect dispatch.

## Impact

- `crates/core/src/ast.rs` — `Rule` struct: `effects: Vec` → `effect: Spanned<Effect>`
- `crates/config/src/rule.rs` — Parser: enforce exactly 2 args (+ optional checks)
- `crates/engine/src/eval.rs` — Evaluator: remove effects loop, evaluate single effect
- `crates/engine/src/fold.rs` — Fold trait: signatures that take `Vec<EffectOut>` simplify
- `crates/config/src/migrate.rs` — Migration rules: wrap multi-child output in combinators
- `crates/config/src/starter_config.lisp` — Rewrite multi-effect rules
- `REFERENCE.txt` — Update syntax reference
- All test files touching rule parsing, evaluation, and migration
