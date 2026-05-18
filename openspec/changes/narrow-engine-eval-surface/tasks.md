## 1. Verify caller inventory

- [ ] 1.1 Confirm zero external callers for each demotion target: `BindingValue`, `Bindings`, `parse_argv`, `EvalUnit`, `decompose`, `parser_positional_args`, `tokenise`. Use `grep -rln` across `src/`, `crates/`, `tests/` and exclude paths under `crates/engine/`.
- [ ] 1.2 Confirm external callers for each retained export: `Evaluator`, `EvalContext`, `PredicateResult`, `evaluate`, `evaluate_with_fold`, `evaluate_command`, `evaluate_command_with_fold`.

## 2. Demote re-exports

- [ ] 2.1 Edit `crates/engine/src/eval/mod.rs`: change `pub use bindings::{BindingValue, Bindings, parse_argv};` and `pub use decompose::{EvalUnit, decompose};` to `pub(crate) use`.
- [ ] 2.2 In the same file, change `pub use entry::{Evaluator, evaluate, evaluate_with_fold, parser_positional_args, tokenise};` so `parser_positional_args` and `tokenise` are demoted to `pub(crate)` while `Evaluator`, `evaluate`, and `evaluate_with_fold` remain public.

## 3. Document the surface

- [ ] 3.1 Add a module-level doc comment to `crates/engine/src/eval/mod.rs` listing the public surface and stating that any addition requires a corresponding `code-quality` spec update.

## 4. Verify

- [ ] 4.1 Run `cargo check --workspace`. Resolve any consumer that was missed by the grep audit by either keeping the item public (and updating the spec) or by routing the consumer through the supported `Evaluator` API.
- [ ] 4.2 Run `cargo test --workspace`. Confirm no test failures introduced by the visibility change.
- [ ] 4.3 Run `openspec validate narrow-engine-eval-surface --strict`.
