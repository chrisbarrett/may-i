## 1. AST: recursive positional term

- [ ] 1.1 Write a failing test constructing `(? "run" (? "--"))` as a nested `Group`/`Single` term against the new API shape.
- [ ] 1.2 Introduce `PosTerm { Single { quantifier, pattern: Expr }, Group { quantifier, seq: Vec<PosTerm> } }` in `crates/core/src/pattern.rs`, with smart constructors; keep invariant-bearing fields private per the project Rust rule.
- [ ] 1.3 Migrate `ArgPattern::Ordered` to carry `Vec<PosTerm>`; update `PositionalArg::one`/`with_quantifier` call sites and `#[cfg(test)]` constructors to compile.
- [ ] 1.4 Update `to_doc`/`Display` for `PosTerm` to render `(Q elem …)` with nested groups.

## 2. Parser: accept one-or-more sub-patterns

- [ ] 2.1 Write failing parser tests: `(? "run" (? "--"))` parses to a nested group; single-arg `(? PAT)` still parses to `Single`; an empty quantifier body `(?)` is rejected.
- [ ] 2.2 In `crates/config/src/pattern.rs` `parse_positional_arg`, drop the arity-2 check; parse one sub-pattern to `Single`, more than one to `Group`; recurse for nested quantifier elements.
- [ ] 2.3 Update or remove the wrong-arity error tests (`parse_*_quantifier_wrong_arity_error`) to reflect the new minimum-arity-1 rule.

## 3. Matcher: groups, termination, soundness

- [ ] 3.1 Write a failing matcher test for the four `(? "run" (? "--")) *` scenarios from the `patterns` delta (skip, partial, full, leading-element-required).
- [ ] 3.2 Write a failing matcher test for repeated groups: `(+ "--opt" *)` and `(* "--opt" *)` over `--opt a --opt b`.
- [ ] 3.3 Introduce the fused `MatchEvidence { facts, unresolved }` smart-constructor type (`match_token`) and `and` combinator in `crates/engine/src/eval/positional.rs`; private fields; replace the two-call `match_expr_with_binding` + `unprovable_match` sites in the existing flat arms with it.
- [ ] 3.4 Write a failing proptest asserting the `and` combinator is associative and total over arbitrary `MatchEvidence`.
- [ ] 3.5 Rewrite `match_positional_recursive` to walk `PosTerm`: `Group` matches its `seq` as a unit; `+`/`*` over a group repeat with greedy-then-backtrack.
- [ ] 3.6 Add the nullable-iteration guard: a `+`/`*` iteration consuming zero args terminates the repetition. Write a failing test `(* (? "x"))` terminates.
- [ ] 3.7 Add the step-budget parameter threaded through `match_positional_recursive`; on exhaustion return no-match. Write a failing test that a pathological nested Pattern hits the budget and floors to `:ask`, never `:allow`.
- [ ] 3.8 Write a failing test: a non-wildcard element inside a repeated group matching an expansion-bearing arg records provenance and floors the decision; a bare-wildcard element does not.
- [ ] 3.9 Update `build_positional_element_details` for group awareness (resolve the trace-granularity open question: full per-element or "group consumed N args" summary).

## 4. Config structure: step budget

- [ ] 4.1 Write a failing test that the matcher budget is read from config structure with the chosen high default (no surface syntax).
- [ ] 4.2 Add the budget field to the config structure and wire it into the matcher entry point; pick the default against the proptest corpus.

## 5. Bindings & shape pass-through (no semantic change)

- [ ] 5.1 Write a test confirming rule-body `Expr::Bind` inside a repeated group accumulates into `ContextFacts` set-union as before (no correlation), and that `binding-shapes` checking is unaffected.
- [ ] 5.2 Confirm `collect_positional_bindings` / parser-declared positional shapes are untouched by group terms (groups are a rule-body Pattern feature); add a regression test if any code path assumed flat `PositionalArg`.

## 6. Pretty-printer, fmt, trust hashing

- [ ] 6.1 Write a failing idempotence test: `may-i fmt` on a config containing `(? "run" (? "--"))` is stable across two passes.
- [ ] 6.2 Implement/verify `crates/pp` rendering of nested group forms.
- [ ] 6.3 Write a failing test that trust hashing serialises the group node canonically and that a group-free config's hash is unchanged from before.
- [ ] 6.4 Implement canonical serialisation of `PosTerm` in `crates/engine/src/trust.rs`.

## 7. Proptest generators

- [ ] 7.1 Extend the `PositionalArg`/`PosTerm` arbitrary/strategy generators to emit groups with a nesting-depth cap, preferring non-nullable inner terms under repetition.
- [ ] 7.2 Confirm the serialization-roundtrip proptest (incl. nested groups) and the no-hang property hold; check the proptest suite runtime did not regress.

## 8. Docs & rules fixture

- [ ] 8.1 Update the `CONTEXT.md` Quantifier glossary entry to describe sequence groups and note the implicit-seq / set-union-bind / modifiers-get-own-head decisions.
- [ ] 8.1a Update `REFERENCE.md` (the shipped manual via `may-i reference`) for the implicit-sequence form: the quantifier table (REFERENCE.md:166-174) and the `(positional …)` section — `(? A B …)` matches the whole sub-sequence; `+`/`*` repeat it. Consideration task per the doc-sync gate (`scripts/validate-change-doc-sync.sh`); resolves by edit — this change alters user-facing quantifier semantics, so REFERENCE.md must change, not "verified no change".
- [ ] 8.2 Tighten the live terragrunt rule to `(? "run" (? "--"))` form in `home/config/programs/may-i/rules/terragrunt-terraform-tofu.lisp` (closing handoff follow-up #1); verify `may-i eval "terragrunt run -- state pull"` → `allow` and the bogus `terragrunt -- <verb>` no longer matches the read-only branch.

## 9. Verification

- [ ] 9.1 `cargo fmt`, `cargo test --workspace`, `may-i check` all green.
- [ ] 9.2 `cargo tarpaulin` and inspect `lcov.info` for uncovered new code; add unit tests only for branches a proptest cannot hit.
- [ ] 9.3 `openspec validate quantifier-sequence-groups --strict` passes.
