## 1. Core types

- [ ] 1.1 Add `ArgPattern::Flag { names: Vec<String> }` (or
      `name: FlagName` enum) to `crates/core/src/ast.rs`.
- [ ] 1.2 Add `ArgPattern::Parameter { names: Vec<String>, form:
      Box<ArgPattern> }` (or appropriate inner type).
- [ ] 1.3 Update serialisation, pretty-printing, and core trait
      implementations.

## 2. Parser

- [ ] 2.1 Recognise `(flag "x")`, `(flag "long")`, `(flag ["x" "long"])`
      in `crates/config/src/...`.
- [ ] 2.2 Recognise `(parameter "x" FORM)` and equivalents.
- [ ] 2.3 Error: `(flag …)` with empty name; `(parameter …)` with no FORM.
- [ ] 2.4 Round-trip via the pretty-printer.

## 3. Failing tests first

- [ ] 3.1 `(rule "bash" (parameter "c" (may-i *)))` evaluates `bash -c
      "echo hi"` correctly (regression for the broken-rule case).
- [ ] 3.2 `(rule "rm" (not (flag "r")))` allows `rm file` and rejects
      `rm -r dir`.
- [ ] 3.3 `(rule "rm" (not (flag "r")))` rejects `rm -rf dir` (combined
      shorts).
- [ ] 3.4 `(rule "git" (not (flag ["f" "force"])))` rejects `git push -f`
      AND `git push --force`.
- [ ] 3.5 `(rule "curl" (parameter ["X" "request"] "POST"))` matches
      `curl -X POST` AND `curl --request=POST`.
- [ ] 3.6 `(parameter "c" FORM)` consumes the flag-value pair so a sibling
      `(positional …)` matcher sees the remaining args correctly.
- [ ] 3.7 `(flag "v")` is non-consuming (sibling matchers see all args).

## 4. Evaluator

- [ ] 4.1 Add new branches in
      `crates/engine/src/eval/effects.rs::evaluate_arg_pattern_effect_fold`
      for `Flag` and `Parameter`.
- [ ] 4.2 `Flag`: search the annotated stream for matching flag tokens
      (any short or long form named); return Allow if found, Nil
      otherwise.
- [ ] 4.3 `Parameter`: locate the flag, recurse `evaluate_*` on the
      `form` against its value as a single-element arg list.
- [ ] 4.4 Update `match_positional_patterns` to skip tokens consumed by
      sibling `Parameter` patterns (or pre-filter them before positional
      matching runs).

## 5. Tokeniser integration

- [ ] 5.1 Before evaluating a rule, collect the union of `Parameter` flag
      names from all patterns in that rule.
- [ ] 5.2 Merge with the active `Convention.flags_with_values` from
      `args-style` so the tokeniser correctly groups flag-value pairs.
- [ ] 5.3 Verify trace output shows the merged effective list.

## 6. Migration rewrites

- [ ] 6.1 Add rewrite: `(anywhere "-X" …)` → `(flag "X" …)` for tokens
      beginning with `-`.
- [ ] 6.2 Add rewrite: `(forbidden "-X" …)` → `(not (flag "X" …))`.
- [ ] 6.3 Add rewrite: `(positional "-c" . R)` → `(parameter "c" R)`.
- [ ] 6.4 Mixed-token cases: split `(anywhere "-x" "verb")` into
      `(and (flag "x") (anywhere "verb"))`.
- [ ] 6.5 Migration tests.

## 7. Specs

- [ ] 7.1 Modify `openspec/specs/pattern-expressions/spec.md` with the new
      requirements describing `flag` and `parameter` semantics.

## 8. Property tests

- [ ] 8.1 Property: `(flag X)` is true iff at least one tokenised flag's
      name equals `X` (modulo short/long matching).
- [ ] 8.2 Property: `(parameter X *)` matches ⟺ `(flag X)` is true.
- [ ] 8.3 Property: `(not (flag X))` and `(flag X)` are dual.

## 9. Documentation

- [ ] 9.1 Update `may-i reference` output: new section for `flag` and
      `parameter` patterns; deprecate the broken `(positional "-x" …)`
      shape with a pointer to the migration.
- [ ] 9.2 Update sample configs in `examples/`.

## 10. Cleanup

- [ ] 10.1 `cargo fmt`.
- [ ] 10.2 `cargo tarpaulin`; chase down uncovered branches.
- [ ] 10.3 Smoke-test against user oracle: `bash -c "git status"`,
      `git push -f`, `curl -X POST`, `kubectl -n prod get pods`.
