## 1. C′ — value-shape guard (red → green)

- [x] 1.1 Add failing tests for the value-shape guard in
  `crates/engine/src/eval/entry.rs` tests: undeclared flag does NOT consume a
  flag-shaped next token (`--quiet --bin may-i` → residual `[run, --, eval]`);
  undeclared flag before a subcommand (`--release build` → `build` in residual);
  undeclared flag DOES consume a non-flag value (`--output report.txt`).
- [x] 1.2 Add a `next_token_is_plausible_value` helper keyed on the Style's
  short/long prefix: flag-shaped iff begins with a prefix and the next char is a
  letter; digits / bare `-` / prefix-less are plausible values.
- [x] 1.3 Gate the guess in `parser_positional_indices` (and the sibling
  `parser_positional_args` path if separate): `consumes_next` for the undeclared
  branch additionally requires the next token to be a plausible value. Leave the
  `is_declared_param` branch consuming unconditionally.
- [x] 1.4 Add the negative-number scenario (`--threshold -5 input` → `-5`
  consumed, `input` residual) and the declared-parameter scenario
  (`grep --regexp --foo file` → `--foo` consumed) as tests; make them pass.

## 2. C′ — `--` flag-stop protection

- [x] 2.1 Add a failing test: `tool --undeclared -- value` keeps `--` as
  flag-stop and `value` as a positional (undeclared flag must not absorb `--`).
- [x] 2.2 Ensure the consume step never advances past a `--` token; make the
  test pass.

## 3. B — arity-guess Advisory

- [x] 3.1 Add a failing trace test: an undeclared long flag consuming a non-flag
  value emits an Advisory naming the flag and the consumed token; no Advisory
  when the flag is declared or left value-less.
- [x] 3.2 Capture the guess at the consume site (flag spelling + consumed token)
  and thread it to `TracingFold` so it surfaces in human and JSON traces,
  reusing the existing advisory rendering path (`traces` / `output-rendering`).
- [x] 3.3 Confirm the Advisory does not alter the Decision (a `(check …)` case
  whose decision is identical with and without the advisory).

## 4. A — documentation

- [x] 4.1 Update `src/cmd_help.rs` reference text to present `(flag NAME)` and
  `(parameter NAME …)` as parser-body declaration kinds (not only rule-body
  matchers).
- [x] 4.2 Add guidance to the reference: security deny-guards belong on
  `(flag …)` / `(anywhere …)` (raw-argv, immune to arity guessing) rather than
  `(positional …)` (matches the consumption-sensitive residual).
- [x] 4.3 Mirror the 4.1/4.2 reference edits into `REFERENCE.md` (the
  user-facing DSL reference): document the value-shape rule for undeclared long
  flags, the `(flag)`/`(parameter)` parser-body kinds, and the deny-guard
  placement guidance — keeping it in sync with `may-i reference`. If a section
  needs no change, record "verified, no surface change" against it.

## 5. Tests & regression coverage

- [x] 5.1 Proptest over argv shapes (flag-then-flag, flag-then-`--`,
  flag-then-value, negative-number value, declared-vs-undeclared) asserting the
  positional residual matches the value-shape rule.
- [x] 5.2 Add embedded `(check …)` regressions for the `cargo run --quiet …` and
  `cargo --release build` reproductions (under default gnu, no cargo parser).
- [x] 5.3 Run `cargo tarpaulin`; confirm the new branches (plausible-value true
  / false, `--` guard, advisory emit / suppress) are covered.

## 6. Verification & wrap-up

- [x] 6.1 `cargo fmt`; `cargo test`; `may-i check` on the prelude and on
  `.may-i.lisp`.
- [x] 6.2 Re-run the original reproductions end to end; confirm `cargo run
  --quiet --bin may-i -- eval` allows under default gnu without the
  `separators "="` workaround.
- [x] 6.3 Add a release-note entry describing the tokenisation-behaviour change
  and the possible decision shifts for undeclared long flags.
- [x] 6.4 Run `openspec validate refine-undeclared-long-flag-arity`.
