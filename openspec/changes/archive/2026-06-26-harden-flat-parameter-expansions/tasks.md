## 1. Failing tests first (red)

- [x] 1.1 Add engine integration tests asserting `:deny` for the embedded `rm` in
  `echo ${x^$(rm -rf /)}`, `echo ${x,,$(rm -rf /)}`, `echo ${x@Q$(rm -rf /)}`,
  `echo ${!$(rm -rf /)}`, and `echo [$(rm -rf /)]` (mirror the existing operand
  gating tests in `crates/engine/src/eval/tests/expansion.rs`). Confirm they fail.
- [x] 1.2 Un-skip / extend the deferred assertions in
  `crates/engine/src/eval/tests/expansion.rs` (the `NOTE: …deliberately not
  asserted here` block) to cover the patterned/transform/indirect forms.
- [x] 1.3 Add a parser test asserting `${!ref}` parses to the indirect/nameref
  shape (not an opaque flat `ParameterExpansion`), and that `${!AWS_TOKEN}` does
  not report `AWS_TOKEN` as a secret-read.

## 2. AST representation

- [x] 2.1 Add `ParameterOperator` variants `CaseConvert { upper, all, pattern }`,
  `Transform { spec }`, `Unknown { source }`, and `Indirect { listing }` (with a
  `NameListing` enum) in `crates/shell-parser/src/ast/mod.rs`. Keep the
  no-pattern `Uppercase`/`Lowercase` variants for the resolvable case.
- [x] 2.2 Fix the resulting non-exhaustive `match op` compile errors across the
  workspace by routing each new variant through the steps below.

## 3. Lexer — capture substitutions structurally

- [x] 3.1 `param_expansion.rs`: in the `^`/`,` arms, when the pattern is
  non-empty emit `ParameterExpansionOp { op: CaseConvert{…}, embedded }` using
  the `embedded` already returned by `read_operand` (drop the flat-string path).
- [x] 3.2 `param_expansion.rs`: replace the `_` unknown-operator fallback's
  `read_until_char` with `read_operand`, emitting `Transform`/`Unknown` ops that
  carry `embedded`.
- [x] 3.3 `param_expansion.rs`: add a `!` arm (before `read_identifier`)
  producing `Indirect { listing }`, reading the operand with `read_operand` so
  its substitutions are captured; classify plain / prefix-listing / array-key.
- [x] 3.4 `word_parts.rs`: in glob-bracket scanning, lift an inner `$( … )` /
  backtick to its own `CommandSubstitution` / `Backtick` part via the shared
  readers, keeping surrounding bracket text as `Glob`/`Literal` parts (D3).

## 4. Resolution stays unresolved

- [x] 4.1 `resolve.rs`: return `unresolved()` for `CaseConvert`, `Transform`,
  `Unknown`, and `Indirect` (early guard before the resolve match). Confirm no
  existing resolution scenario changes.
- [x] 4.2 `const_env.rs`: handle the new variants (treat as unresolved /
  non-constant) so constant-array and scalar analysis is unaffected.

## 5. Engine consumption

- [x] 5.1 `decompose.rs` `operator_operands`: add arms — scan the
  `CaseConvert.pattern` / `Transform.spec` operand for secret refs; return no
  read-bearing operand for `Indirect` (the literal name is not the read).
- [x] 5.2 Confirm `push_embedded_units_from_word` and `collect_parameter_names`
  gate the new ops' `embedded` with no further change (they already walk
  `ParameterExpansionOp.embedded`); add a regression assertion if not.

## 6. Display / source fidelity

- [x] 6.1 `ast/word.rs`: add display/source-reconstruction arms for each new
  variant (`${name^^pat}`, `${name@Q}`, `${!name}`, `${!prefix*}`,
  `${!arr[@]}`).
- [x] 6.2 Extend `prop_wordpart_reparse_round_trip` (or add a case) covering the
  four forms so re-parse round-trips byte-for-byte.

## 7. Coverage proptest (green + guard)

- [x] 7.1 Widen `prop_every_substitution_yields_embedded_unit`'s `ctx` set with
  `${x^SUB}`, `${x,,SUB}`, `${x@QSUB}`, `${!SUB}`, and `echo [SUB]`; confirm the
  invariant now holds for these positions.
- [x] 7.2 Add a behaviour-preserving proptest: for substitution-free inputs,
  decisions are unchanged from before this change (bounds the blast radius).

## 8. Cleanup & verification

- [x] 8.1 Remove the `KNOWN GAP … deferred` comment block in `param_expansion.rs`
  and the deferred `NOTE` in `expansion.rs` now that the gap is closed.
- [x] 8.2 `cargo fmt`; run `cargo test --workspace`; run `cargo tarpaulin` and
  inspect `lcov.info` for uncovered new arms.
- [x] 8.3 Confirm all tests from §1 pass and the migration system is untouched
  (no config-syntax change; AST-only).
- [x] 8.4 `REFERENCE.md`: verified — no user-facing surface change. This change
  only closes an internal substitution-gating gap (more commands get gated); the
  DSL, decision vocabulary, and documented behaviour are unchanged, so
  `REFERENCE.md` needs no edit.
