## Why

The spec already requires that *every* command substitution in *every* word
position is gated — including inside parameter-expansion operands
(`shell-command-security-model` § "Embedded command substitutions are evaluated
in every word position", scenario "Coverage holds across arbitrary inputs").
Several flat expansion forms violate it today: a command substitution buried in
a patterned case-conversion (`${x^$(cmd)}`, `${x,,$(cmd)}`), a transform or
unknown operator (`${x@Q$(cmd)}`, junk operators), an indirect/nameref form
(`${!$(cmd)}`), or a glob bracket (`echo [$(cmd)]`) runs in bash but is **not
gated** — it floors to `:allow` because the parser collapses the whole form to a
flat `WordPart::ParameterExpansion(String)` / `WordPart::Glob(String)` that
cannot carry the substitution's structure.

This is a soundness hole: `echo ${x^$(rm -rf /)}` is allowed where
`echo ${x:-$(rm -rf /)}` is correctly denied. The existing coverage proptest
misses it because its generator only exercises `${x:-…}`/`${x#…}` operands, and
more fundamentally because the parser discards the substitution structure, so
even the test oracle (which walks AST `CommandSubstitution` parts) is blind to it.

## What Changes

- **Close the gating gap for flat parameter-expansion forms.** The lexer arms
  that today return a flat `ParameterExpansion` string — patterned case
  conversion (`^pat`/`,,pat`), the transform/unknown-operator fallback
  (`@Q`/`@a`/junk), and the non-identifier-name fallback — SHALL preserve any
  command/backtick substitution in their operands as structured, span-carrying
  parts so the engine gates them. The forms stay **unresolved** (they floor an
  `:allow` as before); only the buried substitution becomes visible.
- **Close the gating gap for glob brackets.** A command/backtick substitution
  inside a glob bracket expression (`[$(cmd)]`) SHALL be preserved and gated;
  bash runs command substitution before globbing.
- **Model indirect/nameref expansions.** `${!name}` (and `${!name[@]}`,
  `${!prefix*}`) SHALL be recognised as a distinct, structured shape rather than
  collapsed into an opaque flat string. It stays unresolved (floors `:allow`),
  but any embedded substitution in it is gated and the form is no longer junk.
- **Widen the coverage proptest** to generate substitutions in the
  case-conversion, transform, indirect, and glob-bracket positions, so the gap
  cannot silently reopen.

## Capabilities

### New Capabilities

<!-- none -->

### Modified Capabilities

- `shell-command-security-model`: extend the "Embedded command substitutions are
  evaluated in every word position" requirement to explicitly enumerate the
  patterned case-conversion, transform/unknown-operator, indirect/nameref, and
  glob-bracket positions; add an indirect/nameref recognition requirement that
  keeps the form unresolved while gating its substitutions.

## Impact

- `crates/shell-parser/src/ast/mod.rs` — a flat expansion form that can carry
  `embedded` substitutions (extend `WordPart::ParameterExpansion`, or add a new
  variant), plus an indirect/nameref representation.
- `crates/shell-parser/src/lexer/param_expansion.rs` — the `^`/`,` patterned
  arms, the `_` unknown-operator fallback, and the non-identifier-name fallback
  capture substitutions via `read_operand` instead of `read_until_char`; an
  indirect `${!…}` arm.
- `crates/shell-parser/src/lexer/word_parts.rs` — glob-bracket lexing captures
  embedded substitutions rather than swallowing them into the `Glob` string.
- `crates/engine/src/eval/decompose.rs` — consume the new structure when
  emitting embedded-command units and secret-read taint (`collect_parameter_names`,
  `push_embedded_units_from_word`).
- `crates/shell-parser/src/ast/word.rs`, `const_env.rs`, `resolve.rs` — match
  arms for the changed/new variant; resolution stays unresolved.
- `crates/engine/src/eval/tests/properties.rs` — widen
  `prop_every_substitution_yields_embedded_unit` generator contexts.
