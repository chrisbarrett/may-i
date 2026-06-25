## Context

`shell-command-security-model` already mandates that every command/backtick
substitution in every word position is gated, including parameter-expansion
operands ("Embedded command substitutions are evaluated in every word position";
scenario "Coverage holds across arbitrary inputs"). The parser honours this for
the operator forms whose operands are read through `read_operand`
(`${x:-…}`, `${x:+…}`, `${x:=…}`, `${x:?…}`, `${x#…}`, `${x%…}`, `${x/…/…}`,
substring): `read_operand` lifts each `$( … )` / backtick into a structured
`WordPart` carried in `ParameterExpansionOp.embedded`, and the engine emits an
embedded-command unit per entry.

Four positions escape, all documented as a known gap at
`crates/shell-parser/src/lexer/param_expansion.rs:348`:

1. **Patterned case-conversion** `${x^pat}` / `${x^^pat}` / `${x,pat}` /
   `${x,,pat}` — when `pat` is non-empty the arm emits a flat
   `WordPart::ParameterExpansion(format!("{name}{sigil}{pattern}"))`, discarding
   the `embedded` that `read_operand` collected. It floors deliberately (the
   `Uppercase`/`Lowercase` op carries no pattern and would case-convert the whole
   value, diverging from bash) but loses the substitution.
2. **Transform / unknown operators** `${x@Q}`, `${x@a}`, junk — the `_`
   fallback reads to `}` with `read_until_char`, which never captures
   substitutions.
3. **Indirect / nameref** `${!name}`, `${!prefix*}`, `${!arr[@]}` — the name
   begins with `!`, so `read_identifier` returns empty and the
   non-identifier-name fallback (`read_until_char('}')`) collapses it to an
   opaque flat string.
4. **Glob brackets** `[$(cmd)]` — `word_parts.rs` reads the whole bracket body
   verbatim into a `WordPart::Glob(String)`, swallowing the substitution. Bash
   runs command substitution *before* globbing, so the command executes.

The existing coverage proptest misses all four: its generator only places
substitutions in `${x:-…}`/`${x#…}` operands, and — the deeper reason — for
these flat forms the parser destroys the substitution's structure, so the test
oracle (`collect_cmd_substitution_spans`, which walks AST `CommandSubstitution`
parts) cannot see it either. The fix has to restore structure in the parser
*and* widen the generator.

## Goals / Non-Goals

**Goals:**

- Every command/backtick substitution inside a patterned case-conversion,
  transform/unknown operator, indirect/nameref expansion, or glob bracket is
  represented by an embedded-command unit and gated.
- Indirect/nameref `${!…}` is recognised as a distinct structured shape, not an
  opaque flat string.
- The forms stay **unresolved** (expansion-bearing, floor `:allow`) — no new
  value resolution, no behaviour change for inputs that already gate or resolve.
- The coverage proptest generator exercises the four positions so the gap cannot
  silently reopen.
- Source/display fidelity is preserved: a parsed word re-renders to the same
  bytes (the re-parse round-trip proptest keeps holding).

**Non-Goals:**

- Resolving any of these forms to a literal value (case-conversion against a
  pattern, transform output, nameref dereference). All stay unresolved.
- Associative-array key→value *value* modelling — a separate concern, explicitly
  excluded from this change.
- Changing `${arr[*]}` / unquoted `${arr[@]}` behaviour (IFS-dependent;
  conservatively unresolved by design, already correct).

## Decisions

### D1 — Model the unstructured operators as `ParameterExpansionOp` variants, not a flat string

Extend `ParameterOperator` with variants for the currently-flat forms so each
flows through the existing `ParameterExpansionOp { name, op, embedded }` carrier:

- `CaseConvert { upper: bool, all: bool, pattern: String }` for `${x^pat}` etc.
  (the no-pattern `${x^}`/`${x^^}` keep resolving via the existing
  `Uppercase`/`Lowercase` variants — unchanged).
- `Transform { spec: String }` for `${x@…}`.
- `Unknown { source: String }` for the operator the lexer does not recognise.

The `^`/`,` arms and the `_` fallback call `read_operand` (capturing
substitutions) instead of `read_until_char`, and build the corresponding op with
its `embedded`. Because the engine already walks `ParameterExpansionOp.embedded`
for both embedded-command units (`push_embedded_units_from_word`) and secret-read
taint (`collect_parameter_names`), gating works with no engine change for the
param-expansion side.

`resolve_param_op` returns `unresolved()` for all three new variants — they are
**never** resolved (an early guard before the resolve match keeps the resolver
exhaustive). This preserves today's floor-it behaviour; it is the
gating-without-resolution that was missing, not the resolution.

*Alternative — add `embedded` to the `ParameterExpansion(String)` tuple
variant.* Rejected: it conflates the resolvable simple reference `${VAR}` with
the unresolved operator forms, and forces every `ParameterExpansion` match arm
across `word.rs`/`const_env.rs`/`resolve.rs`/`decompose.rs` to handle a field it
does not need for the common case.

### D2 — Indirect / nameref is its own operator shape

Add `ParameterOperator::Indirect { listing: NameListing }` where `NameListing`
distinguishes plain `${!name}`, the prefix-listing `${!prefix*}` / `${!prefix@}`,
and the array-key `${!arr[@]}`. The lexer gains a `!` arm before
`read_identifier`; the operand (the text after `!`) is read with `read_operand`
so an embedded substitution is captured.

Resolution: always `unresolved()`. Taint: the literal name after `!` is **not**
the variable read (the read is indirect), so it is *not* pushed as a secret-read
— matching the existing `scan_parameter_refs` carve-out for `${!NAME}` at
`decompose.rs:819`. `operator_operands` returns no read-bearing operand for
`Indirect` (its own embedded substitutions are still gated via `embedded`).

*Alternative — keep `${!…}` as the flat fallback but make the fallback carry
embedded.* Rejected: leaves the nameref as structurally opaque junk (the #2
remainder the change is meant to close) and gives `operator_operands` /
display nothing to key off.

### D3 — Glob brackets: lift the substitution to a sibling part, leave `Glob(String)` intact

In `word_parts.rs`, when scanning a glob bracket `[ … ]`, a `$( … )` / backtick
inside it is read via the shared `read_dollar` / `read_backtick` (the same
readers `read_operand` uses) and pushed as its own `WordPart::CommandSubstitution`
/ `WordPart::Backtick` part, with the surrounding bracket text kept as
`Glob`/`Literal` parts around it. The substitution is then a normal structured
part the engine already gates — **zero engine change**.

This avoids turning `WordPart::Glob(String)` into a struct (which would touch
every `Glob` match arm). Bash semantics agree: command substitution runs first
and its output participates in the bracket, so the substitution is genuinely a
separate expansion, not part of the glob pattern text.

*Alternative — `Glob { pattern, embedded }`.* Rejected for churn; the
sibling-part representation reuses existing machinery and round-trips on display
(`[` + `$(cmd)` + `]` re-renders to `[$(cmd)]`).

### D4 — Display/source fidelity for the new variants

`word.rs` reconstructs each `WordPart` back to source in several places
(`display_source`, `to_str`, the pretty/serialise arms). Each new operator
variant gets a display arm that reproduces its original spelling
(`${name^^pattern}`, `${name@Q}`, `${!name}`, `${!prefix*}`). The re-parse
round-trip proptest (`prop_wordpart_reparse_round_trip`) is the guardrail; a
new round-trip case covers the four forms.

### D5 — Widen the coverage proptest

Extend `prop_every_substitution_yields_embedded_unit`'s `ctx` set with
`${x^SUB}`, `${x,,SUB}`, `${x@QSUB}` (transform), `${!SUB}` (indirect), and
`echo [SUB]` (glob bracket). With D1–D3 the parser now exposes the substitution
as a structured part, so the test oracle sees it on both sides and the
invariant becomes enforceable rather than vacuous for these positions.

## Risks / Trade-offs

- **Display divergence on the new variants** → the re-parse round-trip proptest
  plus explicit display arms; CI fails if a form does not round-trip.
- **Resolver exhaustiveness regressions** → the new `ParameterOperator` variants
  force compile errors in every `match op` until each is handled; route them all
  to `unresolved()` and verify no existing resolution scenario changes (a
  behaviour-preserving proptest over substitution-free inputs).
- **Glob re-lex fidelity** → a glob bracket split into sibling parts must
  re-lex to the same substitution span; the round-trip proptest covers it. The
  `Glob("[")`/`Glob("]")` fragments are display-only and never resolved.
- **Over-gating** → these forms already floor `:allow`, so adding embedded units
  can only *add* `:ask`/`:deny` from a real embedded command; it cannot loosen a
  decision. The behaviour-preserving proptest (substitution-free inputs) bounds
  the blast radius.

## Open Questions

- `NameListing` granularity: model `${!prefix*}` vs `${!prefix@}` distinctly, or
  collapse to a single "listing" marker? Soundness needs neither distinction
  (both stay unresolved); leaning toward the minimal marker unless display
  fidelity forces the split.
