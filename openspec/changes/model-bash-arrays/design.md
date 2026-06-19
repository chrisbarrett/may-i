## Context

The scalar (`resolve-constant-argument-expansions`) and loop
(`enumerate-constant-loop-arguments`) changes operate on AST the parser already
produces. Arrays do not exist in the AST at all:

- `Assignment { name, value: Word }` (`crates/shell-parser/src/ast/mod.rs:105`)
  carries a single `Word`, so `arr=(a b c)` cannot be represented. The parser
  errors at `(` and drops the rest of the command (verified:
  `arr=(a b c); echo …` → `Assignment{arr, ""}` + Error, `echo …` gone).
- `${arr[@]}` lexes to `WordPart::ParameterExpansion("arr[@]")` — the subscript
  is part of the name string.

This change is **parser-only modelling**: make arrays representable and stop the
truncation. It deliberately does *not* resolve array values; a subscripted
expansion stays expansion-bearing so decisions are unchanged except that the
previously-dropped trailing command is now evaluated.

## Goals / Non-Goals

**Goals:**

- A faithful AST for array-literal assignment and subscripted expansion.
- Remove the `name=(…)` parse-error-and-truncate behaviour; the rest of the
  command parses normally.
- Keep evaluation behaviour identical (subscript = unresolved) apart from
  recovering the discarded tail.

**Non-Goals:**

- Resolving array values, `[@]` word-count expansion, or `${#arr[@]}` length
  computation — the follow-up `resolve-constant-array-arguments`.
- Associative-array *value* modelling (the key→value map); v1 records that an
  array is associative and parses `declare -A m=([k]=v)` without truncating, but
  does not structure the key→value pairs.
- Namerefs / `${!ref}` indirection.

## Decisions

### D1 — Assignment value becomes scalar-or-array, carrying array kind

Replace `Assignment.value: Word` with a value enum, e.g.
`AssignmentValue::Scalar(Word)` | `AssignmentValue::Array { kind, elements: Vec<Word> }`,
or add a sibling `Command`/assignment node for the array form. `kind` is
`Indexed` | `Associative`, set from `declare -A` (associative) vs `declare -a` /
bare `name=(…)` (indexed). Prefer the enum so all assignment-handling code
(including `constant_env`) sees one assignment type and matches on its value kind.
Every existing consumer of `.value` must be updated to match the scalar arm; the
array arm is new.

The kind matters for soundness downstream: a quoted `"${assoc[@]}"` has
unspecified element order in bash, so the resolver in the follow-up change must
refuse to resolve it. Recording the kind here is what lets it tell indexed
(order-defined) from associative (order-undefined) apart.

### D2 — Subscripted parameter reference in `WordPart`

Add a subscript to parameter-expansion word parts — either a new
`WordPart::ArrayExpansion { name, subscript }` or an optional `subscript` field on
the existing parameter parts. `subscript` is itself a small enum: `Index(Word)`
(may be dynamic), `All` (`@`), `Star` (`*`), with the length form `${#name[@]}`
captured by the existing length operator plus the subscript. The lexer recognises
`[ … ]` immediately after a name inside `${…}` (and for bare `$arr` there is no
subscript — `$arr` is `${arr[0]}`).

### D3 — Lexing the array literal

After `name=` (or `name+=`) at a command-word boundary, an opening `(` begins an
array literal: lex element words until the matching `)`, honouring quoting and
nested expansions, then resume normal command parsing. `name[i]=v` is an indexed
element assignment (scalar value, subscripted target). The previous behaviour
(error at `(`) is removed; a genuinely malformed array (unterminated `(`) still
produces an Error diagnostic per the existing unterminated-construct rules — that
is a real error, not silent truncation.

### D4 — Evaluator accepts but does not resolve

`crates/engine` decompose/eval must handle the new nodes: an array assignment
contributes its element words as embedded-command / taint scan sites exactly as a
scalar value does (so `arr=($(cmd))` still gates the substitution); a subscripted
expansion is `is_expansion_bearing() == true`. No value resolution. This keeps the
change behaviour-preserving except for the recovered tail command.

## Risks / Trade-offs

- **Wide blast radius on `Assignment.value`.** Every match on the assignment value
  must gain an array arm. Mitigated by the enum approach (compiler finds every
  site) and the parser/eval proptests that must not panic on arbitrary input.
- **Lexer complexity / quoting inside `(…)`.** Array elements can contain
  quotes, expansions, and substitutions. Reuse the existing word lexer per
  element rather than a bespoke scanner.
- **Associative and sparse forms.** v1 only guarantees no truncation and no panic
  for `declare -A`, sparse indices, `+=`, `unset 'arr[i]'`. Faithful value
  modelling of these is deferred; the parser must represent or coarsely diagnose
  them without dropping tokens.
- **Behaviour-preserving claim must be tested.** A proptest asserting that, for
  inputs without arrays, decisions are byte-for-byte unchanged guards against
  accidental regressions from the `Assignment.value` refactor.
- **Unblocks but is not consumed yet.** Value only fully realises once
  `resolve-constant-array-arguments` lands; on its own the win is fidelity (no
  truncation) and a recognisable array AST.
