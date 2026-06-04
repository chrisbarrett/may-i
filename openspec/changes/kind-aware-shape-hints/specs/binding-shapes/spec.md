## MODIFIED Requirements

### Requirement: Shape-mismatch error message format

Shape-mismatch error messages SHALL follow the rendering conventions
below. The goal SHALL be to address the reader as a collaborator,
describe in plain language what was found and what was expected, and
propose a concrete fix where one is obvious.

**User-facing vocabulary.** Error messages SHALL describe shapes in
the user-facing register, not in contributor-internal type names:

| Internal shape    | Phrase in error messages         |
| ----------------- | -------------------------------- |
| `Token`           | "a single value"                 |
| `Command`         | "a command line"                 |
| `Collection Token`| "a list of values"               |
| `Count`           | "a count"                        |

The word *shape* SHALL NOT appear in user-facing error text. The word
*type* SHALL NOT appear either; both are contributor vocabulary.
"Binding" MAY appear; "value" is preferred when context allows.

**Structure.** Every shape-mismatch message SHALL contain, in order:

1. A one-line header naming the problem in plain English, beginning
   with the rule-body operator that triggered the mismatch.
2. The source location (file, line, column) of the offending form,
   followed by a code excerpt showing the form in context with a
   caret/underline pointing to the binding reference.
3. A "But" paragraph stating what the binding actually is and where it
   was declared, including a code excerpt of the parser declaration
   with location.
4. A "Hint:" line, when a concrete fix is identifiable from the
   mismatch, proposing the rewrite that resolves it.

**Tone.** Messages SHALL address the reader directly using second
person or impersonal description. Messages SHALL NOT use blaming
language ("you wrote this wrong", "invalid", "illegal"). Messages
SHALL NOT use internal jargon ("type error", "shape mismatch",
"AST node") in the user-facing body — these terms MAY appear in JSON
output for tooling consumers, but the rendered text SHALL prefer plain
language.

**Hints.** A hint SHALL be included when the mismatch has a
single-step textual remedy that recovers the rule's apparent intent.
Hint selection SHALL be driven by the **declaration kind** of the
binding — `Parameter { name }`, `Flag { name }`, `Positional`, or
`Rest` — in addition to the operator and the found shape. A hint
SHALL NOT propose a rewrite that does not apply to the binding's
declaration kind (e.g. SHALL NOT suggest a `(parameter NAME …)`
rewrite for a binding declared by `(positional …)` or `(rest …)`).

The required hint families are:

- `(every?/some? #v …)` against a `Token`-shaped binding declared by
  a `(parameter NAME #v)` → hint to rewrite the parser declaration as
  `(parameter "NAME" (set #v))`.
- `(every?/some? #v …)` against a `Token`-shaped binding declared by
  a `(positional #v)` (no quantifier or `?`) → hint to widen the
  quantifier, e.g. `(positional #v +)` for one-or-more or
  `(positional #v *)` for zero-or-more.
- `(every?/some? #v …)` against a `Count`-shaped binding declared by
  `(flag "NAME" (count #v))` → hint that a count is not a list and
  point at the count-presence check (`(bound? #v)`) until count
  comparisons are surfaced.
- `(every?/some? #v …)` against a `Command`-shaped binding declared
  by a `(parameter NAME #v)` (single-occurrence command-bearing) →
  hint that the parameter carries a command line; suggest
  `(parameter "NAME" (set #v))` if the parameter is repeated.
- `(every?/some? #v …)` against a `Command`-shaped binding declared
  by `(rest #v)` → hint that rest captures the whole tail; suggest
  recursing with `(authorise #v)` if iteration was not intended.
- `(authorise #v)` against a `Collection Token`-shaped binding
  declared by `(parameter NAME (set #v))` → hint with both arms:
  `(every? #v PRED)` / `(some? #v PRED)` if iteration was intended,
  or rewrite the parser declaration as
  `(parameter "NAME" (command #v))` if the parameter was meant to
  carry a single command line.
- `(authorise #v)` against a `Collection Token`-shaped binding
  declared by a `(positional #v *|+)` → hint with the iteration arm
  only (`(every? #v PRED)` / `(some? #v PRED)`). SHALL NOT mention
  `(parameter (command …))` because positionals have no parameter
  name and no `(command …)` form.
- `(matches? #v …)` against a `Count`-shaped binding → hint that
  counts compare to numbers, not patterns; until count comparisons
  surface, suggest `(bound? #v)`.
- `(authorise #v)` against a `Count`-shaped binding → hint that
  counts are not command lines; suggest reviewing the parser
  declaration.

When no single-step remedy is identifiable, the hint line SHALL be
omitted rather than padded with generic advice.

**Example renderings.** The following illustrate the intended shape of
rendered text. Whitespace and exact wording MAY evolve; the
structural elements (header, both excerpts, "But" framing, optional
"Hint:" with concrete rewrite) are normative.

```
-- LIST EXPECTED -------------------------------- config.lisp:42:11

This `every?` is looking at every value in a list of values:

    42 |   (when (every? #procs (regex "^[0-9]+$"))
                         ^^^^^^

But `#procs` is a single value, declared here:

    17 |   (parameter "n" #procs))
                          ^^^^^^

Hint: To collect every -n occurrence into a list, change the parser
declaration to:

    (parameter "n" (set #procs))
```

```
-- LIST EXPECTED -------------------------------- config.lisp:6:17

This `every?` is looking at every value in a list of values:

    6 |   (when (every? #target (regex "^/tmp/"))
                        ^^^^^^^

But `#target` is a single value, declared here:

    4 |   (positional #target *))
                      ^^^^^^^

Hint: To collect every positional, widen the quantifier:

    (positional #target +)
```

```
-- COMMAND LINE EXPECTED ------------------------ config.lisp:31:9

This `authorise` runs a command line:

    31 |   (authorise #opts))
                      ^^^^^

But `#opts` is a list of values, declared here:

    12 |   (parameter "o" (set #opts))
                          ^^^^^^^^^^^

Hint: Did you mean to inspect each value? Try:

    (every? #opts safe-opt?)

or, if `-o` was meant to carry a single command line, rewrite the
parser declaration as:

    (parameter "o" (command #opts))
```

#### Scenario: Message uses user-facing vocabulary

- **GIVEN** any shape-mismatch error message rendered by the loader or
  by `may-i check`
- **WHEN** the message is rendered as text
- **THEN** the words "shape", "type", "AST", and the bare internal
  shape names (`Token`, `Command`, `Collection Token`, `Count`) SHALL
  NOT appear in the rendered text
- **AND** the message SHALL describe binding shapes using the
  user-facing phrases ("a single value", "a command line", "a list of
  values", "a count").

#### Scenario: Header summarises the expectation

- **GIVEN** an `(every? …)` against a `Token`-shaped binding
- **WHEN** the message is rendered
- **THEN** the header line SHALL state the operator-level expectation
  (e.g. "LIST EXPECTED" or equivalent phrasing summarising that a
  list-shaped binding is needed)
- **AND** SHALL include the source location of the offending form.

#### Scenario: Both source locations rendered with excerpts

- **GIVEN** a shape mismatch where the rule body references a binding
  declared in a parser
- **WHEN** the message is rendered
- **THEN** the rendered text SHALL include a code excerpt for the
  rule-body form
- **AND** SHALL include a code excerpt for the parser declaration
- **AND** each excerpt SHALL underline or otherwise mark the relevant
  span.

#### Scenario: Parameter hint suggests `(set …)`

- **GIVEN** `(every? #v PRED)` applied to a binding declared as
  `(parameter "o" #v)`
- **WHEN** the message is rendered
- **THEN** the rendered text SHALL include a hint line
- **AND** the hint SHALL propose rewriting the parser declaration to
  `(parameter "o" (set #v))`
- **AND** SHALL NOT propose any `(positional …)` rewrite.

#### Scenario: Positional hint suggests widening the quantifier

- **GIVEN** `(every? #target PRED)` applied to a binding declared as
  `(positional #target *)` (single-token quantifier)
- **WHEN** the message is rendered
- **THEN** the rendered text SHALL include a hint line
- **AND** the hint SHALL propose `(positional #target +)` (or
  `(positional #target *)` for the zero-or-more variant)
- **AND** SHALL NOT propose any `(parameter NAME (set …))` rewrite.

#### Scenario: Positional collection routed away from `(command …)` arm

- **GIVEN** `(authorise #paths)` applied to a binding declared as
  `(positional #paths * +)` (collection-shaped positional)
- **WHEN** the message is rendered
- **THEN** the hint SHALL propose iteration (`(every? #paths PRED)`
  or `(some? #paths PRED)`)
- **AND** SHALL NOT propose `(parameter NAME (command #paths))`
  because positionals carry no parameter name and no `(command …)`
  form applies.

#### Scenario: Rest hint avoids parameter-only suggestions

- **GIVEN** a hypothetical mismatch where `(every? #rest PRED)` is
  applied to a `Command`-shaped binding declared as `(rest #rest)`
- **WHEN** the message is rendered
- **THEN** the hint SHALL describe rest as the captured tail and
  SHALL suggest `(authorise #rest)` for recursion
- **AND** SHALL NOT propose any `(parameter NAME …)` rewrite.

#### Scenario: Hint omitted when no single-step remedy is identifiable

- **GIVEN** a shape mismatch whose remediation depends on broader rule
  restructuring (e.g. multiple bindings interact)
- **WHEN** the message is rendered
- **THEN** the hint line SHALL be omitted rather than filled with
  generic advice.
