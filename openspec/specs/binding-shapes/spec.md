---
audience: contributor
bucket: parsing
trust-relevant: true
---
# binding-shapes Specification

## Purpose

This is a contributor-facing spec. It defines the closed shape vocabulary
(`Token`, `Command`, `Collection Token`, `Count`) that the type checker assigns
to every parser-declared `#var` binding, the shape signatures of the rule-body
operators that consume bindings, and the load-time diagnostics raised on a shape
mismatch. It uses contributor vocabulary (shape, type checker) for the internal
machinery, but pins the user-facing rendering of shape-mismatch errors to plain
language (a single value, a command line, a list of values, a count) so that
those terms never leak into messages a user reads.

Shape declarations participate in canonical form and therefore in trust hashing:
changing a parameter from `(parameter NAME #v)` to `(parameter NAME (set #v))`
changes the hash and requires re-approval. See `trust-hashing` for the canonical-
form and hashing rules this spec depends on, and `migration-system` for the
Class B (semantics-changing) classification that prevents automatic rewrites.

## Requirements

### Requirement: Binding shape vocabulary

Every parser-declared `#var` binding SHALL carry exactly one shape
drawn from a fixed, closed vocabulary. The vocabulary is:

- `Token` — a single argv token (a string).
- `Command` — a captured value that is itself a command line, either as a
  single string (per-parameter `-c`-style capture) or as a token list
  whose first element is a command name (per-`(rest …)` capture).
- `Collection Token` — an ordered sequence of zero or more tokens.
- `Count` — a non-negative integer derived from counting flag
  occurrences.

The shape vocabulary SHALL be closed: no other shape kinds participate
in the type system at this time. Subtyping SHALL NOT be introduced;
`Token` and `Command` are distinct shapes even though both are
string-valued at the storage layer.

#### Scenario: Shapes form a closed set

- **WHEN** the type checker classifies a binding
- **THEN** the resulting shape SHALL be one of `Token`, `Command`,
  `Collection Token`, or `Count`
- **AND** no other shape kind SHALL be produced.

### Requirement: Each parser declaration assigns a shape to its binding

The type checker SHALL assign a shape to every `#var` declared in a
parser body, derived from the declaration form:

- `(parameter NAME #v)` (no shape form) SHALL assign shape `Command` when
  used with `(authorise …)` semantics where the captured value is a
  single command-bearing argument (e.g. `bash -c`), and shape `Token`
  otherwise. The default assignment SHALL be `Token` unless the parser
  declaration is for a known command-bearing parameter recognised by
  the prelude or marked by `(command)` (see below).
- `(parameter NAME (one  #v))` SHALL assign shape `Token`.
- `(parameter NAME (last #v))` SHALL assign shape `Token`.
- `(parameter NAME (set  #v))` SHALL assign shape `Collection Token`.
- `(parameter NAME (many-till PAT) #v)` SHALL assign shape `Command`
  (the token list joined with single spaces becomes a command line per
  the existing `(many-till …)` semantics).
- `(parameter NAME (command #v))` SHALL assign shape `Command` (explicit
  marker for command-bearing single-occurrence parameters such as
  `bash -c`).
- `(positional #v)` with no quantifier or `?` quantifier SHALL assign
  shape `Token`.
- `(positional #v *|+)` SHALL assign shape `Collection Token`.
- `(rest #v)` SHALL assign shape `Command` (the token list whose first
  element is the inner command name).
- `(flag NAME (count #v))` SHALL assign shape `Count`.

Shape assignment SHALL be a pure function of the surface declaration —
no inference from rule-body uses.

#### Scenario: `(parameter NAME (set #v))` is Collection Token

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)) (rest #cmd))`
- **WHEN** the type checker runs over this parser body
- **THEN** `#opts` SHALL have shape `Collection Token`
- **AND** `#cmd` SHALL have shape `Command`.

#### Scenario: `(flag NAME (count #v))` is Count

- **GIVEN** `(parser "curl" (style gnu) (flags permute) (flag "v" (count #verbosity)))`
- **WHEN** the type checker runs
- **THEN** `#verbosity` SHALL have shape `Count`.

#### Scenario: Unannotated `(parameter NAME #v)` defaults to Token

- **GIVEN** `(parser "xargs" (style gnu) (flags posix) (parameter "n" #procs) (rest #cmd))`
- **WHEN** the type checker runs
- **THEN** `#procs` SHALL have shape `Token`
- **AND** the binding SHALL track the value of the last `-n` occurrence,
  consistent with existing single-occurrence semantics.

### Requirement: Rule-body operators have declared shape signatures

Each rule-body form that consumes a `#var` SHALL declare the shape(s) it
accepts. The type checker SHALL reject a use whose argument shape does
not match.

The signatures SHALL be:

- `(authorise #v)` — `#v : Command`. Other shapes SHALL fail at load.
- `(bound?    #v)` — `#v : ∀τ. τ` (any shape). Always permitted.
- `(matches?  #v PAT)` — `#v : Token | Command`. Collection and Count
  shapes SHALL fail at load.
- `(every?    #v PRED)` — `#v : Collection Token`. Other shapes SHALL
  fail at load.
- `(some?     #v PRED)` — `#v : Collection Token`. Other shapes SHALL
  fail at load.
- `(with-facts [[:k #v]] BODY)` — `#v : Token | Command | Collection
  Token`. `Count` SHALL fail at load.

`PRED` in `(every? …)` and `(some? …)` SHALL be a single-token Pattern
expression (literal, regex, wildcard `*`, `(or …)`, `(and …)`, `(not
…)`, fact-binding `[:k *]`); shapes carried by sub-expressions are
unconstrained because the predicate operates on individual tokens, not
on a `#var` directly.

#### Scenario: `(authorise …)` on Collection rejects

- **GIVEN** `(parser "ssh" (style gnu) (flags posix) (parameter "o" (set #opts)))` and `(rule "ssh" (authorise #opts))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with a shape-mismatch diagnostic
- **AND** the diagnostic SHALL name `#opts` as `Collection Token` and
  `(authorise …)` as requiring `Command`.

#### Scenario: `(every? …)` on Token rejects

- **GIVEN** `(parser "xargs" (style gnu) (flags posix) (parameter "n" #procs) (rest #cmd))` and `(rule "xargs" (when (every? #procs (regex "^[0-9]+$")) (allow)))`
- **WHEN** the config is loaded
- **THEN** loading SHALL fail with a shape-mismatch diagnostic
- **AND** the diagnostic SHALL name `#procs` as `Token` and `(every?
  …)` as requiring `Collection Token`.

#### Scenario: `(matches? …)` on Collection rejects

- **GIVEN** `(parser "find" (style single-dash-long) (flags permute) (parameter "exec" (many-till ";") #args))` evaluated under a hypothetical rule `(rule "find" (when (matches? #args (regex "rm")) (ask)))`
- **WHEN** the config is loaded
- **THEN** the loader SHALL accept the rule because the `(many-till …)`
  capture has shape `Command` (string-joined), not `Collection Token`
- **AND** the existing `(matches? …)` semantics over a `Command`-shaped
  binding SHALL apply.

### Requirement: Shape mismatches surface as load-time diagnostics

A shape mismatch detected during config load SHALL be reported as an
error-severity diagnostic. Shape mismatches SHALL NOT be silently
downgraded to no-match at evaluation time — this is the durable
distinction from the pre-shape-system behaviour where typos and shape
errors manifested as unexplained no-match outcomes.

The diagnostic SHALL carry the data needed to render the error
message described in "Shape-mismatch error message format" below: the
source span of the offending rule-body form, the `#var` name, the
binding's declared shape, the operator name, the operator's expected
shape(s), and (where the parser declaration is the proximate cause)
the source span of the parser declaration that assigned the binding's
shape.

#### Scenario: Diagnostic carries both spans

- **GIVEN** a config where `(every? #v …)` in a rule references a
  binding declared as `(parameter "o" #v)` in the parser
- **WHEN** the loader detects the shape mismatch
- **THEN** the emitted diagnostic SHALL include the source span of the
  `(every? …)` form
- **AND** SHALL include the source span of the `(parameter "o" #v)`
  declaration.

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
single-step textual remedy that recovers the rule's apparent intent:

- `(every? #v …)` or `(some? #v …)` against a `Token`-shaped binding
  declared as `(parameter NAME #v)` → hint to rewrite the parser
  declaration as `(parameter NAME (set #v))`.
- `(authorise #v)` against a `Collection Token`-shaped binding declared
  as `(parameter NAME (set #v))` → hint to use `(some? #v PRED)` or
  `(every? #v PRED)` if iteration was intended, or to rewrite the
  parser declaration as `(parameter NAME (command #v))` if the
  parameter was meant to bear a single command line.
- `(matches? #v …)` against a `Count`-shaped binding → hint that
  counts compare to numbers, not patterns; suggest `(>= #v N)` or the
  equivalent when that surface lands (see the design doc for the
  count-comparison forms; until then, the hint SHALL point at the
  underlying `(flag NAME)` presence check).
- `(authorise #v)` against a `Count`-shaped binding → hint that counts
  are not command lines; suggest reviewing the parser declaration.

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

#### Scenario: Hint proposes a single-step rewrite

- **GIVEN** `(every? #v PRED)` applied to a binding declared as
  `(parameter "o" #v)`
- **WHEN** the message is rendered
- **THEN** the rendered text SHALL include a hint line
- **AND** the hint SHALL propose rewriting the parser declaration to
  `(parameter "o" (set #v))`.

#### Scenario: Hint omitted when no single-step remedy is identifiable

- **GIVEN** a shape mismatch whose remediation depends on broader rule
  restructuring (e.g. multiple bindings interact)
- **WHEN** the message is rendered
- **THEN** the hint line SHALL be omitted rather than filled with
  generic advice.

### Requirement: `may-i check` runs the shape checker

The `may-i check` subcommand SHALL invoke the shape checker over every
loaded rule body and SHALL surface all shape mismatches as part of its
output. `may-i check` SHALL exit non-zero when any shape mismatch is
reported.

`may-i check` SHALL emit shape-mismatch diagnostics alongside other
check-time diagnostics in source order. No deduplication SHALL occur
across check-mode runs; every mismatch in the config SHALL appear.

#### Scenario: Check exits non-zero on shape mismatch

- **GIVEN** a config containing one shape mismatch
- **WHEN** `may-i check` is invoked
- **THEN** the shape-mismatch diagnostic SHALL appear in the output
- **AND** the process SHALL exit non-zero.

### Requirement: Shape declarations participate in canonical form

The canonical-form serialisation of a parser body SHALL include the
shape-bearing declaration forms verbatim. Changing a parameter from
`(parameter NAME #v)` to `(parameter NAME (set #v))` SHALL produce a
different canonical form and therefore a different trust hash. The
unannotated form `(parameter NAME #v)` SHALL canonicalise to its
current form unchanged, so existing trust-store entries continue to
verify.

This change category SHALL be classified Class B (semantics-changing)
for migration purposes: `may-i migrate` SHALL NOT automatically rewrite
unannotated parameters into shape-bearing forms, and trust SHALL NOT
auto-carry across such rewrites.

#### Scenario: Unannotated form canonicalises unchanged

- **GIVEN** a trust-store entry hashed under `(parameter "n" #procs)`
- **WHEN** the new shape system is in effect with no rewrite applied
- **THEN** the canonical form SHALL be unchanged
- **AND** the trust entry SHALL continue to verify.

#### Scenario: Shape annotation changes the hash

- **GIVEN** a parser body rewritten from `(parameter "o" #opts)` to
  `(parameter "o" (set #opts))`
- **WHEN** the canonical form is recomputed
- **THEN** the resulting hash SHALL differ
- **AND** any pre-existing trust entry SHALL require re-approval.
