## Context

The `#var` binding system landed before any quantification surface
existed in rule bodies. Today's bindings are essentially untyped: the
engine knows whether a name is bound, and stores either a single
string or a token list, but rule-side forms (`(authorise …)`,
`(matches? …)`, `(bound? …)`, `(with-facts …)`) all accept any
binding and behave by ad-hoc inspection at evaluation time. Failures
manifest as silent no-matches.

Two pressures arrive together:

1. **Multi-occurrence semantics.** Many programs accept the same flag
   repeatedly with different semantics — set-accumulation (`ssh -o`,
   `docker -e`, `curl -H`), last-wins (`gcc -O`, many `--config`
   parameters), occurrence counts (`-vvv`). The current engine has
   *some* multi-occurrence handling (`(many-till …)` and multi-`-exec`
   under `find`), but no general way for the parser to declare which
   flavour applies, and no rule-side surface to fold a predicate over
   the resulting collection.

2. **Argv-position quantifiers.** The motivating `rm` rule wants "all
   positionals satisfy P" — an idiomatic need that appears wherever a
   variadic command accepts a fan-out of similar arguments.
   `(exact (+ PAT))` accidentally works for the ∀-over-positionals
   case; nothing works for ∃ or for parameters.

The exploration that led here landed on a simply-typed lambda calculus
fragment as the right organising principle. Bindings carry a *shape*;
operators have shape signatures; the loader checks rule bodies
against the parser declarations they reference. The vocabulary stays
small: `Token`, `Command`, `Collection Token`, `Count`. The
user-facing surface keeps to "binding" / "value" / "list of values" /
"command line" / "count" — the word *shape* lives in contributor
docs.

Project context: pre-1.0; back-compat is not promised, but the
trust-hash story matters because users have approved rule bundles
whose canonical form participates in those hashes (see
`openspec/specs/trust-hashing/`, `openspec/specs/parser-bindings/`).
The migration system distinguishes Class A (semantics-preserving
rewrites — trust carries) from Class B (semantics-changing — trust
re-prompts). Shape annotations are deliberately Class B for any
existing parameter whose semantics are being opted into a new shape.

## Goals / Non-Goals

**Goals.**

- Give bindings a small, closed shape vocabulary that the engine can
  check rule bodies against at load time.
- Make multi-occurrence parameters declarative on the parser side
  (`(set …)`, `(last …)`, `(one …)`, `(command …)`) rather than
  implicit-last-wins.
- Add `(every? …)` / `(some? …)` rule-body verbs that fold a Pattern
  predicate over a `Collection Token` binding.
- Replace silent no-match outcomes from binding/operator misuse with
  high-quality, Elm-style load-time errors.
- Preserve every existing rule body and parser declaration unchanged.
  The unannotated `(parameter NAME #v)` form retains last-wins
  semantics and the same canonical-form hash.

**Non-Goals.**

- Polymorphism, type variables in the user-facing surface, or
  user-defined shapes. The four shapes are the fixed set.
- Subtyping between shapes (no `Token <: Command` even though both
  store strings).
- A general arithmetic surface on `Count`. The shape exists so the
  engine can reject obvious misuses (`(authorise #count)`,
  `(matches? #count …)`); the comparison verbs over counts can land
  later if there's demand.
- Rule-author-visible inference. Shapes are computed from parser
  declarations alone; users do not annotate bindings on the rule side.
- Reshaping facts. Facts are out of scope and remain set-of-strings
  keyed by `:k`; they are *not* unified with the shape system (see
  prior conversation: facts may be replaced wholesale eventually, and
  conflation would ossify a mechanism we expect to revisit).
- Migrating existing prelude parameters into `(set …)` etc. on this
  change. Each such migration is its own Class B move with its own
  scenarios; the prelude diff stays minimal here.

## Decisions

### D1. Shape vocabulary is `Token | Command | Collection Token | Count`

`Token` is a single argv token, `Command` is a command-bearing
string-or-list, `Collection Token` is an ordered list of tokens, and
`Count` is a non-negative integer.

**Rationale.** This is the minimum vocabulary that distinguishes the
operator-affecting cases in the current rule-body surface:
`(authorise …)` consumes `Command`; `(matches? …)` consumes
`Token | Command`; `(every? …)`/`(some? …)` consume `Collection
Token`; `(with-facts …)` consumes anything except `Count`. Counts get
their own shape because they are semantically numeric, not strings —
`(matches? #v PAT)` on a count is always a category error.

**Alternatives considered.**

- *Single `Collection τ` parameterised by element shape.* Considered
  generalising to `Collection Command`, `Collection Count`, etc. None
  of these arise in real programs: `-exec` already collapses to a
  joined command line, counts don't repeat, and flag values are
  uniformly token-shaped. Rejected for YAGNI.
- *Subtype `Token <: Command`.* Tempting because a single token is
  trivially also a one-element command line. Rejected because the
  reverse direction is much more common (`(matches? #cmd …)` against
  a multi-token rest-binding intentionally string-joins, and
  pretending a multi-token command is a single token undermines the
  whole point of distinguishing them).
- *No `Count` shape; model `-vvv` as a `Collection Token` of "v"
  strings.* Technically possible. Rejected because every rule-side
  use of a counted flag wants the integer, not the token list, and
  forcing the user to `(every? #vs "v")` to get count semantics is
  absurd.

### D2. Shape is determined entirely by the parser declaration

The shape of a binding is a pure function of the parser-side
declaration form. The rule body never overrides it, never narrows it,
never widens it. Rule-body operators have fixed shape signatures and
the loader checks each `#var` reference against the operator's
signature.

**Rationale.** Unidirectional inference keeps the type system at the
trivial end of STLC: no unification, no inference variables, no
type-variable rewriting. The loader's check is a straight lookup
("binding `#v` has shape S; this operator wants shape T; do they
match?"). Implementation cost stays proportional to the value the
type checker delivers.

**Alternatives considered.**

- *Bidirectional checking or full Hindley-Milner.* Would let the rule
  side influence the binding shape (e.g. `(every? #v …)` would imply
  `#v : Collection Token`). Rejected because (a) it complicates the
  loader without obvious user benefit and (b) it makes error messages
  worse — the "this binding is the wrong shape" error becomes
  "there's no consistent shape assignment," which Elm-style framing
  cannot rescue.
- *Late binding (check at evaluation time).* Lose the static
  guarantee, lose the loader-time error, gain nothing. Rejected.

### D3. Quantifier surface is `(every? …)` / `(some? …)`, not `forall`/`exists`

The two verbs are `(every? …)` and `(some? …)`. The `?` suffix marks
them as boolean-returning, consistent with `(bound? …)` and
`(matches? …)` from `parser-bindings`. Both take a `#var` directly
(no scope-expression argument).

**Rationale.**

- Lisp tradition for boolean-returning predicates (`?` suffix). Names
  read aloud naturally.
- The previous-conversation alternative — `(every? (positional) PAT)`
  with a scope-expression argument — was attractive when bindings
  were untyped because the scope was the only way to name "which
  collection." Once bindings carry shape, the binding *is* the
  collection: `(every? #paths PAT)` says exactly what it does.
- Logic-style `(forall (positional) PAT)` reads colder and has no
  precedent in the rest of the DSL surface.

**Alternatives considered.**

- *`(forall …)` / `(exists …)`.* Considered. Rejected on stylistic
  fit; the rest of the rule body uses `?`-suffix predicates and
  imperative-flavoured verbs.
- *Reuse `(and …)` / `(or …)` over a collection.* `(and PAT…)` and
  `(or PAT…)` already mean per-token alternation in pattern context.
  Overloading would create two semantically different meanings for
  the same head — rejected.
- *Keyword modifier on existing matchers (`(positional :all PAT)`).*
  Rejected as discussed in the exploration: changes the grammar of
  `(positional …)` from "ordered list of patterns" to "one predicate
  folded over positionals" depending on a magic keyword.
- *Generic `(all-positional PAT)` / `(any-positional PAT)`.* Rejected
  because it doesn't generalise to repeated parameters without name
  explosion (`all-parameter-o`, `any-anywhere`, etc.).

### D4. Empty-collection truth values follow logic, not user intuition

`(every? #v PRED)` on an empty collection matches (vacuous truth).
`(some? #v PRED)` on an empty collection does not match.

**Rationale.** The mathematical convention. Most other systems do
this; reversing it would surprise anyone who's used `every`/`all`
elsewhere. The trade-off — that `(every? #paths safe?)` allows `rm
-rf` with no positionals — is mitigated by the fact that the
surrounding rule will usually require at least one positional via
quantifiers in the parser declaration, or via combining with
`(positional …)` in the rule body.

**Alternatives considered.**

- *`every?` on empty is false.* Considered for surprise-minimisation
  but rejected; reversed `every?`-semantics is the kind of inversion
  that ends up in FAQs forever.
- *Configurable.* Rejected as scope creep.

### D5. Single user-facing vocabulary; `shape` stays contributor-side

User-facing surfaces (error messages, REFERENCE.md examples,
diagnostics rendered by `may-i check`) describe binding shapes as "a
single value", "a command line", "a list of values", "a count". The
word *shape* and the type names `Token` / `Command` / `Collection
Token` / `Count` appear only in contributor-facing docs (this design,
the `binding-shapes` spec's Purpose, CONTEXT.md's contributor
vocabulary table). JSON output for tooling consumers MAY surface the
internal names under stable keys.

**Rationale.** CONTEXT.md already enforces this split for the
patterns surface (`Pattern` is user-facing, `Expr<T>`/`ArgPattern`
are contributor-side). Shapes fit the same template. Elm-style errors
in particular depend on plain-English description; importing the type
vocabulary into the rendered text would make messages worse.

### D6. Elm-style error rendering for shape mismatches

Shape-mismatch errors are not "type errors" in the rendered text.
They are concrete descriptions of what was found and what was
expected, with code excerpts and a hint when a single-step rewrite is
identifiable. The structure is:

1. Header naming the operator and the expected shape in plain English
   ("LIST EXPECTED" / "COMMAND LINE EXPECTED" / "SINGLE VALUE
   EXPECTED" / "COUNT EXPECTED" or equivalent).
2. Source excerpt of the offending form with span underlined.
3. "But `#name` is *X*, declared here:" with the parser-declaration
   excerpt and span underlined.
4. Optional "Hint:" with a concrete rewrite when one is obvious.

The normative format lives in the `binding-shapes` spec under
"Shape-mismatch error message format". The principles deserve
their own decision here because they shape every other engineering
choice: span propagation through the loader, source-text retention for
excerpt rendering, and the maintainability cost of hand-tuned hint
messages.

**Rationale.** Elm's error messages are the gold standard for
small-language tooling because they (a) speak to the reader rather
than to a compiler, (b) make the contradiction visible with both
sides of the constraint laid out, and (c) suggest a fix. `may-i`'s
audience is rule authors who are not necessarily type theorists; the
error messages are their compiler.

**Alternatives considered.**

- *Terse rust-style errors with `--explain` codes.* Cheaper to
  produce, harder to act on. Rejected; the language is small enough
  that bespoke hints per mismatch family are tractable.
- *Punt rendering, ship the structured diagnostic only.* Rejected:
  text rendering is the primary surface for `may-i check` and for
  load-failure messages in hook mode.

**Maintenance.** Hint generation is centralised — one function per
mismatch family (operator × binding-shape → hint), kept beside the
shape-check pass. New hints are easy to add; the cost is bounded by
the small number of (operator, shape) pairs.

**Cite for prior art.** Elm's error message philosophy is documented
in Evan Czaplicki, "Compiler Errors for Humans" — `https://elm-
lang.org/news/compiler-errors-for-humans` (last verified 2026-06-03)
and the patterns used in Elm 0.19+'s compiler output (see e.g.
`elm/compiler` v0.19.1, `compiler/src/Reporting/Error.hs`).

### D7. Canonical form changes are Class B; default form's hash unchanged

The new shape forms (`(one …)`, `(last …)`, `(set …)`, `(command …)`,
`(count …)`) participate in the canonical-form serialisation. Adding
or changing a shape form is a Class B migration (the migration system
flags it and trust does not auto-carry). The unannotated
`(parameter NAME #v)` form continues to canonicalise as it does
today — its serialisation is byte-identical — so existing trust-store
entries continue to verify after the upgrade.

**Rationale.** Shape-bearing forms change runtime semantics for
multi-occurrence parameters (collection vs last-wins vs explicit
single). That is exactly what Class B is for: the user needs to
re-approve because the rule's effective decision can change. Keeping
the unannotated form byte-stable means a no-op upgrade for users who
don't opt anything into the new shapes.

**Alternatives considered.**

- *Always Class A (auto-carry trust).* Rejected: opting a parameter
  into `(set …)` *changes which inputs the rule matches*, which is
  the definition of Class B.
- *Canonicalise unannotated `(parameter NAME #v)` to `(parameter NAME
  (one #v))`.* Considered for uniformity but rejected: it would break
  every existing trust-store hash for no semantic gain. The two forms
  remain canonically distinct; the migration command can advise users
  who want the explicit form to rewrite manually.

### D8. Implementation order: parser-side declarations → shape checker → rule-side quantifiers

The implementation lands in three phases inside the single change:

1. Parser-side shape declaration parsing and binding-shape assignment
   (the data structures; no behaviour change).
2. Shape checker pass over rule bodies; existing rule-body operators
   gain shape signatures; mismatches become diagnostics.
3. Rule-side `(every? …)` / `(some? …)` evaluation; multi-occurrence
   collection accumulation for `(set …)` and `(count …)`.

Each phase is independently testable: phase 1 against parser fixtures
that round-trip; phase 2 against a corpus of intentionally
mismatched rules (with golden Elm-style messages); phase 3 against
evaluation-level proptests folding predicates over generated argv.

**Rationale.** This order minimises the time the engine is in an
inconsistent state: shapes exist before any checker reads them; the
checker exists before quantifier evaluation gives shapes runtime
meaning.

## Risks / Trade-offs

- **Risk: introducing a type system raises the bar for contributing
  to the engine.** → Mitigation: keep the vocabulary closed at four
  shapes; document them in `CONTEXT.md` alongside the existing
  contributor terms; resist adding new shapes without an ADR.
- **Risk: Elm-style error rendering is maintenance-heavy.** →
  Mitigation: hint generation is per-(operator, shape) pair, a small
  matrix; golden-output tests pin the rendered format; rendering
  lives behind a single function so style changes are localised.
- **Risk: users have rules whose `(authorise …)` against a
  multi-occurrence parameter currently silently works.** →
  Mitigation: under the new system, `(authorise #v)` against
  `(parameter NAME #v)` (default `Token` shape, last-wins) continues
  to recurse on the last occurrence's value — unchanged behaviour.
  Only explicit opt-in to `(set …)` changes the shape and triggers
  the type checker.
- **Risk: empty-collection vacuous truth surprises users.** →
  Mitigation: error messages and REFERENCE.md examples lead with the
  combination idiom — `(every? #paths safe?)` is almost always
  guarded by an outer `(flag …)` or `(positional …)` requirement that
  precludes the empty case from mattering.
- **Trade-off: shape inference is unidirectional.** A user who writes
  `(every? #v PAT)` and has not yet declared the parser side gets a
  "binding not declared" error, not a "this binding should be a
  collection" inference. Acceptable — the loader's job is to point
  at the offending site, and the user's task list flows naturally
  from there.
- **Trade-off: counts have no comparison surface yet.** A user who
  writes `(flag "v" (count #n))` cannot directly test `#n` until
  count comparators land. The shape exists so future surfaces can be
  added without re-touching trust hashes; users who don't need the
  count shape can keep declaring `(flag "v")` as today.

## Open Questions

- **Should `(set …)` deduplicate?** Today's facts deduplicate
  (set-of-strings). A `Collection Token` binding from `(set …)` is
  meant as ordered-with-duplicates, since `ssh -o A=1 -o A=2` is a
  real (if unusual) input. Currently the spec preserves duplicates
  in the binding but deduplicates when promoted to a fact via
  `(with-facts …)`. Confirm before implementation that this matches
  user expectation.
- **Count-comparison surface.** Land in this change (`(>= #n 2)` or
  similar) or defer to a follow-up? Deferring keeps this change
  scoped, but the `Count` shape is somewhat anaemic without it.
- **Hint coverage for nested shape mismatches.** When a rule contains
  multiple shape errors, do we render all of them, or stop at the
  first? Elm shows all per top-level form; the current spec is
  silent on this and tests should pin the answer.
- **Prelude opt-ins.** Once the system lands, which prelude parameters
  should opt into `(set …)` / `(count …)`? ssh `-o` and curl `-v` are
  obvious candidates; doing them in this change extends scope, doing
  them later means the prelude is briefly less expressive than it
  could be. Lean defer-to-follow-up, but flag in tasks.md.
