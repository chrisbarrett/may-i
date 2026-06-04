## Context

`shape-typed-bindings` shipped the four-shape type system and Elm-style
diagnostics. In real use, the demo at `/tmp/may-i-demo/01-every-on-
token.lisp` exposed a hint-keying gap: applying `(every? #v PRED)` to a
`(positional #v *)` binding produces a diagnostic that correctly
identifies the mismatch but offers a remediation hint that says
"declare the parameter as a list: `(parameter NAME (set #v))`." The
binding is not a parameter, so the rewrite is meaningless.

The hint generator in `src/shape_diag.rs:78-128` keys on
`(operator, found shape, decl_name)` where `decl_name: Option<String>`
is populated for parameter/flag declarations and `None` for positional
and rest declarations. Two structurally different declaration kinds
share the `None` arm, and the name-less fallback hints all assume
"parameter, just no name yet" — which is wrong.

This is a tightening of design D6 ("Elm-style error rendering"). The
fix is contained to the rendering pipeline; AST, canonical form, trust
hashes, and evaluation semantics are untouched.

## Goals / Non-Goals

**Goals.**

- Make every shape-mismatch hint propose a rewrite that actually
  applies to the binding's declaration kind.
- Cover all four declaration kinds — `Parameter { name }`,
  `Flag { name }`, `Positional`, `Rest` — distinctly in the hint
  matrix.
- Pin each kind-aware hint family with a golden test, so regressions
  in copy or routing fail loudly.

**Non-Goals.**

- Changing the AST or the parser's binding model. Declarations are
  already kind-typed inside the engine; we just need to surface that
  information into `ShapeMismatch`.
- Adding new operators or new shapes. The fix is in the
  `(operator × shape × kind) → hint` matrix, not the type system.
- Reworking the diagnostic *structure* (header, both spans, "but"
  framing, hint line) — that's normatively pinned by the existing
  spec and stays as-is.
- Adding count-comparison verbs. The count-shape hints still admit
  the open limit; the wording stays the same.

## Decisions

### D1. Add `DeclKind` enum; replace `decl_name: Option<String>`

In `crates/engine/src/shape.rs`, replace the `decl_name: Option<String>`
field on `ShapeDecl` with a `decl_kind: DeclKind` enum:

```rust
pub enum DeclKind {
    Parameter { name: String },
    Flag { name: String },
    Positional,
    Rest,
}
```

`ShapeMismatch` carries the same enum through to the renderer.

**Rationale.** The current `Option<String>` collapses two distinct
declaration kinds into the `None` arm. Replacing it with a closed enum
makes the kinds explicit at the type level and prevents the
"option-as-tristate" anti-pattern from creeping back. The Rust skill's
"invariant-bearing ADTs" guidance applies: `DeclKind` is the union of
the four kinds that can produce a binding, and the renderer's hint
dispatch is exhaustive over them.

**Alternatives considered.**

- *Add a separate `decl_kind: DeclKind` field beside `decl_name`.*
  Rejected: leaves two ways to say the same thing and invites
  inconsistency.
- *Encode kind via a `decl_name: Option<DeclName>` where `DeclName`
  is itself an enum.* Rejected as needlessly indirect.
- *Pass the full `ResolvedParser` to the renderer and let it
  introspect.* Rejected: bloats the diagnostic payload and couples
  rendering to the parser representation.

### D2. Hint dispatch is a match on `(operator, found_shape, decl_kind)`

The `hint_for` function in `src/shape_diag.rs` becomes a match over
the triple. Each arm produces either `Some(text)` or `None`. The
spec's hint families enumerate the arms; the match SHALL be
exhaustive over the cartesian product up to the cases the spec calls
out, with a default of `None` for everything else.

**Rationale.** A triple-keyed match makes the bug class structurally
impossible: you cannot have a hint that recommends `(parameter …)`
for a `Positional` binding, because the arm that fires for
`Positional` doesn't know how to say that. Exhaustiveness over the
spec'd families also gives us a single place to update copy.

**Alternatives considered.**

- *Compute hints via a builder pattern over individual condition
  predicates.* Rejected: harder to test exhaustively and easier to
  drift from the spec.
- *Keep the existing nested `match` and add a third axis.* Rejected:
  less legible than a flat triple match, and the bug came partly
  from the existing structure hiding the missing axis.

### D3. Test each kind-aware hint family with a golden snapshot

Add per-family tests in `src/shape_diag.rs`'s `tests` module covering
at least:

- Parameter / `Token` / `every?` (existing test, kept).
- Positional / `Token` / `every?` (the bug case, new).
- Positional / `Collection Token` / `authorise` (new, asserts the
  `(command …)` arm is *absent*).
- Rest / `Command` / `every?` (new, asserts `(authorise …)` is the
  suggested move).
- Flag-count / `Count` / `matches?` (existing wording, kept).

Snapshots SHALL go through the same `GraphicalReportHandler` configured
with `unicode_nocolor` already used in `every_on_token_renders_…` so
output is deterministic.

**Rationale.** Goldens catch copy drift and routing regressions in one
shot. The cost is bounded — five small fixtures.

**Alternatives considered.**

- *Pure string-contains assertions (the existing style).* Rejected for
  the positional/rest cases because the *absence* of a string (no
  `(parameter NAME …)` mention) is the assertion that matters, and
  goldens express absence implicitly.
- *insta snapshot files.* Considered. Could land alongside or replace
  the inline `contains` style. Left to implementer's discretion — the
  spec requires the families to be tested, not the testing harness.

## Risks / Trade-offs

- **Risk: ShapeDecl is used outside the renderer.** → Verified
  in-scope: a grep for `decl_name` across `crates/` and `src/` shows
  uses in `shape.rs`, `shape_check.rs`, and `shape_diag.rs` only. All
  are updated in lockstep by this change.
- **Risk: existing snapshot tests in `src/shape_diag.rs` break.** →
  Acceptable. Their assertions are kept where the rendered text is
  unchanged (parameter case) and updated where the rendering changes
  (positional case). Each change to a snapshot is a deliberate spec
  alignment.
- **Trade-off: more enum variants to maintain.** Future declaration
  kinds would need to be added to `DeclKind`. Mitigated by the
  closed set of kinds being a parser-side fact, not a rule-side
  choice; new kinds are infrequent and intentional.

## Open Questions

- **Should the positional hint mention both `+` and `*`?** Today the
  spec text suggests "`(positional #v +)` for one-or-more or
  `(positional #v *)` for zero-or-more." If the user wrote `*` already,
  suggesting `*` is a no-op. The implementation can branch on the
  observed quantifier, but the spec is silent. Lean: keep the spec
  permissive (either is fine), implement the smarter branch if cheap.
