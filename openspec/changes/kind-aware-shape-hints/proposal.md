## Why

The shape-mismatch hint renderer (`src/shape_diag.rs:78-128`) keys hints on
`(operator, found shape, decl_name presence)`. The `decl_name` field is
`Some(name)` for parameter and flag bindings and `None` for positional and
rest bindings. That collapses two distinct declaration kinds —
`(positional …)` and `(rest …)` — into the same name-less hint branch as
"a parameter without a name."

Result: when `(every? #v PRED)` is applied to a `(positional #v *)`
binding, the rendered hint reads:

> To match every occurrence, declare the parameter as a list:
> (parameter NAME (set #v)).

…even though there is no parameter to declare. The actual fix is
`(positional #v +)`. The user is pointed at the wrong slot.

A second, smaller miss: the hint for `(authorise #v)` against a
`Collection Token`-shaped binding without a name suggests
`(parameter (command #v))`, which is parameter-only. For a positional or
rest collection (rest is always `Command`, but the principle applies to
analogous future shapes), the suggestion is structurally meaningless.

## What Changes

- Extend the binding declaration metadata threaded into the shape checker
  so each mismatch knows the declaration *kind* — `Parameter { name }`,
  `Flag { name }`, `Positional`, or `Rest` — rather than just whether a
  name is present.
- Update the hint generator in `src/shape_diag.rs` to branch on the
  declaration kind. Each `(operator, found shape, decl kind)` triple
  picks the rewrite that actually applies:
  - `(every?/some?, Token, Positional)` → "use a multi-positional quantifier: `(positional #v +)` or `(positional #v *)`."
  - `(every?/some?, Token, Parameter { name })` → existing "declare `(parameter \"NAME\" (set #v))`" hint.
  - `(every?/some?, Token, Flag { name })` → "a flag has no value to collect; if you meant `(count #v)`, use `(bound? #v)` or wait for count comparisons."
  - `(authorise, CollectionToken, Positional)` → suggest only the iteration alternatives (`every?` / `some?`); drop the parameter-only `(command …)` arm.
  - `(authorise, CollectionToken, Parameter { name })` → unchanged.
  - All other variants similarly tightened.
- Add tests pinning each kind-aware hint family with golden snapshots.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `binding-shapes`: tighten "Shape-mismatch error message format" so hint
  selection is normatively driven by the declaration *kind*, not just by
  `decl_name` presence. Add scenarios for the positional and rest
  variants.

## Impact

- **`src/shape_diag.rs`** — `hint_for` rewrites; consumes new declaration
  kind enum from the engine.
- **`crates/engine/src/shape.rs`** — `ShapeDecl` gains a `kind` field
  (or replaces `decl_name: Option<String>` with a `DeclKind` enum). The
  module-internal `from_parser` builder populates it.
- **`crates/engine/src/shape_check.rs`** — `ShapeMismatch` carries the
  new kind through to the renderer.
- **Tests** — new golden cases in `src/shape_diag.rs` covering positional
  and rest bindings under each mismatch family; existing parameter-based
  tests stay green.
- **Canonical form / trust hashes** — unaffected (renderer-only change;
  AST + serialisation untouched).
- **Migration** — none. Existing rule configs and parser declarations
  parse and behave identically.
- **Dependencies** — none new.
