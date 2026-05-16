## Context

`crates/config/` parses the surface DSL into the core AST defined in
`may_i_core`. Rule-body parsing — everything between a rule's command
position and its trailing optional `(check …)` forms — is currently
fragmented across five modules, each owning one shape of the
contributor-only Pattern-internals split:

| Module             | LOC  | Entry point                                | Contributor type produced       |
| ------------------ | ---- | ------------------------------------------ | ------------------------------- |
| `pattern.rs`       | 1234 | `parse_arg_pattern`, `parse_positional_arg`| `ArgPattern`, `PositionalArg`   |
| `predicate.rs`     | 659  | `parse_predicate`                          | `Predicate`                     |
| `effect.rs`        | 711  | `parse_effect`                             | `Spanned<Effect>`               |
| `parser_form.rs`   | 800  | `parse_parser_form`                        | `ParserForm` (per-program decl) |
| `rule.rs`          | 340  | `parse_rule`, `parse_define`               | `Rule`, `Define`                |

The first three (`parse_effect`, `parse_predicate`, `parse_arg_pattern`)
are re-exported from `crates/config/src/lib.rs` as `pub` — they are
*advertised* to be part of the crate's contract — but in fact zero callers
outside the config crate use them. A workspace grep:

```
$ rg 'may_i_config::(parse_effect|parse_predicate|parse_arg_pattern|parse_positional_arg)' src/ crates/
$  # no hits
```

The downstream crates that *do* operate on rule bodies (`may_i_engine`'s
`engine/src/trust.rs`, the annotation paths in
`engine/src/annotation.rs`, every integration test) consume the
**core AST types** directly — `may_i_core::ast::{Effect, Predicate}`,
`may_i_core::pattern::ArgPattern` — not the config crate's parsers.

CONTEXT.md (lines 81–90, "Pattern internals") is explicit about not
surfacing this split:

> The internal representation is richer than the surface syntax —
> argv-shaped matchers are an `ArgPattern` enum, single-token matchers
> are `Expr<T>`, and tests in conditional position go through a
> `Predicate` enum. Resist the urge to surface this split in user docs,
> error messages, or DSL forms; users see one kind of thing.

The four `pub` sub-parser exports are exactly that surfacing — at the
config crate's API seam rather than in user docs. They have no consumers
to justify the public-ness; they invite future drift (a contributor
glancing at the seam will assume the split is a real contract worth
preserving in further refactors). Tightening the seam removes the
invitation.

## Goals / Non-Goals

**Goals:**

- Single public entry point for parsing a rule body:
  `may_i_config::parse_rule_body(sexpr) -> Result<Spanned<Effect>, RawError>`.
- The contributor-only sub-parser split (`ArgPattern` / `Predicate` /
  `Effect`) stops leaking past the config crate's `pub` seam. Renaming
  a `Predicate` variant becomes a one-crate change inside `crates/config/`.
- No behavioural change. No DSL change. No trust-hash change.
- One acceptance scenario per axis (seam shape; no external callers;
  trust-hash invariance) anchored in `code-quality`.

**Non-Goals:**

- Renaming or restructuring the core AST types (`Effect`, `Predicate`,
  `ArgPattern`). Those live in `may_i_core` and are consumed widely;
  changing them is a separate, much larger change.
- Introducing a new `RuleBody` newtype distinct from `Spanned<Effect>`.
  The existing `Spanned<Effect>` is what `Rule::effect` already holds;
  inventing a parallel type doubles the conceptual surface for no
  caller benefit.
- Introducing a new traversal API (visitor or evaluator trait) on the
  config crate's surface. Engine and annotation consume
  `may_i_core::ast` types directly today; routing them through a
  config-crate traversal would add an unjustified hop. (Considered and
  rejected — see Decisions.)
- Consolidating the *five* modules' source files into one file. The
  modules can remain separated on disk for readability; only the
  *public seam* changes. (Module consolidation, if desired, is a
  follow-up that would not touch any spec.)
- Merging `parse_parser_form` into `parse_rule_body`. Parser
  declarations are top-level forms, not rule bodies; they are correctly
  scoped today.

## Decisions

### Aggregate behind `parse_rule_body`, do not introduce a new `RuleBody` type

`Rule::effect: Spanned<Effect>` is already the canonical "rule body" in
the core AST. `parse_rule_body` returns `Result<Spanned<Effect>, RawError>`
— the same shape `parse_effect` returns today. The function is a thin
re-naming that documents the intended use site (rule body) and is the
only function the public API needs to expose for body parsing.

**Alternative considered: introduce `pub struct RuleBody(Spanned<Effect>);`**
A newtype would make the seam more explicit but would force every
caller (engine, annotation, tests) to unwrap to reach the existing
`Effect` they already operate on. The existing AST already has the right
shape; renaming the entry point is sufficient. Rejected.

**Alternative considered: keep the existing `parse_effect` name as the
public entry, drop the others.** `parse_effect` is a contributor-vocab
name; the rule body is a *user* concept (the body of a `(rule …)` form).
Using `parse_rule_body` aligns the public surface with the user vocab.
The contributor-vocab name stays alive as a `pub(crate)` internal.
Chosen for vocabulary hygiene; the cost is a one-line forwarding
function.

### No new traversal API (visitor / evaluator trait) on the config seam

The original problem statement raised "visitor vs evaluator trait" as a
design axis. Investigation shows neither is needed at the *config* seam:

- `crates/engine/src/trust.rs` (`canonical_effect`, `canonical_predicate`,
  `references_any_define`) walks the AST by pattern-matching on
  `may_i_core::ast::Effect` and `may_i_core::ast::Predicate` variants
  directly.
- `crates/engine/src/eval/*` (the evaluator) similarly pattern-matches
  on core AST types.
- Annotation paths in `crates/engine/src/annotation.rs` walk the same
  core AST.

These walks live on the *engine* side of the seam and consume *core*
AST types. They do not enter via the config crate. Adding a traversal
API on the config crate's surface would be unused new public surface —
the opposite of what this change is trying to achieve.

If a future refactor wants a shared visitor for engine + annotation,
that visitor belongs on `may_i_core` next to the AST types, not on the
config crate. Out of scope for this change.

**Alternative considered: define `trait RuleBodyVisitor { fn visit_effect, fn visit_predicate, fn visit_arg_pattern }` in the config crate.**
This would re-surface the three-way split — exactly the leak the change
is removing — and would have zero callers on day one. Rejected.

### Downgrade scope: four functions, not all five module exports

Downgraded to `pub(crate)`:

- `parse_effect` (effect.rs)
- `parse_predicate` (predicate.rs)
- `parse_arg_pattern` (pattern.rs)
- `parse_positional_arg` (pattern.rs)

These four are the rule-body sub-parsers. Each contains contributor
vocabulary in its name (Effect, Predicate, ArgPattern) and produces
contributor types.

Kept `pub`:

- `parse_rule`, `parse_define` (rule.rs) — top-level forms.
- `parse_parser_form` (parser_form.rs) — top-level form (per-program
  declaration); the noun "parser" is in the *user* vocabulary
  (CONTEXT.md table).
- `parse_style_definition` (style.rs) — top-level form; "Style" is in
  the user vocabulary.
- `parse_command_pattern` (command.rs) — the command-dispatch position
  of a `(rule …)`. The noun "command" is in the user vocabulary.
- Everything else already public (`parse_config`, `canonicalise_*`,
  `LoadResult`, etc.).

The rule body is the only sub-parse path that produces contributor
types and is split along the contributor-vocab axis. The other top-level
form parsers correspond to *user-vocab nouns* (Rule, Define, Parser,
Style, Command) — keeping them `pub` does not leak the
ArgPattern/Predicate/Effect split.

### Trust-hash invariance is checked by snapshot, not by spec

Canonical-form serialisation in `crates/engine/src/trust.rs` consumes
`may_i_core::ast::{Effect, Predicate}` directly. This change touches no
core AST type and no canonicalisation code. Therefore the trust hash
*cannot* change as a mechanical consequence.

To guard against a slip — e.g. a tasks-time accidental edit of
`effect.rs` that changes a parse-time normalisation — we snapshot the
canonical form of a hand-crafted rule-body fixture (inline string in
the `trust.rs` snapshot test) before and after, and assert byte
equality. The fixture is designed to exhaustively cover every
rule-body shape the consolidation could disturb: every `Effect`
variant (Terminal × {Allow, Ask, Deny}, And, Or, Not, When, Unless,
If, Cond, ArgPattern, CommandPattern, Authorise), every `Predicate`
variant (Fact, NamedRef, And, Or, Not), every `ArgPattern` shape
(positional, exact, anywhere, forbidden, flag, parameter), and one
`(define …)` for the canonical-define path. Two simpler candidates
were rejected: the prelude (`prelude.lisp`) contains only
`(parser …)` and `(define-arg-style …)` forms with no rules or
defines; the starter config (`starter_config.lisp`) still uses legacy
`(check :deny …)` syntax that no longer parses (a separate bug, out
of scope here). The snapshot is the test; no new spec requirement is
needed in `trust-hashing` because the requirement the snapshot
enforces (canonical form is deterministic) is already covered there.

## Risks / Trade-offs

- **[Risk]** A `pub` → `pub(crate)` flip breaks an external caller we
  missed. **Mitigation:** workspace `rg 'may_i_config::(parse_effect|parse_predicate|parse_arg_pattern|parse_positional_arg)' src/ crates/`
  before the flip; expect zero hits. `cargo build` after the flip
  surfaces any miss as a compile error, not silent breakage.

- **[Risk]** A parse-time normalisation slip changes the canonical form
  of some rule and silently invalidates a user's trust entries.
  **Mitigation:** snapshot-test the canonicalised serialisation of a
  hand-crafted rule-body fixture pre/post and assert byte equality.
  The fixture exercises every rule-body shape (combinators,
  predicates, arg patterns, decisions) — see Decisions.

- **[Risk]** Test code outside `crates/config/` imports the four
  downgraded names and we don't notice until later.
  **Mitigation:** workspace `rg` includes `tests/`, `fuzz/`, and
  `crates/*/src/`. `cargo build --tests` is part of the verification
  task group.

- **[Trade-off]** A workspace-public `parse_rule_body` is a tiny new
  contract that future contributors will be tempted to expand
  ("just one more body-parse entry point"). The seam needs the
  acceptance scenario in `code-quality` to pin it as the *only* entry
  point.

## Migration Plan

Single commit. No user-facing migration (no config syntax change, no
trust-hash change, no DSL change). No `may-i migrate` step.

For any hypothetical out-of-tree consumer that imports the four
downgraded names: the migration is `use may_i_config::parse_rule_body`
and rebind their result type from the more specific (`Predicate`,
`ArgPattern`) to `Spanned<Effect>`. Pre-1.0; no compatibility window.
