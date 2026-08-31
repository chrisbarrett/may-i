## Context

See `proposal.md` — Why. This section records only the mechanics the decisions
turn on, all verified against v0.12.0 (`cbf9dd8`).

**Fact storage** is `BTreeMap<Keyword, BTreeSet<String>>`
(`crates/core/src/context.rs:11`). The only insertion operation is
`insert_scalar`, which unions into the set (`context.rs:42`). `:via`'s
accumulation across nested Carriers is a consequence of that, not a deliberate
kind — the engine calls the same `insert_scalar`
(`crates/engine/src/eval/command.rs:295`, `:774`, `entry.rs:142`). The map also
distinguishes *key present with an empty set* (`insert_present`, `has()` true)
from *key absent*.

**Capture** is a second pass. `Expr::Bind` is transparent as a predicate —
`is_match` delegates to the inner expression (`crates/core/src/pattern.rs:78`) —
and the write happens when `eval_body_with_captures` re-walks the matched
predicate to harvest bindings (`crates/engine/src/eval/effects.rs:24-28`).
Because pass one discards which disjunct matched, `collect_captures` re-evaluates
every `Or` child to find out (`crates/engine/src/eval/predicates.rs:276-285`).

**Capture selects, never extracts.** The bind arm stores the whole matched token
— `insert_scalar(key.clone(), value)` where `value` is the token under test
(`crates/engine/src/eval/positional.rs:503`). No regex subgroup is reachable.

**Matcher scope** is `split_outer_tail(ctx.args, &ctx.parser).outer`
(`crates/engine/src/eval/effects.rs:581`), which under `posix` ends *before* the
first positional (`crates/engine/src/eval/entry.rs:539-543`). Meanwhile
`bindings::parse_argv` computes a mode-aware residual that under `posix` is
exactly the declared-positional tokens (`crates/engine/src/eval/bindings.rs:257-279`),
documents itself as "the positional residual that rule-body matchers walk"
(`bindings.rs:164-167`), is asserted by unit tests (`bindings.rs:617`, `:728`,
`:974`) — and is discarded at both call sites (`crates/engine/src/eval/context.rs:126`,
`crates/engine/src/eval/effects.rs:1075`).

## Goals / Non-Goals

**Goals:**

- One writer, one semantics: every fact write rebinds for a lexical extent.
- Predicates become pure — no test that also mutates the fact environment.
- Preserve the expressiveness Quantifier capture had, including `(some? …)`'s
  filtered subset.
- Keep the value sublanguage closed and enumerable in a single table.

**Non-Goals:**

- A lexical binder for `#var`. See Open Questions.
- Regex subgroup extraction. Capture never had it and nothing asks for it.
- Reconciling `[:k "v"]` with `:ns/name` spellings. They stay distinct; the
  Advisory covers the confusion.
- Trace rendering defects (`has` vs `fact?`; wrong witness on a set query).

## Decisions

### Rebinding, not merging

A write replaces the key for the extent of its body. Chosen so "the innermost
enclosing Carrier" is expressible; under union it is not, at any query
complexity.

*Alternative — keep union everywhere.* Rejected: the nested-Carrier hole is the
first policy anyone writes with this feature, and it fails open.

*Alternative — two fact kinds, scalar and accumulating.* Rejected: needs a kind
registry, a declaration or inference mechanism, and a mismatch error class.
`:via` does not need one — the engine can rebind it to its previous value plus
the Carrier name, expressing accumulation in the single primitive.

*Alternative — encode the kind in the identifier* (`::k` for sets, or `@`).
Rejected by the author. Worth recording that `::k` costs nothing in the reader —
`is_atom_char` already admits `:` (`crates/sexpr/src/cst.rs:704`), atoms
classify on `starts_with(':')` (`cst.rs:106`), and `Keyword::new` validates only
the leading colon (`crates/core/src/primitives.rs:18`) — so `::k` parses today as
an ordinary distinct key. Under sigil-as-identity a misspelled sigil is a
different key, silently absent, which is the existing untrapped failure mode
amplified.

### Total rebind on an unbound value

The key is removed for the body, not left at its enclosing value and not set to
an empty set. Storage distinguishes empty-set presence from absence, so an
empty-set rebind would leave `(fact? :k)` presence queries firing.

The invariant this buys: **no enclosing value is readable through a `let-facts`
site.** A reader can determine a key's value inside a body from the body's own
header, without tracing the Carrier chain above it.

This contradicts the existing unimplemented requirement at
`openspec/specs/parser-bindings/spec.md:503`, which says the fact "stays at its
parent-scope value, or absent". That requirement is being replaced, and the
contradiction is deliberate.

*Alternative — form does not fire when the value is unbound*, matching
`(authorise #var)`'s precedent. Rejected: it makes the enclosing value visible
again in exactly the case the author was trying to override, and it silently
skips a body that may contain a `deny`.

*Alternative — reject at load time.* Rejected: most positional and rest
declarations can yield unbound, so nearly every site would need a `(bound? …)`
guard.

### `let-facts`, not `let`, `set` or `with-facts`

`with-` already means merge in this codebase — check-block `with-facts` and
`with-env` both nest-and-merge by union (`REFERENCE.md:710`). Reusing it for a
rebinding form would put two opposite semantics on one name. The convention this
change fixes: **`with-` merges, `let-` rebinds.**

`set` is taken as a parameter shape form (`one | last | set | command`,
`crates/config/src/parser_form.rs:558`), where it means *collection*.

Bare `let` is reserved. The DSL's name-like binders are `#var`; a reader meeting
`(let …)` will expect it to bind one. `let-facts` binds fact keys, which the body
reaches through `(fact? …)` rather than by reference. Keeping `let` free also
leaves it available if a lexical binder is ever added.

Check-block `with-facts` is untouched — different name, no collision, no
migration.

### `let-facts` is the only writer; the bind Pattern is deleted

`Expr::Bind` is accepted in six positions and honoured in one. Making it work
everywhere would spread the second-pass harvest — and the `Or` re-evaluation —
across all six, and would leave the merge-versus-rebind question to be answered
twice. Deleting it removes the concept instead.

Consequence: capturing from argv now requires a Parser declaration, because
undeclared programs (gnu + permute) bind no `#var`. Accepted — it pushes argv
grammar into the one place that is centrally auditable, which is the same reason
Carrier parsers ship in the Prelude.

*Alternative — argv-addressing values* (`(arg 0)`, `(matching PAT)`) so
undeclared programs keep fact capture. Rejected: reopens "which slice is arg 0?"
— the question the scoping fix exists to settle — and lets rules reach into argv
around the Parser.

### Minimal value sublanguage

`#var` | `(filter #var PAT)` | literal string | nothing.

`filter` alone covers `(some? …)`'s subset capture. Because capture only ever
selected whole tokens, there is no case for `map`, destructuring, or subgroup
extraction. Literals are included for symmetry with check-block `with-facts` and
because they let a rule pass information down that is not in any Binding.

The trade this respects: may-i configs are human-audited under the Trust gate. A
rule that cannot be read at a glance is a security problem, so the sublanguage
must stay small enough to enumerate in one table.

### Advisory, not error, for unwritten keys

The known-written set is computable at load time from engine facts (`:via`),
`let-facts` sites, and check-block `with-facts`. Runtime `--fact :k=v`
(`src/main.rs:96`) admits arbitrary keys, so a query against a key no config
writes may still be satisfied at runtime. Advisory severity, not an error.

## Risks / Trade-offs

- **Scoping fix changes matcher scope for every Parser declaring positionals**
  (`ssh`, `direnv`, others in the Prelude) → audit the Prelude and the example
  corpus before landing; a rule that previously could not see a host token now
  can, which can only tighten or newly-fire a matcher, never hide one.
- **Rebinding silently changes behaviour for configs that relied on union across
  a Quantifier capture** → not a syntax change, so migration cannot rewrite it.
  Mitigate with a migration note and a `may-i check` run over the corpus.
- **Retiring bind Patterns breaks configs whose authors believed they worked**
  → most did not work. Quantifier sites migrate mechanically; the rest become
  load-time errors naming the replacement, so nothing fails silently.
- **`let-facts` bodies nest, and a deep chain makes the effective fact set
  harder to read than a flat union** → the total-rebind invariant bounds this:
  the nearest enclosing site for a key fully determines it.

## Migration Plan

1. Add `let-facts`, the value sublanguage, and the rebinding operation. Leave
   bind Patterns working.
2. Add the rewrite pass: `(when (every? #o (and PAT [:k *])) BODY)` →
   `(when (every? #o PAT) (let-facts [[:k #o]] BODY))`;
   `(some? #o (and PAT [:k *]))` → guard plus `(filter #o PAT)`. Precedent for
   CST rewrites of this shape: `crates/config/src/migrate/rename_has_to_fact.rs`,
   `may_i_to_authorise.rs`.
3. Rewrite the Prelude, `examples/*.lisp` and the fixture corpus. Fix the dead
   rule in `examples/ssh-sudo-prod-demo.lisp:29-32` and give it a check block.
4. Delete `Expr::Bind` and its evaluator support. Non-quantifier bind sites
   become load-time errors with suggested rewrites.
5. Wire the residual through `matcher_scope`; audit the Prelude.
6. Add the unwritten-key Advisory.

Rollback: steps 1–2 are additive and independently revertable. Step 4 is the
irreversible one and should land last.

## Open Questions

- Should the value sublanguage eventually gain a `first`/`last` selector for
  ordered collection Bindings? Not needed by any known policy, and addable later
  without disturbing the specs or the form's semantics.

## Follow-up, explicitly out of scope

The DSL has a binding construct with no binding form. Parsers destructure argv
into `#var`; rules consume those names; the two are joined by a name-keyed side
channel (`EvalContext::parser_bindings`) rather than by lexical structure. Every
symptom this change addresses follows from that: the shape checker exists to
reconstruct a connection the language does not state, bindings cannot nest or
shadow because there is no structure to nest in, and the extent question had to
be *decided* rather than read off a scope.

This change does not fix it — it fixes the dynamic half, which is irreducible:
`(authorise …)` evaluates a different command against the whole ruleset, so no
lexical binder can carry a value into the rule that handles it. `let-facts` is
load-bearing under any future design.

Worth a separate design pass: whether the Parser→Rule connection should be
stated in the language, and whether `crates/engine/src/shape.rs` survives the
answer.
