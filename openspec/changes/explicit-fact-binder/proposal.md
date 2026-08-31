## Why

Facts can only be written implicitly, as a side effect of a Pattern matching
inside a Quantifier. Everywhere else the `[:k …]` bind Pattern is accepted, the
captured value is silently dropped — six accepting positions, one that works.
A rule cannot pass what its Parser bound to the command it authorises, so
host-scoped policy ("allow `sudo` only under `ssh` to media-server") is not
expressible.

The write model is also unsound for nesting. Facts merge by set union, so
`ssh jump-host ssh media-server sudo …` leaves the inner `sudo` seeing both
hosts; a guard on the inner host matches under the wrong hop. "The innermost
enclosing Carrier" cannot be said at all.

Two of these behaviours are already specified and unbuilt:
`parser-bindings` requires a rule-body `(with-facts [[:k #var]] BODY)` form that
does not exist, and REFERENCE.md documents bind Patterns as generally visible
downstream. The docs, the module comments, the unit tests and the stable specs
agree with each other and disagree with what runs.

## What Changes

- **Add `(let-facts [[:key VALUE] …] BODY)`** as a rule-body form. It rebinds:
  each `:key` takes the given value for `BODY` and everything `BODY` authorises,
  shadowing any enclosing value. Dynamic scope, lexical extent.
- **Rebinding is total.** When the value is an unbound Binding, the key is
  *removed* for `BODY` rather than left at its enclosing value. No enclosing
  value is ever readable through a `let-facts` site.
- **Add a closed value sublanguage** for the right-hand side: a Binding
  (`#var`), a filtered Binding (`(filter #var PAT)`), a literal string, or
  nothing (a presence Fact). Rules can push literals down as well as promote
  Bindings.
- **BREAKING — remove the `[:k …]` bind Pattern.** `let-facts` becomes the only
  way anything becomes a Fact besides `:via` and `--fact`. Predicates stop
  writing. Migration rewrites Quantifier capture sites; the other positions
  become load-time errors naming the replacement.
- **BREAKING — Quantifier capture is retired.** `(every? #o (and PAT [:k *]))`
  becomes `(when (every? #o PAT) (let-facts [[:k #o]] …))`;
  `(some? …)`'s filtered capture becomes `(filter #o PAT)`.
- **Add an Advisory for Fact keys queried but never written.** `(fact? :via/sudo)`
  and `(fact? [:via "sudo"])` are different keys; only the second is real.
  `examples/ssh-sudo-prod-demo.lisp` ships a rule that can never fire because of
  it. Both spellings stay; the Advisory catches the mismatch.
- **Fix outer-slice scoping for declared positionals.** Tokens claimed by a
  Parser's `(positional …)` are currently invisible to rule-body Patterns,
  though tokenisation already computes the residual that includes them and both
  callers discard it. Wire it through, making REFERENCE.md's existing claim true.

Not in scope: whether the DSL should also gain a *lexical* binder, and whether
the Parser→Rule connection should be stated in the language rather than
reconstructed by the shape checker. Recorded as a follow-up in `design.md`.

## Capabilities

Buckets: **parsing** (`patterns`, `parser-bindings`, `binding-shapes`),
**facts** (`facts`), **migration** (`migration-system`).

### New Capabilities

None. Every behaviour lands in an existing capability.

### Modified Capabilities

- `parser-bindings`: replace the unimplemented `(with-facts [[:k #var]] BODY)`
  requirement with `(let-facts …)` under rebinding semantics, including the
  total-rebind rule for unbound Bindings, the value sublanguage, and literal
  values. Update the binding-visibility requirement, which names the old form.
- `patterns`: remove the two bind-Pattern requirements (validity in
  `positional`/`exact`/`anywhere`; Fact-binding capture under Quantifiers). Add
  declared-positional token visibility to the outer-slice scoping requirement.
- `facts`: state the write model — `let-facts`, `:via` and `--fact` are the only
  writers; a write rebinds for the extent of its body; `:via` accumulates
  because the engine rebinds it to its previous value plus the Carrier name.
  Add the queried-but-never-written Advisory.
- `binding-shapes`: shape signatures for `let-facts` and `filter` — which
  Binding shapes may be promoted, and what a Count or a command-line Binding
  does.
- `migration-system`: the rewrite pass retiring bind Patterns.

## Impact

**Deleted.** `Expr::Bind` (`crates/core/src/pattern.rs:56`); `captured_facts` and
`collect_captures` including their `Or` re-evaluation
(`crates/engine/src/eval/predicates.rs:233-289`); `eval_body_with_captures`
(`crates/engine/src/eval/effects.rs:17-28`); the bind arm of
`match_expr_with_binding` (`crates/engine/src/eval/positional.rs:496-508`) and
the `contains_bind` guard (`crates/config/src/pattern.rs:262`).

**Changed.** `ContextFacts` gains a rebinding operation alongside `merge`
(`crates/core/src/context.rs`). `matcher_scope`
(`crates/engine/src/eval/effects.rs:581`) consumes the residual that
`bindings::parse_argv` already computes (`crates/engine/src/eval/bindings.rs:257-279`)
instead of `split_outer_tail(…).outer`; both discard sites
(`crates/engine/src/eval/context.rs:126`, `effects.rs:1075`) are wired up.

**Risk.** The scoping fix changes what rule-body Patterns see for every Parser
declaring positionals — `ssh`, `direnv` and others in the Prelude. Needs a
compatibility audit across the Prelude and the example corpus before it lands.

**User configs.** Pre-1.0, no back-compatibility guarantee, but Quantifier
capture sites migrate mechanically. Capturing from argv now requires declaring a
Parser: undeclared programs have no `#var` to promote.

**Docs.** REFERENCE.md's Patterns table, Facts section and the
`(parser "ssh")`/`(rule "ssh")` worked example; CONTEXT.md's Binding row, which
names a rule-body form that is Check-block-only.

**Separately tracked, not in this change.** The Trace renders `has` where source
says `fact?`, and names the wrong witness for a Fact query against a
multi-member set — querying `[:o/all "a=1"]` against `{BAD, a=1}` renders
`"BAD" → yes`.
