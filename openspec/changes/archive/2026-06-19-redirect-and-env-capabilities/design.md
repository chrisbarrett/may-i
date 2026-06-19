# Design

## Context

The engine already decomposes a segment into `EvalUnit`s
(`crates/engine/src/eval/decompose.rs`): `Command`, `EnvPrefix`,
`RedirectTarget`, `EmbeddedCommand`. `command.rs` folds their decisions
strictest-wins. `EnvPrefix` already consults `config.security.safe_env_vars`
(allowlist; floors a non-member to `:ask`). `RedirectTarget` always floors a
non-standard file target with no opt-out. The `:safe-env-vars` trust scope
exists (`crates/engine/src/trust.rs`). So the substrate for capabilities is in
place — this change adds decision-bearing capability units and the config
surface for them.

The governing invariant is "Match and parse imprecision never widens toward
allow" (shell-command-security-model). Every decision below is checked against
it.

## Decisions

### D1 — A capability contributes a decision to the existing segment meet

Each capability resolves to a `Decision` and joins the segment's strictest-wins
meet (`:allow < :ask < :deny`) alongside the command unit. This reuses the
combination semantics CONTEXT.md already defines for across-rules combination;
no new combinator.

Consequence — **polarity is structural, not special-cased**: `:allow` is the
lattice bottom, so a capability that contributes `:allow` can never *raise* a
segment the command did not already earn. `(env "FOO" (allow))` on
`evil-cmd FOO=x` still yields `evil-cmd`'s decision. A capability `:allow` is
therefore only ever a *floor release*. A capability `:deny` is a genuinely new
power (per-effect active denial) that `safe-env-vars` lacked.

- *Alternative — capabilities are allowlist-only (no `(deny)`), like
  `safe-env-vars` today.* Rejected: it cannot express secret taint (the
  exfiltration gap), and it makes `safe-env-vars` a special form rather than an
  instance of a uniform concept. The meet framing subsumes it for free.
- *Alternative — capabilities can originate `:allow` (authorise a command by
  structure).* Rejected: it breaks the "`:allow` originates only at a command
  anchor" property and multiplies the surface where a user can author an
  unsound widening. The lattice-bottom reading keeps allow non-widening.

### D2 — Read is not a capability; only the deny direction of read exists

Read and write are not symmetric:

| axis | allow | ask/deny | unlisted default |
| --- | --- | --- | --- |
| env-**write** (`FOO=bar` prefix) | lift floor (`safe-env-vars`) | forbid (`LD_PRELOAD`) | `:ask` (writes suspect) |
| env-**read** (`$FOO` in argv) | — (empty) | secret taint | `:allow` (reads benign) |

`read + allow` is empty for two reasons: (1) vacuous — reads already default to
allow, so "allow read of FOO" says nothing; (2) unsound — if it meant "let
`$FOO` satisfy a guard", it re-opens the `rm /tmp/$HOME` → `/root` bypass that
"Expansion-bearing words do not satisfy an allow constraint" closes. So
`(allow)` is **silently write-only**: it lifts the env-write floor and has no
effect on a read-position expansion. The defaults are *opposite* by threat
model: writing the environment is presumed dangerous (code injection via
`LD_PRELOAD`/`BASH_ENV`); reading it is benign except for designated secrets.

### D3 — Secret-read enforcement is structural, not dataflow

A tainted name (`(env NAME (ask|deny))`) floors when `NAME` is read into the
command — matched on the `name` field of `WordPart::Parameter` /
`ParameterExpansion` / `ParameterExpansionOp` (`crates/shell-parser/src/ast/mod.rs`).
may-i floors on the *token it already sees*; it never traces the value to a sink.

The read sites are every position the shell expands a parameter into the command
text. Ownership is partitioned across the three decompose passes so no site is
scanned twice:

- `decompose_simple_command` — argv words and command-prefix assignment values.
- `push_embedded_units_from_redirect_targets` — every redirect target word: the
  stdin data feeds (unquoted here-document body, here-string) *and* file-target
  pathnames (`> /tmp/$NAME`, `< /tmp/$NAME`, where the secret becomes the
  filename). Scanned wherever they attach, *including* a compound command's
  redirect wrapper (`while …; done <<EOF`). This is why the scan lives in the
  whole-tree pass, not in `decompose_simple_command`.
- `push_embedded_units_from_structural_words` — bare assignments (`z=$NAME`),
  `for` iteration words, and `case` subject/pattern words.

A nested reference inside an expansion *operand* (`${X:-$NAME}`, `${X/foo/$NAME}`)
is also a read site; the operand keeps its `$NAME` as verbatim text rather than a
structured `WordPart`, so the operand strings are scanned for references. The same
applies to text the parser leaves on or beside a `WordPart`: an array subscript
(`${arr[$NAME]}`), a glob bracket (`[$NAME]`), and a brace-expansion element
(`{a,$NAME}`) are scanned, and a parameter name is normalized to its leading
identifier so a trailing transform operator (`${NAME@Q}`) does not hide the
variable. So is a reference in arithmetic context
(`$((NAME))`, `$(($NAME))`, and the obsolete `$[NAME]` — lexed to the same
`Arithmetic` part): bash dereferences the bare identifier, so arithmetic source is
scanned for identifiers. A quoted
here-document (`<<'EOF'`) suppresses expansion and does not taint; an indirect
expansion (`${!NAME}`) reads the variable named by `$NAME`'s value, not `NAME`,
so it does not taint on `NAME`.

This stays inside the Non-Goals ("no filesystem/network/process policy beyond
command structure"). The coarseness is accepted: `echo $TOKEN` floors the same
as `curl ?$TOKEN` — may-i cannot tell exfiltration from benign use, and the
sound rule is to floor any expansion of the name into the command text.
Crucially, a **legitimate consumer reads its secret from its own environment**
(`aws s3 cp`, `gh`, `docker login`) — the name never appears as an expansion in
the command text, so those are unaffected. Only an explicit
expansion-into-the-command — the exfiltration shape — is caught. The escape hatch
for a deliberate `echo $TOKEN` is the human answering the `:ask`.

- *Alternative — taint only when the secret reaches a network sink.* Rejected:
  requires sink modelling (dataflow, a Non-Goal) and is unsound anyway —
  structure cannot reveal `curl`'s network behaviour.

### D4 — `safe-env-vars` lowers to the env capability; migration rehashes trust

`(safe-env-vars "A" "B")` is exactly `(env "A" (allow)) (env "B" (allow))`. The
parser keeps `(safe-env-vars …)` as an alias that lowers to env-allow
capabilities, and `may-i migrate` rewrites it to the `(env …)` form. Because the
lowering is semantics-preserving, this is a **Class A** migration — the
`:safe-env-vars` trust hash is recomputed under the generalized scope and
approvals carry over (per migration-system Class A). The redirect read-floor
relaxation (the write/read split in the "Redirect targets are not silently
ignored" requirement) needs no migration: it only loosens decisions.

Open: whether to retain `(safe-env-vars …)` as permanent sugar or remove it
after a migration window. Pre-1.0, leaning remove (one way to spell it).

### D5 — Capability decision is the fact-conditioned subset of the rule-body language

The DECISION position is not a bare terminal but an expression in a restricted
subset of the existing `Effect`/`Predicate` AST (`crates/core/src/ast.rs`):

| keep | drop |
| --- | --- |
| `Effect::Terminal` (allow/ask/deny) | `Effect::CommandPattern` |
| `Effect::And/Or/Not` | `Effect::ArgPattern` (positional/flag/parameter/anywhere/exact/forbidden) |
| `Effect::When/Unless/If/Cond` | `Effect::Authorise` |
| `Predicate::Fact` | `Predicate::Arg` |
| `Predicate::And/Or/Not` | `Predicate::Bound/Matches/Every/Some` |
| `Predicate::Named` → resolves to fact-only | |

Reuse, not reinvention: the same evaluator runs the expression with an empty
binding environment and the active facts. A **load-time validation pass** (in the
spirit of `crates/engine/src/shape.rs`) rejects the dropped variants in
capability position with a diagnostic. The bare `(env NAME (allow))` is the
degenerate terminal case.

Two reasons the argv layer is excluded:

1. **No referent.** A capability is command-agnostic; argv matchers and `#var`
   bindings presuppose a parser declaration for a specific command, which a
   capability does not have.
2. **Soundness.** Facts are exact runtime context (no parse/expansion
   imprecision), so a fact-conditioned `(allow)` is sound toward `:allow`. The
   excluded argv layer is exactly the expansion-bearing, imprecise one. The
   capability language is the sound-toward-allow subset by construction.

### D6 — Subject stays as addressing, not folded into the expression

`(env NAME EXPR)` and `(redirect PAT EXPR)` keep the subject (the variable name /
redirect target) as positional addressing; EXPR is purely fact-conditioned. This
matches the `safe-env-vars` shape and keeps EXPR free of operand-matching. The
redirect target is the bare first operand — no `(target …)` wrapper — giving both
forms the same `(HEAD SUBJECT DECISION)` shape; an omitted PAT matches any write
target.

The env SUBJECT additionally accepts an `(or NAME…)` name-set — `(env (or "A"
"B") DECISION)` — that applies one DECISION to each listed name (exactly
equivalent to repeating the form per name). This is sugar for the common
"taint a family of secrets" case; it stays in addressing position and does not
add operand-matching to EXPR, so the "facts only" line in the decision language
is preserved. (Pattern-addressed names — `(name (regex …))` — remain deferred
per the alternative below.)

- *Alternative — fold the subject into the expression* as a `(name PAT)` /
  `(target PAT)` predicate: `(env (when (and (name (regex "^AWS_")) (fact? :ci))
  (deny)))`. More uniform and lets one form address many names by pattern, but
  it adds operand-matching predicates to the expression language and blurs the
  "facts only" line. Deferred; revisit if pattern-addressed env names are
  wanted.

### D7 — Settled syntax; trust scopes per axis

Both forms are bare top-level forms — `(env …)` and `(redirect …)` — with no
umbrella head, consistent with the existing top-level policy forms `(audit …)`,
`(safe-env-vars …)`, `(rule …)`, `(parser …)`. "Capability" is the prose /
glossary term for the category, not a DSL head. Both share the shape
`(HEAD SUBJECT DECISION)`:

```lisp
(env      "LD_PRELOAD"   (deny))
(env      "AWS_TOKEN"    (ask "secret — confirm before it enters a command"))
(env      "GIT_PAGER"    (allow))
(redirect (regex "^/tmp/") (allow))
(redirect (allow))                      ; SUBJECT omitted → any write target
```

The redirect SUBJECT is the bare target matcher (no `(target …)` wrapper); the
DECISION is a fact-conditioned expression (D5). Trust scopes generalize
`:safe-env-vars` into `:env` and `:redirect` (granular approval).

- *Rejected — an explicit `(capability (env …))` head.* It would break the
  headless precedent of `(audit …)`/`(safe-env-vars …)`; the category word lives
  in prose, not the syntax.
- *Rejected — `(effect …)`* as the category term: retired user vocabulary.
- *Deferred — a `(redirect … (operator …))` filter.* Read vs write is settled by
  construction (only writes floor; see the redirect requirement), so no operator
  filter is needed now.

## Risks

- **Secret taint false positives** on benign `echo $TOKEN` in interactive
  debugging. Mitigated: severity is the user's choice (`ask` vs `deny`); `ask`
  just prompts.
- **Read-floor relaxation** is a behaviour change to shipped v0.9.0. It only
  loosens (reads stop flooring), so it cannot newly authorise a write; safe
  under the asymmetric-soundness invariant.
- **Decision-term generalization** touches the most protected vocabulary in
  CONTEXT.md. The meet semantics are unchanged; only the set of things that emit
  a decision grows. Captured as an explicit CONTEXT.md task.
