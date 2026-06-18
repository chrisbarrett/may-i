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

A tainted name (`(env NAME (ask|deny))`) floors when `NAME` appears as a
parameter expansion (`$NAME`, `${NAME…}`) in any argv word — matched on the
`name` field of `WordPart::Parameter` / `ParameterExpansion` /
`ParameterExpansionOp` (`crates/shell-parser/src/ast/mod.rs`). may-i floors on
the *token it already sees*; it never traces the value to a sink.

This stays inside the Non-Goals ("no filesystem/network/process policy beyond
command structure"). The coarseness is accepted: `echo $TOKEN` floors the same
as `curl ?$TOKEN` — may-i cannot tell exfiltration from benign use, and the
sound rule is to floor any argv expansion of the name. Crucially, a **legitimate
consumer reads its secret from its own environment** (`aws s3 cp`, `gh`,
`docker login`) — the name never appears in argv, so those are unaffected. Only
an explicit expansion-into-argv — the exfiltration shape — is caught. The escape
hatch for a deliberate `echo $TOKEN` is the human answering the `:ask`.

- *Alternative — taint only when the secret reaches a network sink.* Rejected:
  requires sink modelling (dataflow, a Non-Goal) and is unsound anyway —
  structure cannot reveal `curl`'s network behaviour.

### D4 — `safe-env-vars` lowers to the env capability; migration rehashes trust

`(safe-env-vars "A" "B")` is exactly `(env "A" (allow)) (env "B" (allow))`. The
parser keeps `(safe-env-vars …)` as an alias that lowers to env-allow
capabilities, and `may-i migrate` rewrites it to the `(env …)` form. Because the
lowering is semantics-preserving, this is a **Class A** migration — the
`:safe-env-vars` trust hash is recomputed under the generalized scope and
approvals carry over (per migration-system Class A). The read-floor relaxation
(D-redirect) needs no migration: it only loosens decisions.

Open: whether to retain `(safe-env-vars …)` as permanent sugar or remove it
after a migration window. Pre-1.0, leaning remove (one way to spell it).

### D5 — Provisional syntax; trust scopes per axis

Forms are provisional (parallel to how `rules-grant-redirect-capability` left
spelling open):

```lisp
(env      "LD_PRELOAD" (deny))
(env      "AWS_TOKEN"  (ask "secret — confirm before it enters a command"))
(env      "GIT_PAGER"  (allow))
(redirect (target (glob "/tmp/**")) (allow))
```

Trust scopes generalize `:safe-env-vars` into `:env` and `:redirect` (granular
approval). Open questions for the spelling: `(env NAME DECISION)` vs an
explicit `(capability …)` head; whether `(redirect …)` should also accept a
`(operator …)` filter or stay write-only-by-construction. The DSL uses
alist-style option sub-forms elsewhere (`dsl-option-form-alist-style`), which
the `(target …)` sub-form follows.

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
