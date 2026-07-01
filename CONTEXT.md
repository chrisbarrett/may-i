# may-i Context

`may-i` is a bash command authorisation tool for agent harnesses. The harness
calls it before executing a shell command; `may-i` decides whether to allow,
ask, or deny based on user policy, by inspecting command structure only.

## Four-Layer Model

Everything serves one of:

1. **Rules** — static policy authored by the user.
2. **Facts** — runtime context supplied by the harness per invocation.
3. **Parsing** — how a program's argv is tokenised before rules see it.
   Covers `(parser …)` and `(define-arg-style …)`.
4. **Trust** — gate on whether externally-loaded rules may participate.

If a change doesn't fit one of these, question whether it belongs.

## User vocabulary

| Term      | Definition                                                                                                                                                                                                                                                                | Example                                                            |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Rule      | Pattern + decision for one top-level command.                                                                                                                                                                                                                             | `(rule <command> <expr>)`                                          |
| Decision  | The answer a rule **or capability** gives. Spelled with the verbs `(allow REASON?)`, `(ask REASON?)`, `(deny REASON?)`. Combined strictest-wins under `:allow < :ask < :deny`; `:allow` is the lattice bottom, so a contributor (rule or capability) yielding `:allow` never widens past what another unit already earned. _Avoid_: "verdict", "effect".                                                                                                                                       | `(allow)`, `(ask "review")`, `(deny "danger")`                     |
| Capability | A config-level decision attached to a shell-language **effect** — a redirect-write target (`(redirect PAT? DECISION)`) or an environment variable (`(env NAME DECISION)`) — rather than to a command. It contributes its decision to the same strictest-wins meet as the command's rule, independently of which command runs. Because `:allow` is the lattice bottom, a capability `allow` only *releases a floor*; a capability `deny`/`ask` actively tightens. `(safe-env-vars …)` is one instance (env-write allowlist). The DECISION is the fact-conditioned subset of the rule-body language (facts + `(if/when/unless/cond/and/or/not …)`; no argv analysis). Primary-config-governed and trust-scoped (`:env`, `:redirect`). | `(env "LD_PRELOAD" (deny))`, `(redirect (regex "^/tmp/") (allow))` |
| Reason    | Optional explanatory string passed to a decision verb. Shown in traces and prompts.                                                                                                                                                                                       | `"Confirm recursive deletion"`                                     |
| Fact      | Keyed runtime context. See below.                                                                                                                                                                                                                                         | `:via`, `[:env "prod"]`                                            |
| Entry environment | The names-only snapshot of the exported environment at the start of an invocation. Distinct from a **Fact**: observed ground truth (not asserted policy) consulted *structurally* by the env-write floor, never reachable through `(fact? …)`. Carries names only — never values — so it can never leak a secret into a trace, audit record, or error message. `hook` captures it live; `eval` injects it via `--env NAME` / `--inherit-env` (default empty); `check` is hermetic (only `(with-env …)`). See below. | `(with-env ["PATH"] (ask "PATH=/evil:$PATH"))`, `may-i eval --env PATH …` |
| Pattern   | Anything that matches part of a command. Includes argv matchers (`(flag …)`, `(positional …)`, …) and the smaller matchers used inside them (`"lit"`, `*`, `(regex …)`, `(or …)`, …). One name, one mental model. See below.                                              |                                                                    |
| Predicate | A test returning match / no-match. Patterns are predicates; so are `(fact? …)`, `(matches? #var PAT)`, `(bound? #var)`, and `(define …)`d names referring to any of those. Children of `and`/`or`/`not` and the test arm of `if`/`when`/`unless`/`cond` are predicates. | `(fact? [:env "prod"])`, `(and prod-host (flag ["r" "recursive"]))` |
| Authorise | Recurse on an inner command. Spelled `(authorise #var)` — takes a binding reference. The parser declares `#var` via `(rest …)`, `(parameter NAME #var)`, `(positional #var …)`, or `(parameter NAME (many-till PAT) #var)`. Pushes a `:via` fact for the carrier program (see _Carrier_ below). | `(parameter "c" #cmd)` + `(authorise #cmd)`                        |
| Binding   | A parser-bound name. Written `#name` in the surface DSL — a fourth sigil alongside `:keyword`, bare symbol, and `"string"`. Parsers declare bindings; rules consume them through `(authorise #var)`, `(bound? #var)`, `(matches? #var PAT)`, or `(with-facts [[:k #var]] …)`. | `(rest #cmd)`, `(positional #host (regex "^[^-].*"))`              |
| Style     | A reusable description of _how_ a program spells flags — prefixes, separators, combining rules. Bound by name with `(define-arg-style …)`. The prelude ships `gnu`, `single-dash-long`, `legacy-bundle`, `key-value`.                                                     | `(define-arg-style java (overrides gnu) (separators " " "=" ":"))` |
| Parser    | A per-program declaration that picks a Style, declares its flag-scanning mode via `(flags MODE)`, lists value-bearing parameters, and optionally names positionals / the rest tail with `#var` bindings. The three modes are `posix` (first non-flag stops scanning; default for Carriers), `permute` (flags interleave with positionals; default for undeclared programs), and `(until STR…)` (scan flags up to one of the named boundary tokens, which is consumed and dropped — used by `mise`, `nix --command|-c`). Undeclared programs default to `gnu` + `permute`. Common Carriers ship pre-declared in the Prelude. | `(parser "ssh" (style gnu) (flags posix) (positional #host (regex "^[^-].*")) (rest #cmd))` |
| Trust     | The approval mechanism for rules loaded from outside the primary config. Rules from `(load …)` are inert until you approve them with `may-i trust`. Primary config is implicitly trusted. Approvals are keyed by canonical-form hash; `may-i migrate` preserves approval across syntactic rewrites (see _Class A / Class B_ below).   |                                                                    |
| Advisory  | A rendered notice in CLI output for non-decision concerns: untrusted `(load …)` rules awaiting `may-i trust`, trust-store integrity failures, repo-local config approval, migration warnings. Distinct from a Trace (which explains a decision). Carries a level — `info`, `warn`, or `error` — and never blocks on its own.       | "⚠ 3 loaded rules untrusted — run `may-i trust`"                   |
| Trace     | A rendered explanation of how a decision was reached for one command: which rules participated, which patterns matched or didn't, which facts contributed, the final combined decision and reasons. Spans recursion — each `(authorise …)` frame contributes its own layer. Emitted by `may-i eval` and `may-i check`; never emitted in hook mode (JSON decision only). |                                                                    |
| Audit log | A persisted, append-only JSONL stream of evaluation outcomes, one **audit record** per evaluation, for after-the-fact forensics (which commands failed to parse, asked, or were denied). The audit record is _machine-facing and persisted_, in contrast to a _Trace_ (rendered and ephemeral) and an _Advisory_ (a notice about config health, not a record of a decision). Configured by the primary-config-only `(audit …)` form, gated by a single `:threshold` (`off`/`deny`/`ask`/`all`, parse-failures always included). Written only by the Eval and Hook invocation modes. _Avoid_: "log", "history", "logging". | `(audit (threshold :ask) (file "…"))` |                                                                    |
| Prelude   | The built-in s-expression bundle loaded before user config. Pre-declares standard arg Styles (`gnu`, `single-dash-long`, `legacy-bundle`, `key-value`) and Parsers for common Carriers (`sudo`, `bash`, `xargs`, `env`, `find`, `ssh`, `nix`, `mise`, `timeout`, …). Implicitly trusted. User declarations come after the prelude and shadow it silently (last-wins). Source lives at `crates/config/src/prelude.lisp` and is inlined at compile time. | `(parser "nix" …)` in user config shadows the prelude `nix` parser |
| Carrier   | A program that carries an inner command or program in its argv (`sudo`, `bash -c`, `xargs`, `env`, `timeout`, `find -exec`, `ssh`, `nix-shell`, …). Carrier parsers bind the inner command (typically as `#cmd`) so rules recurse via `(authorise …)`. Each recursion pushes the carrier's name onto the `:via` fact. Mis-parsing a carrier lets the inner command escape rule coverage, so common carriers ship pre-declared in the Prelude. | `sudo`, `bash -c`, `xargs`                                         |
| Quantifier | A prefix s-expr operator on a `(positional …)` or `(anywhere …)` Pattern that controls how many args it consumes. Four cases: bare `PAT` (exactly one — the default), `(? PAT)` (zero or one), `(+ PAT)` (one or more), `(* PAT)` (zero or more). A quantifier head takes **one or more** sub-patterns; more than one is an **implicit sequence** — the whole sub-sequence is the quantified unit, matched against consecutive args, and `+`/`*` repeat the sub-sequence (`(? "run" (? "--"))` matches nothing, `run`, or `run --`). Sub-patterns nest. Binds inside a repeated group accumulate by **set-union** (no per-occurrence correlation). Any future quantifier _modifier_ (separator, bounded repeat, group bind) gets its own head, never trailing options on `? + *`, so the arglist stays pure sequence elements. | `(positional "push" (? "--force"))`, `(positional (? "run" (? "--")) *)` |
| Wildcard  | The atom `*` in Pattern expression position. Matches any single string; value is ignored. Distinct from the `*` glyph used as a quantifier head — they sit in different syntactic positions and may compose, e.g. `(* *)` is the zero-or-more quantifier applied to the wildcard.                                                                                                                                                            | `(positional *)`, `(positional (* *))`                             |
| Many-till | A parser-only capture form used inside a parameter declaration: `(parameter NAME (many-till PAT) #var)` consumes tokens until one matches PAT (exclusive) and binds the run to `#var`. Used for sentinel-terminated argument lists such as `find -exec ... \;`. Not valid inside rule bodies.                                                                                                                                                  | `(parameter "exec" (many-till ";") #cmd)`                          |
| Outer slice | The portion of argv that rule-body matchers (`(flag …)`, `(parameter …)`, `(positional …)`, `(anywhere …)`, `(forbidden …)`, `(exact …)`) operate on. The split between outer and the rest is determined by the parser's `(flags MODE)`: under `posix` outer ends at the first non-flag; under `(until STR…)` outer ends at the boundary token; under `permute` outer is the whole argv. Tokens past the outer slice are claimed by `(rest …)` and are **invisible** to matchers — recurse into them with `(authorise #rest)`. | For `bash -c 'rm -rf /'`, matchers see `-c`'s value but not the inner shell command; reach it via `(authorise #cmd)` |

### Decision

A user thinks in **decisions** — _the rule allows this, asks about this,
denies this._ The surface verbs are `(allow REASON?)`, `(ask REASON?)`,
`(deny REASON?)`. (The internal AST node is `Effect::Terminal` — that
name stays in contributor docs but doesn't surface to users.)

Two distinct combination layers:

- **Across rules** (top-level): the strictest decision wins under
  `:allow < :ask < :deny`. Tied reasons are deduplicated, sorted, and
  joined with `"; "` so the result does not depend on rule order.
  **Capabilities** join this same meet: each segment's decision is the
  strictest of its command rule plus every capability (redirect-write,
  env-write, env-read taint) that applies. Because `:allow` is the lattice
  bottom, a capability `allow` only releases a floor another unit imposed —
  it can never authorise a command the command rule did not already allow.
- **Inside a rule body** (`and`, `or`, `not`): matching, not strictness.
  A child either yields a decision or yields _no match_. `and`
  short-circuits on the first no-match and otherwise returns the last
  child's decision; `or` returns the first child's decision; `not`
  flips no-match ↔ `allow` and preserves `ask`/`deny`.

### Capability

A **capability** attaches a decision to an _effect the shell offers_, not to
a command: writing a redirect target (`(redirect PAT? DECISION)`), setting an
environment variable, or reading a secret one into argv (`(env NAME DECISION)`).
It contributes to the strictest-wins meet alongside the command's rule, so a
capability is O(1) policy for an O(rules) shell concern.

The env axis is **asymmetric by threat model**, and the asymmetry is
deliberate:

- **Write** (`NAME=VALUE` prefix) defaults to suspect (`:ask`): a prefix like
  `LD_PRELOAD=…` changes what executes. `(env NAME (allow))` lifts that floor
  (it _is_ `(safe-env-vars NAME)`); `(env NAME (ask|deny))` tightens.
- **Read** (`$NAME` in an argv word) defaults to benign (`:allow`).
  `(env NAME (ask|deny))` taints the name: its appearance as a parameter
  expansion in argv contributes `:ask`/`:deny` — secret-exfiltration defence.
  `(env NAME (allow))` is **silently write-only**; it does nothing in read
  position (an allow cannot make an unprovable expansion provable).

Secret-read enforcement is **structural, not dataflow**: it fires on the
parameter-expansion token may-i already sees in the parsed command and never
traces the value to a sink. A legitimate consumer that reads its secret from
its _own_ environment (`aws`, `gh`, `docker login`) never puts `$NAME` in
argv, so it is unaffected; only an explicit expansion-into-argv — the
exfiltration shape — is caught.

A capability's DECISION is the **fact-conditioned subset** of the rule-body
language: the decision verbs, `(and|or|not …)`, `(if|when|unless|cond …)`, and
`(fact? …)` (and `(define …)`d names resolving to those). Argv analysis and
parser bindings (`(positional …)`, `(flag …)`, `(authorise …)`, `(matches? …)`,
…) are rejected at load time — a capability is command-agnostic, so it has no
argv referent, and excluding the expansion-bearing argv layer is what keeps a
fact-conditioned `(allow)` sound toward `:allow`. Capabilities are
primary-config-governed and trust-scoped exactly as `(safe-env-vars …)` is.

### Fact

A fact is keyed runtime context — `--fact :ci` from the harness, a `[:k *]`
binding captured in a pattern, or an automatic fact like `:via` set during
recursion. Each key holds a _set_ of values, not a single one, so wrappers
stack: a `sudo ssh host rm …` recursion accumulates `:via` = `{sudo, ssh}`.
Patterns test set membership; wildcard matches the non-empty set.

### Entry environment

The **entry environment** is the set of environment-variable _names_ exported
into the process at the start of an invocation. The env-write floor consults it
to decide whether a write **reaches a child**: a bare reassignment
(`PATH=/evil`) of a name already in the entry environment re-crosses to children
(bash preserves the export attribute), so it floors; a bare assignment of a name
_not_ in the entry environment is shell-local and does not.

It is _not_ a fact. A fact is asserted policy context you query with
`(fact? …)`; the entry environment is observed ground truth the floor reads
structurally, and it is **not** reachable through `(fact? …)`. It carries
**names only** — never values — so presence is the only observable, and a trace
can explain `PATH=/evil → :ask` without exposing environment contents.

Its source depends on the invocation mode: `may-i hook` captures the live
process environment; `may-i eval` defaults to empty and accepts `--env NAME`
(repeatable) plus `--inherit-env`; `may-i check` is hermetic — it never reads
the host environment and a case declares names with `(with-env [NAME …] …)`.

### Pattern

There is _one_ kind of thing, the **Pattern**. Users write patterns the way
they write any small program — combining literals, regexes, quantifiers
(`?` `*` `+`), and `(and …)` / `(or …)` / `(not …)` freely with argv
matchers like `(flag …)`, `(parameter …)`, `(positional …)`,
`(anywhere …)`, `(forbidden …)`, `(exact …)`. Bindings (`[:k *]`) capture
matches as facts for inner eval.

### Trust

You approve loaded rules with `may-i trust`. Until then they're inert —
the engine sees them as if they didn't exist. Primary config is implicitly
trusted. Approvals are keyed by canonical-form hash, so reformatting or
commenting a rule keeps it trusted but reordering or editing it requires
re-approval.

## Contributor vocabulary

These terms are for design discussion, code review, and ADRs — not user
docs, error messages, or DSL forms.

| Term            | Definition                                                                                                                                                                                                                                                                                                  | Example                                              |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| Effect          | The internal AST node for a rule's body. The terminal subset is `Effect::Terminal { decision, reason }`; combinators (`And`, `Or`, `When`, `Cond`, …) are the rest. The legacy surface form `(effect :decision REASON?)` is retired — users write `(allow|ask|deny REASON?)` directly. _Not user-facing._ | `Effect::Terminal { decision: Decision::Ask, … }`    |
| Shape           | The type of a parser-declared `#var` binding, checked against rule-body operators at load time. A closed set of four: `Token` (a single value), `Command` (a command line), `Collection Token` (a list of values), `Count` (an occurrence count). Computed from the declaration alone (`shape_of_*` in `crates/engine/src/shape.rs`); no inference from rule bodies. _Not user-facing_ — error text uses "a single value", "a command line", "a list of values", "a count". | `Shape::CollectionToken` for `(parameter "o" (set #opts))` |
| Define          | Two surface forms, currently distinct: `(define NAME PAT)` binds a Pattern; `(define-arg-style NAME (PLIST))` binds a Style. We intend to unify these (likely via a typed body or usage inference); avoid entrenching the split.                                                                            | `(define prod-host …)` / `(define-arg-style java …)` |
| Provenance      | Tags where a rule or parser came from: `Prelude` (built-in, auto-trusted), `PrimaryConfig` (user config, auto-trusted), or `Loaded { path }` (pulled in via `(load …)`, requires explicit approval).                                                                                                        | `Prelude`, `PrimaryConfig`, `Loaded { path }`        |
| Canonical form  | Deterministic, span-free s-expression serialisation used for hashing and diffs. Formatting/comments invisible to hash.                                                                                                                                                                                      |                                                      |
| Class A / Class B | Two categories of migration rewrite. _Class A_ is syntactic and semantics-preserving (e.g. `(effect :allow)` → `(allow)`, `:style S` → `(style S)`, `(may-i *)` → `(authorise)`) — `may-i migrate` silently rehashes trust-store entries so approvals carry over. _Class B_ changes what a rule decides — the user is warned and no trust state is auto-updated. Full spec: `openspec/specs/migration-system/spec.md`. | `(effect :allow)` → `(allow)` is Class A |
| Tokenisation    | The per-program argv split performed by a Parser declaration: assigning tokens to flags, parameters, positionals, the outer slice and rest binding per the declared Style and `(flags MODE)`. Distinct from the shell parser (which lexes the bash source into argv) — tokenisation runs over the resulting argv. Tokenisation errors (e.g. a `many-till` sentinel never seen, a required positional missing) emit error-severity diagnostics; by the engine invariant, the rule's decision floors to `:ask`. | `parse_argv` in `crates/engine/src/eval/bindings.rs` |
| Integrity (trust) | The property that every entry in the trust store re-hashes to its stored hash key when its canonical form is recomputed. Verified before any trust-mutating command. Two failure modes are reported via the same Advisory path: _suspect entries_ (one or more entries' stored forms don't match their hash key, e.g. tampered file) and _corrupt store_ (the file fails to load at all). Interactive runs prompt for repair; non-interactive runs treat the store as unavailable and `(load …)` rules stay inert. Scope is canonical-form hashes only — schema/version concerns are separate. | `TrustStore::verify_integrity` returns `Vec<SuspectEntry>` |
| Invocation mode | How `may-i` was called. Three modes reach the decision pipeline (`pipeline::run_hook`, `run_eval`, `run_check`); other subcommands (`fmt`, `migrate`, `trust`, `parse`) are utilities that bypass it. _Hook mode_ — harness-invoked via Claude Code hook protocol; JSON only; consults trust; exit 2 on deny. _Eval mode_ — `may-i eval`, direct CLI; text or JSON; consults trust; advisory (never blocks). _Check mode_ — `may-i check`, lint/validation; text or JSON; **never consults trust** and **never blocks**. | `may-i` (stdin JSON) / `may-i eval 'cmd'` / `may-i check` |

### Canonical-form ordering

The canonicaliser sorts a body form **only when both** of the following
hold; otherwise authored order is preserved verbatim:

1. **Engine-order-independent** — reordering children is a semantic
   no-op (no short-circuit, no positional binding).
2. **Not human-curated** — the form has no convention of embedded
   organisation such as section-header comments or mnemonic grouping
   between children.

Either condition alone is enough to preserve order. `(rule …)` bodies
fail #1 (short-circuit `and`/`or`). `(check …)` cases fail #2 — cases
are engine-order-independent test assertions, but users group them with
comments and the formatter must not scramble that authored structure.
`(flag [a b])` name vectors and `(define-arg-style …)` attribute sub-forms
(head-keyed `(attr value)` lists — the alist-style convention all option
forms use, including `(audit …)`; not keyword plists) pass both and are sorted.

This principle is independent of trust-hash participation. `(check …)`
does not enter the hash but is still order-preserving because of #2.
Conversely, the sorted forms remain sorted even when they enter the
hash, because their chosen order carries no information.

### Pattern internals

The internal representation is richer than the surface syntax — argv-shaped
matchers are an `ArgPattern` enum, single-token matchers are `Expr<T>`, and
tests in conditional position go through a `Predicate` enum. Resist the
urge to surface this split in user docs, error messages, or DSL forms;
users see one kind of thing.

"Predicate" is fine in casual conversation as a synonym for "pattern in
conditional position". Avoid it in precise writing — say **Pattern**.

### Fact storage

Storage is `key → set<string>`. `Predicate::Fact` checks membership;
`Expr::Bind` pushes captures into the inner evaluation's facts.

### Trust internals

`trust_gate::evaluate` is the consumer-facing surface — CLI commands consult
it once per invocation for filtering, advisory layout, and block decisions.

## Boundaries

- `may-i` decides; the harness enforces. A `:deny` decision exits with code
  2, which Claude Code's hook protocol treats as a block.
- Eval is pure: no IO, no execution, no network.
- Auto-migration applies to `~/.config/may-i/config.lisp` only.

## Invariants

- When the shell parser or tokenisation emits an _error_-severity
  diagnostic, the decision floors to `:ask` (`:deny` stays `:deny`).
- Rule order preserved; reordering changes the trust hash.
- S-expression parser, evaluator, and migration must not panic on
  arbitrary input.
- Trust integrity verified before any trust-mutating command; mismatch prompts
  repair (interactive) or treated as unavailable (non-interactive).
- `Cargo.toml` `version` agrees with the git release tag.

## Non-Goals

- Sandboxing or executing commands.
- Filesystem, network, or process policy beyond command structure.
- Replacing the harness's approval UI on `:ask`.
