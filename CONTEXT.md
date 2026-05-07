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

| Term      | Definition                                                                                                                                                                                                                            | Example                                                              |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Rule      | Pattern + decision for one top-level command.                                                                                                                                                                                         | `(rule <command> <expr>)`                                            |
| Decision  | The answer a rule gives. One of `:allow`, `:ask`, `:deny`. _Avoid_: "verdict", "effect".                                                                                                                                              | `:allow`, `:ask`, `:deny`                                            |
| Reason    | Optional explanatory string in `(effect DECISION REASON)`. Shown in traces and prompts.                                                                                                                                               | `"Confirm recursive deletion"`                                       |
| Fact      | Keyed runtime context. See below.                                                                                                                                                                                                     | `:via`, `[:env "prod"]`                                              |
| Pattern   | Anything that matches part of a command. Includes argv matchers (`(flag …)`, `(positional …)`, …) and the smaller matchers used inside them (`"lit"`, `*`, `(regex …)`, `(or …)`, …). One name, one mental model. See below.          |                                                                      |
| Recursion | Recursive eval of a wrapper's inner command; pushes a `:via` fact. Triggered from a rule body (`(positional . (may-i *))`) or from a parser parameter (`(parameter NAME (may-i *))` in `(parser …)`). Same mechanism either way.      | `(may-i *)`                                                          |
| Style     | A reusable description of _how_ a program spells flags — prefixes, separators, combining rules. Bound by name with `(define-arg-style …)`. The prelude ships `gnu`, `single-dash-long`, `legacy-bundle`, `key-value`.                 | `(define-arg-style java (:overrides gnu :separators (" " "=" ":")))` |
| Parser    | A per-program declaration that picks a Style and lists which flags carry values. Programs without one default to `gnu`.                                                                                                               | `(parser "kubectl" :style gnu (parameter ["n" "namespace"]))`        |
| Trust     | The approval mechanism for rules loaded from outside the primary config. Rules from `(load …)` are inert until you approve them with `may-i trust`. Primary config is implicitly trusted. Approvals are keyed by canonical-form hash. |                                                                      |

### Decision

A user thinks in **decisions** — _the rule allows this, asks about this,
denies this._ The `(effect …)` form is the artefact of how that decision
gets returned through the evaluator; it surfaces in the surface syntax
because users still need to write it, but user docs and prompts should
talk about the rule's _decision_, not its _effect_.

Combiners take the strictest decision: `:allow < :ask < :deny`.

### Fact

A fact is keyed runtime context — `--fact :ci` from the harness, a `[:k *]`
binding captured in a pattern, or an automatic fact like `:via` set during
recursion. Each key holds a _set_ of values, not a single one, so wrappers
stack: a `sudo ssh host rm …` recursion accumulates `:via` = `{sudo, ssh}`.
Patterns test set membership; wildcard matches the non-empty set.

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
| Effect          | The `(effect DECISION REASON)` form. Internal name for the surface syntax; not a user-facing concept. In user docs say "the rule allows / asks / denies".                                                                                                                                                   | `(effect :ask "Recursive deletion")`                 |
| Define          | Two surface forms, currently distinct: `(define NAME PAT)` binds a Pattern; `(define-arg-style NAME (PLIST))` binds a Style. We intend to unify these (likely via a typed body or usage inference); avoid entrenching the split.                                                                            | `(define prod-host …)` / `(define-arg-style java …)` |
| Provenance      | Tags whether a rule came from the primary config (auto-trusted) or was pulled in via `(load …)` (requires explicit approval).                                                                                                                                                                               | `PrimaryConfig`, `Loaded { path }`                   |
| Canonical form  | Deterministic, span-free s-expression serialisation used for hashing and diffs. Formatting/comments invisible to hash.                                                                                                                                                                                      |                                                      |
| Invocation mode | How `may-i` was called. _Hook mode_ — invoked by a harness with structured stdin (Claude Code hook protocol); exit 2 on deny. The harness fires hooks for every tool, so hook mode silently exits 0 on non-Bash tool calls. _Eval mode_ — `may-i eval`, direct CLI use; outputs trace or JSON.              | `may-i` (stdin JSON) vs `may-i eval 'cmd'`           |

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

- When the shell parser emits an _error_-severity diagnostic, the
  decision floors to `:ask` (`:deny` stays `:deny`).
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
