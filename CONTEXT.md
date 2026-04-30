# may-i Context

`may-i` is a bash command authorisation tool for agent harnesses. The harness
calls it before executing a shell command; `may-i` returns `allow` / `ask` /
`deny` based on user policy, by inspecting command structure only.

## Three-Layer Model

Everything serves one of:

1. **Rules** — static policy authored by the user.
2. **Facts** — runtime context supplied by the harness per invocation.
3. **Trust** — gate on whether externally-loaded rules may participate.

If a change doesn't fit one of these, question whether it belongs.

## Vocabulary

**Rule** — `(rule <command> <expr>)`. Pattern + effect for one top-level
command.

**Effect** — terminal decision: `:allow`, `:ask`, `:deny`, with optional reason.
Lattice `:allow < :ask < :deny`; combiners take the strictest.

**Predicate** — boolean expr over args/facts. `(fact? :k)` and
`(fact? [:k pat])` are the predicates that query facts. `define` names a
predicate.

**Fact** — runtime `key → set<string>`. Set-valued so wrappers stack (`:via`
accumulates `ssh`, `sudo`). Wildcard matches non-empty set; patterns test set
membership.

**Pattern / Expr** — argument matchers: literals, regex, quantifiers (`?` `*`
`+`), combinators (`positional`, `exact`, `anywhere`, `forbidden`). `Expr::Bind`
captures matches as facts for inner eval.

**Recursive Check (`may-i *`)** — recursive eval of a wrapper's inner command;
pushes a `:via` fact.

**Provenance** — `PrimaryConfig` (root file) or `Loaded { path }` (via `load`).
Decides whether trust applies.

**Trust** — per-rule approval keyed by canonical-form hash. Loaded rules inert
until approved; primary rules bypass. Store v3.

**Canonical form** — deterministic, span-free s-expression serialisation used
for hashing and diffs. Formatting and comments invisible to hash.

**v1 / v2 syntax** — v1: `(rule (command "echo") ...)`; v2 (canonical):
`(rule "echo" ...)`. v1 migrated transparently for the user's config only.

## Boundaries

- `may-i` decides; harness enforces. Exit code 2 = block (Claude Code hook).
- Hook mode silently exits 0 for non-Bash tools.
- Eval is pure: no IO, no execution, no network.
- Auto-migration applies to `~/.config/may-i/config.lisp` only.

## Invariants

- Parse error of `Error` severity floors decision to `:ask` (`:deny` stays
  `:deny`).
- Rule order preserved; reordering changes the trust hash.
- Parser, evaluator, migration must not panic on arbitrary input.
- Trust integrity verified before any trust-mutating command; mismatch prompts
  repair (interactive) or treated as unavailable (non-interactive).
- `Cargo.toml` `version` agrees with the git release tag.

## Non-Goals

- Sandboxing or executing commands.
- Filesystem, network, or process policy beyond command structure.
- Replacing the harness's approval UI on `:ask`.
