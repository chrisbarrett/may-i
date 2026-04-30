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

| Term            | Definition                                                                                                             | Example                                                   |
| --------------- | ---------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| Rule            | Pattern + effect for one top-level command.                                                                            | `(rule <command> <expr>)`                                 |
| Effect          | Terminal decision, with optional reason. See glossary.                                                                 | `:allow`, `:ask`, `:deny`                                 |
| Predicate       | Boolean expr over args/facts. `define` names a predicate.                                                              | `(fact? :k)`, `(fact? [:k pat])`, `define`                |
| Fact            | Runtime data supplied by the harness per invocation. See glossary.                                                     | `key → set<string>`                                       |
| Pattern / Expr  | Argument matchers and combinators. See glossary.                                                                       |                                                           |
| Recursive Check | Recursive eval of a wrapper's inner command; pushes a `:via` fact.                                                     | `may-i *`                                                 |
| Provenance      | Root file vs loaded via `load`. Decides whether trust applies.                                                         | `PrimaryConfig`, `Loaded { path }`                        |
| Trust           | Per-rule approval keyed by canonical-form hash. See glossary.                                                          |                                                           |
| Canonical form  | Deterministic, span-free s-expression serialisation used for hashing and diffs. Formatting/comments invisible to hash. |                                                           |
| v1 / v2 syntax  | v1 deprecated, v2 canonical. See glossary.                                                                             | v1 `(rule (command "echo") ...)` / v2 `(rule "echo" ...)` |

### Effect

Lattice `:allow < :ask < :deny`; combiners take the strictest.

### Fact

Set-valued so wrappers stack (`:via` accumulates `ssh`, `sudo`). Wildcard
matches non-empty set; patterns test set membership.

### Pattern / Expr

Literals, regex, quantifiers (`?` `*` `+`), combinators (`positional`, `exact`,
`anywhere`, `forbidden`). `Expr::Bind` captures matches as facts for inner eval.

### Trust

Loaded rules inert until approved; primary rules bypass. Store v3.

### v1 / v2 syntax

v1 migrated transparently for the user's config only
(`~/.config/may-i/config.lisp`); fresh and temp files must use v2.

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
