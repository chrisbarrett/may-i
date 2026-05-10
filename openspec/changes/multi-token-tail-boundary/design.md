## Context

`Tail::AfterToken(String)` (`crates/core/src/ast.rs:732`) declares a single-token boundary between a wrapper's outer flags and its inner command. It maps cleanly to tools like `mise … -- INNER` (boundary = `--`) but cannot express tools whose boundary has multiple spellings. `nix shell` and `nix develop` accept both `--command` and `-c` as the same boundary marker; the existing single-token form forces users to pick one and silently lose the other.

Compounding this, the v1 → v2 migration of `(wrapper "nix" (positional (or "shell" "develop")) (flag "--command" :command+args))` currently produces:

```lisp
(rule "nix" (when (positional (or "shell" "develop") "--command") (tail (authorise))))
```

Under GNU parsing, `--command` is consumed as a long flag (consuming the next argv token as its value) and never appears in the positional stream. The `(positional … "--command")` clause therefore never matches. Evaluation falls through to a broader rule that allows all `nix shell *` invocations blanket — so `nix shell nixpkgs#hello --command mkfs /dev/sda` is currently allowed in the user's working configuration. (Confirmed via `may-i eval` against the real config at `~/.config/nix-configuration/home/config/programs/may-i/config.lisp`.)

A second engine bug compounds this: `evaluate_tail_authorise_fold` (`crates/engine/src/eval/effects.rs:387`) falls back to recursing on the full argv when the parser declares a tail but the boundary is absent in argv. This silently re-runs the rule on the same command — masking missing-boundary cases as accidental matches.

Stakeholders: any user whose config contains a migrated `(wrapper "nix" …)` form; future contributors writing wrapper-tool parsers (terragrunt, kubectl exec, docker exec, etc.) that may have aliased boundary tokens.

## Goals / Non-Goals

**Goals:**

- Express multi-spelling boundary tokens declaratively in the parser DSL.
- Make the v1-wrapper-to-v2-rule migration produce correct, evaluator-equivalent output for nix.
- Eliminate the silent-fallback behaviour of `(tail (authorise))` when the parser declares a tail and the boundary is absent.
- Keep the prelude useful out of the box for nix users without forcing every nix user to write a parser declaration.

**Non-Goals:**

- Generalising tail boundaries to non-literal patterns (regex, predicates). Boundary tokens are always literal spellings of a flag-equivalent marker.
- Rewriting `(flag …)` and `(parameter …)` to use `(or …)` instead of bracket alias-lists. Evaluated and rejected — see Decisions below.
- Generalising the migration pipeline to emit multiple top-level forms from a single rewrite (the 1-node-in / 1-node-out architecture stays intact; the prelude addition is what makes the migration produce a self-consistent result).
- Adding parsers to the prelude for arbitrary third-party wrappers. Only nix is added now; the scope note is broadened to cover "wrapper tools whose argv semantics are silent-bypass footguns" so future additions have a principled justification.

## Decisions

### Bracket alias-list `[…]` for multi-token, not `(or …)`

User explicitly considered `(tail (after (or "--command" "-c")))` and asked whether `(flag …)` / `(parameter …)` should follow suit. Rejected, for three reasons:

1. **Distinct semantic categories already exist in the DSL.** Bracket lists `["a" "b"]` declare an alias set — multiple spellings of one identity (e.g. `["X" "request"]` for the `-X`/`--request` curl flag). `(or …)` is a pattern-position disjunction allowing non-literal subterms (regex, fact-binds). Boundary tokens, like flag aliases, are literal spellings of a single identity; they fit the alias-set shape.

2. **Bracket form is structurally tighter.** Allowing `(or "x" (regex "^pre-") [:fact *])` inside `(after …)` invites the question "can I split at any token matching a regex?" — a bizarre capability with no real use case. Bracket-list-of-literals carries that constraint in the type.

3. **Migration cost is not free.** Rewriting `(flag […])` / `(parameter […])` across all user configs is pure churn; both forms expand to `Vec<String>` internally, and the bracket form is shorter and visually distinct from value-pattern slots like `(parameter ["X" "request"] (or "POST" "GET"))`.

Decision: extend `Tail::AfterToken` to `Vec<String>`. DSL accepts `(after STR)` (single shorthand) and `(after [STR…])` (alias-set). Reject empty `(after [])` at parse time.

### Tighten `(tail (authorise))` to no-match on missing boundary

When the parser declares a tail but the boundary is absent, the existing fallback to full-argv-recursion is a footgun. Any rule that uses `(tail (authorise))` is implicitly asserting "there is an inner command to authorise" — that assertion is false when the boundary token is missing.

Alternatives considered:

- **Keep the fallback, document it.** Rejected — it makes rule-firing depend on whether the user happens to have written a parser-level `(tail …)` declaration. Confusing and footgun-laden.
- **Always treat missing tail as no-match, even when no parser tail is declared.** Rejected — `(rule "sudo" (tail (authorise)))` and similar idioms in REFERENCE.md depend on the no-tail fallback to mean "recurse on full argv minus program."

Decision: distinguish "parser has tail declared but boundary absent in argv" (no-match) from "parser declares no tail" (fall back to ctx.args, existing behaviour). Implementation: check `ctx.parser.tail.is_some()` in `evaluate_tail_authorise_fold` before applying the fallback.

### Add `nix` to the prelude

Without a prelude entry, every nix user must declare `(parser "nix" (style gnu) (tail (after ["--command" "-c"])))` themselves. The migration's `strip_redundant_boundary` pass — which keeps configs clean — fires only for prelude-declared parsers, so the v1-nix-wrapper migration would otherwise leave a broken positional-literal that requires manual editing.

Alternatives:

- **Leave nix to user config; emit a migration warning.** Rejected — nix is widely used, the wrong-by-default behaviour is a security footgun, and the migration warning is easy to miss.
- **Generalise the migration to emit sibling parser declarations.** Rejected — requires changing `RewriteFn` from `1-in-1-out` to `1-in-N-out`. Significant architecture churn for one wrapper.

Decision: add `(parser "nix" (style gnu) (tail (after ["--command" "-c"])))` to `crates/config/src/prelude.lisp`. Update the prelude scope note in REFERENCE.md from "tools that ship with a regular Linux distribution" to "wrapper tools shipped with regular Linux distros, plus widely-used wrappers whose argv semantics are silent-bypass footguns."

### Single-token shorthand stays

Existing user configs and the prelude itself use `(tail (after "--"))`. Forcing those to migrate to `(tail (after ["--"]))` is gratuitous churn. The parser accepts both forms. Display normalises to the single-string form when the alias-set has exactly one member.

## Risks / Trade-offs

[Risk] Out-of-tree code matching exhaustively on `Tail::AfterToken(String)` breaks. → Mitigation: pre-1.0 project, breaking changes are explicitly permitted (CLAUDE.md). The compiler will catch every match site at the consuming crates.

[Risk] Tightening `(tail (authorise))` to no-match-on-missing-boundary changes evaluation outcomes for any existing rule that relied on the fallback when a parser tail was declared. → Mitigation: the fallback was undocumented and unintuitive; any rule depending on it was probably accidentally working. Migration test suite + the user's real config are the regression net.

[Risk] Adding nix to the prelude expands prelude scope. Future "should X be in the prelude?" questions get harder. → Mitigation: revise the scope note explicitly. Document that prelude-eligibility is "argv semantics tricky enough to be a security footgun" plus "widely deployed."

[Risk] User configs that already migrated and committed the broken `(positional … "--command")` form keep the broken pattern until they re-run `may-i fmt`. → Mitigation: `strip_redundant_boundary` runs as part of the migration pipeline; `may-i fmt` invokes the pipeline; users will get the cleanup on their next format pass. Optionally surface a warning during eval if a rule's positional pattern contains a literal that matches a parser-declared boundary token.

## Migration Plan

This change is itself part of the v2 migration story; it does not require a separate user migration. Existing user configs benefit by re-running `may-i fmt`. No rollback strategy needed — pre-1.0 project.

## Open Questions

None.
