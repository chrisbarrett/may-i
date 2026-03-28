## Why

The spec corpus has drifted from the implemented DSL and the author's mental
model. Several specs describe v1 grammar (`context`/`has`/`defcontext`) that has
been entirely replaced by the fact-based system (`fact?`/`define`). Others
contain features that should be removed (`At` matcher), use incorrect naming
conventions (keyword-style define names), or miss key evaluation semantics
(top-level rule dispatch, set-based facts). A sweep is needed to make the specs
a reliable source of truth again.

## What Changes

- **Archive** `context-aware-configuration` and `harness-adapters` specs
  (superseded by fact-based system and simplified Claude Code detection)
- **Remove** the `At`/`(= N PATTERN)` matcher from specs and implementation
  (`positional` with wildcards covers the same cases)
- **Correct** the command selector description: first arg to `rule` is a
  name/pattern selector (Literal/Regex/Or), not an effect
- **Add** top-level evaluation semantics: implicit `or` across rules, `:ask`
  global fallback, `Nil` is internal-only
- **Introduce** set-based fact model: all facts are `Map<Keyword, Set<String>>`
  internally, `(fact? [:key "val"])` is set-membership
- **Add** `:via` as a built-in set-valued fact pushed by `(may-i *)` during
  recursive evaluation
- **Update** `define` names from keyword-style (`:is-ssh`) to bare symbols
  (`is-ssh`)
- **Update** all `has` syntax references to `fact?` across affected specs
- **Note** that `Expr::Bind` is valid in `positional`/`exact`/`anywhere` but
  NOT `forbidden`
- **Collapse** three testing specs into a single testing philosophy spec
- **Add** migration philosophy spec (sexpr rewrite passes, any-version support)

## Capabilities

### New Capabilities

- `top-level-evaluation-semantics`: Evaluator tries rules in order (implicit
  `or`), global default is `:ask`. Nil never surfaces to users.
- `set-based-facts`: All facts are sets internally. Bind and `--fact` produce
  singletons. `(fact? [:key "val"])` is set-membership.
- `via-fact-builtin`: `:via` is a built-in set-valued fact. `(may-i *)`
  pushes the current command name onto it during recursive evaluation.
- `migration-philosophy`: Migration via sexpr rewrite passes before AST
  parsing. Each version bump adds a pass. Configs from any era are supported.
- `testing-philosophy`: Prefer property tests with proptest/Arbitrary. Fall
  back to targeted unit tests. Key invariants: no panics, boolean algebra,
  determinism, recursion limits.

### Modified Capabilities

- `unified-effect-evaluation`: Add top-level dispatch semantics; fix command
  pattern description from "effect" to "selector"
- `arg-pattern-evaluation`: Remove `At` matcher
- `partial-pattern-matching`: Remove `At` references
- `define-resolution`: Change define names from keywords to bare symbols
- `fact-value-evaluation`: Update for set-based fact model
- `runtime-context`: Update ContextValue to set-based model
- `type-primitives`: Update ContextValue description for set model
- `v2-expr-fact-binding`: Add bind-site restrictions (not valid in `forbidden`)
- `human-evaluation-trace`: Update `has` syntax to `fact?`
- `opencode-context`: Update `has`/`context` syntax to `fact?`, remove adapter
  references
- `fact-predicates-in-args`: Update `has` syntax to `fact?`

## Impact

- **Specs**: ~15 spec files modified or created, 2 archived, 3 collapsed
- **Core crate**: `ContextValue` changes from Present/Scalar to set-based;
  `At` variant removed from `ArgPattern`
- **Engine crate**: Evaluator changes for set-based fact matching; `(may-i *)`
  pushes `:via` fact; `At` evaluation removed
- **Config crate**: Parser changes to reject `At`; migration rewrite passes
- **CLI**: No external interface changes (`:via` is internal to recursive eval)
