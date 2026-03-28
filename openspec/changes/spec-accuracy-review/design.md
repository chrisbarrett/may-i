## Context

The spec corpus was built incrementally as features were designed and
implemented. Over time, the DSL evolved (v1 `context`/`has` → v2 `fact?`/
`define`), features were added then reconsidered (`At` matcher), and internal
models shifted (scalar facts → set-based facts). The specs no longer reflect the
author's mental model or the implemented system.

This change is purely a spec-and-code alignment pass. The DSL's surface syntax
is largely stable; the work is making the specs say what the system actually does
and what it should do going forward.

## Goals / Non-Goals

**Goals:**

- Specs accurately describe the current DSL grammar and evaluation semantics
- Superseded specs are archived, not left to confuse future readers
- New foundational concepts (set-based facts, `:via` builtin, top-level
  evaluation) have explicit specs
- Dead code (`At` matcher) is removed from implementation
- Testing and migration philosophies are documented at the right level of
  abstraction

**Non-Goals:**

- Changing the DSL's user-facing syntax (this is a documentation/alignment pass)
- Implementing set-based facts or `:via` in this change (specs only; the
  implementation is a follow-up)
- Rewriting the evaluation engine
- Adding new DSL features

## Decisions

### Set-based fact model replaces Present/Scalar distinction

All facts become `Map<Keyword, Set<String>>`. A presence fact is a key with a
non-empty set. A scalar fact is a singleton set. `(fact? [:key "val"])` is
set-membership.

**Rationale**: Eliminates the need for per-wrapper namespace keys like
`:via/ssh`, `:via/sudo`. The `:via` key accumulates values naturally during
recursive unwrapping. Simpler internal model with one fewer enum variant.

**Alternative considered**: Three-variant model (Present/Scalar/Set). Rejected
as over-specific — the set model subsumes both and is easier to reason about.

### `:via` is a built-in, not a user convention

`(may-i *)` automatically pushes the current command name onto the `:via` set.
Users don't need to manually bind `:via` facts.

**Rationale**: Every recursive unwrap wants this fact. Making it automatic
eliminates boilerplate and ensures consistency. Other facts (`:ssh/host`, etc.)
remain user-bound via `Expr::Bind`.

### Command selector is not an effect

The first argument to `rule` is a restricted command selector (Literal/Regex/Or)
that gates rule applicability. It is NOT part of the effect algebra.

**Rationale**: Keeps rule dispatch predictable. You can look at the first arg of
every rule and know exactly which commands it handles without evaluating
arbitrary effect expressions.

### Define names are bare symbols, not keywords

`(define prod-host ...)` not `(define :prod-host ...)`. Keywords (`:foo`) are
reserved for the DSL's own use (effects, fact keys).

**Rationale**: Clean separation between user-defined names and DSL-reserved
names. Prevents confusion about whether `:prod-host` is a fact key or a define
reference.

### Migration via sexpr rewrites

Each DSL version bump adds a rewrite pass over the sexpr tree before AST
parsing. The CST roundtrip property ensures comments and formatting are
preserved.

**Rationale**: Decouples migration from AST changes. A config from any era runs
through the full rewrite chain. No version-specific parser paths needed.

### Collapse testing specs into philosophy

Three detailed testing specs (engine-property-tests, core-pattern-property-tests,
generator-implementation) become one lightweight spec focused on approach and
invariant classes rather than individual invariant IDs.

**Rationale**: The detailed specs were written to guide implementation agents
and have served their purpose. The philosophy is what matters for ongoing
development.

## Risks / Trade-offs

- **Set-based facts are a semantic change** → Spec-only in this change;
  implementation follow-up gives time to validate the model before committing
  code changes
- **Archiving specs loses detail** → The archive is preserved in git history and
  the OpenSpec archive directory; nothing is truly deleted
- **Collapsing test specs loses granularity** → Individual invariants are still
  encoded in the property tests themselves; the spec just doesn't enumerate them
