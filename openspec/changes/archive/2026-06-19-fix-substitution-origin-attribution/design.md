## Context

A substitution that produces a reason is annotated by `annotate_embedded_reason`
(`crates/engine/src/eval/command.rs:142`) with a suffix naming its origin
command, e.g. `($(...) substitution in `set`)`. The origin name comes from
`outer_command_name` (`command.rs:282`), which is computed as the first
`EvalUnit::SimpleCommand` in the whole input:

```rust
let outer_command_name = units.iter().find_map(|u| match u {
    EvalUnit::SimpleCommand { command, .. } => Some(command.clone()),
    _ => None,
});
```

This is a global guess, not a lexical relationship. When the substitution lives
in a position with no enclosing simple command — a bare assignment
(`dest=$(…)`), a `for` word, a `case` subject, or a redirect on a compound — the
guess reaches past it to whatever command happens to appear first (`set`).

Crucially, `decompose` **already partitions** substitution ownership by exactly
these syntactic positions: `decompose_simple_command` owns simple-command words
and assignment-prefix values; `push_embedded_units_from_structural_words`
(`decompose.rs:183`) owns bare-assignment values, `for` words, and `case`
subject/pattern words; `push_embedded_units_from_redirect_targets`
(`decompose.rs:233`) owns redirect targets. Each pass knows the owning context
at the moment it emits the `EmbeddedCommand` — the information thrown away and
mis-reconstructed later.

## Goals / Non-Goals

**Goals:**

- The substitution-origin annotation names the syntactic position that lexically
  contains the substitution.
- A substitution is never attributed to a command that does not own it.
- The descriptor is more informative than today's best case (it surfaces the
  assignment target / structural context rather than a command name only).

**Non-Goals:**

- Naming the enclosing function (`main`) — the immediate syntactic owner of
  `dest=$(…)` is the assignment, not the function it sits in. The annotation
  describes the immediate owner.
- Changing classification or decisions. This is purely the diagnostic string.

## Decisions

### D1 — Per-origin descriptor tagged at the owning decompose pass

Carry a `SubstitutionOrigin` descriptor on `EvalUnit::EmbeddedCommand`, set by
the pass that emits the unit. The variants mirror the existing ownership
partition:

| Origin | Annotation |
| --- | --- |
| simple-command word (command `c`) | `in \`c\`` |
| assignment value (target `v`) | `in assignment to \`v\`` |
| `for` list word | `in \`for\` list` |
| `case` subject / pattern | `in \`case\` subject` |
| redirect target | `in redirect target` |

`annotate_embedded_reason` consumes this descriptor; `outer_command_name` and its
global scan are deleted. Computing the descriptor where the unit is born is both
structurally correct (attribution at the site of ownership) and free — each pass
already holds the owning AST node, so no new walk is introduced.

**Alternative rejected — generic fallback for non-command owners.** Falling back
to a bare `(embedded substitution)` whenever the owner is not a simple command
discards real provenance: `dest=$(…)` *does* have a syntactic owner (the
assignment to `dest`), and surfacing it is strictly more useful to an agent
reading the prompt. The richer taxonomy costs the same single field.

**Alternative rejected — keep `outer_command_name`, just pick a closer
command.** Any approach that reconstructs the owner after `decompose` has to
re-derive the lexical relationship the decompose passes already had in hand.
Tagging at the source is simpler and cannot cross-attribute by construction.

## Risks / Trade-offs

- **New field on `EvalUnit::EmbeddedCommand`.** Additive; affects only the
  diagnostic string. No decision or classification impact.
- **Label-string churn in snapshots.** Existing snapshot tests that assert the
  old `in `set``-style suffix must be updated; the change shrinks how often the
  label appears at all once recognition lands (separate change).

## Migration

None. Internal diagnostic string only; no config, DSL, or trust-hash surface.

## Open Questions

<!-- none -->
