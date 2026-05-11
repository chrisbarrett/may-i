## Why

The spec set under `openspec/specs/` does not yet conform to the conventions
declared in `spec-conventions`. The audit below summarises the gap; this
change closes it without altering any requirement's meaning.

Audit findings (2026-05-12):

- **18 stable specs** lack the canonical `# <Capability> Specification`
  level-one heading and skip directly to `## Purpose` or `## Requirements`
  (violates `spec-conventions` Requirement 1).
- **`trust-hashing/spec.md`** opens with `## ADDED Requirements` — a
  delta-style heading that should appear only under `openspec/changes/` (also
  Requirement 1).
- **~16 contributor-facing specs** do not declare their audience in their
  Purpose section (Requirement 3).
- **~7 trust-relevant specs** do not declare `Trust-relevant: yes`
  (Requirement 4).

Separately, the meta-spec itself has a gap: it requires user-facing specs to
*use* CONTEXT.md vocabulary in their requirements/scenarios, but says nothing
about the spec's *name* (filename / capability identifier). Several existing
spec names use contributor-only terms (`evaluator-error-handling`,
`expr-combinator-matching`, `human-evaluation-trace`, `var-trace-breakout`,
`v2-expr-fact-binding`, …). Forthcoming consolidation changes will rename
these; we add the vocabulary-applies-to-spec-names rule first so the
consolidations can cite it.

This change is mechanical: it edits Purpose sections, fixes one delta-style
heading, and adds one requirement to `spec-conventions`. No other spec's
requirements or scenarios are altered.

## What Changes

- **Add canonical `# X Specification` title** to 18 stable specs that lack
  one. Existing `## Purpose` / `## Requirements` content is preserved
  verbatim; only the missing top-level heading is inserted.
- **Rewrite `trust-hashing/spec.md`** to canonical structure: replace
  `## ADDED Requirements` with `# Trust-Hashing Specification` + `## Purpose`
  + `## Requirements`. Existing requirement bodies are preserved verbatim.
- **Add `contributor-only` declaration** to the Purpose section of each
  contributor-facing spec that lacks one (see `tasks.md` for the list).
- **Add `Trust-relevant: yes` declaration** + cross-reference to the Purpose
  section of each trust-affecting spec that lacks one (see `tasks.md`).
- **Add a new requirement to `spec-conventions`** — *Spec names use user
  vocabulary* — extending the existing audience/vocabulary rule (Requirement
  3) to cover the spec's capability identifier itself, with the meta-spec /
  contributor-spec exemption the user asked for.
- **Update `.claude/rules/openspec-specs.md`** to reference the new
  spec-name requirement so future agents check it during pre-merge review.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `spec-conventions`: ADD one requirement covering vocabulary alignment of
  spec names, with explicit meta-spec / contributor-spec exemption.

The remaining edits — restructuring `trust-hashing` headings, Purpose-section
additions to 18 + ~16 + ~7 specs — are non-requirement editorial touch-ups.
They are listed in `tasks.md` rather than expressed as spec deltas, because
they do not change any `### Requirement:` block's content. The OpenSpec delta
format models semantic requirement changes; pure structural edits to a spec's
scaffold are tracked via tasks. This treatment matches the spirit of
`spec-conventions` Requirement 1 (which governs structure, not requirements
per se).

## Impact

- `openspec/specs/spec-conventions/spec.md` — add one requirement.
- `openspec/specs/trust-hashing/spec.md` — restructure heading scaffold.
- `openspec/specs/<18 specs>/spec.md` — insert top-level title.
- `openspec/specs/<~16 contributor specs>/spec.md` — insert
  `Contributor-only.` lead in Purpose.
- `openspec/specs/<~7 trust-relevant specs>/spec.md` — insert
  `Trust-relevant: yes — see <ref>.` line in Purpose.
- `.claude/rules/openspec-specs.md` — add a bullet referencing the new
  spec-name requirement.
- No source code, test, or runtime config changes. No migration. No risk to
  any consumer of any spec.

## Compatibility

This change introduces no new requirement on any subsystem outside
`openspec/`. The new spec-conventions requirement applies to spec authors
and the pre-merge checklist; it does not affect runtime behaviour, the DSL,
the trust gate, or any user-visible surface.
