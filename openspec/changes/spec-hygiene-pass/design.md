## Context

The May 2026 spec audit (recorded in conversation; see also the `spec-conventions` change that landed alongside this one) catalogued 50 files under `openspec/specs/` and classified each by topic, format conformance, and current relevance. Three files came back as not-actually-specifications:

- `arg-tokenisation/spec.md` — describes a retired DSL surface. Concrete contradictions with the canonical `dsl-form-list-syntax` spec:
  - `arg-tokenisation`: `(define NAME (PLIST))` with `:long-prefix`, `:short-prefix`, `:separators`, `:combined-shorts`, `:first-token-bundle`, `:pun`, `:overrides` PLIST keys.
  - `dsl-form-list-syntax`: `(define-arg-style NAME …)` with `(overrides …)`, `(long-prefix …)`, `(separators …)`, … attribute forms; "the legacy PLIST `(define-arg-style NAME (:k v :k v))` body SHALL retire".
  - Similar pair on parser declarations: `arg-tokenisation` uses `:style STYLE`; `dsl-form-list-syntax` retires the PLIST key in favour of `(style NAME)`.
  - And on recursion: `arg-tokenisation` documents `(may-i *)`; `dsl-form-list-syntax` says `(authorise)` is the sole verb and `(may-i *)` retires.

- `config-load-surface/spec.md` — two requirements, both about code shape: "CLI consumes LoadResult directly" and "User-facing behaviour preserved". The latter is tautological ("removing the wrapper SHALL NOT change any user-visible output"). The Purpose is the literal stub left by the archiver after `deepen-loaded-config` landed. The refactor has happened; nothing here remains to enforce as a spec.

- `review-followup/spec.md` — single requirement: "All pre-release review tasks are completed". The scenario points at archived task files (`- [ ]` → `- [x]`). This is a tracker artefact, not a specification.

Three deletions, three sentences of justification each. No other specs depend on these — verified by grepping for the capability names across `openspec/specs/` and `openspec/changes/`.

## Goals / Non-Goals

**Goals:**

- Remove the three files. Live spec tree shrinks from 50 to 47.
- Reduce contradiction surface (the `arg-tokenisation` ↔ `dsl-form-list-syntax` pair is the most active source of misreading for new contributors).
- Set up a worked example of how subsequent hygiene passes will operate: small, focused, one structural class of change per proposal.

**Non-Goals:**

- Format normalisation across the 22 specs still using `## ADDED Requirements` / `## MODIFIED Requirements` at top level. Separate hygiene pass.
- Filling Purpose sections that are currently `TBD` (17 specs). Separate hygiene pass.
- Folding thin specs into parents. Several depend on the in-flight `parser-named-bindings` and `order-independent-rules` changes; sequencing matters and is deferred.
- Cross-reference sweep (trust↔eval, parser↔tail). Deferred to after `order-independent-rules` lands.

## Decisions

### Decision 1: Delete rather than mark deprecated

Alternative considered: keep the files with a `## DEPRECATED` marker pointing at the replacement spec.

Rejected because:

- Pre-1.0 (per `CLAUDE.md`): "back-compatibility not required".
- A deprecated stale spec is still a stale spec. The reading risk (contradiction with `dsl-form-list-syntax`) survives the deprecation marker.
- Git history preserves the file; anyone curious why it disappeared can `git log -- openspec/specs/arg-tokenisation/`.

### Decision 2: One delta file per removed capability, listing all removed requirements

The openspec change schema requires a delta spec under `changes/<change>/specs/<capability>/spec.md` for every modified capability. For removal of a whole capability, the precedent (see `2026-03-11-add-with-facts-check-syntax/specs/context-aware-configuration/spec.md`) is `## REMOVED Requirements` listing each requirement by heading.

Each delta file gives the exact requirement headings being removed plus a one-line rationale tying back to this change's `proposal.md`. This keeps the change machine-verifiable (openspec validate can confirm requirement names match what was in the source spec).

### Decision 3: The `config-load-surface` code invariant becomes an unstated convention

Removing `config-load-surface` removes the written requirement that "the codebase SHALL NOT define a structural duplicate wrapper around `LoadResult` that adds no behaviour". This invariant survives in code review and the `code-quality` spec's general "avoid duplication" stance (see e.g. its "Decision parsing is not duplicated" and "Span type is not duplicated" requirements).

If the wrapper pattern returns, the right response is a `code-quality` requirement explicitly naming `LoadResult`, not a resurrection of `config-load-surface`. Code-shape invariants belong with their cohort.

### Decision 4: `review-followup`'s task list is left where it is

The archived changes that produced `review-followup`'s task list still exist under `openspec/changes/archive/`. Anyone wanting the original task content can read it there. The live spec adds no information beyond "those tasks are done", which is also recorded by the absence of `- [ ]` markers in the archived files.

## Open questions

- Should the design call out specific successor specs in deprecation comments at the top of the removed files? Decided no — deletion is cleaner and git log is sufficient. If a maintainer reverses this, the comment can be added in a follow-up.
- After deletion, should a one-line entry under `dsl-form-list-syntax`'s Purpose mention "supersedes arg-tokenisation"? Marginal value — the substantive cross-reference is already implicit in the syntax-retirement scenarios. Leave for the format-normalisation pass to consider when it writes Purposes for `dsl-form-list-syntax`.
