## Why

`openspec/specs/spec-conventions/spec.md` currently mixes two kinds of content: **normative rules** the pre-merge checklist (and a future validator) enforce, and **AI-steering prose** that exists to guide artifact generation (vocabulary tables, bucket bullets, trust-relevance criteria, delta-authoring reminders). The steering content was duplicated wholesale into `openspec/config.yaml` (commit `b8e7ffe`), so the same material now lives in two places:

- `openspec/config.yaml` — `context:` / `rules.specs:` — prompt-injected into every artifact generation. Authoritative for *steering*.
- `openspec/specs/spec-conventions/spec.md` — `### Requirement:` blocks. Authoritative for *enforcement*.

The duplication is silent: nothing wires the two together, the spec doesn't acknowledge `config.yaml`, and a future edit to one will drift from the other. This change resolves the drift by **trimming spec-conventions to its normative core** and **pointing its Purpose at `config.yaml` as the steering source**.

This follow-up was anticipated when the `add-spec-frontmatter` change was scoped: that change's validator (`scripts/validate-spec-frontmatter.sh`) gives spec-conventions a concrete enforcement story, which makes the steering content's separate fate plain.

Confirmed via OpenSpec source-code audit (`src/core/project-config.ts:19-41`, `src/core/artifact-graph/instruction-loader.ts:202-280`, `src/core/validation/validator.ts`):

- `config.yaml` supports exactly `schema`, `context`, `rules.<artifactId>`. Pure prompt-injection.
- Validator never reads `config.yaml`.
- `rules.specs` keys the delta artifact under `openspec/changes/<name>/specs/`, never the stable store.

So normative content **must** stay in the spec; steering content **can** move into `config.yaml`. The rubric is captured in the `openspec-customisation` skill loaded via `.claude/rules/openspec-conventions.md`.

## What Changes

- **Trim `Requirement: Each spec belongs to one documented bucket`**: remove the inline ten-bullet bucket list (now in `config.yaml:context`). Retain the SHALL rule that every spec fits one bucket. Cross-reference `config.yaml` as the bucket-list source. Cross-reference the frontmatter validator (introduced by `add-spec-frontmatter`) as the enforcement mechanism.
- **Trim `Requirement: User-facing and contributor-facing specs do not mix audiences`**: remove the inline user / contributor vocabulary recitation (now in `config.yaml:context` and `CONTEXT.md`). Retain the SHALL rule that audiences don't mix and that user-facing specs use user vocabulary. Cross-reference both sources.
- **Trim `Requirement: Spec names use user vocabulary`**: remove the inline vocabulary lists; cross-reference `CONTEXT.md` and `config.yaml`. Retain the SHALL rule + exemptions.
- **Update the Purpose section**: explicitly state that this spec carries normative rules only, and that AI-steering content (vocabulary, bucket list, what-counts-as-X criteria, delta-authoring reminders) lives in `openspec/config.yaml`. Cross-reference the `openspec-customisation` rubric.
- **Update `.claude/rules/openspec-specs.md`**: bullet (2) and bullet (3) become cross-references to `config.yaml` instead of inlining the bucket list and vocabulary tables. The rule's authority pointer to `spec-conventions/spec.md` stays.

The Requirements being trimmed do not change their normative meaning. Each MODIFIED block preserves SHALL clauses byte-for-byte where possible; only the *steering paragraphs and bullet lists* are removed.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `spec-conventions`: MODIFY three requirements (bucket assignment, audience separation, spec-name vocabulary) to drop inlined steering content and cross-reference `config.yaml` as the steering source. MODIFY the spec's Purpose section to acknowledge the steering/normative split.

The `.claude/rules/openspec-specs.md` edit is a non-spec rule update and is tracked in `tasks.md`, not as a spec delta.

## Impact

- `openspec/specs/spec-conventions/spec.md` — MODIFY three requirements + Purpose section.
- `.claude/rules/openspec-specs.md` — replace inline bucket list and vocabulary recitation with cross-references to `config.yaml`.
- No source-code, runtime-behaviour, DSL, or trust-gate changes. No migration. No risk to any consumer of the engine.
- No edits to `openspec/config.yaml` — its content is already authoritative.

## Compatibility

The MODIFIED requirements retain the same SHALL-level obligations. Reviewers and agents follow the same rules; they read the bucket list / vocabulary tables from `config.yaml` (which they already see during artifact generation) instead of from inline lists in the spec.

## Sequencing

- **Should land after `add-spec-frontmatter`**: that change introduces the frontmatter validator and adds frontmatter to every spec. spec-conventions' bucket requirement, once trimmed, cross-references the validator — so the validator needs to exist first. If `add-spec-frontmatter` slips, this change either waits or rewords the cross-reference as a forward reference.
