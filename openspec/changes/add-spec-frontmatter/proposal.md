## Why

Spec metadata (audience, bucket, trust-relevance) currently lives in unstructured prose inside each `## Purpose` section. Agents and humans must read each spec to discover what it covers and whom it is written for. The `2026-05-12-spec-hygiene` change added prose conventions (`Contributor-only.`, `Trust-relevant: yes`) but left metadata unparseable — there is no way to grep the user-facing spec set, no way to enforce one-bucket-per-spec mechanically, and the `audience` declaration is `SHOULD`-strength only.

This change promotes spec metadata into YAML frontmatter so it can be parsed, validated, and queried without LLMs. Audit prompted by the question "how should agents discover user-facing surface specs quickly?" — frontmatter answers that with one `yq` call.

## What Changes

- **Add YAML frontmatter to every stable spec under `openspec/specs/<cap>/spec.md`** with three fields:
  - `audience: user | contributor` (required)
  - `bucket: <one of the 10 documented buckets>` (required)
  - `trust-relevant: true | false` (optional, default `false`)
- **Migrate the existing `Trust-relevant: yes` Purpose line** into the `trust-relevant: true` frontmatter field. The trust-spec cross-reference stays in Purpose prose (it is a human-readable pointer, not metadata).
- **Add a prek hook + shell validator** (`scripts/validate-spec-frontmatter.sh`) that walks `openspec/specs/*/spec.md`, parses frontmatter with `yq`, and fails on:
  - missing or unknown `audience` value
  - missing or unknown `bucket` value
  - `audience: user` paired with `bucket: contributor-internals` (invalid combination)
- **Install `yq` in the Nix devshell** (`builder.nix`) so the validator runs reproducibly.
- **Modify `spec-conventions`**:
  - ADD requirement: *Every stable spec declares metadata in YAML frontmatter*. Names the three fields, the value enums, the audience/bucket invariant, and the validator obligation.
  - MODIFY existing trust-relevance requirement: replace the `Trust-relevant: yes` Purpose-line rule with the frontmatter `trust-relevant: true` field. Pre-merge checklist grows from 7 to 8 items (frontmatter present and valid).
- **Update `.claude/rules/openspec-specs.md`** to mention the frontmatter convention and the grep recipe `yq '.audience == "user"' openspec/specs/*/spec.md`.
- **Backfill all 31 existing specs** with frontmatter. Audience and bucket assignments derive from the existing `Contributor-only.` declarations and the bucket list in `spec-conventions`. The audit happens during backfill and surfaces ambiguous specs (e.g., `fact-predicates-in-args`, `wordpart-source-spans`) for explicit decision.

OpenSpec tolerates frontmatter: its markdown parser ignores everything before the first `#` header, and its archive logic round-trips the `before` block verbatim (`src/core/parsers/markdown-parser.ts`, `src/core/specs-apply.ts`). Confirmed via source-code audit before this change was drafted.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `spec-conventions`: ADD one requirement covering YAML frontmatter (fields, enums, validator); MODIFY the existing trust-relevance requirement to reference frontmatter instead of the Purpose-line form.

The backfill of 31 specs is purely structural — frontmatter blocks added above the existing `# X Specification` title — and does not modify any `### Requirement:` body. Per `spec-conventions` Requirement 1 (which governs structure) and matching the `2026-05-12-spec-hygiene` precedent, structural edits are tracked in `tasks.md` rather than as per-spec delta files.

## Impact

- `openspec/specs/spec-conventions/spec.md` — ADD frontmatter requirement, MODIFY trust-relevance requirement.
- `openspec/specs/<all 31 specs>/spec.md` — insert YAML frontmatter block at the top of each file. For trust-relevant specs, also remove the prose `Trust-relevant: yes` line (replaced by frontmatter field).
- `scripts/validate-spec-frontmatter.sh` (new) — shell + `yq` validator invoked by prek.
- `prek.toml` — add `validate-spec-frontmatter` hook (`stages = ["pre-commit"]`, `files = "^openspec/specs/"`).
- `builder.nix` — add `yq-go` to the devshell `packages` list.
- `.claude/rules/openspec-specs.md` — add bullet for frontmatter convention + grep recipe; bump checklist count.
- No source-code, runtime-behaviour, DSL, or trust-gate changes. No migration. No risk to any consumer of the engine.

## Compatibility

OpenSpec itself does not read the frontmatter — it tolerates and preserves it (audited). The convention is private to this repository. If OpenSpec later defines its own frontmatter schema, the key collision is bounded to three keys and migration is mechanical. The pre-1.0 status of this project (`CLAUDE.md`) makes the convention cost acceptable.
