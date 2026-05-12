## Context

Spec metadata in `openspec/specs/<cap>/spec.md` is currently encoded as unstructured prose in the `## Purpose` section:

- Audience: lead-in sentence "Contributor-only." for contributor specs; absence implies user-facing.
- Trust-relevance: literal line `Trust-relevant: yes` followed by a cross-reference.
- Bucket: implicit in the spec's directory name.

This works for humans reading specs end-to-end but is hostile to machine queries:

- Agents discovering "which specs cover user-visible behaviour?" must open and parse Purpose prose.
- No mechanical check that `audience: contributor` and `bucket: contributor-internals` are consistent.
- The `audience` declaration is currently `SHOULD`-strength (per `spec-conventions` Requirement 3), so absence is ambiguous.

The `2026-05-12-spec-hygiene` change recently backfilled the prose conventions across 31 specs. This change reuses that audit work: every spec now carries an explicit audience marker we can promote into structured form.

OpenSpec parser audit (performed before drafting):
- `src/core/parsers/markdown-parser.ts:128-166` — section parser keys on `^#{1,6}\s+`. YAML `---` fences and `key: value` lines never match. Content before the first header is dropped (not surfaced in the parser's section list).
- `src/core/specs-apply.ts:334-337` — `buildUpdatedSpec` concatenates `[before, headerLine, requirementsBody, after]`; the `before` block is round-tripped byte-identical (modulo `\n{3,}` collapse to `\n\n`).
- No `gray-matter` dependency in `package.json`. No official frontmatter convention.

Conclusion: frontmatter is tolerated and preserved. Safe to use as a private convention.

## Goals / Non-Goals

**Goals:**

- Make spec metadata greppable in one shell command. Reference query: `yq '. | select(.audience == "user") | filename' openspec/specs/*/spec.md`.
- Promote `audience` from `SHOULD`-declared to `MUST`-declared with machine-enforceable validation.
- Make `bucket` explicit per spec so the one-bucket-per-spec rule (`spec-conventions` Requirement 2) is mechanically checkable.
- Catch the one invariant that prose cannot enforce: `audience: user` paired with `bucket: contributor-internals` is contradictory.
- Single source of truth for trust-relevance: frontmatter field, not prose line.

**Non-Goals:**

- Inventing a richer schema (`owner`, `since`, `deprecated`, `see-also`). Wait for evidence each is needed; current rule is "audience is the only field we lack".
- Migrating OpenSpec's parser to read the frontmatter. The convention is one-way; OpenSpec ignores it, we read it.
- Consolidating the over-granular spec clusters (trust-*, traces-*, testing-*). That is a separate change pass. Backfill here may surface candidates as a side effect.
- Renaming specs whose names use contributor vocabulary (`fact-predicates-in-args`, `wordpart-source-spans`, `dsl-form-list-syntax`). Backfill flags them via the audience/bucket combination but leaves names alone; renames are tracked separately.

## Decisions

### Decision: YAML frontmatter over inline `Audience:` line

Use a YAML frontmatter block at the top of each spec file:

```
---
audience: user
bucket: parsing
trust-relevant: false
---
# Patterns Specification

## Purpose
...
```

**Why**: structured, parseable with one `yq` call, extensible without inventing a new convention per field. The existing `Trust-relevant: yes` Purpose-line convention was a workaround for not having frontmatter.

**Alternative considered**: `Audience: <user|contributor>` line in Purpose, mirroring the existing `Trust-relevant: yes` prior art. Rejected because:
- Each new field requires a new prose convention.
- No structural enforcement — typos in the field name (`Auidence:`) silently pass.
- Cannot encode invariants between fields (audience ↔ bucket consistency).

**OpenSpec collision risk**: if OpenSpec later defines official frontmatter, the three keys (`audience`, `bucket`, `trust-relevant`) might collide. Mitigation: pre-1.0 project; migration is mechanical via `yq` rewrite. Accept the risk.

### Decision: Three fields — `audience`, `bucket`, `trust-relevant`

| Field | Type | Required | Values |
|---|---|---|---|
| `audience` | enum | yes | `user`, `contributor` |
| `bucket` | enum | yes | one of the 10 buckets documented in `spec-conventions` |
| `trust-relevant` | bool | no (default `false`) | `true`, `false` |

Buckets (from `spec-conventions` Requirement 2):

`rules-and-evaluation`, `facts`, `parsing`, `trust`, `loading`, `tracing-and-output`, `migration`, `cli`, `testing`, `contributor-internals`.

**Why required `bucket`**: `spec-conventions` Requirement 2 already mandates one-bucket-per-spec but leaves the bucket implicit in the spec's name. Making it explicit kills the ambiguity for suspect names and lets the validator enforce membership.

**Why `trust-relevant` optional**: only ~7 of 31 specs are trust-relevant. Most specs omit the prose `Trust-relevant: yes` line today. Default `false` matches current behaviour.

### Decision: Cross-field invariant

`audience: user` MUST NOT pair with `bucket: contributor-internals`. This is the one invariant the validator enforces beyond field-level enum checks.

**Why**: `spec-conventions` Requirement 3 forbids audience mixing, but a user-facing spec filed under the `contributor-internals` bucket is a contradiction that the prose rule cannot mechanically catch. The reverse (`audience: contributor` + non-internals bucket) is fine — contributor specs about CLI, parsing, etc., are legitimate (e.g., `parser-engine-invariants` is a contributor spec in the `parsing` bucket).

### Decision: Shell + `yq` validator, not a Rust integration test

`scripts/validate-spec-frontmatter.sh` invoked by `prek` as a pre-commit hook. `yq-go` installed via `builder.nix` devshell `packages`.

**Why**:
- User explicitly requested shell + prek.
- Shell + `yq` matches the existing prek hook style (`openspec-validate` already uses a system entry).
- Validator does not need to share code with the engine — it is a hygiene check, not a runtime concern.
- Faster than a `cargo test` that recompiles for one file walk.

**Alternative considered**: Rust integration test with `serde_yaml` deserialization. Rejected — adds a build-time dependency on the spec convention, couples test runtime to spec hygiene, and the user named the desired form.

Script skeleton:

```sh
#!/usr/bin/env bash
set -euo pipefail

errors=0
buckets="rules-and-evaluation facts parsing trust loading tracing-and-output migration cli testing contributor-internals"

for spec in openspec/specs/*/spec.md; do
  # Extract frontmatter block; yq fails on missing frontmatter
  if ! audience=$(yq -f extract '.audience' "$spec" 2>/dev/null); then
    echo "$spec: missing or invalid frontmatter" >&2
    errors=$((errors + 1))
    continue
  fi
  bucket=$(yq -f extract '.bucket' "$spec")
  trust=$(yq -f extract '.trust-relevant // false' "$spec")

  case "$audience" in
    user|contributor) ;;
    *) echo "$spec: audience must be 'user' or 'contributor', got '$audience'" >&2; errors=$((errors + 1)) ;;
  esac

  if ! grep -qw "$bucket" <<< "$buckets"; then
    echo "$spec: unknown bucket '$bucket'" >&2
    errors=$((errors + 1))
  fi

  if [ "$audience" = "user" ] && [ "$bucket" = "contributor-internals" ]; then
    echo "$spec: audience=user incompatible with bucket=contributor-internals" >&2
    errors=$((errors + 1))
  fi
done

exit $((errors > 0 ? 1 : 0))
```

Exact `yq` invocation depends on `yq-go` syntax for frontmatter extraction; tasks.md will verify the exact form during implementation.

### Decision: `trust-relevant` migrates from prose to frontmatter; cross-reference stays

Today's pattern:

```
## Purpose

Trust-relevant: yes — see `trust-gate` for the gating semantics.

<prose paragraph>
```

After:

```
---
audience: contributor
bucket: trust
trust-relevant: true
---
# Trust-Gate Specification

## Purpose

Trust-relevance is gated on `trust-gate` — see that spec for semantics.

<prose paragraph>
```

**Why split**: the boolean is metadata (frontmatter); the cross-reference is documentation (prose). Splitting them lets the validator check the boolean without parsing prose.

### Decision: Backfill in one change, not many

All 31 specs get frontmatter in this change. Alternative: introduce the requirement first, backfill over many small changes. Rejected because:
- Validator cannot be made mandatory until backfill is complete; partial state is worse than either end.
- The prose audience markers were already backfilled by `2026-05-12-spec-hygiene` — bucket and audience derivation is a mechanical 31-row table.
- Matches the precedent set by `spec-hygiene`.

## Risks / Trade-offs

- **OpenSpec adopts conflicting frontmatter schema later** → manual migration via `yq` rewrite. Pre-1.0; accepted.
- **`yq` version drift between Nix devshell and CI / contributor environments** → pin via `yq-go` in `builder.nix`; document the install in tasks.md. The prek hook runs in the devshell so dev parity is enforced.
- **Backfill misclassifies an ambiguous spec** (e.g., `fact-predicates-in-args` reads as parsing but mostly governs Pattern internals) → backfill table is reviewed in `tasks.md` row-by-row; suspect specs flagged inline with a `# REVIEW` comment in their tasks entry; reviewer must resolve before the change merges.
- **Existing prose `Trust-relevant: yes` lines duplicate the new field during the transition window** → not a transition window: this change's `tasks.md` removes the prose line in the same commit it adds the frontmatter field. Single state, no overlap.
- **Validator false negatives on malformed frontmatter** (`yq` parses garbage) → enum checks plus the audience/bucket invariant cover the cases that matter; further hardening (schema file, strict mode) deferred until a real false negative is observed.

## Migration Plan

Phased, single-change:

1. Land validator script + `yq-go` devshell addition + prek hook (hook initially set to `stages = []` or unregistered so it does not block until step 3).
2. Land spec-conventions delta and backfill all 31 specs in the same commit.
3. Enable the prek hook (`stages = ["pre-commit"]`, `files = "^openspec/specs/"`).
4. Update `.claude/rules/openspec-specs.md`.

Rollback: revert the change. No runtime impact; no migration state.

## Open Questions

- Should the prek hook also run on `pre-push` (full sweep) in addition to `pre-commit` (touched files only)? Lean: pre-commit only. The check is fast, and pre-push duplication does not earn its keep.
- `yq-go` vs `yq` (Python)? Lean: `yq-go` (Go binary, single-file, in nixpkgs as `yq-go`, faster, no Python runtime dependency).
- Should the validator also enforce that the spec body starts with `# <Capability> Specification` immediately after the frontmatter? That overlaps with `spec-conventions` Requirement 1 which is currently human-reviewed. Lean: out of scope here; revisit if R1 gets a separate validator.
