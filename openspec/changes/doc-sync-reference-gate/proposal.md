# Proposal: doc-sync-reference-gate

## Why

`REFERENCE.md` is not docs *near* the code — it is the shipped manual.
`src/cmd_help.rs` does `include_str!("../REFERENCE.md")` and `may-i
reference` renders it verbatim, so a stale REFERENCE.md ships a wrong
manual the same way stale `--help` text would. Yet nothing forces an
author to touch it when the user-facing DSL changes.

The gap just bit a live change. `quantifier-sequence-groups` alters the
semantics of an already-documented form (`?`/`+`/`*` go from wrapping one
Pattern to wrapping an implicit sequence), but its `tasks.md` task 8.1
lists only `CONTEXT.md` and silently omits REFERENCE.md. No test catches
this: the existing example blocks still parse, the existing quantifier
prose still renders. "Already-documented form, changed meaning" is a
failure class no executable check can see — only forcing the author to
*open REFERENCE.md* catches it.

## What Changes

- A **proposal-time gate**: a change whose delta touches a user-facing
  capability MUST carry a task in `tasks.md` that names `REFERENCE.md`.
  The task is a **consideration task** — it resolves to either an edit OR
  an explicit "verified, no surface change" note. It never hard-blocks a
  typo/reword delta; it always forces the author to look.
- The rule is **enforced by a standalone validator** —
  `scripts/validate-change-doc-sync.sh`, wired into prek scoped to
  `^openspec/changes/`, mirroring `scripts/validate-spec-frontmatter.sh`.
  The third-party `openspec validate` CLI is not forked.
- The rule is **specified** as a new requirement in the `spec-conventions`
  meta-spec, which already governs change/spec structure and names
  "future siblings" of `validate-spec-frontmatter.sh`.
- A matching **authoring reminder** is added to `openspec/config.yaml`
  under `rules.tasks:` so agents emit the task by construction.
- The **motivating omission is fixed**: `quantifier-sequence-groups`
  task 8.1 gains its missing REFERENCE.md consideration task, so the
  change that exposed the gap is the first to satisfy it.

**Trigger resolution.** Delta specs under `openspec/changes/<name>/specs/`
carry no frontmatter; `audience: user` lives on the stable spec. The
validator resolves each delta capability to its stable spec
(`openspec/specs/<cap>/spec.md`) and reads audience there. A delta for a
brand-new capability with no stable spec is treated as user-facing unless
its bucket is `contributor-internals` (the conservative default —
over-prompting here is a cheap "verified, no change" note).

This is captured in OpenSpec, not an ADR, per project convention.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities

- `spec-conventions` (bucket: contributor-internals, contributor-facing):
  add a requirement that a change with a user-facing spec delta must carry
  a REFERENCE.md consideration task, enforced by a named validator script.

## Impact

- New: `scripts/validate-change-doc-sync.sh` (+ `--self-test`).
- `prek.toml`: new `validate-change-doc-sync` hook, `files =
  "^openspec/changes/"`, pre-commit.
- `openspec/specs/spec-conventions/spec.md`: one new requirement.
- `openspec/config.yaml`: one `rules.tasks` reminder bullet.
- `openspec/changes/quantifier-sequence-groups/tasks.md`: task 8.1 gains
  the REFERENCE.md consideration sub-task.
- No Rust, no runtime behaviour, no trust-relevance.
