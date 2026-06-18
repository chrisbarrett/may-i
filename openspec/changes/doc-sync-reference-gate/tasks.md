# Tasks: doc-sync-reference-gate

## 1. Validator script

- [x] 1.1 Write `scripts/validate-change-doc-sync.sh` with `--self-test`
      first: synthetic fixtures for the four spec scenarios (user-facing
      add without task → fail; with task → pass; contributor-only → pass;
      removal-only → pass). Mirror the structure of
      `scripts/validate-spec-frontmatter.sh` (`set -euo pipefail`,
      mikefarah/yq re-exec guard, self-test harness).
- [x] 1.2 Implement the trigger algorithm from design.md D4: for each
      `openspec/changes/*/specs/*/spec.md`, skip unless it has `## ADDED
      Requirements` or `## MODIFIED Requirements`; resolve the capability
      to its stable spec and read `audience` (new capability with no
      stable spec → user-facing unless bucket `contributor-internals`);
      if any user-facing delta and the change's `tasks.md` has no line
      matching `REFERENCE.md`, fail naming the change and the missing task.
- [x] 1.3 `chmod +x` the script and confirm `scripts/validate-change-doc-sync.sh --self-test` is green.

## 2. Wire into prek

- [x] 2.1 Add a `validate-change-doc-sync` hook to `prek.toml` after
      `validate-spec-frontmatter`: `entry = "scripts/validate-change-doc-sync.sh"`,
      `language = "system"`, `files = "^openspec/changes/"`,
      `pass_filenames = false`, `stages = ["pre-commit"]`.

## 3. Specify and steer

- [x] 3.1 Apply the `spec-conventions` delta: add the new requirement to
      `openspec/specs/spec-conventions/spec.md` under `## Requirements`.
- [x] 3.2 Add a `rules.tasks:` reminder bullet to `openspec/config.yaml`:
      a change with a user-facing spec delta must carry a REFERENCE.md
      consideration task.

## 4. Documentation impact (REFERENCE.md consideration)

- [x] 4.1 Review REFERENCE.md for impact from this change. Resolution:
      **verified, no surface change** — this change governs the OpenSpec
      contributor workflow and adds no user-facing DSL surface, so the
      shipped manual is unaffected. (This task exists to make this change
      the first to satisfy its own gate.)

## 5. Fix the motivating omission

- [x] 5.1 In `openspec/changes/quantifier-sequence-groups/tasks.md`, add a
      REFERENCE.md consideration sub-task under group 8 (Docs): update the
      quantifier table (REFERENCE.md:166-174) and the `(positional …)`
      section for the implicit-sequence form, alongside the existing
      CONTEXT.md task 8.1.

## 6. Verification

- [x] 6.1 `scripts/validate-change-doc-sync.sh --self-test` green.
- [x] 6.2 Run the validator over live changes; confirm it now flags any
      user-facing change lacking a REFERENCE.md task and passes this
      change and the amended `quantifier-sequence-groups`.
- [x] 6.3 `scripts/validate-spec-frontmatter.sh` still green (spec-conventions edit).
- [x] 6.4 `openspec validate doc-sync-reference-gate --strict` passes.
- [x] 6.5 `prek run --all-files` (or the pre-commit subset) green.
