## Why

A change can be archived with unchecked tasks, and nothing catches it.

This happened in `fast-iteration-loop`. Task 5.1 — "record the baseline
`cargo test --workspace -- --list` output and its test count" — was never done
and stayed `- [ ]`. Task 6.1 — "confirm the test count matches the 5.1 baseline
exactly" — was marked `- [x]` anyway. The change then archived cleanly.

That pairing is the dangerous shape. 5.1 existed *because* consolidating 32
integration test targets into 5 fails open: a test lost in the move leaves a
green suite. 6.1 was the backstop, and it was recorded as passing against a
reference that did not exist. The merge turned out to be correct — verified
afterwards by diffing test function names across it, 348 before and 348 after —
but that verification happened by luck of a later review, not by the gate the
tasks described.

`openspec archive` has no task-completeness check. Its flags are `--yes`,
`--skip-specs`, `--no-validate`, and `--json`; none inspect checkbox state.
`openspec validate --strict` passes a change with zero completed tasks. So the
only thing standing between an unfinished change and the archive is whoever runs
the command.

It is not a one-off. Scanning every archived change for `- [ ]` finds **19 with
unchecked tasks**:

| Unchecked / total | Change |
| ---: | :--- |
| 30/79 | `2026-03-28-improve-test-suite-with-property-tests` |
| 16/78 | `2026-05-11-parser-named-bindings` |
| 6/30 | `2026-04-09-migration-regression-tests` |
| 5/106 | `2026-05-11-dsl-coherence` |
| 4/13 | `2026-04-09-add-missing-proptests` |
| 2 each | `may-i-recurse-compound-inner`, `add-integration-tests`, `spec-hygiene-pass` |
| 1 each | 11 further changes |

`fast-iteration-loop` itself carried two, not one: 5.1 and 5.2, each with a
downstream task (6.1 and 5.9) marked complete against it. Both were closed
retroactively once the outcomes were verified by other means. The first was
found by review; the second only by this scan — which is the point. A reviewer
looking for this finds some of it; a script finds all of it.

## What Changes

- **Block archiving a change with unchecked tasks.** A validator reads the
  change's `tasks.md` and fails when any `- [ ]` remains, naming each one.
- **Require a deliberate, recorded opt-out.** A task that turns out to be
  unnecessary is normal — `fast-iteration-loop` task 3.4 was correctly withdrawn
  after measurement contradicted its premise. The validator SHALL accept such a
  task as resolved only when it is checked *and* carries a note saying what
  replaced it, which is what 3.4 did. An unchecked box is never resolved.
- **Wire it into the pre-commit stage** alongside the existing OpenSpec
  validators, so the failure surfaces when the archive commit is made rather
  than at review.

Not in scope: verifying that a task's recorded outcome is *true*. The validator
enforces that every task reached a recorded decision; whether the recorded
decision is honest stays a review concern, exactly as the REFERENCE.md doc-sync
gate already treats its consideration task.

## Capabilities

Bucket: **contributor-internals**.

### New Capabilities

None.

### Modified Capabilities

- `spec-conventions`: add a requirement that a change SHALL NOT be archived
  while any task is unchecked, and that a withdrawn task is resolved by checking
  it with a recorded reason rather than by leaving it unchecked. This sits
  beside the existing "Pre-merge checklist applies to every spec-touching
  change" and "User-facing spec deltas require a REFERENCE.md consideration
  task" requirements, both of which are process rules enforced by a script.

## Impact

**Scripts.** New `scripts/validate-archive-complete.sh`, following the shape of
the two existing validators — `set -euo pipefail`, re-exec into the Nix devshell
when the right `yq` is absent, a `--self-test` mode with fixture cases, and a
per-change loop.

**Hooks.** A new `prek.toml` entry at the `pre-commit` stage scoped to
`^openspec/changes/`, matching `validate-change-doc-sync`.

**Backlog.** 19 already-archived changes would fail the new gate. They are
history, and retro-fitting outcomes onto work finished months ago would invite
exactly the unfounded claims this change exists to prevent. The design settles
whether they are grandfathered by a recorded allowlist or by a cutoff date.

**Docs.** `AGENTS.md` needs no change; the gate is enforced, not remembered.
No `REFERENCE.md` surface change — `spec-conventions` is contributor-facing.
