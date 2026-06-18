## ADDED Requirements

### Requirement: User-facing spec deltas require a REFERENCE.md consideration task

A change with a user-facing spec delta SHALL include a `tasks.md` task naming `REFERENCE.md`. Concretely, when a delta under `openspec/changes/<change>/specs/<capability>/spec.md` adds or modifies a requirement (`## ADDED Requirements` or `## MODIFIED Requirements`) for a user-facing capability, the change's `tasks.md` SHALL contain at least one task whose text names `REFERENCE.md`. This guards the shipped user manual: REFERENCE.md is compiled into the binary (`src/cmd_help.rs`, via `include_str!`) and rendered by `may-i reference`, so a surface change that skips it ships a stale manual — and an *already-documented* form whose meaning changed is invisible to automated example checks. The task
SHALL be a *consideration* task: it is satisfied by either editing
REFERENCE.md or by recording an explicit "verified, no surface change"
resolution. The validator enforces the task's **presence**, not its
resolution; the honesty of a "verified, no change" resolution is a review
concern.

A capability is user-facing for this purpose when its stable spec
(`openspec/specs/<capability>/spec.md`) declares `audience: user`. When no
stable spec exists yet (a new capability), the capability SHALL be treated
as user-facing unless its bucket is `contributor-internals`. A delta that
only removes requirements (`## REMOVED Requirements`) or makes structural
edits SHALL NOT trigger the requirement.

This requirement is enforced by `scripts/validate-change-doc-sync.sh`, a
sibling of `scripts/validate-spec-frontmatter.sh`, wired into prek scoped
to `^openspec/changes/`.

#### Scenario: User-facing add without a REFERENCE.md task is rejected

- **GIVEN** a change with `specs/patterns/spec.md` containing `## ADDED Requirements`
- **AND** the stable spec `openspec/specs/patterns/spec.md` declares `audience: user`
- **AND** the change's `tasks.md` contains no line naming `REFERENCE.md`
- **WHEN** `scripts/validate-change-doc-sync.sh` runs over the change
- **THEN** it SHALL fail and name the change and the missing task

#### Scenario: Consideration task satisfies the gate

- **GIVEN** the same user-facing `## ADDED Requirements` delta
- **AND** the change's `tasks.md` contains a task naming `REFERENCE.md` (whether an edit or a "verified, no surface change" note)
- **WHEN** the validator runs
- **THEN** it SHALL pass

#### Scenario: Contributor-only delta does not trigger the gate

- **GIVEN** a change whose only delta is `specs/spec-conventions/spec.md` with `## ADDED Requirements`
- **AND** the stable spec `openspec/specs/spec-conventions/spec.md` declares `audience: contributor`
- **WHEN** the validator runs
- **THEN** it SHALL pass even with no REFERENCE.md task

#### Scenario: Removal-only delta does not trigger the gate

- **GIVEN** a change whose user-facing delta contains only `## REMOVED Requirements`
- **WHEN** the validator runs
- **THEN** it SHALL pass even with no REFERENCE.md task
