## ADDED Requirements

### Requirement: A change is not archived while any task is unchecked

A change under `openspec/changes/` SHALL NOT be archived while its `tasks.md`
contains an unchecked task (`- [ ]`). Every task SHALL reach a recorded outcome —
done, or withdrawn with the reason — before the change moves to
`openspec/changes/archive/`.

An unchecked box is never a resolved task. A task that turns out to be
unnecessary SHALL be resolved by checking it and recording what replaced it, in
the task's own body, so the archive shows the decision rather than an absence.
Leaving it unchecked is indistinguishable from having forgotten it, and a
downstream task that claims to verify against it then reports a check that could
not have run.

This is enforced by a validator, not by reviewer memory. The validator enforces
that every task reached a recorded outcome; whether that record is accurate
remains a review concern, as with the REFERENCE.md consideration task.

#### Scenario: Unchecked task blocks the archive

- **GIVEN** a change whose `tasks.md` contains at least one `- [ ]` task
- **WHEN** the archive validator runs
- **THEN** it SHALL fail and name each unchecked task by its number and text
- **AND** the change SHALL NOT be archived until each is resolved

#### Scenario: Withdrawn task is resolved by checking it with a reason

- **GIVEN** a task whose premise is contradicted by measurement during
  implementation
- **WHEN** the implementer resolves it
- **THEN** the task SHALL be checked `- [x]` and its body SHALL record what was
  found and why the original work was not done
- **AND** the archive validator SHALL accept it

#### Scenario: All tasks checked permits the archive

- **GIVEN** a change whose `tasks.md` contains no `- [ ]` task
- **WHEN** the archive validator runs
- **THEN** it SHALL pass

#### Scenario: Verification task cannot depend on an unrecorded baseline

- **GIVEN** a task that verifies an outcome against a baseline recorded by an
  earlier task
- **WHEN** the earlier task is unchecked
- **THEN** the validator SHALL fail on the earlier task, so the dependent claim
  cannot reach the archive unexamined
