## MODIFIED Requirements

### Requirement: Capability renames are filesystem moves driven by tasks.md

A capability rename or merge SHALL be applied as a filesystem move (1:1) or set of moves (N:1 absorption) plus a cross-reference sweep, driven by the change's `tasks.md`, rather than as paired `## ADDED Requirements` and `## REMOVED Requirements` blocks for every moved requirement. The move SHALL preserve every `### Requirement:` body, every `#### Scenario:` child, and any frontmatter field byte-identical except for the surviving spec's top-level title heading and Purpose section (which is refreshed to cover the union when absorbing).

A **rename** is a 1:1 capability move: `openspec/specs/A/` → `openspec/specs/B/`, no other capability involved.

A **merge** is an N:1 absorption: requirements from one or more source capabilities are appended into a single surviving capability, and the source directories are removed. The surviving Purpose is rewritten once to cover the union; absorbed requirement bodies are byte-identical except for surrounding heading order.

The spec-delta artefacts under `openspec/changes/<change>/specs/` for a rename or merge change SHOULD be limited to changes that genuinely modify spec content (e.g. a one-requirement edit that justifies the rename, a refreshed Purpose section in the surviving spec, or — as in this change itself — a meta-rule about how such moves are applied). The bulk of the rename or merge work is enumerated as filesystem operations and cross-reference sweeps in `tasks.md`, not as duplicated requirement bodies.

This rule exists because OpenSpec's per-requirement delta format would otherwise force every rename or merge to copy every requirement body twice (once into `## REMOVED Requirements` of the old capability, once into `## ADDED Requirements` of the new capability), introducing hundreds-to-thousands of lines of duplicated text that obscure rather than reveal the change's intent — which is purely structural.

#### Scenario: Rename change uses tasks-driven move

- **GIVEN** a proposal that renames `pattern-expressions` to `patterns` with no requirement-content changes
- **WHEN** the change is reviewed against this requirement
- **THEN** the change SHALL drive the rename through `tasks.md` filesystem operations
- **AND** the change SHALL NOT contain `## ADDED Requirements` or `## REMOVED Requirements` blocks for the moved requirements
- **AND** the verification step SHALL confirm requirement bodies are byte-identical except for the spec's top-level title heading.

#### Scenario: Merge change uses tasks-driven absorption

- **GIVEN** a proposal that folds capability `migration-diff-display` into `migration-system` with no requirement-content changes
- **WHEN** the change is reviewed against this requirement
- **THEN** the change SHALL drive the merge through `tasks.md` filesystem operations: appending the absorbed requirement blocks into the surviving spec and removing the source directory
- **AND** the change SHALL NOT contain `## ADDED Requirements` blocks for the absorbed requirements in the surviving spec's delta, nor `## REMOVED Requirements` blocks in the source spec's delta
- **AND** the surviving Purpose section MAY be refreshed via a `MODIFIED Requirements` delta only if the refresh genuinely changes assertion content; cosmetic Purpose-prose updates SHALL go in `tasks.md`
- **AND** the verification step SHALL confirm absorbed requirement bodies are byte-identical in their new home.

#### Scenario: Rename or merge change does not bypass content review

- **GIVEN** a proposal that renames or merges a capability AND modifies any requirement body
- **WHEN** the change is reviewed
- **THEN** the body modification SHALL be expressed as a normal `## MODIFIED Requirements` delta in the surviving capability directory
- **AND** the rename or merge portion SHALL still be driven by `tasks.md`
- **AND** reviewers SHALL be able to distinguish the two intents at a glance.
