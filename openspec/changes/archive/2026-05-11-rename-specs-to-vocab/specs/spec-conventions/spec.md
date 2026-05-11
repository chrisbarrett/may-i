## ADDED Requirements

### Requirement: Capability renames are filesystem moves driven by tasks.md

A capability rename SHALL be applied as a filesystem move plus a cross-reference sweep, driven by the change's `tasks.md`, rather than as paired `## ADDED Requirements` and `## REMOVED Requirements` blocks for every moved requirement. The rename SHALL preserve every
`### Requirement:` body, every `#### Scenario:` child, and any
`Trust-relevant: yes` declaration byte-identical except for the spec's
top-level title heading.

The spec-delta artefacts under `openspec/changes/<change>/specs/` for a
rename change SHOULD be limited to changes that genuinely modify spec
content (e.g. a one-requirement edit that justifies the rename, or — as
in this change itself — a meta-rule about how renames are applied). The
bulk of the rename work is enumerated as filesystem operations and
cross-reference sweeps in `tasks.md`, not as duplicated requirement
bodies.

This rule exists because OpenSpec's per-requirement delta format would
otherwise force a rename to copy every requirement body twice (once into
`## REMOVED Requirements` of the old capability, once into
`## ADDED Requirements` of the new capability), introducing thousands of
lines of duplicated text that obscure rather than reveal the change's
intent — which is purely structural.

#### Scenario: Rename change uses tasks-driven move

- **GIVEN** a proposal that renames `pattern-expressions` to `patterns`
  with no requirement-content changes
- **WHEN** the change is reviewed against this requirement
- **THEN** the change SHALL drive the rename through `tasks.md`
  filesystem operations
- **AND** the change SHALL NOT contain `## ADDED Requirements` or
  `## REMOVED Requirements` blocks for the moved requirements
- **AND** the verification step SHALL confirm requirement bodies are
  byte-identical except for the spec's top-level title heading.

#### Scenario: Rename change does not bypass content review

- **GIVEN** a proposal that renames a capability AND modifies any
  requirement body
- **WHEN** the change is reviewed
- **THEN** the body modification SHALL be expressed as a normal
  `## MODIFIED Requirements` delta in the new capability directory
- **AND** the rename portion SHALL still be driven by `tasks.md`
- **AND** reviewers SHALL be able to distinguish the two intents at a
  glance.
