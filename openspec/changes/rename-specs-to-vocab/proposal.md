## Why

`spec-hygiene` adds *Spec names use user vocabulary* to `spec-conventions`.
Several existing user-facing spec names violate that requirement because
they use contributor vocabulary (CONTEXT.md):

| Current name              | Vocab violation               | Renamed to             |
|---------------------------|-------------------------------|------------------------|
| `pattern-expressions`     | "expression" → contributor    | `patterns`             |
| `trace-system`            | "system" → redundant suffix   | `traces`               |
| `human-evaluation-trace`  | "evaluation" → contributor    | `decision-trace`       |
| `rule-evaluation`         | "evaluation" → contributor    | `rule-decisions`       |
| `claude-code-hook`        | hook is one harness adapter   | `harness-integration`  |
| `fact-system`             | "system" → redundant suffix   | `facts`                |

(`fact-system` → `facts` is already handled by `consolidate-facts-specs`;
listed here for completeness so the umbrella rename isn't ambiguous.)

This change applies AFTER the consolidation changes (`consolidate-trust-specs`,
`consolidate-parsing-specs`, `consolidate-tracing-specs`,
`consolidate-rules-specs`, `consolidate-cli-hooks`, `consolidate-testing-specs`,
`consolidate-facts-specs`) so each rename moves the post-consolidation
contents into the new directory.

The rename is a filesystem/content rewrite — every requirement, scenario,
and Purpose section moves verbatim. There is no requirement-content change,
so this proposal carries only one spec delta (a small clarification on
`spec-conventions` about how renames are applied) and drives the bulk of
the work through `tasks.md`.

## What Changes

For each old → new pair:

1. Create the new directory `openspec/specs/<new>/`.
2. Move `spec.md` from `openspec/specs/<old>/` to `openspec/specs/<new>/`.
3. Update the level-one heading from `# <Old> Specification` to
   `# <New> Specification` (per `spec-conventions` Requirement 1).
4. Update Purpose-section vocabulary so any internal references to the
   old capability name use the new name.
5. `rm -rf openspec/specs/<old>/`.
6. `grep -rln '<old>' openspec/specs/ .claude/ CONTEXT.md CLAUDE.md README.md` —
   repoint every cross-reference.

The rename is mechanical. Requirement bodies, `#### Scenario:` children,
and (where applicable) `Trust-relevant: yes` declarations are preserved
byte-identical except for the title line.

`spec-conventions` gains one small additional requirement clarifying that
renames are applied as filesystem moves driven by the change's `tasks.md`,
not as cross-spec requirement migrations — so reviewers know to expect
single ADDED/REMOVED pairs in future rename changes rather than
per-requirement deltas.

## Capabilities

### New Capabilities

- None. Each rename creates a new capability directory, but the
  capability's *requirements* are all carried over from the predecessor.
  OpenSpec's spec-delta format is awkward for pure renames (every
  requirement would have to be ADDED in the new and REMOVED in the old);
  the rename is therefore tracked as a tasks-driven filesystem operation
  rather than as per-requirement deltas.

### Modified Capabilities

- `spec-conventions` — ADD one requirement clarifying the
  capability-rename apply procedure (filesystem move + cross-reference
  sweep, no per-requirement deltas required).

## Order of operations

This change MUST archive after all consolidation changes have archived.
Specifically: `consolidate-parsing-specs`, `consolidate-tracing-specs`,
`consolidate-rules-specs`, `consolidate-cli-hooks`, and
`consolidate-trust-specs` (which doesn't include a rename of its own but
must finish settling first). `consolidate-facts-specs` already includes
its rename inline.

## Impact

- 5 capability directories renamed (`pattern-expressions`, `trace-system`,
  `human-evaluation-trace`, `rule-evaluation`, `claude-code-hook`).
- ~70 cross-references repointed across `openspec/specs/`,
  `.claude/rules/`, `CONTEXT.md`, `CLAUDE.md`, `README.md`.
- One requirement added to `spec-conventions`.
- No source-code, test, or runtime config changes.

## Compatibility

No requirement content changes. All renames preserve every `### Requirement:`
block byte-identical except for the spec's title line.
