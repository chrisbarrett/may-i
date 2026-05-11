## Why

The Testing bucket holds 5 specs: `testing-strategy`, `test-infrastructure`,
`integration-test-coverage`, `oracle-trace-testing`, `migration-testing`.
Two of those are sub-spec stubs that read more clearly inside their
natural parent: `integration-test-coverage` (1 req) restates a
top-level testing-strategy invariant, and `migration-testing` (55 lines,
6 reqs about migration property tests) is *about migrations*, not about
the testing approach in general — it belongs with the rest of the
migration documentation.

This change folds the two stubs and leaves the three sized specs
(`testing-strategy`, `test-infrastructure`, `oracle-trace-testing`)
standalone. Net 5 → 3 testing specs.

## What Changes

- **Fold `integration-test-coverage` → `testing-strategy`**: 1
  requirement (*All CLI subcommands have integration tests*) is a
  testing-strategy invariant.
- **Fold `migration-testing` → `migration-system`**: 6 requirements
  about migration property tests, generators, and real-world wrapper
  patterns belong inside the migration documentation alongside the
  classification and rewrite rules they test.
- **Keep standalone**: `testing-strategy`, `test-infrastructure`,
  `oracle-trace-testing`. Each is a sized contributor-only spec covering
  a distinct aspect (strategy/policy, harness mechanics, oracle pattern).

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `testing-strategy` — ABSORBS `integration-test-coverage` (1
  requirement).
- `migration-system` — ABSORBS `migration-testing` (6 requirements).
  Purpose may need a brief addition noting that migration test policy
  lives here rather than in the testing bucket.

### Removed Capabilities

- `integration-test-coverage` — folded into `testing-strategy`.
  Directory removed.
- `migration-testing` — folded into `migration-system`. Directory
  removed.

## Spec-delta convention

Same as the other consolidation changes. Source-spec deltas list
`## REMOVED Requirements` as bullets; target-spec deltas list `## ADDED
Requirements` by name; the apply step copies bodies verbatim.

## Impact

- `openspec/specs/testing-strategy/spec.md` — receives 1 requirement.
- `openspec/specs/migration-system/spec.md` — receives 6 requirements.
- 2 source spec directories removed at archive.
- No source-code, test, or runtime config changes.

## Compatibility

No requirement content changes. Cross-references updated in `tasks.md`.
