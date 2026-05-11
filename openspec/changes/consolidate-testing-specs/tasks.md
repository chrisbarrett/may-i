## 1. Fold `integration-test-coverage` into `testing-strategy`

- [ ] 1.1 Copy *All CLI subcommands have integration tests* — body and
  `#### Scenario:` children — verbatim from
  `integration-test-coverage/spec.md` into `testing-strategy/spec.md`.
- [ ] 1.2 `rm -rf openspec/specs/integration-test-coverage/`.

## 2. Fold `migration-testing` into `migration-system`

- [ ] 2.1 Append a brief sentence to the `migration-system` Purpose
  noting that migration test policy (property generators, real-world
  wrapper patterns, mixed-config migration) is documented here.
- [ ] 2.2 Copy each of the 6 requirements verbatim from
  `migration-testing/spec.md` into `migration-system/spec.md`:
  - *Property test generators for compound v1 forms*
  - *Compound v1 forms preserve evaluation semantics*
  - *Real-world wrapper patterns migrate correctly*
  - *has with complex value patterns migrates correctly*
  - *Mixed v1/v2 configs migrate correctly*
  - *Proptest generators cover compound v1 forms*
- [ ] 2.3 `rm -rf openspec/specs/migration-testing/`.

## 3. Update cross-references

- [ ] 3.1 `grep -rln 'integration-test-coverage\|migration-testing' openspec/specs/ .claude/ CONTEXT.md CLAUDE.md README.md`
  — repoint each hit.

## 4. Verify

- [ ] 4.1 Each absorbed requirement appears once and only once in its
  new home.
- [ ] 4.2 `testing-strategy` retains its `Contributor-only.` Purpose
  declaration; `migration-system` Purpose still reads as user-facing
  (the absorbed requirements are about migration *behaviour*, not
  internal test mechanics — though some scenarios naturally describe
  test setup).
- [ ] 4.3 `openspec validate consolidate-testing-specs --strict` passes.
