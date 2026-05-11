## 1. Create `facts` (renamed from `fact-system`)

- [x] 1.1 `mkdir openspec/specs/facts/`.
- [x] 1.2 Move all 4 existing requirements from `fact-system/spec.md`
  into the new `facts/spec.md`. Preserve order, bodies, scenarios.
- [x] 1.3 Write a Purpose using user vocabulary: facts as keyed runtime
  context, set-valued storage, the `--fact` CLI surface, automatic facts
  including `:via`.
- [x] 1.4 `rm -rf openspec/specs/fact-system/`.

## 2. Fold `via-fact-builtin` into `facts`

- [x] 2.1 Copy *`(authorise …)` pushes wrapper command name onto :via set*
  — body and `#### Scenario:` children — verbatim into `facts/spec.md`.
- [x] 2.2 Copy *:via is the only automatically pushed fact* — body and
  `#### Scenario:` children — verbatim into `facts/spec.md`.
- [x] 2.3 `rm -rf openspec/specs/via-fact-builtin/`.

## 3. Update cross-references

- [x] 3.1 `grep -rln 'fact-system\|via-fact-builtin' openspec/specs/ .claude/ CONTEXT.md CLAUDE.md README.md`
  — repoint each hit to `facts`.

## 4. Verify

- [x] 4.1 Each absorbed requirement appears once and only once in
  `facts`.
- [x] 4.2 `facts` Purpose passes the vocabulary check.
- [x] 4.3 `openspec validate consolidate-facts-specs --strict` passes.
