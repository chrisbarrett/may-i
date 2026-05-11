## 1. Fold absorbed render specs into `trace-system`

### 1a. From `unified-renderer` → `trace-system`

- [ ] 1a.1 *Heading and label widths use visible character width* — copy
  verbatim.

### 1b. From `var-trace-breakout` → `trace-system`

- [ ] 1b.1 *Trace shows define name at point of use* — copy verbatim.
- [ ] 1b.2 *Trace includes a breakout section for the define body* —
  copy verbatim.
- [ ] 1b.3 *Unmatched var breakout is still shown* — copy verbatim.

## 2. Update `trace-system` Purpose

- [ ] 2.1 Append a sentence noting that the spec now also covers visible
  character-width arithmetic for headings/labels and the var-breakout
  section for `Predicate::Named` references.

## 3. Remove absorbed spec directories

- [ ] 3.1 `rm -rf openspec/specs/unified-renderer/`
- [ ] 3.2 `rm -rf openspec/specs/var-trace-breakout/`

## 4. Update cross-references

- [ ] 4.1 `grep -rln 'unified-renderer\|var-trace-breakout' openspec/specs/ .claude/ CONTEXT.md CLAUDE.md README.md`
  — repoint each hit to `trace-system`.

## 5. Verify

- [ ] 5.1 Each absorbed requirement appears once and only once in
  `trace-system`.
- [ ] 5.2 `openspec validate consolidate-tracing-specs --strict` passes.

## 6. Note: renames deferred

- [ ] 6.1 The renames `trace-system` → `traces` and
  `human-evaluation-trace` → `decision-trace` (vocab alignment per
  `spec-conventions`) are deferred to `rename-specs-to-vocab`.
