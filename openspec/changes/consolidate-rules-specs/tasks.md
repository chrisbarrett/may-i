## 1. Fold absorbed specs into `rule-evaluation`

For each move, copy the `### Requirement: NAME` block — body and
`#### Scenario:` children — verbatim from the source file. Append after
the existing 6 requirements in source-spec order.

### 1a. From `evaluator-error-handling` → `rule-evaluation`

- [ ] 1a.1 *Check evaluation propagates errors* — copy verbatim. The
  requirement's audience is contributor; reviewers may choose to mark it
  as a *Contributor-detail* sub-section in the parent spec.

### 1b. From `eval-segment-decisions` → `rule-evaluation`

- [ ] 1b.1 *EvalResult exposes per-segment decisions* — copy verbatim.
- [ ] 1b.2 *Segment decisions describe non-overlapping byte ranges* —
  copy verbatim.
- [ ] 1b.3 *Display does not re-evaluate to colourise* — copy verbatim.
- [ ] 1b.4 *Aggregate decision unchanged* — copy verbatim.

## 2. Update `rule-evaluation` Purpose

- [ ] 2.1 Append a sentence to the existing Purpose noting that
  per-segment decisions and check-evaluation error propagation are now
  documented here. Retain `Trust-relevant: no.`

## 3. Remove absorbed spec directories

- [ ] 3.1 `rm -rf openspec/specs/evaluator-error-handling/`
- [ ] 3.2 `rm -rf openspec/specs/eval-segment-decisions/`

## 4. Update cross-references

- [ ] 4.1 `grep -rln 'evaluator-error-handling\|eval-segment-decisions' openspec/specs/ .claude/ CONTEXT.md CLAUDE.md README.md`
  — repoint each hit to `rule-evaluation`.

## 5. Verify

- [ ] 5.1 Each absorbed requirement appears once and only once in
  `rule-evaluation`.
- [ ] 5.2 `openspec validate consolidate-rules-specs --strict` passes.

## 6. Note: rename deferred

- [ ] 6.1 The rename `rule-evaluation` → `rule-decisions` (vocab
  alignment per `spec-conventions`) is deferred to the
  `rename-specs-to-vocab` change.
