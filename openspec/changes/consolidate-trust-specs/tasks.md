## 1. Rewrite `trust-command` Purpose

- [x] 1.1 Replace the existing `trust-command` Purpose with text covering
  the full CLI surface: review flow, listing approved/pending, interactive
  approval prompts, JSON output. Retain
  `Trust-relevant: yes — see trust-store, trust-hashing, trust-provenance,
  trust-gate.`

## 2. Rewrite `trust-advisory-boxes` Purpose

- [x] 2.1 Replace the existing `trust-advisory-boxes` Purpose with text
  covering both the in-trace advisory box (around loaded rules) AND the
  block-context output rendered when the trust gate blocks evaluation.
  Retain `Trust-relevant: yes` and cross-reference `trust-gate` and
  `trust-store`.

## 3. Move requirements verbatim

For each move below, copy the `### Requirement: NAME` block — body and all
`#### Scenario:` children — from the source spec into the target spec.
Preserve wording. Append in source order.

### 3a. From `trust-ui-listing` → `trust-command`

- [x] 3a.1 *Trust listing groups by file when all trusted*
- [x] 3a.2 *Trust listing shows detail for untrusted programs*
- [x] 3a.3 *Interactive approval for trust operations*
- [x] 3a.4 *Trust listing JSON includes metadata*

### 3b. From `interactive-trust-review` → `trust-command`

- [x] 3b.1 *Screen-cleared per-rule review flow*
- [x] 3b.2 *Trusted summary line always visible*
- [x] 3b.3 *Progress counter in HRule separator*
- [x] 3b.4 *Pretty-printed rule forms in review*
- [x] 3b.5 *Pretty-printed diff for changed rules*
- [x] 3b.6 *Direct entry to review from list_status*

### 3c. From `trust-block-context` → `trust-advisory-boxes`

- [x] 3c.1 *Eval TTY mode shows advisory box instead of blocking*
- [x] 3c.2 *Hook block response includes source files*

## 4. Update cross-references

- [x] 4.1 `grep -rln 'trust-ui-listing\|interactive-trust-review\|trust-block-context' openspec/specs/`
  — update each hit to point to `trust-command` or `trust-advisory-boxes`
  as appropriate.
- [x] 4.2 Same grep over `.claude/rules/`, `CONTEXT.md`, `CLAUDE.md`,
  `README.md`.

## 5. Remove absorbed spec directories

- [x] 5.1 `rm -rf openspec/specs/trust-ui-listing/`
- [x] 5.2 `rm -rf openspec/specs/interactive-trust-review/`
- [x] 5.3 `rm -rf openspec/specs/trust-block-context/`

## 6. Verify

- [x] 6.1 Each absorbed requirement appears once and only once in the
  target spec.
- [x] 6.2 No requirement bodies were rewritten — diff each moved
  requirement against its pre-archive source verbatim.
- [x] 6.3 The pre-merge checklist in `.claude/rules/openspec-specs.md`
  passes for both `trust-command` and `trust-advisory-boxes` (canonical
  scaffold; vocabulary alignment; granularity threshold; no overlap).
- [x] 6.4 `openspec validate consolidate-trust-specs --strict` passes
  (if available).
