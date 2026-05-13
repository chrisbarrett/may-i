## 1. Pre-conditions

- [ ] 1.1 Confirm `add-spec-frontmatter` has landed (its commit is on `main`, `scripts/validate-spec-frontmatter.sh` exists, every spec under `openspec/specs/` carries YAML frontmatter). If not, pause this change.
- [ ] 1.2 Re-read `openspec/config.yaml`. Confirm `context:` covers the bucket list, the user/contributor vocabulary registers, and the trust-relevance criteria. Confirm `rules.specs:` covers delta-authoring reminders. If any steering content the trimmed requirements reference is missing from `config.yaml`, add it in this change before trimming the spec.

## 2. Apply spec deltas

- [ ] 2.1 Apply the MODIFIED requirement `Each spec belongs to one documented bucket` to `openspec/specs/spec-conventions/spec.md`. Replace the existing block byte-for-byte with the version under `openspec/changes/split-spec-conventions/specs/spec-conventions/spec.md`. Confirm the inline bullet list of buckets is removed and replaced with the `openspec/config.yaml` cross-reference.
- [ ] 2.2 Apply the MODIFIED requirement `User-facing and contributor-facing specs do not mix audiences`. Confirm the inline vocabulary recitation is removed and replaced with cross-references to `CONTEXT.md` and `openspec/config.yaml`.
- [ ] 2.3 Apply the MODIFIED requirement `Spec names use user vocabulary`. Confirm the inline vocabulary list is removed and replaced with cross-references; confirm the exemption language uses `audience: contributor` (the frontmatter field) rather than the legacy prose form.
- [ ] 2.4 Update the spec's `## Purpose` section to acknowledge the steering/normative split. Write 2–3 sentences naming `openspec/config.yaml` as the steering source and naming the validator scripts under `scripts/` as the enforcement entry point for invariants that are machine-checkable. Keep the `Contributor-only.` declaration prose (it aids human readers) alongside the frontmatter `audience: contributor` field.

## 3. Rule alignment

- [ ] 3.1 Update `.claude/rules/openspec-specs.md`:
  - Replace the inline bucket list in bullet (2) with a cross-reference: `Spec fits one bucket — list lives in openspec/config.yaml:context`.
  - Replace the inline vocabulary recitation in bullet (3) with a cross-reference: `User-facing specs use CONTEXT.md / config.yaml user vocabulary (including in the spec's directory name)`.
  - Keep the authority pointer to `openspec/specs/spec-conventions/spec.md` and the existing other bullets unchanged.
  - Trim the rule body to remove duplication only — do not change any normative obligation.

## 4. Trust-relevance requirement audit

- [ ] 4.1 Read `openspec/specs/spec-conventions/spec.md` after sections 2 and 3 land. Locate `Requirement: Trust-relevance is declared in frontmatter` (introduced by `add-spec-frontmatter`). Inspect for inline "what counts as trust-relevant" criteria that duplicate `config.yaml:context`.
- [ ] 4.2 If duplication is present: extend this change's delta to MODIFY the trust-relevance requirement, trimming the inline criteria and cross-referencing `config.yaml`. Re-run `openspec validate --all --strict` afterwards.
- [ ] 4.3 If no duplication is present (criteria already terse): leave the requirement unchanged. Note the decision in this change's commit message.

## 5. Verification

- [ ] 5.1 Run `openspec validate --all --strict --no-interactive`. Expect 0 violations.
- [ ] 5.2 Run `scripts/validate-spec-frontmatter.sh` (introduced by `add-spec-frontmatter`). Expect 0 violations — this change does not touch frontmatter.
- [ ] 5.3 Diff `openspec/specs/spec-conventions/spec.md` against `main`. Confirm every removed sentence is steering content (vocabulary recitation, bullet lists, criteria) and every retained sentence is a SHALL/MUST clause or a scenario. Spot-check by grepping for `SHALL` and `MUST` — counts should not decrease.
- [ ] 5.4 Sanity-check the rule edit: in a fresh shell, `cat .claude/rules/openspec-specs.md` and confirm the bullet count and authority pointer match the pre-change rule (only inline content swapped for cross-references).
- [ ] 5.5 Open `openspec/config.yaml` and the trimmed `spec-conventions/spec.md` side-by-side. Confirm cross-references resolve: every "see `openspec/config.yaml:context`" in the spec corresponds to material actually present in the config.
