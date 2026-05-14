## Why

The stable spec set has drifted from `spec-conventions`: three specs contradict their declared audience, two are filed under the wrong bucket, fourteen still cite retired `(effect :…)` syntax in scenarios, and several buckets carry overlapping specs that should be consolidated (the `trust` bucket alone holds 7 specs with redundant scope). Fixing inline as specs are touched is explicitly disallowed by the openspec rule (`existing violations: open a hygiene change proposal`); this is that proposal.

## What Changes

Five hygiene concerns, all surface / structural — no requirement semantics change.

1. **Audience contradictions resolved.**
   - `trust-gate` and `traces` use contributor vocabulary (`trust_gate::evaluate`, `TracingFold`, `EvalFold`, `Doc<Ann>`) but declare `audience: user`. Flip frontmatter to `audience: contributor` and strip the Purpose-prose audience marker per `spec-conventions` §"Trust-relevance is declared in frontmatter".
   - `parser-bindings` is genuinely user-facing surface (`#var` sigil, `(parser ssh …)` DSL) but its Purpose carries a stray "Contributor-only." prefix. Strip the prefix; frontmatter stays `audience: user`.

2. **Bucket corrections.** `fact-predicates-in-args` (BoolExpr internals) moves from `parsing` → `contributor-internals`. `traces` moves from `tracing-and-output` → `contributor-internals` (after audience flip).

3. **Retired-vocabulary sweep.** Scenarios in `rule-combination`, `rule-decisions`, `per-rule-trust`, `repo-local-config`, `trust-command`, `harness-integration`, `decision-trace`, `fmt-command`, `patterns` still use `(effect :allow)` etc. Replace with current `(allow)` / `(ask)` / `(deny)` surface verbs per CONTEXT.md. Migration-system v1 references stay (they legitimately quote v1).

4. **Consolidations.** Filesystem merges driven by `tasks.md` per the sharpened `spec-conventions` rule:
   - `trust`: fold `per-rule-trust` and `trust-provenance` into `trust-store`. (7 → 5) `trust-advisory-boxes` stays separate — it is user-facing trace output, distinct from the contributor-internal `trust-gate`.
   - `rules-and-evaluation`: fold `rule-combination` into `rule-decisions`. (2 → 1)
   - `parsing`: fold `dsl-form-list-syntax` into `parser-bindings`. Both cover the `(parser …)` body surface; `parser-bindings` is the larger and more general spec.
   - `testing`: fold `oracle-trace-testing` and `test-infrastructure` into `testing-strategy`. (3 → 1)
   - `migration`: fold `migration-diff-display` into `migration-system`. (2 → 1)

5. **Pretty-printing relocation.** `pretty-printing` moves from `tracing-and-output` → `cli` (it governs `may-i fmt`'s output, not eval traces). Considered a merge into `fmt-command` but kept separate: the indent-spec table is substantial enough to justify a sibling.

**Net result**: 31 specs → 24 specs (7 absorbed). No `### Requirement:` body semantics change; this is structural cleanup only.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

All edits are filesystem moves and prose / frontmatter touch-ups per `spec-conventions` §"Capability renames are filesystem moves driven by tasks.md" — driven by `tasks.md`, not paired `ADDED`/`REMOVED` deltas. The only spec whose `### Requirement:` body content needs review is the meta-spec:

- `spec-conventions`: confirm the existing "Capability renames" requirement covers spec-into-spec merges (not just 1:1 renames). If the body needs sharpening, a `MODIFIED Requirements` delta is added; otherwise the change is pure tasks.

Affected buckets: `trust`, `rules-and-evaluation`, `parsing`, `testing`, `migration`, `tracing-and-output`, `cli`, `contributor-internals`.

## Impact

- `openspec/specs/`: 7 directories removed (`per-rule-trust`, `trust-provenance`, `rule-combination`, `dsl-form-list-syntax`, `oracle-trace-testing`, `test-infrastructure`, `migration-diff-display`), content folded into 6 surviving siblings; 3 directories change bucket via frontmatter (`fact-predicates-in-args`, `traces`, `pretty-printing`).
- `openspec/changes/`: in-flight changes — none (only `archive` exists).
- Cross-references: ripgrep for old spec names (`per-rule-trust`, `trust-provenance`, `rule-combination`, `dsl-form-list-syntax`, `oracle-trace-testing`, `test-infrastructure`, `migration-diff-display`) across `openspec/`, `.claude/rules/`, `CONTEXT.md`, `CLAUDE.md` and rewrite to merged-spec target.
- Validator: `scripts/validate-spec-frontmatter.sh` must continue to pass after frontmatter edits.
- No code, no migration, no trust-store change.
