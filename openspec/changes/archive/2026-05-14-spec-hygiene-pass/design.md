## Context

Stable specs under `openspec/specs/` have drifted from `spec-conventions` over the lifetime of the project. The drift falls into two classes:

1. **Surface drift** — frontmatter / Purpose / scenario-text edits that lag the canonical vocabulary (retired `(effect …)` form, audience-prose markers superseded by frontmatter, occasional bucket misfile).
2. **Structural drift** — small specs that should have been folded into a parent at authoring time but stand alone (`per-rule-trust`, `trust-provenance`, `trust-advisory-boxes`, `migration-diff-display`, `rule-combination`), and pairs of specs covering the same surface (`dsl-form-list-syntax` + `parser-bindings`).

`.claude/rules/openspec-specs.md` directs that "existing violations: don't fix inline; open a hygiene change proposal citing `spec-conventions`." This is that proposal. The whole change is structural — no `### Requirement:` body semantics change.

The in-flight surface area is small: only `openspec/changes/archive/` exists alongside this change, so consolidation will not collide with other authors.

## Goals / Non-Goals

**Goals:**

- Bring every stable spec into compliance with `spec-conventions` (audience, bucket, vocabulary).
- Reduce spec count from 30 → 21 by merging specs that cover overlapping scope, so future navigation surfaces fewer redundant entries.
- Drive every move through `tasks.md` per `spec-conventions` §"Capability renames", so the change is reviewed as filesystem operations + cross-reference sweeps rather than thousands of lines of duplicated requirement bodies.
- Leave validator (`scripts/validate-spec-frontmatter.sh`) and pre-commit (`prek`) passing at every commit boundary.

**Non-Goals:**

- No `### Requirement:` body semantics change. If a merge surfaces a genuine content edit, that edit is expressed as a `MODIFIED Requirements` delta in a follow-up change, not bundled here.
- No code change. No migration. No trust-store change.
- No new buckets. The bucket set in `openspec/config.yaml` is unchanged.
- No rename of capabilities that aren't being merged (e.g. `parser-engine-invariants` stays as-is despite containing contributor vocabulary in its name — that's already allowed by `spec-conventions` §"Spec names use user vocabulary" exemption 2).

## Decisions

### Tasks-driven moves, not paired delta blocks

`spec-conventions` §"Capability renames are filesystem moves driven by tasks.md" mandates that capability renames be driven by `tasks.md` rather than paired `## ADDED Requirements` + `## REMOVED Requirements` blocks. We extend that interpretation to **merges** (rename + concat into a parent): they are filesystem moves of `### Requirement:` blocks from spec A into spec B, with the merged spec's Purpose section refreshed to cover the union.

**Alternative considered:** Author a `MODIFIED Requirements` delta for each merged-into spec listing every absorbed requirement. **Rejected:** duplicates thousands of lines of requirement-body text the verifier already checks byte-equality of, obscures the structural intent of the change, and contradicts the spirit of the rename rule.

### Audience: flip frontmatter for two, strip prose for one

Three specs declare `audience: user` but carry a "Contributor-only." Purpose marker or contributor vocabulary. Triage:

- **`trust-gate`** — Purpose centres on `trust_gate::evaluate` and gate-mode discriminators. Content is contributor-internal. **Flip frontmatter to `audience: contributor`; strip the Purpose marker.**
- **`traces`** — content references `TracingFold`, `EvalFold`, `Doc<Option<Ann>>`, `Predicate::Named`. Contributor-internal. **Flip frontmatter to `audience: contributor`** (no Purpose marker to strip).
- **`parser-bindings`** — content is genuinely the user-facing DSL surface: the `#var` sigil, `(parser ssh (style gnu) …)`, `(authorise #var)`, `(bound? #var)`. The "Contributor-only." Purpose prefix is a stray copy-paste from a sibling spec. **Frontmatter stays `audience: user`; strip the stray Purpose prefix.**

**Rationale:** the content drives audience, not the lagging metadata. For `trust-gate` and `traces`, the content is genuinely contributor (Rust-API signatures); for `parser-bindings`, the content is genuinely user (DSL forms a user writes).

**Alternative considered:** Rewrite scenarios into user vocabulary for `trust-gate` and `traces` and keep `audience: user`. **Rejected:** would erase the contributor-precision the specs exist to communicate (`Doc<Option<Ann>>` is the contract — phrasing it as "the trace renders" loses signal).

### Bucket relocation for `fact-predicates-in-args` and `traces`

`fact-predicates-in-args` declares `bucket: parsing` but its content is the internal `BoolExpr` AST. `traces` declares `bucket: tracing-and-output` but its content is the `TracingFold` / `EvalFold` contract. Both move to `bucket: contributor-internals`.

**Rationale:** `parsing` and `tracing-and-output` are user-facing buckets (per `CONTEXT.md` and `openspec/config.yaml` `context:`). A contributor-audience spec belongs in `contributor-internals` unless its content is genuinely about the user surface (e.g. `parser-engine-invariants` could arguably stay under `parsing` but is also fine where it is). The frontmatter validator (`scripts/validate-spec-frontmatter.sh`) already rejects `audience: user` + `bucket: contributor-internals`; it does not reject `audience: contributor` + `bucket: <user-bucket>`, but `spec-conventions` §"Each spec belongs to one documented bucket" reads naturally as "fit the content".

### `pretty-printing` stays a sibling of `fmt-command`, doesn't merge

`pretty-printing` (431 lines, indent-spec table + canonical layout rules) and `fmt-command` (147 lines, the CLI surface) cover related but separable concerns. Moving `pretty-printing` from `tracing-and-output` → `cli` aligns its bucket with `fmt-command`; merging would create a 580-line spec that mixes "what the canonical form is" with "how the CLI invokes it".

**Alternative considered:** Merge entirely into `fmt-command`. **Rejected:** the indent-spec table is referenced by the parser, the migration system, and the formatter; binding it tightly to the CLI surface obscures that.

### `spec-conventions` rule sharpened to cover merges

The meta-spec's "Capability renames are filesystem moves driven by tasks.md" requirement strictly covers 1:1 renames. This change relies on extending that interpretation to N:1 merges (folding one or more capabilities into a single survivor). Recent precedent (archived `2026-05-12-consolidate-testing-specs`) used paired `## ADDED Requirements` + `## REMOVED Requirements` blocks for merges, producing ~900 lines of duplicated requirement bodies — exactly what the renames rule was written to avoid.

We sharpen the rule: a `MODIFIED Requirements` delta on `spec-conventions` updates the existing requirement so its body and scenarios explicitly name merges (N:1 absorption) alongside renames (1:1 moves). The rationale stays the same: the bulk of a merge is structural, and the delta format duplicates content the verifier already checks for byte equality.

**Alternative considered:** Leave the rule unchanged and rely on a tasks.md note interpreting it. **Rejected:** silent extension of a written rule is the kind of thing the meta-spec exists to prevent; if merges work this way, the rule should say so.

## Risks / Trade-offs

- **Cross-reference rot** → ripgrep sweep in `tasks.md` covers `openspec/`, `.claude/rules/`, `CONTEXT.md`, `CLAUDE.md`, plus `src/` for any rustdoc references. Verification step greps for removed spec names returning zero matches.
- **Merged Purpose drift** → each merged-into Purpose is rewritten once and reviewed; risk is forgetting to absorb a cross-reference target the absorbed spec carried. Mitigation: each merge task lists the Purpose entries to copy.
- **Validator gap** → `validate-spec-frontmatter.sh` does not check audience-vs-content alignment (it can't). The audience flip relies on author review. Mitigation: commit history per merge so flips are isolated and reviewable.
- **Trust-bucket consolidation hides cross-references** → `trust-provenance`, `per-rule-trust`, `trust-advisory-boxes` are currently cross-referenced from other specs. Folded targets need anchor IDs or section headings stable enough that "see `trust-store` §Per-rule granularity" works. Mitigation: in the merged spec, give absorbed material a `### Requirement:` heading that names the original capability.
- **Reviewer cognitive load** → bundling 5 hygiene concerns and 5 merges in one change is large. Mitigation: tasks grouped per concern; each group is one logical commit.

## Migration Plan

Per-commit groups (each leaves the validator + cross-references green):

1. **Frontmatter / audience flips** (3 specs). Validator-only check.
2. **Bucket moves** (2 specs). Frontmatter edit + cross-reference grep.
3. **Retired `(effect …)` sweep** in scenarios across 9 specs. Mechanical fastmod.
4. **Trust merges** (3 absorbed → 4 survivors). Move requirements, refresh Purposes, ripgrep cross-refs.
5. **Rule-combination → rule-decisions**.
6. **dsl-form-list-syntax → parser-bindings**.
7. **Testing merges** (2 absorbed → 1 survivor).
8. **Migration merge** (1 absorbed → 1 survivor).
9. **Pretty-printing bucket move** to `cli`.
10. **Verification**: frontmatter validator passes; `rg -F` for removed spec names returns zero hits in `openspec/`, `.claude/`, root markdown.

Rollback: each group is a separate commit. Revert offending group; re-run validator.

## Open Questions

- **Q1**: Should `parser-engine-invariants` (currently `bucket: contributor-internals`, `audience: contributor`) absorb `wordpart-source-spans`? Both cover span invariants; the split is parser-AST vs engine-eval, but the boundary is thin. **Default: leave separate this change.** Out of scope here; possible follow-up.
- **Q2**: Should `code-quality` survive as a standalone spec, or fold into `testing-strategy`? Both are contributor / testing-strategy adjacent. **Default: leave separate.** Different concerns (production code lints vs test discipline).
