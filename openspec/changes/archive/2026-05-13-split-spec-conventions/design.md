## Context

`openspec/specs/spec-conventions/spec.md` was authored before `openspec/config.yaml` carried project context. Vocabulary, buckets, and "what counts as trust-relevant" lived inline in the spec's normative requirements because there was no other home. After commit `b8e7ffe` (Populate openspec/config.yaml context and per-artifact rules), the steering content lives in `config.yaml`; the spec retains its original full text, producing silent duplication.

The `openspec-customisation` skill (loaded via `.claude/rules/openspec-conventions.md`) codifies the rubric:

| Content kind | Authoritative home |
|---|---|
| AI-steering prose, vocabulary, criteria | `config.yaml:context` |
| Per-artifact authoring reminders | `config.yaml:rules.<artifactId>` |
| Normative requirements + checklists | `openspec/specs/<meta>/spec.md` + validator script |
| Machine-checkable invariants | validator (shell + `yq`, Rust, …) |

This change brings spec-conventions into compliance with the rubric.

## Goals / Non-Goals

**Goals:**

- Make `spec-conventions/spec.md` the single source of truth for *normative* spec rules.
- Make `openspec/config.yaml` the single source of truth for *steering* content (vocabulary, bucket list, criteria).
- Cross-reference each from the other so a reader of either can find the complement.
- Preserve every SHALL/MUST obligation byte-for-byte where the trim allows.

**Non-Goals:**

- Adding new requirements. This is a re-homing pass, not a behavioural change.
- Migrating any rule outside the spec into the validator. That happens incrementally per validator script (today: `validate-spec-frontmatter.sh`; future: `validate-spec-headings.sh`, etc.).
- Touching `CONTEXT.md`. Its vocabulary tables are the upstream source — `config.yaml` already references them.
- Editing `openspec/config.yaml`. Its content is already authoritative.

## Decisions

### Decision: Trim three requirements, not delete them

The three requirements that currently inline steering content (`bucket`, `audience`, `spec-names`) retain their normative SHALL clauses. Only the steering paragraphs / bullet lists are removed.

**Why**: the SHALL obligations are normative — a spec must fit a bucket, audiences must not mix, names must use user vocabulary. Those rules continue to apply and continue to be enforceable (eventually by validator scripts). Removing the requirements wholesale would erase the obligation; trimming preserves it.

**Alternative considered**: split each requirement into a stub (the SHALL) plus an example block (the steering content). Rejected — the example block has no enforcement story and would duplicate `config.yaml` content without adding value. The cross-reference is enough.

### Decision: Cross-reference `config.yaml` from the spec, not the reverse

The spec's Purpose section names `config.yaml` as the steering source. `config.yaml` is *not* edited to reference back.

**Why**: `config.yaml` is consumed by OpenSpec and injected into every artifact generation. Adding human-facing cross-references there bloats every prompt without adding value. The spec is the navigation entry point for humans; cross-references belong on its side.

### Decision: Update `.claude/rules/openspec-specs.md` in lock-step

Bullet (2) of the rule currently inlines the bucket list. Bullet (3) inlines vocabulary. Both are duplicates of `config.yaml`. They become cross-references in this change.

**Why**: the rule fires when an agent touches `openspec/specs/**` or `openspec/changes/**`. The agent already has `config.yaml:context` injected via OpenSpec instructions; re-injecting via the rule is duplicate prompt material. Cross-references keep the rule terse and avoid drift.

**Alternative considered**: leave the rule alone, trim only the spec. Rejected — same drift problem at one removal, and rules fire on every spec touch, so the inflation cost is high.

### Decision: Wait for `add-spec-frontmatter` to land

This change cross-references the frontmatter validator. If `add-spec-frontmatter` slips, the cross-reference becomes a forward reference (acceptable but less crisp).

**Why**: the validator exists to enforce the audience invariant the trimmed `audience` requirement still mandates. Pointing at a real script is stronger than pointing at a planned one.

**Sequencing**: `add-spec-frontmatter` lands → backfill stable specs with frontmatter → land this change. If `add-spec-frontmatter` is abandoned, this change adjusts its forward references and lands anyway.

## Risks / Trade-offs

- **Spec readers lose the convenience of inline bucket / vocabulary lists.** → The cross-reference points one click away; agents always have the lists via prompt injection.
- **`config.yaml` becomes load-bearing.** → It already is, since commit `b8e7ffe`. This change formalises the existing reality.
- **Drift between `config.yaml` and `CONTEXT.md` vocabulary tables.** → Pre-existing concern; out of scope here. Worth a future change that scripts a check: `config.yaml:context` substring-matches `CONTEXT.md` vocabulary headings.
- **A bucket-list edit now requires editing `config.yaml` only.** → That is the goal. The validator (added by `add-spec-frontmatter`) hard-codes the enum, so the bucket list also lives in the validator script. Both update together when a bucket is added — out of scope to merge those today.

## Migration Plan

Single change, no migration state:

1. Land `add-spec-frontmatter` first (separate change).
2. Apply MODIFIED requirements to `spec-conventions/spec.md`. Verify SHALL clauses survive byte-identical.
3. Update `.claude/rules/openspec-specs.md` to cross-reference `config.yaml`.
4. Run `openspec validate --all --strict`. Confirm the spec still parses; confirm cross-references resolve to real paths.

Rollback: revert the change. `config.yaml` remains populated; the spec regains the duplicated content. No data state to worry about.

## Open Questions

- Should `Requirement: Trust-relevance is declared in frontmatter` (introduced by `add-spec-frontmatter`) also be trimmed in this change to drop its inline "what counts as trust-relevant" criteria? Lean: yes, fold into this change. Confirm during apply once the frontmatter change lands and the requirement's final text is visible.
- Should we document a fourth tier — "machine-checkable invariants enforced by validators" — in the spec's Purpose? Currently the spec says "normative rules"; a sentence calling out which rules have a validator script would help readers find the enforcement entry point. Lean: yes, add a short list with cross-references to validator script paths.
