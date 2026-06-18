---
audience: contributor
bucket: contributor-internals
---
# spec-conventions Specification

## Purpose

Contributor-only. Carries the normative rules for specs under `openspec/specs/`: heading structure, bucket assignment, audience separation, frontmatter metadata, trust-relevance declaration, granularity threshold, the TBD ban, capability renames, and the pre-merge checklist every spec-touching change applies.

AI-steering content — the vocabulary registers, the bucket bullet list, the criteria for "what counts as trust-relevant", and the per-artifact authoring reminders — lives in `openspec/config.yaml` under `context:` and `rules.<artifactId>:`. The two artifacts are complements: this spec is what reviewers and validator scripts (`scripts/validate-spec-frontmatter.sh` and future siblings) enforce; `config.yaml` is what OpenSpec injects into agent prompts when artifacts are generated. The placement rubric (steering vs normative) is documented in the `openspec-customisation` skill.

## Requirements

### Requirement: Stable specs use the canonical heading structure

A file under `openspec/specs/<capability>/spec.md` SHALL begin with a level-one heading of the form `# <Capability> Specification`, followed by a `## Purpose` section containing one or two sentences naming what the capability covers, followed by a `## Requirements` section containing one or more `### Requirement: …` blocks. Each `### Requirement: …` block SHALL state its rules using `SHALL` or `MUST` and SHALL be followed by one or more `#### Scenario: …` blocks giving GIVEN/WHEN/THEN bullets.

Delta-style headings — `## ADDED Requirements`, `## MODIFIED Requirements`, `## REMOVED Requirements` — SHALL appear only in `openspec/changes/<change>/specs/<capability>/spec.md` files. They describe the delta a change applies and have no meaning in stable specs.

#### Scenario: Stable spec uses canonical headings

- **GIVEN** a file `openspec/specs/foo/spec.md`
- **WHEN** the file is opened
- **THEN** it begins with `# Foo Specification`
- **AND** the next heading is `## Purpose` with prose, not "TBD"
- **AND** the next heading is `## Requirements`

#### Scenario: Delta headings flagged in stable specs

- **GIVEN** a stable spec under `openspec/specs/` that contains `## ADDED Requirements` or `## MODIFIED Requirements` at top level
- **WHEN** the spec is reviewed against this requirement
- **THEN** the review SHALL flag the headings as non-conforming and require they be replaced with the canonical structure before any further edit lands

### Requirement: Each spec belongs to one documented bucket

Every spec under `openspec/specs/` SHALL fit into exactly one bucket. The set of buckets is documented in `openspec/config.yaml` under `context:` (kebab-case identifiers). The first four buckets correspond to the four-layer model documented in `CONTEXT.md` (Rules, Facts, Parsing, Trust) and are treated as the spine of the spec set; the remaining buckets cover cross-cutting and contributor-only concerns.

A spec that does not fit any documented bucket SHALL justify a new bucket in its proposing change's `design.md` and amend `openspec/config.yaml` in the same change.

The bucket value SHALL be declared via the `bucket:` field in the spec's YAML frontmatter (see "Stable specs declare metadata in YAML frontmatter") and SHALL be checked by the frontmatter validator (`scripts/validate-spec-frontmatter.sh`).

#### Scenario: New spec fits an existing bucket

- **GIVEN** a proposal adding a spec named `carrier-rest-recursion`
- **WHEN** the bucket assignment is reviewed
- **THEN** the spec SHALL be filed under `parsing` with no new bucket required
- **AND** its frontmatter `bucket: parsing` SHALL pass the validator

#### Scenario: New spec proposes a new bucket

- **GIVEN** a proposal adding a spec for behaviour that does not fit any documented bucket
- **WHEN** the change is opened
- **THEN** the spec's proposing change SHALL amend `openspec/config.yaml` to add the new bucket value
- **AND** the spec's `design.md` SHALL include a "Decision: new bucket X" entry explaining why an existing bucket is wrong

### Requirement: User-facing and contributor-facing specs do not mix audiences

A spec SHALL be either *user-facing* (covering observable behaviour: the DSL surface, decisions, traces, CLI output, configuration semantics) or *contributor-facing* (covering internals: type-level invariants, code quality, parser/engine span contracts, testing strategy, these conventions). The two vocabulary registers — user vocabulary and contributor vocabulary — are documented in `CONTEXT.md` and summarised in `openspec/config.yaml` under `context:`.

User-facing specs SHALL use only user vocabulary in their requirements and scenarios. Contributor-facing specs MAY use contributor vocabulary. A user-facing spec SHALL NOT introduce contributor vocabulary into requirements or scenarios.

Every spec SHALL declare its audience via the `audience:` field in its YAML frontmatter (see "Stable specs declare metadata in YAML frontmatter"); the legacy convention of declaring audience in prose ("contributor-only" / "internal") is no longer the source of truth and SHOULD be removed when a spec is touched. The frontmatter validator (`scripts/validate-spec-frontmatter.sh`) enforces the `audience:` value and rejects the contradictory `audience: user` + `bucket: contributor-internals` combination.

#### Scenario: User-facing spec uses user vocabulary

- **GIVEN** a spec named `rule-decisions` documenting how decisions combine
- **WHEN** the spec is reviewed
- **THEN** requirements refer to user-vocabulary terms (Decision, Rule), not contributor-vocabulary internals (`Effect::Terminal`, `Decision::Ask`)
- **AND** the spec's frontmatter contains `audience: user`

#### Scenario: Contributor spec declares its audience in frontmatter

- **GIVEN** a contributor-only spec (`code-quality`, `parser-engine-invariants`, `spec-conventions`)
- **WHEN** the spec is opened
- **THEN** the frontmatter contains `audience: contributor`
- **AND** the spec MAY use contributor vocabulary in requirements and scenarios

### Requirement: Spec names use user vocabulary

A stable spec under `openspec/specs/<capability>/spec.md` SHALL choose its capability identifier (the directory name) from the user vocabulary documented in `CONTEXT.md` and summarised in `openspec/config.yaml` under `context:`, or from neutral domain words that do not collide with the contributor vocabulary table. A spec name SHALL NOT include any term from the contributor vocabulary unless one of the exemptions below applies.

Two exemptions:

1. **The meta-spec `spec-conventions` itself** is exempt — it documents conventions and is named after that purpose.
2. **Contributor-only specs** (those declaring `audience: contributor` in their frontmatter, per the audience requirement above) are exempt: their name MAY use contributor vocabulary, because the audience declaration warns the reader.

This requirement applies to stable specs only. Change deltas under `openspec/changes/<change>/specs/<capability>/spec.md` follow the name of their target spec; renaming happens through proposals that move requirements between specs (see "Capability renames are filesystem moves driven by tasks.md").

#### Scenario: User-facing spec named with contributor vocabulary fails review

- **GIVEN** a proposal that adds a stable spec `expr-combinator-matching` whose audience is users
- **WHEN** the pre-merge checklist runs
- **THEN** the spec name SHALL be flagged: `Expr` is contributor vocabulary
- **AND** the proposal SHALL rename the spec to use user vocabulary (e.g. `patterns`) before merge

#### Scenario: Contributor spec named with contributor vocabulary passes

- **GIVEN** a stable spec `parser-engine-invariants` whose frontmatter declares `audience: contributor`
- **WHEN** the pre-merge checklist runs
- **THEN** the contributor-vocabulary terms in the name (`engine`, `invariants`) SHALL NOT be flagged
- **AND** the spec MAY retain its name

#### Scenario: Meta-spec name passes by exemption

- **GIVEN** the meta-spec `spec-conventions`
- **WHEN** the pre-merge checklist runs
- **THEN** its name SHALL NOT be flagged even though `spec` is not in the user vocabulary table
- **AND** no further justification is required

### Requirement: Trust-relevance is declared in frontmatter

A spec whose requirements meet the trust-relevance criteria (documented in `openspec/config.yaml` under `context:`) SHALL set `trust-relevant: true` in its YAML frontmatter (see "Stable specs declare metadata in YAML frontmatter"). The Purpose section SHALL additionally cross-reference the relevant trust-model spec(s) in prose so a human reader can navigate to them.

A spec that does not affect trust state SHOULD omit the `trust-relevant` field (or set it to `false`). The legacy `Trust-relevant: yes` line in the Purpose section is no longer the source of truth and SHALL be removed when a spec is touched; the frontmatter field replaces it. Authors uncertain whether their spec is trust-relevant SHOULD set `trust-relevant: true` and let review confirm.

#### Scenario: Trust-relevant spec declares it in frontmatter

- **GIVEN** a spec that changes how rules are aggregated for hashing
- **WHEN** the spec is opened
- **THEN** the frontmatter contains `trust-relevant: true`
- **AND** the Purpose section cross-references the relevant trust-model spec(s) in prose

#### Scenario: Non-trust spec omits the field

- **GIVEN** a spec for human-readable trace layout
- **WHEN** the spec is opened
- **THEN** the frontmatter omits `trust-relevant` or sets it to `false`
- **AND** the Purpose section does not contain a `Trust-relevant: yes` line

#### Scenario: Legacy Purpose-line form flagged on touch

- **GIVEN** an existing spec that still carries a `Trust-relevant: yes` line in its Purpose alongside a `trust-relevant: true` frontmatter field
- **WHEN** any change touches that spec
- **THEN** the change SHALL remove the Purpose-line form, retaining only the frontmatter field and the prose cross-reference

### Requirement: Specs meet a granularity threshold or fold into a parent

A spec under `openspec/specs/` SHOULD contain at least two requirements OR span at least ~40 lines of substantive content (excluding heading and Purpose). Specs below this threshold SHALL either fold into a parent spec or document in their Purpose why standalone status is justified (typically: a small invariant that other specs depend on by reference).

A new spec MUST cross-reference any existing spec covering related behaviour rather than restating overlapping requirements. Silent overlap is a defect; explicit cross-reference is correct.

#### Scenario: Thin spec folds into parent

- **GIVEN** a proposal adding a single-requirement spec for `--` flag-stop behaviour
- **WHEN** the review applies this requirement
- **THEN** the requirement SHALL be folded into the existing `patterns` spec
- **AND** no new top-level spec SHALL be created

#### Scenario: Justified thin spec stands alone

- **GIVEN** a proposal adding a 15-line spec stating a single load-time invariant on which migration, evaluation, and trust hashing all depend
- **WHEN** the review applies this requirement
- **THEN** the spec MAY stand alone provided its Purpose explains why and lists the dependent specs

### Requirement: TBD is forbidden in the Purpose section

A spec's `## Purpose` section SHALL NOT contain the literal text "TBD" or the phrase "Update Purpose after archive". Auto-archive of a change proposal SHALL NOT create a stable spec with a TBD purpose; the author SHALL write a proper Purpose as part of the change before archiving.

If a Purpose cannot be written, the spec is not ready to merge.

#### Scenario: Archive blocked on TBD

- **GIVEN** a change whose stable-spec output would have `Purpose: TBD - created by archiving change …`
- **WHEN** archive is attempted
- **THEN** the archive SHALL be rejected until the Purpose is written by the author

#### Scenario: Existing TBD purposes flagged

- **GIVEN** a stable spec already in tree with `TBD` in its Purpose
- **WHEN** any change touches that spec
- **THEN** the change SHALL replace the TBD with a written Purpose before landing

### Requirement: Pre-merge checklist applies to every spec-touching change

A change proposal under `openspec/changes/` that creates or modifies a file under `specs/` SHALL pass the following checklist before merge. The checklist may be applied by a human reviewer or by an agent that has loaded `.claude/rules/openspec-specs.md`.

1. Each new or modified stable spec uses canonical headings; no delta-style headings appear under `openspec/specs/`.
2. Each new spec is filed under one documented bucket, or justifies a new bucket in design.md.
3. Each spec is either user-facing or contributor-facing; audience is consistent across requirements and scenarios; the audience is declared via the `audience` field in frontmatter.
4. Trust-relevant specs declare `trust-relevant: true` in frontmatter and cross-reference the trust-model spec(s) in their Purpose section.
5. New specs meet the granularity threshold or justify standalone status.
6. No Purpose section contains `TBD`.
7. Cross-references to overlapping specs are explicit; silent restatement is removed.
8. YAML frontmatter is present and passes the frontmatter validator: `audience` and `bucket` set to valid enum values; `trust-relevant` boolean when present; `audience: user` not paired with `bucket: contributor-internals`.

#### Scenario: Checklist surfaces in the rule

- **WHEN** an agent reads or edits a file under `openspec/specs/**` or `openspec/changes/**`
- **THEN** the agent has loaded `.claude/rules/openspec-specs.md`
- **AND** the rule directs the agent to this spec
- **AND** the agent applies the eight-point checklist before completing the edit

#### Scenario: Checklist failure blocks merge

- **GIVEN** a change proposal that adds a stable spec with `## ADDED Requirements` at top level
- **WHEN** the pre-merge checklist runs
- **THEN** item (1) flags the spec
- **AND** the change SHALL NOT merge until the headings are rewritten

#### Scenario: Frontmatter check blocks merge

- **GIVEN** a change proposal that adds a stable spec without YAML frontmatter
- **WHEN** the pre-merge checklist runs
- **THEN** item (8) flags the spec
- **AND** the change SHALL NOT merge until frontmatter is added and validated

### Requirement: Capability renames are filesystem moves driven by tasks.md

A capability rename or merge SHALL be applied as a filesystem move (1:1) or set of moves (N:1 absorption) plus a cross-reference sweep, driven by the change's `tasks.md`, rather than as paired `## ADDED Requirements` and `## REMOVED Requirements` blocks for every moved requirement. The move SHALL preserve every `### Requirement:` body, every `#### Scenario:` child, and any frontmatter field byte-identical except for the surviving spec's top-level title heading and Purpose section (which is refreshed to cover the union when absorbing).

A **rename** is a 1:1 capability move: `openspec/specs/A/` → `openspec/specs/B/`, no other capability involved.

A **merge** is an N:1 absorption: requirements from one or more source capabilities are appended into a single surviving capability, and the source directories are removed. The surviving Purpose is rewritten once to cover the union; absorbed requirement bodies are byte-identical except for surrounding heading order.

The spec-delta artefacts under `openspec/changes/<change>/specs/` for a rename or merge change SHOULD be limited to changes that genuinely modify spec content (e.g. a one-requirement edit that justifies the rename, a refreshed Purpose section in the surviving spec, or — as in this change itself — a meta-rule about how such moves are applied). The bulk of the rename or merge work is enumerated as filesystem operations and cross-reference sweeps in `tasks.md`, not as duplicated requirement bodies.

This rule exists because OpenSpec's per-requirement delta format would otherwise force every rename or merge to copy every requirement body twice (once into `## REMOVED Requirements` of the old capability, once into `## ADDED Requirements` of the new capability), introducing hundreds-to-thousands of lines of duplicated text that obscure rather than reveal the change's intent — which is purely structural.

#### Scenario: Rename change uses tasks-driven move

- **GIVEN** a proposal that renames `pattern-expressions` to `patterns` with no requirement-content changes
- **WHEN** the change is reviewed against this requirement
- **THEN** the change SHALL drive the rename through `tasks.md` filesystem operations
- **AND** the change SHALL NOT contain `## ADDED Requirements` or `## REMOVED Requirements` blocks for the moved requirements
- **AND** the verification step SHALL confirm requirement bodies are byte-identical except for the spec's top-level title heading.

#### Scenario: Merge change uses tasks-driven absorption

- **GIVEN** a proposal that folds capability `migration-diff-display` into `migration-system` with no requirement-content changes
- **WHEN** the change is reviewed against this requirement
- **THEN** the change SHALL drive the merge through `tasks.md` filesystem operations: appending the absorbed requirement blocks into the surviving spec and removing the source directory
- **AND** the change SHALL NOT contain `## ADDED Requirements` blocks for the absorbed requirements in the surviving spec's delta, nor `## REMOVED Requirements` blocks in the source spec's delta
- **AND** the surviving Purpose section MAY be refreshed via a `MODIFIED Requirements` delta only if the refresh genuinely changes assertion content; cosmetic Purpose-prose updates SHALL go in `tasks.md`
- **AND** the verification step SHALL confirm absorbed requirement bodies are byte-identical in their new home.

#### Scenario: Rename or merge change does not bypass content review

- **GIVEN** a proposal that renames or merges a capability AND modifies any requirement body
- **WHEN** the change is reviewed
- **THEN** the body modification SHALL be expressed as a normal `## MODIFIED Requirements` delta in the surviving capability directory
- **AND** the rename or merge portion SHALL still be driven by `tasks.md`
- **AND** reviewers SHALL be able to distinguish the two intents at a glance.

### Requirement: Stable specs declare metadata in YAML frontmatter

Every stable spec under `openspec/specs/<capability>/spec.md` SHALL begin with a YAML frontmatter block delimited by `---` lines, placed before the level-one title heading. The frontmatter SHALL contain at least the following fields:

- `audience`: required string, value SHALL be exactly `user` or `contributor`.
- `bucket`: required string, value SHALL be one of the buckets enumerated in the "Each spec belongs to one documented bucket" requirement (using kebab-case identifiers: `rules-and-evaluation`, `facts`, `parsing`, `trust`, `loading`, `tracing-and-output`, `migration`, `cli`, `testing`, `contributor-internals`).
- `trust-relevant`: optional boolean, default `false`. SHALL be `true` exactly when the spec's requirements affect (a) which rules participate in evaluation, (b) which rules require approval, or (c) how rules are hashed for trust storage.

The combination `audience: user` with `bucket: contributor-internals` is contradictory and SHALL be rejected: a user-facing spec cannot be filed under the contributor-internals bucket.

A repository-level validator script SHALL parse the frontmatter of every file under `openspec/specs/*/spec.md` and fail on any of the following: missing frontmatter, unknown `audience` value, unknown `bucket` value, missing required field, or the contradictory `user`/`contributor-internals` combination. The validator SHALL be invoked as a pre-commit hook via `prek` so that violations block commits affecting `openspec/specs/`.

Delta-spec files under `openspec/changes/<change>/specs/<capability>/spec.md` SHALL NOT carry frontmatter — they describe deltas against an already-frontmattered stable spec and inherit metadata from the target.

#### Scenario: Spec without frontmatter rejected

- **GIVEN** a stable spec under `openspec/specs/foo/spec.md` whose first non-blank line is `# Foo Specification`
- **WHEN** the frontmatter validator runs
- **THEN** the validator SHALL report the spec as missing frontmatter
- **AND** the pre-commit hook SHALL exit non-zero

#### Scenario: Frontmatter with unknown audience rejected

- **GIVEN** a spec with frontmatter `audience: internal`
- **WHEN** the validator runs
- **THEN** the validator SHALL report `audience must be 'user' or 'contributor'`
- **AND** the commit SHALL be blocked

#### Scenario: Contradictory audience-bucket pairing rejected

- **GIVEN** a spec with frontmatter `audience: user` and `bucket: contributor-internals`
- **WHEN** the validator runs
- **THEN** the validator SHALL report the combination as invalid and reference the requirement that forbids it
- **AND** the commit SHALL be blocked

#### Scenario: Trust-relevant field controls trust-relevance signalling

- **GIVEN** a spec whose requirements affect rule hashing
- **WHEN** the spec is reviewed against this requirement
- **THEN** its frontmatter SHALL contain `trust-relevant: true`
- **AND** the Purpose section SHALL cross-reference the relevant trust-model spec(s) in prose

#### Scenario: Delta spec carries no frontmatter

- **GIVEN** a change proposal whose `openspec/changes/<change>/specs/spec-conventions/spec.md` begins with `## MODIFIED Requirements`
- **WHEN** the validator runs over `openspec/changes/**`
- **THEN** the validator SHALL skip the delta file
- **AND** the absence of frontmatter SHALL NOT be reported as an error

### Requirement: User-facing spec deltas require a REFERENCE.md consideration task

A change with a user-facing spec delta SHALL include a `tasks.md` task naming `REFERENCE.md`. Concretely, when a delta under `openspec/changes/<change>/specs/<capability>/spec.md` adds or modifies a requirement (`## ADDED Requirements` or `## MODIFIED Requirements`) for a user-facing capability, the change's `tasks.md` SHALL contain at least one task whose text names `REFERENCE.md`. This guards the shipped user manual: REFERENCE.md is compiled into the binary (`src/cmd_help.rs`, via `include_str!`) and rendered by `may-i reference`, so a surface change that skips it ships a stale manual — and an *already-documented* form whose meaning changed is invisible to automated example checks. The task SHALL be a *consideration* task: it is satisfied by either editing REFERENCE.md or by recording an explicit "verified, no surface change" resolution. The validator enforces the task's **presence**, not its resolution; the honesty of a "verified, no change" resolution is a review concern.

A capability is user-facing for this purpose when its stable spec (`openspec/specs/<capability>/spec.md`) declares `audience: user`. When no stable spec exists yet (a new capability), the capability SHALL be treated as user-facing unless its bucket is `contributor-internals`. A delta that only removes requirements (`## REMOVED Requirements`) or makes structural edits SHALL NOT trigger the requirement.

The requirement applies once the change has a `tasks.md`. A change with a user-facing delta but no `tasks.md` (a proposal-stage change, not yet apply-ready under `applyRequires`) SHALL NOT be flagged; the gate fires when `tasks.md` is authored.

This requirement is enforced by `scripts/validate-change-doc-sync.sh`, a sibling of `scripts/validate-spec-frontmatter.sh`, wired into prek scoped to `^openspec/changes/`.

#### Scenario: User-facing add without a REFERENCE.md task is rejected

- **GIVEN** a change with `specs/patterns/spec.md` containing `## ADDED Requirements`
- **AND** the stable spec `openspec/specs/patterns/spec.md` declares `audience: user`
- **AND** the change's `tasks.md` contains no line naming `REFERENCE.md`
- **WHEN** `scripts/validate-change-doc-sync.sh` runs over the change
- **THEN** it SHALL fail and name the change and the missing task

#### Scenario: Consideration task satisfies the gate

- **GIVEN** the same user-facing `## ADDED Requirements` delta
- **AND** the change's `tasks.md` contains a task naming `REFERENCE.md` (whether an edit or a "verified, no surface change" note)
- **WHEN** the validator runs
- **THEN** it SHALL pass

#### Scenario: Contributor-only delta does not trigger the gate

- **GIVEN** a change whose only delta is `specs/spec-conventions/spec.md` with `## ADDED Requirements`
- **AND** the stable spec `openspec/specs/spec-conventions/spec.md` declares `audience: contributor`
- **WHEN** the validator runs
- **THEN** it SHALL pass even with no REFERENCE.md task

#### Scenario: Removal-only delta does not trigger the gate

- **GIVEN** a change whose user-facing delta contains only `## REMOVED Requirements`
- **WHEN** the validator runs
- **THEN** it SHALL pass even with no REFERENCE.md task

#### Scenario: Proposal-stage change with no tasks.md is not flagged

- **GIVEN** a change with a user-facing `## ADDED Requirements` delta but no `tasks.md`
- **WHEN** the validator runs
- **THEN** it SHALL pass, deferring the gate until `tasks.md` is authored
