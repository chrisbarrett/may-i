## MODIFIED Requirements

### Requirement: Each spec belongs to one documented bucket

Every spec under `openspec/specs/` SHALL fit into exactly one bucket. The set of buckets is documented in `openspec/config.yaml` under `context:` (kebab-case identifiers). The first four buckets correspond to the four-layer model documented in `CONTEXT.md` (Rules, Facts, Parsing, Trust) and are treated as the spine of the spec set; the remaining buckets cover cross-cutting and contributor-only concerns.

A spec that does not fit any documented bucket SHALL justify a new bucket in its proposing change's `design.md` and amend `openspec/config.yaml` in the same change.

The bucket value SHALL be declared via the `bucket:` field in the spec's YAML frontmatter (see "Stable specs declare metadata in YAML frontmatter") and SHALL be checked by the frontmatter validator (`scripts/validate-spec-frontmatter.sh`).

#### Scenario: New spec fits an existing bucket

- **GIVEN** a proposal adding a spec named `wrapper-tail-recursion`
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
