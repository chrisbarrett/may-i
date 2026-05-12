## ADDED Requirements

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

## MODIFIED Requirements

### Requirement: User-facing and contributor-facing specs do not mix audiences

A spec SHALL be either *user-facing* (covering observable behaviour: the DSL surface, decisions, traces, CLI output, configuration semantics) or *contributor-facing* (covering internals: type-level invariants, code quality, parser/engine span contracts, testing strategy, these conventions). User-facing specs SHALL use the user vocabulary documented in `CONTEXT.md` (Rule, Decision, Pattern, Fact, Trust, Authorise, Tail, Style, Parser). Contributor-facing specs MAY use internal vocabulary (`Effect`, `Predicate`, `ArgPattern`, `Expr<T>`, span/source-text terms).

A user-facing spec SHALL NOT introduce internal vocabulary into requirements or scenarios. Every spec SHALL declare its audience via the `audience` field in its YAML frontmatter (see "Stable specs declare metadata in YAML frontmatter"); the legacy convention of declaring audience in prose ("contributor-only" / "internal") is no longer the source of truth and SHOULD be removed when a spec is touched, in favour of the frontmatter field.

#### Scenario: User-facing spec uses user vocabulary

- **GIVEN** a spec named `rule-decisions` documenting how decisions combine
- **WHEN** the spec is reviewed
- **THEN** requirements refer to "Decisions" and "Rules", not `Effect::Terminal` or `Decision::Ask`
- **AND** the spec's frontmatter contains `audience: user`

#### Scenario: Contributor spec declares its audience in frontmatter

- **GIVEN** a contributor-only spec (`code-quality`, `parser-engine-invariants`, `spec-conventions`)
- **WHEN** the spec is opened
- **THEN** the frontmatter contains `audience: contributor`
- **AND** the Purpose section MAY additionally name the contributor audience in prose for human readers, but this is not the authoritative declaration

### Requirement: Trust-relevance is declared in frontmatter

A spec whose requirements affect (a) which rules participate in evaluation, (b) which rules require approval, or (c) how rules are hashed for trust storage, SHALL set `trust-relevant: true` in its YAML frontmatter (see "Stable specs declare metadata in YAML frontmatter"). The Purpose section SHALL additionally cross-reference the relevant trust-model spec(s) in prose so a human reader can navigate to them.

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
