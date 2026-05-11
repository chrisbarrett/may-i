## ADDED Requirements

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

Every spec under `openspec/specs/` SHALL fit into one of the following buckets. The bucket SHALL be implicit in the spec's name and Purpose; an explicit field is not required. A spec that does not fit any bucket SHALL justify a new bucket in its Purpose paragraph before merge.

The first four buckets correspond to the four-layer model documented in `CONTEXT.md` (Rules, Facts, Parsing, Trust) and SHALL be treated as the spine of the spec set. The remaining buckets cover cross-cutting and contributor-only concerns.

Buckets:

- **Rules-and-Evaluation** — how rules combine, how decisions reach a verdict, the security lattice
- **Facts** — fact storage, fact queries, `--fact` CLI surface, automatic facts like `:via`
- **Parsing** — argv tokenisation, the surface DSL, pattern matchers, parser declarations, prelude parsers, shell-command parsing
- **Trust** — provenance, hashing, the trust store, the gate, the trust CLI surface, advisories
- **Loading** — `(load …)` directive, repo-local discovery
- **Tracing-and-Output** — trace rendering, pretty-printing, segment colourisation, JSON output shape
- **Migration** — config-file rewrites, classification, diff display, migration tests
- **CLI** — `may-i eval`, `may-i check`, `may-i fmt`, hook mode, stdin handling
- **Testing** — strategy, property-test obligations, test harness
- **Contributor-Internals** — invariants, code-quality rules, spec conventions; not user-facing behaviour

#### Scenario: New spec fits an existing bucket

- **GIVEN** a proposal adding a spec named `wrapper-tail-recursion`
- **WHEN** the bucket assignment is reviewed
- **THEN** the spec SHALL be filed under **Parsing** with no new bucket required

#### Scenario: New spec proposes a new bucket

- **GIVEN** a proposal adding a spec for behaviour that does not fit any documented bucket
- **WHEN** the change is opened
- **THEN** the spec's Purpose section SHALL explain why an existing bucket is wrong
- **AND** the design.md SHALL include a "Decision: new bucket X" entry

### Requirement: User-facing and contributor-facing specs do not mix audiences

A spec SHALL be either *user-facing* (covering observable behaviour: the DSL surface, decisions, traces, CLI output, configuration semantics) or *contributor-facing* (covering internals: type-level invariants, code quality, parser/engine span contracts, testing strategy, these conventions). User-facing specs SHALL use the user vocabulary documented in `CONTEXT.md` (Rule, Decision, Pattern, Fact, Trust, Authorise, Tail, Style, Parser). Contributor-facing specs MAY use internal vocabulary (`Effect`, `Predicate`, `ArgPattern`, `Expr<T>`, span/source-text terms).

A user-facing spec SHALL NOT introduce internal vocabulary into requirements or scenarios. A contributor-facing spec SHOULD state its audience in its Purpose ("contributor-only" / "internal").

#### Scenario: User-facing spec uses user vocabulary

- **GIVEN** a spec named `rule-evaluation` documenting how decisions combine
- **WHEN** the spec is reviewed
- **THEN** requirements refer to "Decisions" and "Rules", not `Effect::Terminal` or `Decision::Ask`

#### Scenario: Contributor spec declares its audience

- **GIVEN** a contributor-only spec (`code-quality`, `parser-engine-invariants`, `spec-conventions`)
- **WHEN** the spec is read
- **THEN** the Purpose section names the contributor audience explicitly

### Requirement: Trust-relevance is declared in the Purpose

A spec whose requirements affect (a) which rules participate in evaluation, (b) which rules require approval, or (c) how rules are hashed for trust storage, SHALL include the literal line `Trust-relevant: yes` in its Purpose section, followed by a cross-reference to the relevant trust-model spec(s).

A spec that does not affect trust state SHOULD omit the line. Authors uncertain whether their spec is trust-relevant SHOULD include the line and let review confirm.

#### Scenario: Trust-relevant spec declares it

- **GIVEN** a spec that changes how rules are aggregated for hashing
- **WHEN** the spec is opened
- **THEN** the Purpose section contains `Trust-relevant: yes` and names the trust spec it interacts with

#### Scenario: Non-trust spec omits the line

- **GIVEN** a spec for human-readable trace layout
- **WHEN** the spec is opened
- **THEN** the Purpose section does not contain `Trust-relevant: yes`

### Requirement: Specs meet a granularity threshold or fold into a parent

A spec under `openspec/specs/` SHOULD contain at least two requirements OR span at least ~40 lines of substantive content (excluding heading and Purpose). Specs below this threshold SHALL either fold into a parent spec or document in their Purpose why standalone status is justified (typically: a small invariant that other specs depend on by reference).

A new spec MUST cross-reference any existing spec covering related behaviour rather than restating overlapping requirements. Silent overlap is a defect; explicit cross-reference is correct.

#### Scenario: Thin spec folds into parent

- **GIVEN** a proposal adding a single-requirement spec for `--` flag-stop behaviour
- **WHEN** the review applies this requirement
- **THEN** the requirement SHALL be folded into the existing `pattern-expressions` spec
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
3. Each spec is either user-facing or contributor-facing; audience is consistent across requirements and scenarios; contributor specs declare their audience in Purpose.
4. Trust-relevant specs declare `Trust-relevant: yes` and cross-reference the trust-model spec(s).
5. New specs meet the granularity threshold or justify standalone status.
6. No Purpose section contains `TBD`.
7. Cross-references to overlapping specs are explicit; silent restatement is removed.

#### Scenario: Checklist surfaces in the rule

- **WHEN** an agent reads or edits a file under `openspec/specs/**` or `openspec/changes/**`
- **THEN** the agent has loaded `.claude/rules/openspec-specs.md`
- **AND** the rule directs the agent to this spec
- **AND** the agent applies the seven-point checklist before completing the edit

#### Scenario: Checklist failure blocks merge

- **GIVEN** a change proposal that adds a stable spec with `## ADDED Requirements` at top level
- **WHEN** the pre-merge checklist runs
- **THEN** item (1) flags the spec
- **AND** the change SHALL NOT merge until the headings are rewritten
