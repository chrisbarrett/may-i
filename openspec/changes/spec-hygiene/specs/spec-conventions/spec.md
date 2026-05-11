## ADDED Requirements

### Requirement: Spec names use user vocabulary

A stable spec under `openspec/specs/<capability>/spec.md` SHALL choose its
capability identifier (the directory name) from the user vocabulary
documented in `CONTEXT.md` (Rule, Decision, Pattern, Fact, Trust, Authorise,
Tail, Style, Parser, Reason, Binding) and from neutral domain words that do
not collide with the contributor vocabulary table (Effect, Predicate,
ArgPattern, Expr, Provenance, Canonical form, Invocation mode, Wordpart,
Span). A spec name SHALL NOT include any term from the contributor
vocabulary unless one of the exemptions below applies.

Two exemptions:

1. **The meta-spec `spec-conventions` itself** is exempt — it documents
   conventions and is named after that purpose.
2. **Contributor-only specs** that declare their audience in their Purpose
   (per the audience requirement above) are exempt: their name MAY use
   contributor vocabulary, because the audience declaration warns the
   reader.

This requirement applies to stable specs only. Change deltas under
`openspec/changes/<change>/specs/<capability>/spec.md` follow the name of
their target spec; renaming happens through proposals that move
requirements between specs.

#### Scenario: User-facing spec named with contributor vocabulary fails review

- **GIVEN** a proposal that adds a stable spec `expr-combinator-matching`
  whose audience is users
- **WHEN** the pre-merge checklist runs
- **THEN** the spec name SHALL be flagged: `Expr` is contributor vocabulary
- **AND** the proposal SHALL rename the spec to use user vocabulary
  (e.g. `patterns`) before merge.

#### Scenario: Contributor spec named with contributor vocabulary passes

- **GIVEN** a stable spec `parser-engine-invariants` whose Purpose section
  begins `Contributor-only.`
- **WHEN** the pre-merge checklist runs
- **THEN** the contributor-vocabulary terms in the name (`engine`,
  `invariants`) SHALL NOT be flagged
- **AND** the spec MAY retain its name.

#### Scenario: Meta-spec name passes by exemption

- **GIVEN** the meta-spec `spec-conventions`
- **WHEN** the pre-merge checklist runs
- **THEN** its name SHALL NOT be flagged even though `spec` is not in the
  user vocabulary table
- **AND** no further justification is required.
