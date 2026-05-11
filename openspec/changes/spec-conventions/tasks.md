## 1. Author the spec

- [x] 1.1 Draft `openspec/changes/spec-conventions/specs/spec-conventions/spec.md` with the seven requirements (heading structure, bucket assignment, audience split, trust-relevance declaration, granularity threshold, TBD ban, pre-merge checklist)
- [x] 1.2 Confirm the spec itself conforms to the rules it prescribes: change-side artefact uses `## ADDED Requirements` per openspec delta convention (correct under `openspec/changes/`); each requirement uses `SHALL`/`MUST` and is followed by at least one `#### Scenario`. Archive-time Purpose text is staged below (task 4.2) so the live spec lands with a written Purpose and avoids the TBD that this spec forbids
- [x] 1.3 Cross-reference CONTEXT.md from both the bucket-assignment requirement (first four buckets = the four-layer model) and the audience-split requirement (user vocabulary list)

## 2. Add the path-scoped rule

- [x] 2.1 Create `.claude/rules/openspec-specs.md` with YAML frontmatter `paths: ["openspec/specs/**", "openspec/changes/**"]`
- [x] 2.2 Body of the rule: pointer at the spec plus six-item checklist (item 7 from spec is checklist-gate meta and was dropped from the rule body as tautological)
- [x] 2.3 Rule fires confirmed in this apply session — system-reminder loaded the rule body when the spec file was read

## 3. Validate against existing specs

- [x] 3.1 Pre-merge checklist applied to three representative specs. Findings:
  - `dsl-form-list-syntax` (user-facing, canonical-form): item 6 catches Purpose beginning `TBD — established by the dsl-coherence change …`
  - `code-quality` (contributor, canonical-form): item 1 catches missing `# X Specification` heading and missing `## Purpose`; item 3 catches contributor audience not declared in (missing) Purpose
  - `opencode-context` (delta-form): item 1 catches `## MODIFIED Requirements` at top level of a stable spec
- [x] 3.2 No tightening required — every known issue in the audited specs is surfaced by at least one checklist item
- [x] 3.3 No contradictions with CONTEXT.md. First four buckets map to the four-layer model (Rules, Facts, Parsing, Trust); user vocabulary list matches; CLI bucket items align with the invocation modes section; contributor vocab is a non-exhaustive subset of CONTEXT.md's contributor table (Define, Provenance, Canonical form, Invocation mode also appear there — not contradictory, just additional)

## 4. Land

- [x] 4.1 Merge the worktree branch into main locally
- [ ] 4.2 Before running `openspec archive`, write the live Purpose section — auto-archive will otherwise insert `TBD - created by archiving change spec-conventions. Update Purpose after archive.`, which violates this spec's own requirement 6. Use the following Purpose text:

  ```
  # spec-conventions Specification

  ## Purpose

  Contributor-only. Document the conventions for authoring specs under
  `openspec/specs/`: heading structure, bucket assignment, audience
  separation, trust-relevance declaration, granularity threshold, the
  TBD ban, and the pre-merge checklist every spec-touching change
  applies. The first four buckets correspond to the four-layer model
  in `CONTEXT.md` (Rules, Facts, Parsing, Trust).
  ```

- [ ] 4.3 First follow-on change proposal (`spec-hygiene-pass`) opens citing this spec's requirements; that proposal does the broad cleanup (TBD purposes, delta-format headings, spec mergers) batch by batch
