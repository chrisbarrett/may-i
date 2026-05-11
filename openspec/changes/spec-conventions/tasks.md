## 1. Author the spec

- [ ] 1.1 Draft `openspec/changes/spec-conventions/specs/spec-conventions/spec.md` with the seven requirements (heading structure, bucket assignment, audience split, trust-relevance declaration, granularity threshold, TBD ban, pre-merge checklist)
- [ ] 1.2 Confirm the spec itself conforms to the rules it prescribes: canonical heading structure, Purpose is one sentence with no TBD, requirements use `SHALL`/`MUST`, each requirement has at least one `#### Scenario`
- [ ] 1.3 Cross-reference CONTEXT.md from the audience-split and bucket-assignment requirements so the vocabulary is anchored to a single source

## 2. Add the path-scoped rule

- [ ] 2.1 Create `.claude/rules/openspec-specs.md` with YAML frontmatter `paths: ["openspec/specs/**", "openspec/changes/**"]`
- [ ] 2.2 Body of the rule: one-paragraph pointer at `openspec/specs/spec-conventions/spec.md`, plus a bulleted teaser of the seven requirement names
- [ ] 2.3 Verify the rule fires by reading any file under `openspec/specs/` in a fresh session and checking the rule content appears in context

## 3. Validate against existing specs

- [ ] 3.1 Run the pre-merge checklist mentally against three representative existing specs (one user-facing, one contributor, one in delta format) and confirm the checklist surfaces the known issues
- [ ] 3.2 If the checklist fails to flag an obvious issue (e.g. doesn't catch delta-format headings on a stable spec), tighten the relevant requirement before merge
- [ ] 3.3 Confirm the conventions do not contradict CONTEXT.md (vocabulary, four-layer model, invocation modes)

## 4. Land

- [ ] 4.1 Open the change as a PR; reviewer is the maintainer
- [ ] 4.2 On merge, openspec archive moves the spec to `openspec/specs/spec-conventions/spec.md`
- [ ] 4.3 First follow-on change proposal (`spec-hygiene-pass`) opens citing this spec's requirements; verify the citation works as intended in practice
