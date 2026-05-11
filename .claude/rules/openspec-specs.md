---
paths:
  - "openspec/specs/**"
  - "openspec/changes/**"
---

Authority: `openspec/specs/spec-conventions/spec.md`. Read first.

Spec-touching edit checklist:

1. Stable spec uses `# X Specification` / `## Purpose` / `## Requirements` / `### Requirement: ...` / `#### Scenario: ...`. Delta headings (`## ADDED/MODIFIED/REMOVED Requirements`) only under `openspec/changes/*/specs/`.
2. Spec fits one bucket: Rules-and-Evaluation, Facts, Parsing, Trust, Loading, Tracing-and-Output, Migration, CLI, Testing, Contributor-Internals. New bucket → design.md decision.
3. User-facing specs use `CONTEXT.md` user vocabulary (Rule, Decision, Pattern, Fact, Trust, Authorise, Tail, Style, Parser) — *including in the spec's directory name / capability identifier*, not only its prose. Contributor specs may use internals (`Effect`, `Predicate`, `ArgPattern`, `Expr<T>`) and declare audience in Purpose; their names MAY use contributor vocabulary. The meta-spec `spec-conventions` is exempt by name.
4. Trust-relevant specs (affect what runs / what gets approved / how rules are hashed) include `Trust-relevant: yes` in Purpose and cross-ref the trust-model spec(s).
5. <2 requirements or <40 lines → fold into parent unless Purpose justifies standalone. Overlap → cross-reference, not restatement.
6. No `TBD` in Purpose. Archive-generated stubs filled before merge.

Existing violations: don't fix inline; open a hygiene change proposal citing `spec-conventions`.
