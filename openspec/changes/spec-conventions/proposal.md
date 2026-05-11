## Why

The spec set has sprawled to 50 specs (~5000 lines) with three structural problems: (1) 22 stable specs still use delta-style `## ADDED/MODIFIED Requirements` headings that belong only in `openspec/changes/*/specs/`; (2) ~17 specs carry literal `TBD` Purpose stubs left over from auto-archive; (3) thin specs (under 40 lines, single requirement) proliferate alongside near-duplicates because there is no documented merge threshold. Two specs (`arg-tokenisation`, `config-load-surface`) are fully superseded but still listed. One (`review-followup`) is a meta task list misfiled as a capability.

The root cause is that the rules for writing specs are nowhere written down. CONTEXT.md gives the domain vocabulary and the four-layer model but says nothing about spec format, granularity, or audience splits. Each new change inherits the format of whatever change archived most recently, which is how delta headings drift into the stable set.

This change writes the rules down once and uses Claude Code's path-scoped rules to surface them to any agent touching `openspec/`.

## What Changes

- Add a new contributor-only capability `spec-conventions` documenting: heading structure, four-layer bucket assignment, user-vs-contributor audience split, trust-relevance declaration, granularity threshold, TBD ban, pre-merge checklist.
- Add `.claude/rules/openspec-specs.md` with `paths: ["openspec/specs/**", "openspec/changes/**"]` frontmatter so Claude Code agents auto-load the conventions whenever they read or edit specs.
- Existing specs are NOT rewritten in this change. Subsequent change proposals (`spec-hygiene-pass`, `consolidate-thin-specs`, post-in-flight merges) cite `spec-conventions` as the authority and bring specs into compliance batch by batch.

No user-facing behaviour changes. No CLI, config, or wire-format changes. Code is untouched.

## Capabilities

### New Capabilities

- `spec-conventions`: contributor-only capability defining the format, organisation, and merge rules for `openspec/specs/`. Joins the existing contributor-only capabilities (`code-quality`, `testing-strategy`, `parser-engine-invariants`).

### Modified Capabilities

(none)

## Impact

- `openspec/specs/spec-conventions/spec.md` — new spec (created on archive of this change).
- `.claude/rules/openspec-specs.md` — new file; path-scoped rule pointing agents at the conventions spec when editing under `openspec/`.
- `AGENTS.md` — optional one-line cross-reference to `spec-conventions` from the section on writing changes. Out of scope for this proposal if it adds noise; can be done later.
- No code changes. No dependency changes. No public API changes.

## Non-Goals

- Rewriting the 22 specs that use delta-style headings, the 17 with TBD purposes, or the thin-spec list. Those are separate change proposals that cite this one.
- Defining buckets beyond what already exists implicitly. The four-layer model (Rules, Facts, Parsing, Trust) plus the supporting buckets (Tracing, Migration, CLI, Testing, Contributor-Internals) is documented as-found, not re-architected.
- Restricting `openspec/specs/` to capability specs only. The `README.md`-style overview spot in `openspec/specs/` is not in scope; this change uses the capability-spec form for consistency with `code-quality` etc.
